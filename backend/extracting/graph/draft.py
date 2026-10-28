"""Brouillon du graphe d'un article et sa vérification STIX 2.1, plus la recherche dans ATT&CK v20.0 offerte au modèle.

    search_attack(query, tactic?)  techniques qui correspondent à un comportement (index FTS5, quelques ms)
    get_attack(id)                 fiche d'une technique, d'un groupe, d'un logiciel ou d'une campagne ATT&CK

La vérification STIX est celle de la bibliothèque `stix2` : chaque entité et chaque relation proposée est CRÉÉE par sa classe
`stix2` (`Malware`, `Relationship`…) en mode strict, et l'exception éventuelle (propriété manquante ou inconnue, valeur
invalide) revient au modèle telle quelle. S'y ajoutent deux contrôles qui ne relèvent pas de STIX :
- ATT&CK : un identifiant doit exister dans la v20.0 (révoqué -> remplaçant) ; une technique, un groupe ou un logiciel connu
  d'ATT&CK est l'objet officiel de MITRE, pas une copie ;
- le texte : les phrases citées existent et nomment le logiciel, la CVE ou la victime reliés. Le texte d'une preuve est relu
  par le code à partir des numéros de phrase : il est exact par construction.
"""

import re
from dataclasses import dataclass, field

from stix2 import ExternalReference
from stix2.exceptions import STIXError
from stix2.v21.vocab import INDUSTRY_SECTOR

from backend.extracting.stix.attack import AttackKB, attack_id, get_attack_kb
from backend.extracting.stix.objects import ENTITY_CLASSES, ArticleContext, entity, relationship

from backend.preprocessing.cleaning.text.evidence import confidence_from_text, mentions, normalize_name
from backend.extracting.graph.places import resolve_location
from backend.preprocessing.cleaning.text.segment import Unit

# Extrémités qui peuvent rester implicites dans la phrase citée : l'acteur (« les opérateurs », « il ») et la technique
# (la phrase décrit le comportement, elle ne nomme pas la technique ATT&CK)
_IMPLICIT = frozenset({"intrusion-set", "threat-actor", "campaign", "attack-pattern"})
_ATTACK_TYPES = {"intrusion-set": ("intrusion-set", "threat-actor"), "threat-actor": ("intrusion-set", "threat-actor"), "malware": ("malware", "tool"), "tool": ("malware", "tool"), "campaign": ("campaign",)}
_TYPE_WORDS = frozenset(ENTITY_CLASSES) | {"attack-pattern", "technique"}
_TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.I)
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
# Une valeur technique (adresse, domaine, URL, hachage) est un IOC, extrait par règles, jamais une entité nommée
_OBSERVABLE = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[a-f0-9]{32,64}|https?://\S+|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|ru|cn|info|xyz|top|cc|biz))$", re.I)
_ADVERSARY_SIDE = frozenset({"intrusion-set", "threat-actor", "campaign", "malware", "tool", "infrastructure"})
CONTEXT_SENTENCES = 3  # phrases précédentes de la même section admises pour retrouver l'entité désignée par « il », « ce malware »
MAX_HITS = 6


def stix_type_of(raw: str) -> str:
    return raw.strip().lower().replace("_", "-").replace(" ", "-")


def relationship_type_of(raw: str) -> str:
    return re.sub(r"[\s_]+", "-", raw.strip().lower())


# --- Connaissance ATT&CK ------------------------------------------------------------------------------------------------
def search_attack(kb: AttackKB, query: str, tactic: str | None = None, limit: int = MAX_HITS) -> str:
    tactics = {t for t, _ in kb.tactics()}
    note = ""
    if tactic and tactic not in tactics:
        note, tactic = f"(tactique « {tactic} » inconnue, recherche sans filtre)\n", None
    hits = kb.search_techniques(query, tactic, limit=limit)
    if not hits:
        return note + "Aucune technique trouvée : reformule avec des mots du comportement (en anglais, vocabulaire ATT&CK)."
    return note + "\n".join(h.line() for h in hits)


def search_attack_many(kb: AttackKB, queries: list, limit: int = MAX_HITS) -> str:
    """Plusieurs recherches en un appel : toutes celles d'un passage tiennent en un tour du modèle au lieu d'un tour chacune.
    Chaque requête est « texte » ou {"query": texte, "tactic": tactique}."""
    blocks = []
    for q in queries:
        query, tactic = (q.get("query", ""), q.get("tactic") or None) if isinstance(q, dict) else (q, None)
        query = str(query).strip()
        if query:
            blocks.append(f"« {query} » :\n{search_attack(kb, query, tactic, limit)}")
    return "\n\n".join(blocks) or "Aucune requête : donner la liste des comportements à chercher (en anglais)."


def get_attack(kb: AttackKB, aid: str, max_chars: int = 700) -> str:
    obj = kb.get(aid)
    if obj is None:
        return f"{aid} n'existe pas dans ATT&CK v{kb.version}."
    head = f"{obj['attack_id']} {obj['full_name']} ({obj['type']}, {obj['status']})"
    if obj["status"] != "active":
        return head + (f" : remplacé par {obj['replaced_by']}" if obj["replaced_by"] else " : ne plus l'employer")
    lines = [head]
    if obj["tactics"]:
        lines.append("Tactiques : " + ", ".join(obj["tactics"]))
    if obj["aliases"]:
        lines.append("Alias : " + ", ".join(obj["aliases"][:12]))
    desc = obj["description"]
    lines.append(desc if len(desc) <= max_chars else desc[:max_chars].rsplit(" ", 1)[0] + "…")
    if obj["type"] == "attack-pattern":
        if obj["parent"]:
            parent = kb.get(obj["parent"])
            lines.append(f"Technique parente : {obj['parent']} {parent['name'] if parent else ''}")
        subs = kb.subtechniques(obj["attack_id"])
        if subs:
            lines.append("Sous-techniques : " + " ; ".join(f"{i} {n}" for i, n in subs))
    return "\n".join(lines)


def parse_relation(line: str) -> tuple[str, str, str, str] | None:
    """(source, relation, cible, numéros) d'une ligne « source|relation|cible|12,13 ». Les types que le modèle intercale
    (« software|FortiOS|has|vulnerability|CVE-2018-13379|1,9 ») sont retirés."""
    parts = [p.strip() for p in str(line).split("|") if p.strip()]
    if len(parts) < 4 or not re.fullmatch(r"[\d,;\s\-]+", parts[-1]):
        return None
    body = [p for p in parts[:-1] if stix_type_of(p) not in _TYPE_WORDS]
    if len(body) != 3:
        return None
    return body[0], relationship_type_of(body[1]), body[2], parts[-1]


def _error(exc: Exception) -> str:
    return f"{type(exc).__name__} : {exc}"


# --- Brouillon de graphe vérifié ------------------------------------------------------------------------------------------
@dataclass
class DraftGraph:
    """Graphe d'un article en construction : seules y entrent les entités et relations qui passent la vérification."""

    units: list[Unit]
    ctx: ArticleContext
    attack: AttackKB = field(default_factory=get_attack_kb)
    objects: dict[str, object] = field(default_factory=dict)  # identifiant STIX -> objet stix2 (entité ou objet ATT&CK)
    specs: dict[str, tuple[str, str, dict]] = field(default_factory=dict)  # entités du projet : (type, nom, propriétés)
    terms: dict[str, set[str]] = field(default_factory=dict)  # identifiant STIX -> noms qui la désignent dans le texte
    names: dict[str, str] = field(default_factory=dict)  # nom normalisé, alias ou identifiant ATT&CK -> identifiant STIX
    evidence: dict[tuple[str, str, str], list[str]] = field(default_factory=dict)  # (source, relation, cible) -> citations
    log: list[str] = field(default_factory=list)  # corrections et refus, pour le rapport
    hallucinated: list[str] = field(default_factory=list)  # identifiants ATT&CK proposés absents de la v20.0

    def __post_init__(self):
        self.by_uid = {u.uid: u for u in self.units}
        self.publisher_key = normalize_name(self.ctx.publisher.name)

    def type_of(self, sid: str) -> str:
        return self.objects[sid]["type"]

    def name_of(self, sid: str) -> str:
        return self.objects[sid].get("name", sid)

    # --- Entités ----------------------------------------------------------------------------------------------------------
    def _register(self, obj, terms: set[str]) -> str:
        sid = obj["id"]
        self.objects.setdefault(sid, obj)
        self.terms.setdefault(sid, set()).update(t for t in terms if t)
        for t in self.terms[sid] | {obj.get("name", ""), *(obj.get("aliases") or [])}:
            if normalize_name(t):
                self.names.setdefault(normalize_name(t), sid)
        if attack_id(obj):
            self.names.setdefault(attack_id(obj).upper(), sid)
        return sid

    def _attack_object(self, aid: str, terms: set[str]) -> tuple[str | None, str | None]:
        """Objet ATT&CK officiel (`stix2.parse` du bundle MITRE) ; refus s'il est absent de la v20.0 ou déprécié."""
        aid = aid.strip().upper()
        status, replaced = self.attack.status(aid)
        if status == "unknown":
            self.hallucinated.append(aid)
            return None, f"{aid} n'existe pas dans ATT&CK v{self.attack.version} : le chercher avec search_attack"
        if status == "revoked" and replaced:
            self.log.append(f"fix {aid} révoqué -> {replaced}")
            aid = replaced
        elif status != "active":
            return None, f"{aid} est {status} dans ATT&CK v{self.attack.version} : choisir un objet actif"
        return self._register(self.attack.stix_object(aid), terms | {aid}), None

    def technique(self, aid: str) -> tuple[str | None, str | None]:
        return self._attack_object(aid, set())

    def declare(self, line: str) -> tuple[str | None, str | None]:
        """« type|nom » (« software|nom|éditeur », « location|nom|code pays », « type|nom|alias1;alias2 »). Retourne
        (identifiant STIX, refus)."""
        parts = [p.strip() for p in str(line).split("|")]
        if len(parts) < 2 or not parts[1]:
            return None, f"« {line} » : format attendu type|nom"
        stix_type, name = stix_type_of(parts[0]), parts[1]
        extra = parts[2] if len(parts) > 2 else ""
        if stix_type in ("attack-pattern", "technique") or _TECHNIQUE.match(name):
            found = re.search(r"T\d{4}(?:\.\d{3})?", line, re.I)
            if not found:
                return None, f"« {line} » : une technique se désigne par son identifiant ATT&CK (search_attack), pas par un nom"
            return self.technique(found.group(0))
        if stix_type not in ENTITY_CLASSES:
            return None, f"« {line} » : type {parts[0]!r} hors périmètre (types : {', '.join(ENTITY_CLASSES)}) ; les IOC ne sont pas extraits"
        if _OBSERVABLE.match(name):
            return None, f"« {line} » : « {name} » est un IOC (adresse, domaine, URL, hachage), extrait par ailleurs"
        if stix_type in _ADVERSARY_SIDE and normalize_name(name) == self.publisher_key:
            return None, f"« {line} » : « {name} » est l'auteur du rapport, pas un composant de l'attaque"

        # Nom connu d'ATT&CK sous un type compatible : l'objet officiel de MITRE
        if stix_type in _ATTACK_TYPES:
            hits = [h for h in self.attack.lookup(name) if h["status"] == "active" and h["type"] in _ATTACK_TYPES[stix_type]]
            if len(hits) == 1:
                return self._attack_object(hits[0]["attack_id"], {name, *[a.strip() for a in extra.split(";") if a.strip()]})

        props: dict = {}
        if stix_type == "software" and extra:
            props["vendor"] = extra
        elif stix_type == "vulnerability":
            cve = _CVE.search(name) or _CVE.search(extra)
            if cve:
                name = cve.group(0).upper()
                props["external_references"] = [ExternalReference(source_name="cve", external_id=name)]
        elif stix_type == "location":
            country, region = resolve_location(name, extra)
            if not (country or region):
                return None, f"« {line} » : ni pays (ISO 3166-1) ni région STIX reconnus pour « {name} »"
            props.update({"country": country} if country else {"region": region})
        elif stix_type == "identity":
            sector = re.sub(r"[^a-z0-9]+", "-", name.casefold()).strip("-")
            if sector in INDUSTRY_SECTOR:  # « government », « technology » : un secteur du vocabulaire STIX
                props.update(identity_class="class", sectors=[sector])
        elif extra:
            props["aliases"] = [a.strip() for a in extra.split(";") if a.strip()]
        try:
            obj = entity(stix_type, name, self.ctx, **props)
        except (STIXError, ValueError) as exc:
            return None, f"« {line} » refusée par stix2 : {_error(exc)}"
        known = self.specs.get(obj["id"])
        if known and props.get("aliases"):  # même entité redéclarée avec de nouveaux alias : recréée avec leur union
            merged = sorted(set(known[2].get("aliases", [])) | set(props["aliases"]))
            obj = entity(stix_type, known[1], self.ctx, **{**known[2], "aliases": merged})
            self.objects[obj["id"]] = obj
            props = {**known[2], "aliases": merged}
        self.specs[obj["id"]] = (stix_type, name, props)
        return self._register(obj, {name, *props.get("aliases", [])}), None

    def resolve(self, ref: str) -> tuple[str | None, str | None]:
        """Une extrémité de relation : identifiant ATT&CK, nom déclaré (ou alias), ou nom connu d'ATT&CK."""
        ref = ref.strip()
        if _TECHNIQUE.match(ref) or re.fullmatch(r"[GSC]\d{4}", ref, re.I):
            return self._attack_object(ref, set())
        sid = self.names.get(ref.upper()) or self.names.get(normalize_name(ref))
        if sid:
            return sid, None
        hits = [h for h in self.attack.lookup(ref) if h["status"] == "active"]
        if len(hits) == 1:  # nommé mais non déclaré : l'objet ATT&CK officiel
            return self._attack_object(hits[0]["attack_id"], {ref})
        return None, f"« {ref} » n'est pas déclarée : l'ajouter à entities (type|nom) ou employer le nom exact déjà déclaré"

    # --- Relations ----------------------------------------------------------------------------------------------------------
    def _context(self, uids: list[int]) -> str:
        """Texte qui doit nommer les extrémités : phrases citées, titres de leur section, et quelques phrases précédentes de la
        même section (référent d'un pronom, sujet d'une section d'analyse)."""
        parts = []
        for uid in uids:
            unit = self.by_uid[uid]
            parts += [unit.text, unit.heading_path]
            for prev in range(uid - 1, uid - 1 - CONTEXT_SENTENCES, -1):
                before = self.by_uid.get(prev)
                if before is None or before.heading_path != unit.heading_path:
                    break
                parts.append(before.text)
        return "\n".join(parts)

    def relate(self, line: str) -> str | None:
        """« source|relation|cible|12,13 ». Ajoute la relation si `stix2.Relationship` l'accepte et que le texte l'étaye ;
        sinon retourne le refus."""
        parsed = parse_relation(line)
        if parsed is None:
            return f"« {line} » : format attendu source|relation|cible|numéros de phrases"
        s_ref, rel, t_ref, numbers = parsed
        uids = [int(n) for n in re.findall(r"\d+", numbers)]
        missing = [n for n in uids if n not in self.by_uid]
        if not uids or missing:
            return f"« {line} » : " + (f"phrase(s) {missing} inexistante(s)" if missing else "citer au moins un numéro de phrase qui l'affirme")
        uids = [n for n in dict.fromkeys(uids) if self.by_uid[n].is_evidence_eligible] or uids[:1]
        s_id, err = self.resolve(s_ref)
        if err:
            return f"« {line} » : {err}"
        t_id, err = self.resolve(t_ref)
        if err:
            return f"« {line} » : {err}"
        if s_id == t_id:
            return f"« {line} » : une entité ne se relie pas à elle-même"
        context = self._context(uids)
        unnamed = [self.name_of(i) for i in (s_id, t_id) if self.type_of(i) not in _IMPLICIT and not mentions(context, self.terms[i])]
        if unnamed:
            return f"« {line} » : les phrases {uids} ne nomment pas {', '.join(unnamed)} (citer la phrase qui le dit)"
        quotes = [self.by_uid[n].text for n in uids]
        try:
            relationship(rel, s_id, t_id, self.ctx, quotes)
        except (STIXError, ValueError) as exc:
            return f"« {line} » refusée par stix2 : {_error(exc)}"
        known = self.evidence.setdefault((s_id, rel, t_id), [])
        known += [q for q in quotes if q not in known]
        return None

    # --- Sortie ----------------------------------------------------------------------------------------------------------
    def relationships(self) -> list:
        """`stix2.Relationship` de chaque relation acceptée, avec toutes ses citations ; confiance tirée de la plus affirmative."""
        return [relationship(rel, s, t, self.ctx, quotes, max(confidence_from_text(q) for q in quotes)) for (s, rel, t), quotes in self.evidence.items()]

    def linked(self) -> list:
        """Entités reliées (une entité sans relation étayée n'est pas gardée)."""
        ids = {i for s, _, t in self.evidence for i in (s, t)}
        return [o for sid, o in self.objects.items() if sid in ids]

    def entity_rows(self) -> list[dict]:
        """Entités reliées sous forme simple (identifiant, type, nom, alias) : pour rattacher IOC et règles."""
        return [{"id": o["id"], "type": o["type"], "name": o.get("name", ""), "aliases": sorted(self.terms.get(o["id"], set()) - {o.get("name", "")})} for o in self.linked()]
