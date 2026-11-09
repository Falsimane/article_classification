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

import os
import re
from dataclasses import dataclass, field

from stix2 import ExternalReference
from stix2.exceptions import STIXError
from stix2.v21.vocab import IDENTITY_CLASS, INDUSTRY_SECTOR

from backend.extracting.stix.attack import AttackKB, attack_id, get_attack_kb
from backend.extracting.stix.objects import ALLOWED_RELATIONS, ENTITY_CLASSES, ArticleContext, entity, relationship

from backend.preprocessing.cleaning.text.evidence import confidence_from_text, mentions, normalize_name
from backend.extracting.graph.places import place_names, resolve_location
from backend.extracting.observables.iocs import is_domain_name
from backend.preprocessing.cleaning.text.segment import Unit

# Extrémités qui peuvent rester implicites dans la phrase citée : l'acteur (« les opérateurs », « il ») et la technique
# (la phrase décrit le comportement, elle ne nomme pas la technique ATT&CK)
# Une mesure de défense et une analyse portent un nom résumé par le modèle, que la phrase ne contient pas mot pour mot
_IMPLICIT = frozenset({"intrusion-set", "threat-actor", "campaign", "attack-pattern", "course-of-action", "malware-analysis"})
_ANALYSIS_RESULTS = ("malicious", "suspicious", "benign", "unknown")
_ATTACK_TYPES = {"intrusion-set": ("intrusion-set", "threat-actor"), "threat-actor": ("intrusion-set", "threat-actor"), "malware": ("malware", "tool"), "tool": ("malware", "tool"), "campaign": ("campaign",)}
_TYPE_WORDS = frozenset(ENTITY_CLASSES) | {"attack-pattern", "technique"}
_TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.I)
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
# Une valeur technique (adresse, domaine, URL, hachage) est un IOC, extrait par règles, jamais une entité nommée
_OBSERVABLE = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[a-f0-9]{32,64}|https?://\S+)$", re.I)
_BUILTIN_SHELLS = frozenset({"powershell", "powershell.exe", "cmd", "cmd.exe", "bash", "sh", "wscript", "cscript", "cscript.exe", "wscript.exe"})
_ADVERSARY_SIDE = frozenset({"intrusion-set", "threat-actor", "campaign", "malware", "tool", "infrastructure"})
# Réparation des relations hors table (CTI_ORIENT=on, d'après TRACE) : flèche inversée, et trois retypages que la norme impose
# (« uses » vers une victime, un lieu, une vulnérabilité ou un produit est « targets » ; un acteur ou une campagne qui « drops »,
# « downloads » ou « delivers » un logiciel l'« uses » ; un acteur ou une campagne qui « exploits » une vulnérabilité la « targets »,
# STIX réservant « exploits » aux malwares). Seulement si la forme réparée est dans la table ; sinon le refus revient au modèle.
ORIENT = os.environ.get("CTI_ORIENT", "off").strip().lower() in ("on", "1", "yes", "true")
_ACTORS = frozenset({"intrusion-set", "threat-actor", "campaign"})
CONTEXT_SENTENCES = 3  # phrases précédentes de la même section admises pour retrouver l'entité désignée par « il », « ce malware »
MAX_HITS = 6
_GENERIC_SOFTWARE = frozenset({
    "windows", "linux", "android", "macos", "ios", "unix", "ubuntu", "debian", "redhat", "centos"
})
_SECURITY_VENDORS = frozenset({
    "clearsky", "crowdstrike", "rapid7", "harfanglab", "unit 42", "unit42", "mandiant",
    "fireeye", "microsoft threat intelligence", "sentinelone", "kaspersky", "symantec",
    "trend micro", "eset", "palo alto networks", "cisco talos", "talos", "cert", "cisa", "fbi"
})


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


def orient(s_type: str, rel: str, t_type: str) -> tuple[bool, str] | None:
    """(inverser, relation) qui rend « s_type --rel--> t_type » conforme à la table, ou None (voir ORIENT)."""
    fixed = rel
    if rel == "uses" and t_type in ("identity", "location", "vulnerability", "software"):
        fixed = "targets"
    elif rel in ("drops", "downloads", "delivers") and s_type in _ACTORS:
        fixed = "uses"
    elif rel == "exploits" and s_type in _ACTORS and t_type == "vulnerability":
        fixed = "targets"
    elif s_type == "software" and t_type == "vulnerability" and rel in ("targets", "exploits"):
        fixed = "has"
    for candidate in dict.fromkeys((fixed, rel)):
        if (s_type, candidate, t_type) in ALLOWED_RELATIONS:
            return False, candidate
        if (t_type, candidate, s_type) in ALLOWED_RELATIONS:
            return True, candidate
    return None


def parse_relation(line: str) -> tuple[str, str, str, str] | None:
    """(source, relation, cible, numéros) d'une ligne « source|relation|cible|12,13 ». Les types que le modèle intercale
    (« software|<product>|has|vulnerability|CVE-YYYY-NNNNN|1,9 ») sont retirés."""
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
    procedures: dict[str, list[str]] = field(default_factory=dict)  # technique -> comportements décrits (en anglais) qui l'ont fait choisir
    log: list[str] = field(default_factory=list)  # corrections et refus, pour le rapport
    hallucinated: list[str] = field(default_factory=list)  # identifiants ATT&CK proposés absents de la v20.0

    def __post_init__(self):
        self.by_uid = {u.uid: u for u in self.units}
        self.publisher_key = normalize_name(self.ctx.publisher.name)

    def type_of(self, sid: str) -> str:
        return self.objects[sid]["type"]

    def name_of(self, sid: str) -> str:
        obj = self.objects[sid]
        return obj.get("name") or obj.get("product") or sid

    # --- Entités ----------------------------------------------------------------------------------------------------------
    def _register(self, obj, terms: set[str]) -> str:
        sid = obj["id"]
        self.objects.setdefault(sid, obj)
        self.terms.setdefault(sid, set()).update(t for t in terms if t)
        for t in self.terms[sid] | {obj.get("name") or obj.get("product", ""), *(obj.get("aliases") or [])}:
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

    def add_terms(self, sid: str, terms: set[str]) -> None:
        """Autres noms sous lesquels le texte désigne une entité déjà déclarée (victimes fusionnées) : la vérification d'une
        relation les reconnaît dans la phrase citée."""
        self._register(self.objects[sid], terms)

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
        if _OBSERVABLE.match(name) or is_domain_name(name):
            return None, f"« {line} » : « {name} » est un IOC (adresse, domaine, URL, hachage), extrait par ailleurs"
        if stix_type in _ADVERSARY_SIDE and normalize_name(name) == self.publisher_key:
            return None, f"« {line} » : « {name} » est l'auteur du rapport, pas un composant de l'attaque"

        # Nom connu d'ATT&CK sous un type compatible : l'objet officiel de MITRE
        if stix_type == "tool" and normalize_name(name) in {normalize_name(s) for s in _BUILTIN_SHELLS}:
            return None, f"« {name} » est un interpréteur système natif (Living-off-the-Land), modélisé par les techniques ATT&CK T1059 et non comme un outil tiers"
        if stix_type in _ATTACK_TYPES:
            hits = [h for h in self.attack.lookup(name) if h["status"] == "active" and h["type"] in _ATTACK_TYPES[stix_type]]
            if not hits:
                for suf in (" Beacon", " Loader", " Downloader", " Trojan", " Malware", " Driver", " tool", " Tool"):
                    if name.lower().endswith(suf.lower()):
                        trimmed = name[:-len(suf)].strip()
                        hits = [h for h in self.attack.lookup(trimmed) if h["status"] == "active" and h["type"] in _ATTACK_TYPES[stix_type]]
                        if len(hits) == 1:
                            name = trimmed
                            break
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
            # Secteur et classe des vocabulaires STIX : en troisième champ (« identity|<victime>|government;class »), ou le nom
            # lui-même (« government ») ; sans classe, une victime nommée par son secteur est une classe, sinon une organisation
            slug = lambda t: re.sub(r"[^a-z0-9]+", "-", t.casefold()).strip("-")  # noqa: E731
            fields = [slug(f) for f in extra.split(";")]
            sector = next((s for s in (*fields, slug(name)) if s in INDUSTRY_SECTOR), None)
            klass = next((f for f in fields if f in IDENTITY_CLASS), None)
            if sector:
                props["sectors"] = [sector]
            if klass or sector:
                props["identity_class"] = klass or ("class" if slug(name) == sector else "organization")
            # Même nom déjà déclaré comme identité (avec ou sans classe) : la même entité, pas un doublon
            known_sid = self.names.get(normalize_name(name))
            if known_sid and self.type_of(known_sid) == "identity":
                return known_sid, None
        elif stix_type == "course-of-action":  # pas d'alias en STIX : le troisième champ est la description de la mesure
            if extra:
                props["description"] = extra
        elif stix_type == "malware-analysis":  # verdict du vocabulaire malware-result-ov ; sans lui, « unknown »
            verdict = extra.strip().lower()
            props["result"] = verdict if verdict in _ANALYSIS_RESULTS else "unknown"
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
        terms = {name, *props.get("aliases", [])}
        if stix_type == "location":  # le lieu est reconnu sous toutes ses graphies, quelle que soit la langue du nom donné
            terms |= place_names(props.get("country"), props.get("region"))
        return self._register(obj, terms), None

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
        s_type, t_type, rel_type = self.type_of(s_id), self.type_of(t_id), relationship_type_of(rel)
        repaired = orient(s_type, rel_type, t_type) if ORIENT and (s_type, rel_type, t_type) not in ALLOWED_RELATIONS else None
        if repaired:
            swap, rel_type = repaired
            if swap:
                s_id, t_id, s_type, t_type = t_id, s_id, t_type, s_type
            self.log.append(f"fix {line} -> {self.name_of(s_id)} --{rel_type}--> {self.name_of(t_id)}")
            rel = rel_type
        if (s_type, rel_type, t_type) not in ALLOWED_RELATIONS:
            if rel_type == "has" and t_type == "vulnerability" and s_type in ("tool", "malware"):
                sw_sid, _ = self.declare(f"software|{self.name_of(s_id)}")
                if sw_sid:
                    s_id, s_type = sw_sid, "software"
        if (s_type, rel_type, t_type) not in ALLOWED_RELATIONS:
            admitted = sorted({f"{r} {t}" for s, r, t in ALLOWED_RELATIONS if s == s_type})
            return f"« {line} » : {s_type} --{rel_type}--> {t_type} n'existe pas en STIX 2.1 ; " + (
                f"depuis {s_type} : {', '.join(admitted)}" if admitted else f"un objet {s_type} n'est jamais la source d'une relation"
            )
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
    def prune_subsumed_techniques(self) -> None:
        """Élagage ontologique de subsomption ATT&CK :
        Si un porteur a une relation « uses » vers une sous-technique (T####.###),
        toute relation « uses » vers sa technique parente (T####) sur les mêmes phrases citées
        est élaguée pour éliminer les doublons artificiels."""
        aid_by_sid = {sid: attack_id(obj) for sid, obj in self.objects.items() if obj.get("type") == "attack-pattern"}
        aid_by_sid = {sid: aid for sid, aid in aid_by_sid.items() if aid}

        # Sub-techniques par porteur : carrier -> list of (sid, aid, quotes_set)
        carrier_subs: dict[str, list[tuple[str, str, set[str]]]] = {}
        for (s, rel, t), quotes in self.evidence.items():
            if rel == "uses" and t in aid_by_sid and "." in aid_by_sid[t]:
                carrier_subs.setdefault(s, []).append((t, aid_by_sid[t], set(quotes)))

        to_prune = []
        for (s, rel, t), quotes in self.evidence.items():
            if rel == "uses" and t in aid_by_sid and "." not in aid_by_sid[t]:
                p_aid = aid_by_sid[t]
                p_quotes = set(quotes)
                subs = carrier_subs.get(s, [])
                for sub_sid, sub_aid, sub_quotes in subs:
                    if sub_aid.startswith(f"{p_aid}."):
                        # Subsomption si les phrases citées se recouvrent ou si la parente n'apporte pas d'autre citation
                        if not p_quotes or not sub_quotes or (p_quotes & sub_quotes) or len(p_quotes - sub_quotes) == 0:
                            to_prune.append((s, rel, t))
                            break

        for key in to_prune:
            s, rel, t = key
            self.evidence.pop(key, None)
            self.log.append(f"subsomption ontologique : retrait {self.name_of(s)} --uses--> {aid_by_sid.get(t, t)} au profit de sa sous-technique")

    def is_salient_orphan(self, sid: str) -> bool:
        """Filtre de saillance contextuelle pour les entités orphelines (sans relation validée).
        Élimine le bruit de fond (éditeurs de sécurité cités en source, OS génériques) tout en
        préservant les entités centrales du rapport."""
        obj = self.objects.get(sid)
        if not obj:
            return False
        stype = obj.get("type", "")
        # Les attack-patterns orphelins sont TOUJOURS élagués
        if stype == "attack-pattern":
            return False

        name = obj.get("name", "").strip()
        norm = normalize_name(name)

        # 1. Élaguer les éditeurs de sécurité et auteurs de rapport
        if norm == self.publisher_key or norm in _SECURITY_VENDORS:
            return False

        # 2. Élaguer les plateformes OS génériques non visées
        if stype == "software" and norm in _GENERIC_SOFTWARE:
            return False

        # 3. Vulnérabilités (CVE) nommées dans le texte : toujours saillantes
        if stype == "vulnerability":
            return True

        # 4. Campagnes nommées dans le texte : toujours saillantes
        if stype == "campaign":
            return True

        # 5. Présence dans le titre de l'article (entité centrale du rapport)
        title = (getattr(self.ctx, "title", None) or self.ctx.article_ref.get("description", "") or "").casefold()
        terms = self.terms.get(sid, {name})
        if any(len(t) >= 4 and t.casefold() in title for t in terms):
            return True

        # 6. Fréquence des mentions dans le corps du texte (au moins 2 unités)
        count = 0
        for u in self.by_uid.values():
            if mentions(u.text, terms):
                count += 1
                if count >= 2:
                    return True

        return False

    def relationships(self) -> list:
        """`stix2.Relationship` de chaque relation acceptée, avec toutes ses citations ; confiance tirée de la plus affirmative.
        Une relation « uses » vers une technique a pour description la procédure (comme dans ATT&CK) : le comportement tel que
        l'article le décrit, plus discriminant pour l'attribution que l'identifiant de technique seul."""
        return [
            relationship(rel, s, t, self.ctx, quotes, max(confidence_from_text(q) for q in quotes),
                         procedure=" ; ".join(self.procedures.get(t, [])) if rel == "uses" else None)
            for (s, rel, t), quotes in self.evidence.items()
        ]  # fmt: skip

    def linked(self, keep_orphans: bool | None = None) -> list:
        """Entités reliées (ou entités orphelines saillantes)."""
        ids = {i for s, _, t in self.evidence for i in (s, t)}
        if keep_orphans is None:
            keep_orphans = os.environ.get("CTI_KEEP_ORPHANS", "on").strip().lower() in ("on", "1", "yes", "true")
        if keep_orphans:
            ids |= {sid for sid in self.objects if self.is_salient_orphan(sid)}
        return [o for sid, o in self.objects.items() if sid in ids]

    def unlinked(self) -> list:
        """Entités acceptées puis écartées faute de relation étayée (pour situer les pertes à l'évaluation)."""
        linked_ids = {o["id"] for o in self.linked()}
        return [o for sid, o in self.objects.items() if sid not in linked_ids]

    def entity_rows(self) -> list[dict]:
        """Entités reliées sous forme simple (identifiant, type, nom, alias) : pour rattacher IOC et règles."""
        return [{"id": o["id"], "type": o["type"], "name": o.get("name", ""), "aliases": sorted(self.terms.get(o["id"], set()) - {o.get("name", "")})} for o in self.linked()]
