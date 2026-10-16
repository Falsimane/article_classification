"""Validation et assainissement d'une extraction : ce qui sépare une sortie de modèle d'un graphe fiable.

Entrée : le dictionnaire produit par le LLM d'extraction
    {"entities":      [{"ref": "e1", "type": "malware", "name": "Qakbot", "aliases": [...], ...}],
     "relationships": [{"source": "e1", "type": "uses", "target": "e2", "evidence": "<citation>"}]}

Sortie : des objets STIX normalisés, avec identifiants déterministes, et la liste motivée de ce qui a été corrigé
ou rejeté. Chaque décision est un `Issue` : elle sert de retour au modèle (boucle de réflexion) et d'audit.

Principe : on ne corrige que ce que l'ontologie ou la base de référence permet de corriger avec certitude
(un identifiant révoqué, une relation à l'envers, un type contredit par ATT&CK). Tout le reste est rejeté,
jamais deviné : un faux positif dans un graphe de menace coûte plus cher qu'un fait manquant.
"""

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Iterable

from .identity import confidence_from_text, normalize_name, stix_id
from .profiles import PROFILES, ExtractionProfile
from .reference import ReferenceKB, get_reference_kb
from .relationships import allowed_relationships, canonical_relationship, is_valid_relationship
from .schema import OBJECT_TYPES
from .vocab import OPEN_VOCABULARIES, PROPERTY_VOCABULARY

MIN_EVIDENCE_CHARS = 15
_ADVERSARY_SIDE = {"threat-actor", "intrusion-set", "campaign", "malware", "tool", "infrastructure"}
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
_ATTACK_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)

# Termes courants de l'anglais informatique qui ne désignent aucune entité précise.
GENERIC_TERMS = frozenset(
    "computer system file folder network payload malware tool executable memory internet protocol victim target user "
    "activity code script software machine application data binary device process service technique attack action "
    "intrusion campaign report article source url hash session access sample flaw bug patch update company "
    "compromise incident attacker actor adversary server database command".split()
)


# Extensions de fichiers qui ne désignent pas un logiciel : un « closeapps.bat » ou un « msimg32.dll » est un observable
# `file`, extrait par règles. `.exe` n'y figure pas : un exécutable peut être un outil légitime (PsExec.exe) ou un
# échantillon de malware nommé par son fichier.
_FILE_EXTENSIONS = frozenset(
    "bat cmd ps1 vbs vbe js sh py dll sys dat tmp lnk msi scr jar iso zip rar 7z tar gz doc docx xls xlsx pdf bin log txt "
    "cfg ini conf json xml hta wsf".split()
)


_OBSERVABLE = re.compile(
    r"^(?:[a-f0-9]{32,64}|(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?|https?://\S+|[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)*\.[a-z]{2,24}(?:/\S*)?)$",
    re.I,
)


@dataclass(frozen=True)
class Issue:
    level: str  # "reject" | "fix" | "warn"
    code: str
    subject: str
    message: str

    def __str__(self) -> str:
        return f"[{self.level}:{self.code}] {self.subject} : {self.message}"


@dataclass
class SanitizedGraph:
    entities: list[dict] = field(default_factory=list)
    relationships: list[dict] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)

    def rejected(self) -> list[Issue]:
        return [i for i in self.issues if i.level == "reject"]


# --- Preuve textuelle -----------------------------------------------------------------------------------------------
def normalize_quote(text: str) -> str:
    """Forme de comparaison d'une citation : insensible à la casse, aux guillemets typographiques, aux balises
    de mise en forme Markdown et aux espaces."""
    text = unicodedata.normalize("NFKC", text or "")
    text = text.translate(str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"', "«": '"', "»": '"'}))
    text = re.sub(r"[*_`]+", "", text)
    return re.sub(r"\s+", " ", text).strip().casefold()


def evidence_in_source(evidence: str, source_text: str) -> bool:
    """La citation figure-t-elle dans le texte ? Les coupes « [...] » ou « … » sont admises : chaque fragment doit
    apparaître, et au moins un fragment doit être assez long pour être probant."""
    parts = [normalize_quote(p) for p in re.split(r"\[\s*\.\.\.\s*\]|\.\.\.|…", evidence or "")]
    parts = [p for p in parts if len(p) >= 8]
    if not parts or max(len(p) for p in parts) < MIN_EVIDENCE_CHARS:
        return False
    haystack = normalize_quote(source_text)
    return all(p in haystack for p in parts)


# Peuvent rester implicites dans la phrase citée (« l'acteur », « l'attaquant », « the threat actor »)
_ADVERSARY_TYPES = frozenset({"threat-actor", "intrusion-set", "campaign", "incident"})


def _tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", normalize_quote(text))


def prepare_text(text: str) -> tuple[set[str], set[str]]:
    """Mots du texte et concaténations de 2 à 4 mots consécutifs : à calculer une fois par texte quand on teste
    beaucoup de termes contre lui."""
    words = _tokens(text)
    joined = {"".join(words[i : i + n]) for n in (2, 3, 4) for i in range(len(words) - n + 1)}
    return set(words), joined


def mentions_prepared(prepared: tuple[set[str], set[str]], terms: Iterable[str]) -> bool:
    """Un terme précédé de `~` est un RADICAL : il reconnaît tout mot qui commence ainsi (secteurs d'activité du
    vocabulaire STIX, que les articles écrivent « financial » ou « telecom » pour `financial-services` et
    `telecommunications`)."""
    vocabulary, joined = prepared
    for term in terms:
        if term.startswith("~"):
            stem = term[1:]
            if len(stem) >= 5 and any(w.startswith(stem) for w in vocabulary):
                return True
            continue
        toks = _tokens(term)
        if toks and all(t in vocabulary for t in toks):
            return True
        if len(toks) == 1 and len(toks[0]) >= 5 and toks[0] in joined:
            return True
    return False


def mentions(evidence: str, terms: Iterable[str]) -> bool:
    """L'un des termes (nom, alias, identifiant externe) apparaît-il dans la citation ?

    Comparaison par mots entiers (« PsExec » est dans « PsExec.exe », pas dans « psexecuted »). Un nom collé
    (« APT29 ») est aussi reconnu quand le texte l'écrit en plusieurs mots (« APT 29 ») : on accepte la
    concaténation de mots entiers consécutifs, jamais une simple sous-chaîne.
    """
    return mentions_prepared(prepare_text(evidence), terms)


# --- Types ----------------------------------------------------------------------------------------------------------
def canonical_type(raw: str) -> str:
    return (raw or "").strip().lower().replace("_", "-").replace("cti:", "").replace("stix:", "")


# --- Entités ------------------------------------------------------------------------------------------------------------
# Mots qui, seuls ou ensemble, ne désignent personne : « Threat actor », « The attacker », « Unknown group »
_FILLER_WORDS = frozenset("the a an this that these those threat unknown unnamed other new same another group groups".split())


def _is_generic(name: str) -> bool:
    words = re.findall(r"[a-z0-9]+", name.casefold())
    return bool(words) and all(w in GENERIC_TERMS or w in _FILLER_WORDS for w in words)


def _clean_list(values, vocab_key: tuple[str, str] | None = None) -> list[str]:
    out = []
    for v in values or []:
        text = str(v).strip()
        if text and text not in out:
            out.append(text)
    return out


def _external_ref(source_name: str, external_id: str, description: str | None = None) -> dict:
    ref = {"source_name": source_name, "external_id": external_id}
    if description:
        ref["description"] = description
    return ref


def _check_vocabularies(stix_type: str, ent: dict, issues: list[Issue], subject: str) -> None:
    """Retire les valeurs hors vocabulaire ouvert STIX (un vocabulaire « ouvert » tolère d'autres valeurs, mais un
    modèle de langage qui en invente produit surtout du bruit : on ne garde que les valeurs reconnues)."""
    for (t, prop), vocab in PROPERTY_VOCABULARY.items():
        if t != stix_type or prop not in ent:
            continue
        allowed = set(OPEN_VOCABULARIES[vocab])
        value = ent[prop]
        values = value if isinstance(value, list) else [value]
        kept = [v for v in values if str(v) in allowed]
        for v in values:
            if str(v) not in allowed:
                issues.append(Issue("fix", "VOCAB", subject, f"{prop}={v!r} hors vocabulaire {vocab}, retiré"))
        if kept:
            ent[prop] = kept if isinstance(value, list) else kept[0]
        else:
            del ent[prop]


def _sector_of(name: str) -> str | None:
    """Valeur de `industry-sector-ov` si le nom EST un secteur (« Financial Services » -> financial-services)."""
    key = re.sub(r"[^a-z0-9]+", "-", name.casefold()).strip("-")
    return key if key in OPEN_VOCABULARIES["industry-sector-ov"] else None


def _normalize_entity(
    raw: dict,
    profile: ExtractionProfile,
    kb: ReferenceKB,
    publishers: set[str],
    issues: list[Issue],
) -> dict | None:
    name = str(raw.get("name") or "").strip()
    stix_type = canonical_type(raw.get("type", ""))
    subject = f"{stix_type}:{name or '?'}"

    if stix_type not in OBJECT_TYPES:
        issues.append(Issue("reject", "UNKNOWN_TYPE", subject, f"type inconnu de l'ontologie : {raw.get('type')!r}"))
        return None
    if len(name) < 2:
        issues.append(Issue("reject", "EMPTY_NAME", subject, "nom vide ou trop court"))
        return None
    if _is_generic(name):
        issues.append(Issue("reject", "GENERIC_TERM", subject, "terme générique : ce n'est pas une entité précise"))
        return None
    if _OBSERVABLE.match(name) and name.rsplit(".", 1)[-1].lower() not in _FILE_EXTENSIONS | {"exe"} and not kb.lookup(name):
        issues.append(Issue("reject", "OBSERVABLE_AS_ENTITY", subject, "hachage, adresse, domaine ou URL : un observable, pas une entité"))
        return None
    extension = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if extension in _FILE_EXTENSIONS and stix_type in ("malware", "tool", "infrastructure") and not kb.lookup(name):
        issues.append(Issue("reject", "FILE_NAME_AS_ENTITY", subject, f"« .{extension} » : un fichier est un observable, pas un logiciel"))
        return None
    if stix_type in _ADVERSARY_SIDE and normalize_name(name) in publishers:
        issues.append(
            Issue("reject", "PUBLISHER_AS_ADVERSARY", subject, "c'est l'auteur du rapport, pas un composant de l'attaque")
        )
        return None

    ent = {k: v for k, v in raw.items() if k not in ("ref", "type", "name") and v not in (None, "", [])}
    ent.update({"type": stix_type, "name": name})
    refs: list[dict] = []
    # Termes tels que le TEXTE peut les citer : la base de référence renomme (T1562.001 -> T1685), pas l'article.
    terms = {name, *_clean_list(raw.get("aliases"))}
    for key in ("attack_id", "cve"):
        if raw.get(key):
            terms.add(str(raw[key]))
    for pattern in (_ATTACK_ID, _CVE):
        terms.update(m.group(0) for m in pattern.finditer(name))

    # --- Rapprochement avec la base de référence, selon le type -------------------------------------------------
    if stix_type in ("threat-actor", "intrusion-set", "campaign", "malware", "tool"):
        conflict = kb.type_conflict(stix_type, name)
        if conflict:
            issues.append(
                Issue(
                    "fix",
                    "TYPE_CORRECTED",
                    subject,
                    f"ATT&CK range « {conflict.name} » ({conflict.attack_id}) en {conflict.stix_type}, pas en {stix_type}",
                )
            )
            stix_type = ent["type"] = conflict.stix_type
        grounding = kb.ground(stix_type, name)
        if grounding.status == "grounded":
            m = grounding.match
            if m.kind == "group" and stix_type == "threat-actor":
                # ATT&CK publie ses groupes (G…) comme `intrusion-set` : le type suit la donnée de référence
                issues.append(Issue("fix", "TYPE_CORRECTED", subject, f"ATT&CK range {m.attack_id} en intrusion-set"))
                stix_type = ent["type"] = "intrusion-set"
            aliases = _clean_list(ent.get("aliases")) + [a for a in (name, *m.aliases) if a != m.name]
            ent["name"] = m.name
            ent["aliases"] = sorted({a for a in aliases if normalize_name(a) != normalize_name(m.name)})
            refs.append(_external_ref("mitre-attack", m.attack_id))
            if normalize_name(name) != normalize_name(m.name):
                issues.append(Issue("fix", "CANONICAL_NAME", subject, f"{name!r} -> {m.name!r} ({m.attack_id})"))
        elif grounding.status == "ambiguous":
            ids = ", ".join(c.attack_id for c in grounding.candidates)
            issues.append(Issue("warn", "AMBIGUOUS_ALIAS", subject, f"plusieurs objets ATT&CK possibles ({ids}) : non rapproché"))

    elif stix_type == "vulnerability":
        found = _CVE.search(str(ent.get("cve") or "")) or _CVE.search(name)
        if found:
            cve = found.group(0).upper()
            ent["name"] = cve
            refs.append(_external_ref("cve", cve))
            ent.pop("cve", None)
        else:
            issues.append(Issue("warn", "NO_CVE", subject, "vulnérabilité sans identifiant CVE"))

    elif stix_type == "attack-pattern":
        id_in_text = ent.get("attack_id") or (_ATTACK_ID.search(name).group(0) if _ATTACK_ID.search(name) else None)
        res = kb.resolve_technique(id_in_text, None if id_in_text and _ATTACK_ID.fullmatch(name) else name)
        if res.attack_id and res.status in ("active", "revoked"):
            if res.original_id:
                issues.append(Issue("fix", "ATTACK_ID_REPLACED", subject, f"{res.original_id} est {res.status}, remplacé par {res.attack_id}"))
            if res.name_conflict:
                issues.append(Issue("fix", "ATTACK_NAME_CORRECTED", subject, f"{res.attack_id} s'appelle « {res.name} », pas « {name} »"))
            ent["name"] = res.name
            refs.append(_external_ref("mitre-attack", res.attack_id))
            if res.tactics:  # propriété STIX standard, avec la chaîne d'attaque ATT&CK
                ent["kill_chain_phases"] = [{"kill_chain_name": "mitre-attack", "phase_name": t} for t in res.tactics]
        elif id_in_text:
            issues.append(Issue("warn", "UNKNOWN_ATTACK_ID", subject, f"{id_in_text} inconnu de la base ATT&CK : identifiant retiré"))
            if _ATTACK_ID.fullmatch(name):  # le nom n'était que l'identifiant : rien d'exploitable
                issues.append(Issue("reject", "UNRESOLVED_TECHNIQUE", subject, "identifiant seul, introuvable"))
                return None
        ent.pop("attack_id", None)

    elif stix_type == "identity":
        sector = _sector_of(name)
        if sector:  # « government », « manufacturing » : un secteur d'activité du vocabulaire STIX, pas une organisation
            ent["identity_class"], ent["sectors"] = "class", [sector]
        elif ent.get("identity_class") not in OPEN_VOCABULARIES["identity-class-ov"]:
            ent["identity_class"] = "unknown"  # le modèle ne précise pas la classe : on ne la devine pas

    elif stix_type == "location":
        country = str(ent.get("country") or "").strip().upper()
        if not country and re.fullmatch(r"[A-Za-z]{2}", name):
            country = name.upper()
        if country:
            if not re.fullmatch(r"[A-Z]{2}", country):
                issues.append(Issue("fix", "COUNTRY_CODE", subject, f"country={country!r} n'est pas un code ISO 3166-1 alpha-2, retiré"))
            else:
                ent["country"] = country

    _check_vocabularies(stix_type, ent, issues, subject)
    if refs:
        ent["external_references"] = refs + [r for r in ent.get("external_references", []) if r not in refs]
    terms.add(ent["name"])
    terms.update(ent.get("aliases", []))
    ent["_mentions"] = sorted(terms)  # interne : retiré avant la sortie
    return ent


def _identity_props(ent: dict) -> dict:
    props = dict(ent)
    for ref in ent.get("external_references", []):
        if ref["source_name"] == "mitre-attack":
            props["attack_id"] = ref["external_id"]
        elif ref["source_name"] == "cve":
            props["cve"] = ref["external_id"]
    return props


def _merge(into: dict, other: dict) -> None:
    for key in ("aliases", "external_references", "labels", "sectors"):
        if other.get(key):
            merged = list(into.get(key, []))
            merged += [v for v in other[key] if v not in merged]
            into[key] = merged
    into["_mentions"] = sorted(set(into.get("_mentions", [])) | set(other.get("_mentions", [])))
    for key, value in other.items():
        into.setdefault(key, value)


# --- Extraction complète ----------------------------------------------------------------------------------------------
def sanitize_extraction(
    raw: dict,
    profile: str | ExtractionProfile,
    source_text: str | None = None,
    publisher_names: Iterable[str] = (),
    kb: ReferenceKB | None = None,
    keep_orphans: bool = False,
) -> SanitizedGraph:
    """Assainit une extraction. `publisher_names` : noms de la source et de ses auteurs (métadonnées de l'article) ;
    ils ne peuvent jamais être un acteur, un outil ou une infrastructure de l'attaque."""
    profile = PROFILES[profile] if isinstance(profile, str) else profile
    kb = kb or get_reference_kb()
    publishers = {normalize_name(p) for p in publisher_names if p}
    out = SanitizedGraph()
    allowed_pairs = set(profile.pairs())

    # 1. Entités ----------------------------------------------------------------------------------------------------------
    by_ref: dict[str, str] = {}  # référence locale ou nom -> identifiant STIX
    objects: dict[str, dict] = {}
    for raw_ent in raw.get("entities", []) or []:
        ent = _normalize_entity(raw_ent, profile, kb, publishers, out.issues)
        if ent is None:
            continue
        if ent["type"] not in profile.entity_types:
            out.issues.append(
                Issue("reject", "TYPE_NOT_IN_PROFILE", f"{ent['type']}:{ent['name']}", f"type non extrait par le profil « {profile.name} »")
            )
            continue
        try:
            sid = stix_id(ent["type"], _identity_props(ent))
        except ValueError as exc:
            out.issues.append(Issue("reject", "NO_IDENTITY", f"{ent['type']}:{ent['name']}", str(exc)))
            continue
        if sid in objects:
            _merge(objects[sid], ent)
        else:
            ent["id"] = sid
            objects[sid] = ent
        for key in (raw_ent.get("ref"), raw_ent.get("id"), raw_ent.get("name"), ent["name"]):
            if key:
                by_ref[str(key)] = sid
                by_ref.setdefault(normalize_name(str(key)), sid)

    # 2. Relations ---------------------------------------------------------------------------------------------------------
    rels: dict[tuple[str, str, str], dict] = {}
    for raw_rel in raw.get("relationships", []) or []:
        rel_type = canonical_relationship(raw_rel.get("type") or raw_rel.get("relationship_type") or raw_rel.get("predicate"))
        s_key, t_key = str(raw_rel.get("source", raw_rel.get("subject", ""))), str(raw_rel.get("target", raw_rel.get("object", "")))
        subject = f"{s_key} --{rel_type}--> {t_key}"
        s_id = by_ref.get(s_key) or by_ref.get(normalize_name(s_key))
        t_id = by_ref.get(t_key) or by_ref.get(normalize_name(t_key))
        if not s_id or not t_id:
            out.issues.append(Issue("reject", "UNKNOWN_ENDPOINT", subject, "extrémité absente des entités retenues"))
            continue
        if s_id == t_id:
            out.issues.append(Issue("reject", "SELF_LOOP", subject, "une entité ne se relie pas à elle-même"))
            continue
        s_type, t_type = objects[s_id]["type"], objects[t_id]["type"]

        if not is_valid_relationship(s_type, rel_type, t_type):
            if is_valid_relationship(t_type, rel_type, s_type):  # relation écrite à l'envers : correction certaine
                s_id, t_id, s_type, t_type = t_id, s_id, t_type, s_type
                out.issues.append(Issue("fix", "DIRECTION_FIXED", subject, "relation inversée, sens corrigé"))
            else:
                hint = ", ".join(r for r in allowed_relationships(s_type, t_type) if r != "related-to") or "aucune"
                out.issues.append(
                    Issue("reject", "INVALID_RELATIONSHIP", subject, f"{s_type} --{rel_type}--> {t_type} n'existe pas en STIX (valides : {hint})")
                )
                continue
        if rel_type != "related-to" and (s_type, rel_type, t_type) not in allowed_pairs:
            out.issues.append(
                Issue("reject", "RELATION_NOT_IN_PROFILE", subject, f"valide en STIX mais non extraite par le profil « {profile.name} »")
            )
            continue

        evidence = str(raw_rel.get("evidence") or "").strip()
        if len(evidence) < MIN_EVIDENCE_CHARS:
            out.issues.append(Issue("reject", "NO_EVIDENCE", subject, f"preuve absente ou trop courte (< {MIN_EVIDENCE_CHARS} car.)"))
            continue
        if source_text is not None and not evidence_in_source(evidence, source_text):
            out.issues.append(Issue("reject", "EVIDENCE_NOT_IN_SOURCE", subject, f"citation introuvable dans le texte : {evidence[:60]!r}"))
            continue

        # La citation doit PARLER des entités reliées. Un acteur peut être désigné par « l'acteur » ou « il » ;
        # toute autre extrémité doit figurer dans la citation, sinon elle étaye une autre relation.
        missing = [
            objects[i]
            for i in (s_id, t_id)
            if objects[i]["type"] not in _ADVERSARY_TYPES and not mentions(evidence, objects[i]["_mentions"])
        ]
        if missing or not any(mentions(evidence, objects[i]["_mentions"]) for i in (s_id, t_id)):
            names = ", ".join(m["name"] for m in missing) or f"{objects[s_id]['name']}, {objects[t_id]['name']}"
            out.issues.append(Issue("reject", "EVIDENCE_NOT_ABOUT_ENTITIES", subject, f"la citation ne mentionne pas : {names}"))
            continue

        key = (s_id, rel_type, t_id)
        confidence = raw_rel.get("confidence")
        confidence = max(0, min(100, int(confidence))) if isinstance(confidence, (int, float)) else confidence_from_text(evidence)
        item = {"quote": evidence}
        if raw_rel.get("section"):
            item["section"] = str(raw_rel["section"])
        if key in rels:
            rels[key]["_evidence"].append(item)
            rels[key]["confidence"] = max(rels[key]["confidence"], confidence)
        else:
            rels[key] = {
                "type": "relationship",
                "id": stix_id("relationship", {"relationship_type": rel_type, "source_ref": s_id, "target_ref": t_id}),
                "relationship_type": rel_type,
                "source_ref": s_id,
                "target_ref": t_id,
                "confidence": confidence,
                "_evidence": [item],  # interne : exporté en description et external_references (STIX standard)
            }

    out.relationships = list(rels.values())

    # 3. Entités orphelines ----------------------------------------------------------------------------------------------------
    linked = {r["source_ref"] for r in out.relationships} | {r["target_ref"] for r in out.relationships}
    for sid, ent in objects.items():
        if keep_orphans or sid in linked:
            out.entities.append({k: v for k, v in ent.items() if k != "_mentions"})
        else:
            out.issues.append(Issue("reject", "ORPHAN", f"{ent['type']}:{ent['name']}", "aucune relation étayée : entité écartée"))
    return out
