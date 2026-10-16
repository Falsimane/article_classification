"""Identité des objets : identifiants déterministes, normalisation des noms, conventions de nommage des éditeurs.

Sans identifiant stable, chaque article recrée ses entités et le graphe se fragmente (« APT29 » et « APT 29 » en
deux nœuds). Ce module fournit :

- `normalize_name` : forme de comparaison d'un nom (casse, accents, séparateurs, suffixes génériques) ;
- `stix_id` : identifiant STIX 2.1 déterministe (UUIDv5) : réextraire le même fait produit le même identifiant ;
- `classify_identifier` : nature d'un identifiant normatif (CVE, CWE, CAPEC, identifiants ATT&CK) ;
- `confidence_from_text` : traduit les formules des analystes (« avec un niveau de confiance modéré »,
  « likely ») en valeur de confiance STIX, selon les échelles normatives de STIX 2.1 (Annexe A).
"""

import re
import unicodedata
import uuid
from dataclasses import dataclass

from .vocab import CONFIDENCE_SCALE, DEFAULT_CONFIDENCE, WEP_SCALE

# Espace de noms fixe du projet : ne jamais le modifier, sous peine de changer tous les identifiants.
PROJECT_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://cti-knowledge-graph.local/stix/2.1")

# --- Normalisation des noms -------------------------------------------------------------------------------------
_GENERIC_SUFFIXES = {"group", "team", "gang", "actor", "actors", "crew", "operators", "threat", "cluster", "apt"}
_LEADING_ARTICLES = {"the"}


def normalize_name(name: str | None) -> str:
    """Forme de comparaison : « APT 29 », « apt-29 » -> « apt29 » ; « Lazarus Group » -> « lazarus »."""
    if not name:
        return ""
    text = unicodedata.normalize("NFKD", str(name))
    text = "".join(c for c in text if not unicodedata.combining(c)).casefold()
    words = re.findall(r"[a-z0-9]+", text)
    while len(words) > 1 and words[0] in _LEADING_ARTICLES:
        words.pop(0)
    while len(words) > 1 and words[-1] in _GENERIC_SUFFIXES:
        words.pop()
    return "".join(words)


# --- Identifiants déterministes ---------------------------------------------------------------------------------
# Propriétés qui fondent l'identifiant. "first" : la première renseignée (identifiant externe avant le nom) ;
# "all" : toutes, car l'identité est composite.
ID_KEYS: dict[str, tuple[str, tuple[str, ...]]] = {
    "threat-actor": ("first", ("name",)),
    "intrusion-set": ("first", ("name",)),
    "campaign": ("first", ("name",)),
    "malware": ("first", ("name",)),
    "tool": ("first", ("name",)),
    "infrastructure": ("first", ("name",)),
    "course-of-action": ("first", ("name",)),
    "incident": ("first", ("name",)),
    "attack-pattern": ("first", ("attack_id", "name")),
    "vulnerability": ("first", ("cve", "name")),
    "location": ("first", ("country", "region", "name")),
    "identity": ("all", ("identity_class", "name")),
    "indicator": ("all", ("pattern_type", "pattern")),
    "report": ("first", ("source_id",)),
    "relationship": ("all", ("relationship_type", "source_ref", "target_ref")),
    "sighting": ("all", ("sighting_of_ref", "where_sighted_refs", "first_seen")),
    "attack-flow": ("first", ("source_id", "name")),
    "attack-action": ("all", ("flow", "name", "technique_id")),
    "attack-asset": ("all", ("flow", "name")),
    "attack-condition": ("all", ("flow", "description")),
    "attack-operator": ("all", ("flow", "operator", "effects")),
}
_RAW_KEYS = {"pattern", "source_ref", "target_ref", "sighting_of_ref", "where_sighted_refs", "first_seen", "source_id"}
_NAME_KEYS = {"name", "description"}


def canonical_key(stix_type: str, props: dict) -> str:
    """Clé canonique d'un objet. Lève ValueError si aucune propriété d'identité n'est renseignée."""
    mode, keys = ID_KEYS[stix_type]
    parts: list[str] = []
    for key in keys:
        value = props.get(key)
        if isinstance(value, (list, tuple)):
            value = ",".join(sorted(str(v) for v in value))
        if value in (None, "", []):
            if mode == "all":
                parts.append("")
            continue
        text = str(value).strip()
        if key == "cve":
            text = text.upper()
        elif key == "attack_id":
            text = text.upper()
        elif key == "country":
            text = text.upper()
        elif key in _NAME_KEYS:
            text = normalize_name(text) or text.casefold()
        elif key not in _RAW_KEYS:
            text = text.casefold()
        parts.append(f"{key}={text}")
        if mode == "first":
            break
    if not any(p.split("=", 1)[-1] for p in parts):
        raise ValueError(f"aucune propriété d'identité renseignée pour {stix_type!r} (attendu : {keys})")
    return "|".join(parts)


def stix_id(stix_type: str, props: dict) -> str:
    """Identifiant STIX 2.1 déterministe : `<type>--<uuid5>`.

    Les observables (SCO) ne passent pas par ici : STIX 2.1 définit leur identifiant à partir de leurs propriétés
    contributrices, et la bibliothèque `stix2` l'applique à leur création.
    """
    return f"{stix_type}--{uuid.uuid5(PROJECT_NAMESPACE, stix_type + '|' + canonical_key(stix_type, props))}"


# --- Identifiants externes ---------------------------------------------------------------------------------------
_EXTERNAL_ID_PATTERNS = (
    ("cve", re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)),
    ("cwe", re.compile(r"^CWE-\d+$", re.I)),
    ("attack-technique", re.compile(r"^T\d{4}(\.\d{3})?$", re.I)),
    ("attack-group", re.compile(r"^G\d{4}$", re.I)),
    ("attack-software", re.compile(r"^S\d{4}$", re.I)),
    ("attack-campaign", re.compile(r"^C\d{4}$", re.I)),
    ("attack-tactic", re.compile(r"^TA\d{4}$", re.I)),
    ("attack-mitigation", re.compile(r"^M\d{4}$", re.I)),
    ("capec", re.compile(r"^CAPEC-\d+$", re.I)),
)


def classify_identifier(text: str) -> str | None:
    """Nature d'un identifiant externe (CVE, technique ATT&CK…), ou None."""
    text = (text or "").strip()
    for kind, pattern in _EXTERNAL_ID_PATTERNS:
        if pattern.match(text):
            return kind
    return None


# --- Confiance -----------------------------------------------------------------------------------------------------
# Priorité : niveau de confiance explicite > mot d'estimation (WEP) > réserve lexicale > affirmation non nuancée.
_CONFIDENCE_LEVEL_CUES = (
    (r"\b(high|strong)\s+confidence\b|confiance\s+(élevée|haute|forte)|(haut|fort)\s+niveau\s+de\s+confiance", "high"),
    (r"\b(moderate|medium)\s+confidence\b|confiance\s+(moyenne|modérée)|niveau\s+de\s+confiance\s+(moyen|modéré)", "medium"),
    (r"\blow\s+confidence\b|confiance\s+faible|faible\s+(niveau\s+de\s+)?confiance", "low"),
)
_WEP_CUES = (
    (r"\b(almost\s+certain(ly)?|highly\s+likely|very\s+likely)\b|quasi[- ]certain|très\s+probable", "highly likely"),
    (r"\b(highly\s+unlikely|almost\s+certainly\s+not|very\s+unlikely)\b|très\s+improbable", "highly unlikely"),
    (r"\b(unlikely|probably\s+not)\b|\bimprobable\b", "unlikely"),
    (r"\b(likely|probably)\b|\bprobablement\b|\bprobable\b", "likely"),
    (r"\beven\s+chance\b|une\s+chance\s+sur\s+deux", "even chance"),
)
_HEDGE_CUES = r"\b(possibly|possible|suspected|may\s+have|might|could\s+be)\b|\b(peut-être|pourrait|potentiellement|présumé|supposé)\b"
_CLAIM_CUES = r"\b(allegedly|reportedly|claims?|claimed)\b|\b(selon\s+les\s+(rapports|affirmations)|prétendument)\b"


def confidence_from_text(text: str | None) -> int:
    """Valeur de confiance STIX (0-100) déduite du texte qui énonce un fait. Sans formule nuancée, le fait est
    affirmé par les auteurs : confiance « High » de l'échelle None/Low/Med/High (85)."""
    t = (text or "").lower()
    for pattern, level in _CONFIDENCE_LEVEL_CUES:
        if re.search(pattern, t):
            return CONFIDENCE_SCALE[level][0]
    for pattern, word in _WEP_CUES:
        if re.search(pattern, t):
            return WEP_SCALE[word]
    if re.search(_CLAIM_CUES, t):
        return WEP_SCALE["unlikely"]  # affirmation d'un tiers, non vérifiée par les auteurs
    if re.search(_HEDGE_CUES, t):
        return WEP_SCALE["even chance"]
    return DEFAULT_CONFIDENCE

# Les noms d'acteurs de menace (familles Microsoft, animaux CrowdStrike, préfixes Mandiant ou Unit 42…) sont des
# conventions propriétaires, sans spécification publiée et qui changent : elles ne sont volontairement PAS codées ici.
# STIX ne normalise pas les noms, il normalise la façon de les relier (un objet, plusieurs `aliases`), et les
# alias convergent par le rapprochement avec ATT&CK (`reference.py`).
