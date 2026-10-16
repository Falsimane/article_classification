"""Vocabulaires de l'ontologie STIX 2.1.

- Vocabulaires ouverts : importés tels quels de la bibliothèque officielle `stix2`. Source unique : aucune copie
  qui puisse dériver de la norme.
- Tactiques ATT&CK : lues dans la base de référence (`reference.py`), car MITRE les fait évoluer
  (ATT&CK v20 : « Stealth » et « Defense Impairment » ont remplacé « Defense Evasion »).
- Échelles de confiance : STIX 2.1, Annexe A (valeurs normatives).
"""

from stix2.v21 import vocab as _v
from stix2.v21 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE

# nom STIX du vocabulaire ouvert -> valeurs autorisées
OPEN_VOCABULARIES: dict[str, tuple[str, ...]] = {
    "attack-motivation-ov": tuple(_v.ATTACK_MOTIVATION),
    "attack-resource-level-ov": tuple(_v.ATTACK_RESOURCE_LEVEL),
    "grouping-context-ov": tuple(_v.GROUPING_CONTEXT),
    "hash-algorithm-ov": tuple(_v.HASHING_ALGORITHM),
    "identity-class-ov": tuple(_v.IDENTITY_CLASS),
    "implementation-language-ov": tuple(_v.IMPLEMENTATION_LANGUAGE),
    "indicator-type-ov": tuple(_v.INDICATOR_TYPE),
    "industry-sector-ov": tuple(_v.INDUSTRY_SECTOR),
    "infrastructure-type-ov": tuple(_v.INFRASTRUCTURE_TYPE),
    "malware-capabilities-ov": tuple(_v.MALWARE_CAPABILITIES),
    "malware-type-ov": tuple(_v.MALWARE_TYPE),
    "pattern-type-ov": tuple(_v.PATTERN_TYPE),
    "region-ov": tuple(_v.REGION),
    "report-type-ov": tuple(_v.REPORT_TYPE),
    "threat-actor-role-ov": tuple(_v.THREAT_ACTOR_ROLE),
    "threat-actor-sophistication-ov": tuple(_v.THREAT_ACTOR_SOPHISTICATION),
    "threat-actor-type-ov": tuple(_v.THREAT_ACTOR_TYPE),
    "tool-type-ov": tuple(_v.TOOL_TYPE),
}

# propriété STIX (par type d'objet) -> vocabulaire ouvert qui la gouverne
PROPERTY_VOCABULARY: dict[tuple[str, str], str] = {
    ("threat-actor", "threat_actor_types"): "threat-actor-type-ov",
    ("threat-actor", "roles"): "threat-actor-role-ov",
    ("threat-actor", "sophistication"): "threat-actor-sophistication-ov",
    ("threat-actor", "resource_level"): "attack-resource-level-ov",
    ("threat-actor", "primary_motivation"): "attack-motivation-ov",
    ("threat-actor", "secondary_motivations"): "attack-motivation-ov",
    ("intrusion-set", "resource_level"): "attack-resource-level-ov",
    ("intrusion-set", "primary_motivation"): "attack-motivation-ov",
    ("intrusion-set", "secondary_motivations"): "attack-motivation-ov",
    ("malware", "malware_types"): "malware-type-ov",
    ("malware", "capabilities"): "malware-capabilities-ov",
    ("malware", "implementation_languages"): "implementation-language-ov",
    ("tool", "tool_types"): "tool-type-ov",
    ("infrastructure", "infrastructure_types"): "infrastructure-type-ov",
    ("identity", "identity_class"): "identity-class-ov",
    ("identity", "sectors"): "industry-sector-ov",
    ("indicator", "indicator_types"): "indicator-type-ov",
    ("indicator", "pattern_type"): "pattern-type-ov",
    ("report", "report_types"): "report-type-ov",
    ("grouping", "context"): "grouping-context-ov",
    ("location", "region"): "region-ov",
}

# Chaîne d'attaque historique de Lockheed Martin (utilisable en `kill_chain_phases`)
LOCKHEED_MARTIN_PHASES = (
    "reconnaissance",
    "weaponization",
    "delivery",
    "exploitation",
    "installation",
    "command-and-control",
    "actions-on-objective",
)
KILL_CHAIN_LOCKHEED = "lockheed-martin-cyber-kill-chain"
KILL_CHAIN_ATTACK = "mitre-attack"

# Tactique d'un ancien rapport -> tactiques ATT&CK actuelles. TA0005, historiquement « Defense Evasion »,
# s'appelle « Stealth » dans ATT&CK v20 et « Defense Impairment » (TA0112) en a été scindée.
LEGACY_TACTICS: dict[str, tuple[str, ...]] = {
    "defense-evasion": ("stealth", "defense-impairment"),
}

# --- Confiance (STIX 2.1, Annexe A) -------------------------------------------------------------------------
# libellé -> (valeur STIX à utiliser, plage normative)
CONFIDENCE_SCALE = {
    "none": (0, (0, 0)),
    "low": (15, (1, 29)),
    "medium": (50, (30, 69)),
    "high": (85, (70, 100)),
}
# Échelle WEP (Words of Estimative Probability) : libellé -> valeur STIX
WEP_SCALE = {
    "impossible": 0,
    "highly unlikely": 10,
    "unlikely": 30,
    "even chance": 50,
    "likely": 70,
    "highly likely": 90,
    "certain": 100,
}
# Affirmation sans réserve par les auteurs du rapport : « High » de l'échelle None/Low/Med/High
DEFAULT_CONFIDENCE = CONFIDENCE_SCALE["high"][0]

# Marquages TLP intégrés à STIX 2.1. Un article public est TLP:WHITE (devenu TLP:CLEAR dans TLP 2.0).
TLP_MARKINGS = {
    "white": TLP_WHITE.id,
    "clear": TLP_WHITE.id,
    "green": TLP_GREEN.id,
    "amber": TLP_AMBER.id,
    "red": TLP_RED.id,
}
DEFAULT_TLP = TLP_MARKINGS["clear"]


def allowed_values(stix_type: str, prop: str) -> tuple[str, ...] | None:
    """Valeurs recommandées pour une propriété à vocabulaire ouvert (None si la propriété est libre)."""
    vocab = PROPERTY_VOCABULARY.get((stix_type, prop))
    return OPEN_VOCABULARIES[vocab] if vocab else None
