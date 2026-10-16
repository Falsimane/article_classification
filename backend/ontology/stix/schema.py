"""Registre des types d'objets de l'ontologie (STIX 2.1 + extensions retenues).

Pour chaque type : sa famille, sa définition opérationnelle (le critère qui le distingue des types voisins : c'est
ce qui évite qu'un LLM range tout dans la même classe) et son mode d'extraction. La clé qui fonde l'identifiant
déterministe de chaque type est dans `identity.ID_KEYS`.

Les propriétés complètes de chaque objet sont celles de STIX 2.1, validées par la bibliothèque `stix2` (voir
`export.py`) : ce module n'en redéfinit pas la liste.

Modes d'extraction :
- `llm`           : extrait du texte par le modèle de langage ;
- `deterministic` : extrait par des règles (expressions régulières, bibliothèque d'IOC), jamais par le LLM ;
- `derived`       : construit par le pipeline à partir des métadonnées de l'article (auteur, date, URL) ;
- `off`           : valide dans STIX mais non extrait par ce pipeline.
"""

from dataclasses import dataclass

from .relationships import SCO_TYPES


@dataclass(frozen=True)
class ObjectType:
    stix_type: str
    family: str  # "sdo" | "sro" | "sco" | "extension"
    label: str  # libellé de nœud Neo4j
    definition: str
    extraction: str = "off"
    origin: str = "stix-2.1"


_LABEL_OVERRIDES = {"ipv4-addr": "IPv4Address", "ipv6-addr": "IPv6Address", "url": "URL", "x509-certificate": "X509Certificate"}


def _label(stix_type: str) -> str:
    """Libellé de nœud Neo4j : `threat-actor` -> `ThreatActor`."""
    return _LABEL_OVERRIDES.get(stix_type) or "".join(part.capitalize() for part in stix_type.split("-"))


def _sdo(stix_type: str, definition: str, extraction="llm", origin="stix-2.1") -> ObjectType:
    return ObjectType(stix_type, "sdo", _label(stix_type), definition, extraction, origin)


OBJECT_TYPES: dict[str, ObjectType] = {
    t.stix_type: t
    for t in [
        # --- Adversaires -------------------------------------------------------------------------------------
        _sdo(
            "threat-actor",
            "Personne, groupe ou organisation réels qui conduisent des attaques (« qui »). Désigné par un nom "
            "propre ou un pseudonyme. Ce n'est PAS un malware, un outil, un éditeur de sécurité ni une victime.",
        ),
        _sdo(
            "intrusion-set",
            "Ensemble cohérent de comportements, d'outils et d'infrastructures attribué à un même opérateur, "
            "souvent un groupe nommé par un éditeur (APT29, Sandworm) sans identité réelle établie. "
            "À préférer à `threat-actor` quand le texte parle d'un « groupe », « cluster » ou « activité ».",
        ),
        _sdo(
            "campaign",
            "Série d'attaques bornée dans le temps, avec un objectif et des cibles, qui porte souvent un nom "
            "propre (« Operation Aurora »). Une campagne n'est pas un acteur : elle est conduite par un acteur.",
        ),
        # --- Capacités ---------------------------------------------------------------------------------------
        _sdo(
            "malware",
            "Code malveillant : famille (is_family=true) ou échantillon précis. Conçu pour nuire "
            "(Qakbot, BlackCat, Cobalt Strike Beacon si utilisé comme implant malveillant).",
        ),
        _sdo(
            "tool",
            "Logiciel LÉGITIME ou à double usage détourné par un attaquant (PsExec, rclone, AnyDesk, PowerShell, "
            "Mimikatz si le texte le présente comme outil). Critère : il n'a pas été écrit pour nuire. "
            "Binaire natif de l'OS détourné (LOLBin) : `tool` avec le label `living-off-the-land`.",
        ),
        _sdo(
            "attack-pattern",
            "Technique, tactique ou procédure d'attaque (« comment »), idéalement rattachée à ATT&CK "
            "(T1059.001). Décrit un comportement, jamais un outil ni un malware précis.",
        ),
        _sdo(
            "vulnerability",
            "Faiblesse d'un logiciel ou d'un système, identifiée par une CVE ou un CWE. En STIX, la CVE "
            "est dans `external_references` (source_name=cve), pas dans une propriété dédiée.",
        ),
        _sdo(
            "infrastructure",
            "Système, service ou ressource réseau qui soutient une attaque : serveur de commande et contrôle, "
            "hébergement de charges utiles, relais, service légitime abusé (label `abused-legitimate-service`). "
            "Une adresse IP ou un domaine seul est un observable, pas une infrastructure.",
        ),
        # --- Victimes et contexte ----------------------------------------------------------------------------
        _sdo(
            "identity",
            "Victime ou entité concernée : organisation, individu, système, ou classe (secteur d'activité : "
            "identity_class=class + sectors). Les éditeurs de sécurité et chercheurs n'entrent ici que comme "
            "auteurs du rapport (created_by_ref), jamais comme acteurs de l'attaque.",
        ),
        _sdo(
            "location",
            "Lieu : pays (code ISO 3166-1 alpha-2), région (vocabulaire region-ov), ville. Sert la victimologie "
            "(`targets`) et l'origine attribuée (`originates-from`).",
        ),
        # --- Défense -----------------------------------------------------------------------------------------
        _sdo(
            "course-of-action",
            "Mesure défensive : parade, durcissement, remédiation, correctif (D3FEND, mitigations ATT&CK).",
        ),
        _sdo(
            "indicator",
            "Motif de détection exploitable : règle YARA, Sigma, Snort, Suricata ou motif STIX, avec `pattern` et "
            "`pattern_type`. Une règle de détection est un `indicator` en STIX 2.1, pas un « DefensiveMeasure ».",
        ),
        # --- Conteneurs et observations ----------------------------------------------------------------------
        _sdo(
            "report",
            "L'article source. Conteneur dont `object_refs` liste tous les objets extraits : c'est la provenance "
            "de chaque fait. Construit à partir des métadonnées de l'article, jamais par le LLM.",
            extraction="derived",
        ),
        _sdo(
            "grouping",
            "Regroupement d'objets sans jugement (contexte suspicious-activity, malware-analysis).",
            extraction="off",
        ),
        _sdo(
            "observed-data",
            "Observation brute de données (au moins un observable) à un instant donné.",
            extraction="off",
        ),
        _sdo(
            "malware-analysis",
            "Résultat d'une analyse (statique ou dynamique) d'un échantillon de malware.",
            extraction="off",
        ),
        _sdo("note", "Annotation d'analyste sur d'autres objets.", extraction="off"),
        _sdo("opinion", "Avis d'un analyste sur l'exactitude d'un objet.", extraction="off"),
        _sdo(
            "incident",
            "L'intrusion décrite par l'article : objet STIX 2.1 réservé, repris par OpenCTI. Construit par le pipeline "
            "(jamais par le LLM) à partir du titre du rapport ; il est le sujet implicite des phrases qui parlent de "
            "« l'acteur », « l'attaquant » ou « the threat actor » quand aucun acteur n'est nommé.",
            extraction="derived",
            origin="stix-2.1/opencti",
        ),
        # --- Relations (SRO) ---------------------------------------------------------------------------------
        ObjectType(
            "relationship",
            "sro",
            "Relationship",
            "Lien typé entre deux objets (voir relationships.py). Porte la preuve textuelle et la confiance.",
            "llm",
        ),
        ObjectType(
            "sighting",
            "sro",
            "Sighting",
            "OBSERVATION : « X a été vu chez Y à telle date ». Distingue ce qui a été observé dans un incident réel "
            "de la connaissance générale portée par `uses` (et du simple PoC ou de la capacité statique).",
            "llm",
        ),
        # --- Extension MITRE Attack Flow (séquence chronologique d'une intrusion) ------------------------------
        ObjectType(
            "attack-flow",
            "extension",
            "AttackFlow",
            "Séquence d'actions d'un adversaire (portée : incident, campagne…). Remplace les liens ad hoc du type "
            "« leads_to_step » : l'ordre est porté par `effect_refs`.",
            "llm",
            "attack-flow-2.0",
        ),
        ObjectType(
            "attack-action",
            "extension",
            "AttackAction",
            "Une action de l'adversaire : technique ATT&CK (technique_id), dates d'exécution, actifs et effets.",
            "llm",
            "attack-flow-2.0",
        ),
        ObjectType(
            "attack-asset",
            "extension",
            "AttackAsset",
            "Actif impliqué dans une action (système, compte, donnée), lié éventuellement à un objet STIX.",
            "llm",
            "attack-flow-2.0",
        ),
        ObjectType(
            "attack-condition",
            "extension",
            "AttackCondition",
            "Condition qui oriente le flux (« si l'accès administrateur est obtenu »).",
            "llm",
            "attack-flow-2.0",
        ),
        ObjectType(
            "attack-operator",
            "extension",
            "AttackOperator",
            "Opérateur logique (AND / OR) qui combine des effets de plusieurs actions.",
            "off",
            "attack-flow-2.0",
        ),
    ]
}

# Observables (SCO) : identifiants déterministes définis par la norme (propriétés contributrices), extraits par règles.
_SCO_EXTRACTED = {"ipv4-addr", "ipv6-addr", "domain-name", "url", "file", "email-addr", "autonomous-system"}
for _t in sorted(SCO_TYPES):
    OBJECT_TYPES[_t] = ObjectType(
        _t,
        "sco",
        _label(_t),
        "Observable (donnée technique brute). Extrait par règles, jamais par le LLM : le LLM ne fait que relier "
        "ces observables à une capacité ou une infrastructure."
        if _t in _SCO_EXTRACTED
        else "Observable STIX valide mais non extrait par ce pipeline.",
        "deterministic" if _t in _SCO_EXTRACTED else "off",
    )

# Identifiant de l'extension Attack Flow (STIX 2.1 `extension-definition`) et portées admises
ATTACK_FLOW_EXTENSION_ID = "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4"
ATTACK_FLOW_SCOPES = ("incident", "campaign", "threat-actor", "malware", "emulation-plan", "attack-tree", "other")

SDO_TYPES = frozenset(t for t, o in OBJECT_TYPES.items() if o.family == "sdo")
KNOWN_TYPES = frozenset(OBJECT_TYPES)


def is_known_type(stix_type: str) -> bool:
    return stix_type in OBJECT_TYPES


def llm_extractable_types() -> frozenset[str]:
    return frozenset(t for t, o in OBJECT_TYPES.items() if o.extraction == "llm")
