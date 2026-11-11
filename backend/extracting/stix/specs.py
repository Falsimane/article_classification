"""Registre des types STIX 2.1 extraits par le modèle (couche sémantique) et table complète de leurs relations.

Une entrée par type : définition montrée au modèle (d'après la norme STIX 2.1, sans aucun nom tiré d'un article), forme de la
déclaration. Les relations sont celles du résumé des relations de STIX 2.1 (annexe « Relationship Summary ») entre ces types,
plus quelques extensions marquées :
- ATT&CK : un outil « uses » une technique, un malware ou un outil (convention des données MITRE ATT&CK) ;
- OpenCTI : le produit visé (`software`, observable) « has » une vulnérabilité, est visé (« targets »), est relié à son éditeur.
Les IOC (adresses, domaines, URL, fichiers), `indicator` et `observed-data` restent dans la couche observable, extraite par
règles : ils ne figurent ni ici ni dans la table.

Hors registre : `grouping`, `note`, `opinion` (méta-objets d'analyste) et `incident` (ébauche dans STIX 2.1, sans relation définie).
`attack-pattern` est toujours un objet ATT&CK v20.0 choisi parmi des candidates, jamais déclaré par un nom.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class TypeSpec:
    definition: str
    form: str  # forme de la déclaration « type|… » attendue du modèle


TYPE_SPECS: dict[str, TypeSpec] = {
    "intrusion-set": TypeSpec(
        "groupe d'attaquants nommé (nom ou code de suivi donné par le rapport ou un éditeur), ensemble de comportements et de "
        "ressources attribués à une même organisation.",
        "intrusion-set|<nom>|<alias1;alias2>",
    ),
    "threat-actor": TypeSpec(
        "personne, organisation ou État réellement identifié derrière l'activité (commanditaire, individu nommé).",
        "threat-actor|<nom>|<alias1;alias2>",
    ),
    "campaign": TypeSpec(
        "opération que le rapport décrit : une vague ou un ensemble d'intrusions contre des cibles, sur une période (une intrusion "
        "racontée de bout en bout en est une). Jamais créée pour relier les éléments.",
        "campaign|<nom descriptif en anglais>",
    ),
    "malware": TypeSpec(
        "code malveillant nommé, ou composant que l'article désigne par un libellé descriptif (reprendre ce libellé).",
        "malware|<nom>|<alias1;alias2>",
    ),
    "tool": TypeSpec(
        "logiciel légitime détourné par l'attaquant (outil d'administration, de tunnel, d'accès à distance, packer). Jamais une "
        "fonction, un appel système ou une bibliothèque de programmation.",
        "tool|<nom>|<alias1;alias2>",
    ),
    "infrastructure": TypeSpec(
        "service ou système NOMMÉ ou décrit que l'attaquant emploie ou contrôle : serveur de commande (C2), botnet, service "
        "d'hébergement ou de stockage détourné, réseau de relais. Jamais une IP, un domaine ou une URL (ce sont des IOC).",
        "infrastructure|<nom ou description courte>",
    ),
    "vulnerability": TypeSpec("vulnérabilité identifiée par une CVE.", "vulnerability|CVE-YYYY-NNNNN"),
    "software": TypeSpec("produit logiciel légitime visé ou compromis, avec son éditeur.", "software|<produit>|<éditeur>"),
    "identity": TypeSpec(
        "victime visée (organisation nommée, secteur entier) ou éditeur du produit visé. Jamais l'auteur du rapport, un chercheur "
        "ou un éditeur de sécurité.",
        "identity|<nom ou secteur>|<secteur STIX;classe>",
    ),
    "location": TypeSpec("pays ou région visés, ou d'où provient l'attaquant.", "location|<pays>|<code ISO 3166-1>"),
    "course-of-action": TypeSpec(
        "mesure de défense que le rapport recommande ou décrit contre l'attaque : correctif, configuration, blocage, détection. "
        "Nom court qui résume l'action.",
        "course-of-action|<action courte en anglais>|<description d'une phrase>",
    ),
    "malware-analysis": TypeSpec(
        "résultat d'une analyse d'échantillon que le rapport rapporte (bac à sable, antivirus, analyse statique) : produit ou "
        "méthode d'analyse et verdict.",
        "malware-analysis|<produit ou méthode d'analyse>|<malicious, suspicious, benign ou unknown>",
    ),
}

_ACTORS = ("campaign", "intrusion-set", "threat-actor")
_TARGETS = ("identity", "location", "vulnerability", "software")

# (sources, relations, cibles)
RELATIONS: tuple[tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]], ...] = (
    # Attribution
    (("campaign",), ("attributed-to",), ("intrusion-set", "threat-actor")),
    (("intrusion-set",), ("attributed-to",), ("threat-actor",)),
    (("threat-actor",), ("attributed-to",), ("identity",)),
    (("threat-actor",), ("impersonates",), ("identity",)),
    (("malware",), ("authored-by",), ("intrusion-set", "threat-actor")),
    # Emploi (techniques, logiciels, infrastructure)
    ((*_ACTORS, "malware"), ("uses",), ("attack-pattern", "malware", "tool", "infrastructure")),
    (("tool",), ("uses",), ("attack-pattern", "malware", "tool", "infrastructure")),  # ATT&CK pour attack-pattern / malware / tool
    (("attack-pattern",), ("uses",), ("malware", "tool")),
    (("attack-pattern", "infrastructure", "tool"), ("delivers",), ("malware",)),
    (("malware", "tool"), ("drops",), ("malware", "tool")),
    (("malware",), ("downloads",), ("malware", "tool")),
    (("malware",), ("controls",), ("malware",)),
    (("malware",), ("variant-of",), ("malware",)),
    # Ciblage et exploitation
    ((*_ACTORS, "malware", "tool", "attack-pattern"), ("targets",), _TARGETS),
    (("malware", "tool"), ("targets",), ("infrastructure",)),
    (("malware",), ("exploits",), ("vulnerability",)),
    (("software", "infrastructure", "tool"), ("has",), ("vulnerability",)),
    (("software",), ("related-to",), ("identity",)),
    # Infrastructure
    (("malware",), ("communicates-with", "beacons-to", "exfiltrates-to"), ("infrastructure",)),
    (("infrastructure",), ("communicates-with", "consists-of", "uses"), ("infrastructure",)),
    (("infrastructure",), ("controls",), ("infrastructure", "malware")),
    (("infrastructure",), ("hosts",), ("malware", "tool")),
    (_ACTORS, ("compromises",), ("infrastructure",)),
    (("intrusion-set", "threat-actor"), ("hosts", "owns"), ("infrastructure",)),
    # Origine et localisation
    (("campaign", "intrusion-set", "malware"), ("originates-from",), ("location",)),
    (("threat-actor", "identity", "infrastructure"), ("located-at",), ("location",)),
    # Défense et analyse
    (("course-of-action",), ("mitigates",), ("attack-pattern", "malware", "tool", "vulnerability")),
    (("course-of-action",), ("remediates",), ("malware", "vulnerability")),
    (("malware-analysis",), ("analysis-of", "characterizes", "static-analysis-of", "dynamic-analysis-of", "av-analysis-of"), ("malware",)),
)


# Sens de chaque type de relation (d'après les définitions de STIX 2.1), montré au modèle avec la table : le nom seul ne suffit
# pas (mesure : « authored-by » pour un malware seulement employé par un groupe, « remediates » pour une enquête).
RELATION_DEFINITIONS: dict[str, str] = {
    "attributed-to": "la source est menée par la cible ou lui est rattachée (campagne menée par un groupe ; groupe rattaché à un acteur ou à son commanditaire)",
    "authored-by": "la cible a ÉCRIT ou développé le malware ; un groupe qui l'emploie seulement n'en est pas l'auteur (c'est « uses »)",
    "impersonates": "l'acteur se fait passer pour cette identité",
    "uses": "la source emploie la cible (technique, logiciel, infrastructure) dans son activité",
    "delivers": "la source livre ou installe le malware sur la victime (document piégé, dropper, serveur de distribution)",
    "drops": "le malware ou l'outil dépose sur le système un autre logiciel qu'il contient",
    "downloads": "le malware récupère un autre logiciel depuis le réseau",
    "controls": "la source pilote la cible (serveur qui commande un malware, malware qui en commande un autre)",
    "variant-of": "la source est une variante ou une nouvelle version de la cible",
    "targets": "la source vise la cible (victime, secteur, lieu, produit, vulnérabilité, infrastructure attaquée)",
    "exploits": "le code du malware exploite lui-même la vulnérabilité ; ce qui seulement dépose ou suit l'exploitation ne l'exploite pas",
    "has": "le produit ou le système comporte la vulnérabilité",
    "related-to": "le produit logiciel est édité par cette identité",
    "communicates-with": "le malware ou l'infrastructure échange avec cette infrastructure sur le réseau",
    "beacons-to": "le malware signale régulièrement sa présence à son serveur de commande",
    "exfiltrates-to": "le malware envoie les données volées vers cette infrastructure",
    "consists-of": "l'infrastructure se compose de la cible",
    "hosts": "la source héberge la cible (serveur qui héberge un malware ou un outil ; acteur qui fournit l'hébergement d'une infrastructure)",
    "owns": "l'acteur possède cette infrastructure",
    "compromises": "l'acteur a pris le contrôle de cette infrastructure appartenant à un tiers",
    "originates-from": "la source provient de ce lieu",
    "located-at": "la source est située dans ce lieu",
    "mitigates": "la mesure empêche ou réduit l'effet de la cible (blocage, durcissement, détection d'une technique ou d'un logiciel)",
    "remediates": "la mesure supprime ou corrige la cible (correctif d'une vulnérabilité, retrait d'un malware) ; une enquête, une surveillance ou une politique générale ne corrigent rien",
    "analysis-of": "l'analyse porte sur cet échantillon de malware",
    "characterizes": "l'analyse décrit ce malware",
    "static-analysis-of": "analyse statique de cet échantillon",
    "dynamic-analysis-of": "analyse dynamique (exécution, bac à sable) de cet échantillon",
    "av-analysis-of": "verdict d'un antivirus sur cet échantillon",
}


def relation_definitions(only: set[str] | None = None) -> str:
    """Sens des types de relation, un par ligne (tous, ou ceux de `only`)."""
    return "\n".join(f"- {r} : {d}" for r, d in RELATION_DEFINITIONS.items() if only is None or r in only)


def type_definitions() -> str:
    """Les types du registre pour le prompt, un par ligne : définition et forme de déclaration."""
    return "\n".join(f"- {t} : {s.definition} Forme : « {s.form} »." for t, s in TYPE_SPECS.items())
