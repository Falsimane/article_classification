"""Relations autorisées entre objets STIX : domaine / codomaine de chaque type de relation.

Trois couches, de la plus à la moins normative. Chaque triplet (source, relation, cible) garde son origine :

- `stix`    : STIX 2.1, Annexe B (« Relationship Summary Table ») et sections 4 et 6 de la spécification OASIS.
              Table générée depuis la spécification elle-même, pas recopiée.
- `attack`  : relations présentes dans les données officielles ATT&CK et absentes de la table STIX
              (ex. 869 relations `tool --uses--> attack-pattern`, `subtechnique-of`).
- `opencti` : extensions de la plateforme OpenCTI (Filigran) retenues parce qu'elles servent la modélisation
              d'articles CTI (`part-of`, `participates-in`, `Incident`…). OpenCTI couvre presque toute la table STIX ;
              il lui manque seulement les relations de `malware-analysis` (modélisé chez lui comme un conteneur) et
              quelques relations d'observables (adresse IP vers MAC / système autonome).

Ce module dit ce qui est *valide*. Ce que le pipeline a le droit d'*extraire* d'un article est un sous-ensemble
bien plus étroit : voir `profiles.py`.
"""

from dataclasses import dataclass

# Les 18 objets observables STIX Cyber-observable Objects (SCO)
SCO_TYPES = frozenset(
    {
        "artifact", "autonomous-system", "directory", "domain-name", "email-addr", "email-message", "file",
        "ipv4-addr", "ipv6-addr", "mac-addr", "mutex", "network-traffic", "process", "software", "url",
        "user-account", "windows-registry-key", "x509-certificate",
    }
)  # fmt: skip
# Alias de la norme : l'Annexe B écrit `exfiltrate-to`, le corps de la spécification et OpenCTI `exfiltrates-to`.
RELATIONSHIP_ALIASES = {"exfiltrate-to": "exfiltrates-to"}

STIX_SPEC: dict[str, dict[str, tuple[str, ...]]] = {
    "attack-pattern": {
        "delivers": ('malware',),
        "targets": ('identity', 'location', 'vulnerability',),
        "uses": ('malware', 'tool',),
    },
    "campaign": {
        "attributed-to": ('intrusion-set', 'threat-actor',),
        "compromises": ('infrastructure',),
        "originates-from": ('location',),
        "targets": ('identity', 'location', 'vulnerability',),
        "uses": ('attack-pattern', 'infrastructure', 'malware', 'tool',),
    },
    "course-of-action": {
        "investigates": ('indicator',),
        "mitigates": ('attack-pattern', 'indicator', 'malware', 'tool', 'vulnerability',),
        "remediates": ('malware', 'vulnerability',),
    },
    "domain-name": {
        "resolves-to": ('domain-name', 'ipv4-addr', 'ipv6-addr',),
    },
    "identity": {
        "located-at": ('location',),
    },
    "indicator": {
        "based-on": ('observed-data',),
        "indicates": ('attack-pattern', 'campaign', 'infrastructure', 'intrusion-set', 'malware', 'threat-actor', 'tool',),
    },
    "infrastructure": {
        "communicates-with": ('domain-name', 'infrastructure', 'ipv4-addr', 'ipv6-addr', 'url',),
        "consists-of": ('infrastructure', 'observed-data', 'sco',),
        "controls": ('infrastructure', 'malware',),
        "delivers": ('malware',),
        "has": ('vulnerability',),
        "hosts": ('malware', 'tool',),
        "located-at": ('location',),
        "uses": ('infrastructure',),
    },
    "intrusion-set": {
        "attributed-to": ('threat-actor',),
        "compromises": ('infrastructure',),
        "hosts": ('infrastructure',),
        "originates-from": ('location',),
        "owns": ('infrastructure',),
        "targets": ('identity', 'location', 'vulnerability',),
        "uses": ('attack-pattern', 'infrastructure', 'malware', 'tool',),
    },
    "ipv4-addr": {
        "belongs-to": ('autonomous-system',),
        "resolves-to": ('mac-addr',),
    },
    "ipv6-addr": {
        "belongs-to": ('autonomous-system',),
        "resolves-to": ('mac-addr',),
    },
    "malware": {
        "authored-by": ('intrusion-set', 'threat-actor',),
        "beacons-to": ('infrastructure',),
        "communicates-with": ('domain-name', 'ipv4-addr', 'ipv6-addr', 'url',),
        "controls": ('malware',),
        "downloads": ('file', 'malware', 'tool',),
        "drops": ('file', 'malware', 'tool',),
        "exfiltrates-to": ('infrastructure',),
        "exploits": ('vulnerability',),
        "originates-from": ('location',),
        "targets": ('identity', 'infrastructure', 'location', 'vulnerability',),
        "uses": ('attack-pattern', 'infrastructure', 'malware', 'tool',),
        "variant-of": ('malware',),
    },
    "malware-analysis": {
        "analysis-of": ('malware',),
        "characterizes": ('malware',),
        "dynamic-analysis-of": ('malware',),
        "static-analysis-of": ('malware',),
    },
    "threat-actor": {
        "attributed-to": ('identity',),
        "compromises": ('infrastructure',),
        "hosts": ('infrastructure',),
        "impersonates": ('identity',),
        "located-at": ('location',),
        "owns": ('infrastructure',),
        "targets": ('identity', 'location', 'vulnerability',),
        "uses": ('attack-pattern', 'infrastructure', 'malware', 'tool',),
    },
    "tool": {
        "delivers": ('malware',),
        "drops": ('malware',),
        "has": ('vulnerability',),
        "targets": ('identity', 'infrastructure', 'location', 'vulnerability',),
        "uses": ('infrastructure',),
    },
}

# Relations observées dans les données ATT&CK de MITRE, hors table STIX.
ATTACK_EXTENSIONS: dict[str, dict[str, tuple[str, ...]]] = {
    "tool": {"uses": ("attack-pattern",)},
    "attack-pattern": {"subtechnique-of": ("attack-pattern",)},
}

# Extensions OpenCTI (Filigran) retenues. `incident` est l'objet STIX 2.1 réservé aux incidents.
OPENCTI_EXTENSIONS: dict[str, dict[str, tuple[str, ...]]] = {
    "incident": {
        "attributed-to": ("campaign", "intrusion-set", "threat-actor"),
        "compromises": ("infrastructure",),
        "originates-from": ("location",),
        "targets": ("identity", "location", "vulnerability"),
        "uses": ("attack-pattern", "infrastructure", "malware", "tool"),
    },
    "indicator": {"indicates": ("incident", "vulnerability"), "based-on": tuple(sorted(SCO_TYPES))},
    "identity": {"part-of": ("identity",), "owns": ("infrastructure",)},
    "threat-actor": {"part-of": ("threat-actor",), "cooperates-with": ("threat-actor",), "participates-in": ("campaign",)},
    "intrusion-set": {"part-of": ("intrusion-set",)},
    "location": {"located-at": ("location",)},
    "software": {"has": ("vulnerability",)},
    "file": {
        "communicates-with": ("domain-name", "ipv4-addr", "ipv6-addr"),
        "drops": ("file", "artifact"),
        "downloads": ("file", "artifact"),
    },
    "artifact": {"communicates-with": ("domain-name", "ipv4-addr", "ipv6-addr")},
    "domain-name": {"belongs-to": ("identity",)},
    "ipv4-addr": {"located-at": ("location",)},
    "ipv6-addr": {"located-at": ("location",)},
    "infrastructure": {"hosts": ("software",), "consists-of": ("software",)},
}

# Relations génériques de STIX 2.1 (section 3.x), valides entre n'importe quels objets (related-to) ou entre
# objets de même type (derived-from, duplicate-of). `revoked-by` (ATT&CK) peut relier deux types voisins
# (ATT&CK publie un `malware revoked-by tool`) : traité comme générique.
SAME_TYPE_RELATIONS = frozenset({"derived-from", "duplicate-of"})
ANY_TYPE_RELATIONS = frozenset({"related-to", "revoked-by"})


@dataclass(frozen=True)
class RelationshipSemantics:
    """Définition d'une relation, rédigée pour être lue par un humain et injectée dans le prompt d'extraction."""

    definition: str
    use_when: str
    avoid: str = ""


SEMANTICS: dict[str, RelationshipSemantics] = {
    "uses": RelationshipSemantics(
        "A emploie B comme moyen ou capacité (technique, malware, outil, infrastructure). Connaissance générale sur A, "
        "comme dans ATT&CK ; ce n'est pas une observation datée (voir Sighting).",
        "Le texte dit que A déploie, exécute, utilise ou s'appuie sur B.",
        "B est seulement cité dans le même paragraphe ; B est un outil de défense ou d'analyse du rapporteur ; "
        "B est une vulnérabilité (utiliser `targets` ou `exploits`).",
    ),
    "targets": RelationshipSemantics(
        "A vise B : une victime (identity : organisation, secteur d'activité, individu), un pays ou une région "
        "(location) ou une vulnérabilité.",
        "Victimologie explicite, ciblage sectoriel ou géographique, exploitation d'une CVE précise.",
        "Victimes d'un événement cité en exemple sans lien avec A ; l'éditeur ou le chercheur auteur du rapport.",
    ),
    "attributed-to": RelationshipSemantics(
        "L'activité de A (campagne, ensemble d'intrusion) est attribuée à B (acteur de la menace) ; "
        "ou l'acteur A est attribué à une identité réelle B.",
        "Attribution explicite : « attribué à », « nous évaluons que X est opéré par Y ».",
        "Simple similarité de TTP, d'outils ou d'infrastructure (« recoupe », « rappelle ») : utiliser `related-to`.",
    ),
    "exploits": RelationshipSemantics(
        "Le malware A exploite la vulnérabilité B. Seul un malware *exploite* une vulnérabilité ; "
        "un acteur, un ensemble d'intrusion ou une campagne la *cible* (`targets`).",
        "Le texte dit que le malware A embarque ou lance l'exploit de B.",
        "Sujet acteur, ensemble d'intrusion ou campagne (utiliser `targets`).",
    ),
    "communicates-with": RelationshipSemantics(
        "A (malware ou infrastructure) communique avec B (adresse IP, nom de domaine, URL ou infrastructure).",
        "Le texte relie explicitement A à une destination réseau précise.",
        "Domaine ou IP cité sans lien avec A.",
    ),
    "beacons-to": RelationshipSemantics(
        "Le malware A émet périodiquement vers l'infrastructure B (balise de commande et contrôle).",
        "Beaconing, check-in vers un serveur C2 identifié.",
    ),
    "exfiltrates-to": RelationshipSemantics(
        "Le malware A exfiltre des données vers l'infrastructure B.",
        "Le texte dit que les données sont envoyées par A vers B.",
        "L'exfiltration est réalisée par un outil légitime (modéliser l'outil comme `tool` qui `uses` l'infrastructure).",
    ),
    "delivers": RelationshipSemantics(
        "A livre le malware B (vecteur de distribution : infrastructure, outil, technique de livraison).",
        "A est le canal par lequel B arrive sur la victime.",
    ),
    "drops": RelationshipSemantics(
        "A dépose ou installe B sur la machine (malware, outil ou fichier).",
        "Le texte dit que A écrit, extrait ou installe B localement.",
        "B est téléchargé à distance (`downloads`).",
    ),
    "downloads": RelationshipSemantics(
        "A télécharge B depuis une source distante.",
        "Le texte dit que A récupère B via le réseau.",
        "B est embarqué dans A (`drops`).",
    ),
    "variant-of": RelationshipSemantics(
        "Le malware A est une variante de la famille B.",
        "Le texte dit que A dérive de B ou partage son code avec B.",
        "Simple ressemblance de comportement.",
    ),
    "authored-by": RelationshipSemantics(
        "Le malware A est développé par B (acteur ou ensemble d'intrusion).",
        "Le texte désigne B comme auteur ou développeur de A.",
        "B est seulement un utilisateur de A (`uses`).",
    ),
    "controls": RelationshipSemantics(
        "A contrôle B : une infrastructure contrôle un malware, ou un malware en contrôle un autre.",
        "Relation de commande explicite (serveur C2 qui pilote un implant).",
    ),
    "hosts": RelationshipSemantics(
        "L'infrastructure A héberge B (malware, outil, ou infrastructure).",
        "Le texte dit que A sert de support d'hébergement à B.",
    ),
    "owns": RelationshipSemantics(
        "A possède ou opère l'infrastructure B.",
        "Propriété ou exploitation explicite.",
        "L'infrastructure est compromise, non possédée (`compromises`).",
    ),
    "compromises": RelationshipSemantics(
        "A compromet l'infrastructure B qui ne lui appartient pas (site légitime piraté, serveur victime).",
        "Le texte dit que A prend le contrôle d'une infrastructure tierce.",
        "L'infrastructure appartient à A (`owns`).",
    ),
    "indicates": RelationshipSemantics(
        "L'indicateur A (règle de détection, motif) signale la présence de B.",
        "Une règle YARA, Sigma, Snort ou un motif STIX décrit explicitement B.",
    ),
    "mitigates": RelationshipSemantics(
        "L'action défensive A atténue B (technique, malware, outil, vulnérabilité).",
        "Le texte recommande ou décrit A comme parade contre B.",
        "A détecte B sans le bloquer (`indicates`).",
    ),
    "remediates": RelationshipSemantics(
        "L'action A corrige B (correctif, suppression du malware).",
        "Correctif ou procédure d'éradication explicite.",
    ),
    "located-at": RelationshipSemantics(
        "A (identité, acteur, infrastructure) est situé en B (lieu).",
        "Localisation explicite.",
    ),
    "originates-from": RelationshipSemantics(
        "A (campagne, ensemble d'intrusion, malware) provient du lieu B.",
        "Origine géographique attribuée par le texte.",
    ),
    "has": RelationshipSemantics(
        "A (infrastructure, outil, logiciel) présente la vulnérabilité B.",
        "Le texte dit que A est affecté par B.",
    ),
    "consists-of": RelationshipSemantics(
        "L'infrastructure A est composée de B (autre infrastructure, ou observables).",
        "Composition explicite.",
    ),
    "part-of": RelationshipSemantics(
        "A est un sous-ensemble ou membre de B (acteur dans un groupe, ensemble d'intrusion dans un autre).",
        "Appartenance ou sous-groupe explicite.",
    ),
    "cooperates-with": RelationshipSemantics(
        "Les acteurs A et B coopèrent.",
        "Coopération explicite.",
    ),
    "participates-in": RelationshipSemantics(
        "L'acteur A participe à la campagne B.",
        "Participation explicite.",
    ),
    "impersonates": RelationshipSemantics(
        "L'acteur A usurpe l'identité B (marque, organisation).",
        "Usurpation explicite (faux site, faux compte).",
    ),
    "subtechnique-of": RelationshipSemantics(
        "La technique A est une sous-technique de B (ATT&CK).",
        "Relation entre identifiants ATT&CK (T1059.001 de T1059).",
    ),
    "related-to": RelationshipSemantics(
        "Lien non typé entre deux objets. À éviter dès qu'un type précis convient.",
        "Chevauchement ou similarité signalés mais non attribués.",
        "Une relation typée existe.",
    ),
    "resolves-to": RelationshipSemantics(
        "Le nom de domaine A se résout en B (adresse IP).", "Résolution DNS indiquée dans le texte."
    ),
    "belongs-to": RelationshipSemantics(
        "L'adresse A appartient à B (système autonome, organisation).", "Appartenance indiquée."
    ),
    "based-on": RelationshipSemantics(
        "L'indicateur A est construit à partir de B (observable ou donnée observée).", "Dérivation explicite."
    ),
}


def canonical_relationship(rel: str) -> str:
    rel = (rel or "").strip().lower().replace("_", "-")
    return RELATIONSHIP_ALIASES.get(rel, rel)


def _build_index() -> dict[tuple[str, str], dict[str, str]]:
    """{(source, relation): {cible: origine}} ; la première origine rencontrée (la plus normative) est conservée."""
    index: dict[tuple[str, str], dict[str, str]] = {}
    layers = (("stix", STIX_SPEC), ("attack", ATTACK_EXTENSIONS), ("opencti", OPENCTI_EXTENSIONS))
    for origin, table in layers:
        for source, rels in table.items():
            for rel, targets in rels.items():
                bucket = index.setdefault((source, rel), {})
                for target in targets:
                    if target == "sco":
                        for sco in SCO_TYPES:
                            bucket.setdefault(sco, origin)
                    else:
                        bucket.setdefault(target, origin)
    return index


_INDEX = _build_index()
ALL_RELATIONSHIP_TYPES = frozenset({rel for _, rel in _INDEX} | SAME_TYPE_RELATIONS | ANY_TYPE_RELATIONS)


def relationship_origin(source: str, rel: str, target: str) -> str | None:
    """Origine de la règle ('stix', 'attack', 'opencti', 'generic') ou None si la relation est invalide."""
    rel = canonical_relationship(rel)
    if rel in ANY_TYPE_RELATIONS:
        return "generic"
    if rel in SAME_TYPE_RELATIONS:
        return "generic" if source == target else None
    return _INDEX.get((source, rel), {}).get(target)


def is_valid_relationship(source: str, rel: str, target: str) -> bool:
    return relationship_origin(source, rel, target) is not None


# Relations de maintenance du graphe : valides, mais jamais proposées pour corriger une extraction.
HOUSEKEEPING_RELATIONS = frozenset({"revoked-by", "derived-from", "duplicate-of"})


def allowed_relationships(source: str, target: str) -> list[str]:
    """Types de relation valides de `source` vers `target`, triés (utile pour corriger un prédicat erroné)."""
    rels = {rel for (s, rel), targets in _INDEX.items() if s == source and target in targets}
    rels |= ANY_TYPE_RELATIONS | (SAME_TYPE_RELATIONS if source == target else frozenset())
    return sorted(rels - HOUSEKEEPING_RELATIONS)


def allowed_targets(source: str, rel: str) -> list[str]:
    rel = canonical_relationship(rel)
    return sorted(_INDEX.get((source, rel), {}))
