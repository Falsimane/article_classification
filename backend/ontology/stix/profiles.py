"""Profils d'extraction : ce que le pipeline a le droit d'extraire d'un article, selon sa catégorie.

L'ontologie complète (schema.py, relationships.py) dit ce qui est *valide* en STIX. Ce module dit ce qui vaut la
peine d'être *extrait* d'un texte. L'écart est volontaire et c'est lui qui limite les faux positifs :

- peu de types d'entités, chacun avec un critère de discrimination explicite ;
- peu de relations, chacune avec sa définition, quand l'utiliser et quand l'éviter ;
- les observables (IP, domaines, condensats) sont extraits par règles, jamais par le modèle ;
- un article opérationnel (récit d'intrusion) ajoute les observations (Sighting) et la séquence (Attack Flow),
  un article stratégique se limite à la victimologie, à l'attribution et aux grandes capacités.

Le profil se choisit avec `primary_category` produit par le classifieur (operational, tactical, strategic).
"""

from dataclasses import dataclass

from .relationships import SEMANTICS, is_valid_relationship
from .schema import OBJECT_TYPES

ADVERSARY = ("threat-actor", "intrusion-set", "campaign")
IMPLANT = ("malware", "tool")


@dataclass(frozen=True)
class RelationSpec:
    sources: tuple[str, ...]
    relationship: str
    targets: tuple[str, ...]

    def pairs(self) -> list[tuple[str, str]]:
        """Couples (source, cible) valides dans l'ontologie : le produit cartésien est filtré par la table STIX."""
        return [
            (s, t) for s in self.sources for t in self.targets if is_valid_relationship(s, self.relationship, t)
        ]


@dataclass(frozen=True)
class ExtractionProfile:
    name: str
    focus: str
    entity_types: tuple[str, ...]
    relations: tuple[RelationSpec, ...]
    sightings: bool = False
    attack_flow: bool = False

    def pairs(self) -> list[tuple[str, str, str]]:
        return [(s, r.relationship, t) for r in self.relations for s, t in r.pairs()]


_R = RelationSpec
_ATTRIBUTION = (
    _R(("campaign",), "attributed-to", ("intrusion-set", "threat-actor")),
    _R(("intrusion-set",), "attributed-to", ("threat-actor",)),
    _R(ADVERSARY + ("malware",), "originates-from", ("location",)),
)
_GROUP_STRUCTURE = (
    _R(("threat-actor",), "part-of", ("threat-actor",)),
    _R(("intrusion-set",), "part-of", ("intrusion-set",)),
    _R(("threat-actor",), "cooperates-with", ("threat-actor",)),
    _R(("threat-actor",), "participates-in", ("campaign",)),
)
_VICTIMOLOGY = (_R(ADVERSARY + IMPLANT, "targets", ("identity", "location", "vulnerability")),)
_CAPABILITY = (
    _R(ADVERSARY + IMPLANT, "uses", ("attack-pattern", "malware", "tool", "infrastructure")),
    _R(("malware",), "exploits", ("vulnerability",)),
)
_LINEAGE = (
    _R(("malware",), "variant-of", ("malware",)),
    _R(("malware",), "authored-by", ("threat-actor", "intrusion-set")),
)
_DELIVERY = (
    _R(("malware", "tool"), "drops", ("malware", "tool")),
    _R(("malware",), "downloads", ("malware", "tool")),
    _R(("infrastructure", "tool", "attack-pattern"), "delivers", ("malware",)),
)
_NETWORK = (
    _R(("malware",), "beacons-to", ("infrastructure",)),
    _R(("malware",), "exfiltrates-to", ("infrastructure",)),
    _R(("malware", "infrastructure"), "communicates-with", ("infrastructure",)),
    _R(("infrastructure",), "controls", ("malware",)),
    _R(("infrastructure",), "hosts", ("malware", "tool")),
    _R(ADVERSARY, "compromises", ("infrastructure",)),
    _R(("threat-actor", "intrusion-set", "identity"), "owns", ("infrastructure",)),
)
_DEFENSE = (
    _R(("indicator",), "indicates", ("attack-pattern", "malware", "tool", "intrusion-set", "threat-actor", "campaign")),
    _R(("course-of-action",), "mitigates", ("attack-pattern", "malware", "tool", "vulnerability")),
)

_CORE_ENTITIES = (
    "threat-actor", "intrusion-set", "campaign", "malware", "tool", "attack-pattern", "vulnerability",
    "infrastructure", "identity", "location",
)  # fmt: skip

PROFILES: dict[str, ExtractionProfile] = {
    "operational": ExtractionProfile(
        "operational",
        "Récit d'une intrusion réelle. Capture QUI a fait QUOI, CHEZ QUI et DANS QUEL ORDRE : objets, observations "
        "(sightings) et séquence d'actions (Attack Flow).",
        _CORE_ENTITIES + ("indicator", "course-of-action"),
        _ATTRIBUTION[:2] + _VICTIMOLOGY + _CAPABILITY + _DELIVERY + _NETWORK + _DEFENSE,
        sightings=True,
        attack_flow=True,
    ),
    "tactical": ExtractionProfile(
        "tactical",
        "Analyse technique (malware, TTP, vulnérabilité, détection). Capture COMMENT une capacité fonctionne : "
        "connaissance générale (`uses`, `exploits`), pas des observations datées.",
        _CORE_ENTITIES + ("indicator", "course-of-action"),
        _ATTRIBUTION[:2] + _VICTIMOLOGY + _CAPABILITY + _LINEAGE + _DELIVERY + _NETWORK + _DEFENSE,
    ),
    "strategic": ExtractionProfile(
        "strategic",
        "Vue d'ensemble pour décideurs. Capture QUI, POURQUOI et CONTRE QUI : attribution, motivations, ciblage "
        "sectoriel et géographique, grandes capacités. Pas de détail d'exécution.",
        ("threat-actor", "intrusion-set", "campaign", "malware", "tool", "vulnerability", "identity", "location"),
        _ATTRIBUTION + _GROUP_STRUCTURE + _VICTIMOLOGY + (_R(ADVERSARY, "uses", ("malware", "tool")),),
    ),
}

ENTITY_RULES = (
    "Une entité est un acteur, une capacité, une victime ou une infrastructure PRÉCIS et NOMMÉS dans le texte. "
    "Jamais un terme générique (« le malware », « l'attaquant », « le serveur », « la victime », « threat actor »).",
    "L'éditeur de sécurité, le chercheur ou le média qui rédige le rapport n'est ni un acteur ni une victime : "
    "il est l'auteur du rapport et n'est pas extrait.",
    "N'extrais PAS les observables : adresses IP, noms de domaine, URL, condensats, e-mails, chemins, noms de "
    "fichier ou de bibliothèque (.dll, .exe, .sys) qui ne sont pas un outil connu. Ils sont extraits par ailleurs.",
    "Une CVE est une `vulnerability`. Une technique ATT&CK est un `attack-pattern` : donne son nom ou son identifiant "
    "(T1059.001) tel que le texte le cite.",
    "Malware ou outil ? Le code écrit pour nuire est un `malware`. Le logiciel légitime détourné (PsExec, rclone, "
    "AnyDesk, binaire natif de l'OS) est un `tool`. Un service légitime abusé (GitHub, Cloudflare, Discord, un bucket "
    "cloud) est une `infrastructure`, jamais un acteur.",
    "Groupe ou acteur ? Un ensemble d'activité nommé par un éditeur, sans identité réelle établie, est un "
    "`intrusion-set`. Réserve `threat-actor` aux personnes et organisations réelles identifiées.",
    "Réunis sous un seul objet les noms que le texte donne comme désignant la même chose (un nom, les autres en "
    "alias). N'en déduis rien de la forme d'un nom : les noms d'acteurs sont des conventions propres à chaque éditeur.",
    "Dans le doute entre un type précis et un autre, ne crée pas l'entité. Une absence vaut mieux qu'un faux positif.",
)
RELATION_RULES = (
    "Une relation exige UNE phrase du texte qui relie explicitement les deux entités. Deux entités citées dans un "
    "même paragraphe ne sont pas reliées pour autant.",
    "Attribution : `attributed-to` UNIQUEMENT si le texte attribue explicitement. Une ressemblance de TTP ou "
    "d'outils n'est pas une attribution.",
    "Un acteur peut être désigné par « l'acteur », « il », « the threat actor » : relie alors la capacité à l'acteur "
    "du contexte. Toute autre entité doit être nommée dans la phrase citée.",
    "Dans le doute, ne crée pas la relation.",
)
EXTRACTION_RULES = ENTITY_RULES + RELATION_RULES

def _entity_lines(profile: ExtractionProfile) -> str:
    return "\n".join(f"- {t} : {OBJECT_TYPES[t].definition}" for t in profile.entity_types)


def _relation_lines(profile: ExtractionProfile) -> str:
    by_rel: dict[str, list[tuple[str, str]]] = {}
    for s, r, t in profile.pairs():
        by_rel.setdefault(r, []).append((s, t))
    lines = []
    for rel, pairs in by_rel.items():
        sem = SEMANTICS[rel]
        by_source: dict[str, list[str]] = {}
        for s, t in pairs:
            by_source.setdefault(s, []).append(t)
        # regroupe les sources qui partagent exactement les mêmes cibles
        by_targets: dict[tuple[str, ...], list[str]] = {}
        for s, ts in by_source.items():
            by_targets.setdefault(tuple(ts), []).append(s)
        shapes = " ; ".join(f"{', '.join(ss)} -> {', '.join(ts)}" for ts, ss in by_targets.items())
        lines.append(f"- {rel} ({shapes})\n    définition : {sem.definition}\n    utiliser quand : {sem.use_when}")
        if sem.avoid:
            lines.append(f"    éviter : {sem.avoid}")
    return "\n".join(lines)


def _first_sentence(text: str) -> str:
    return text.split(". ")[0].rstrip(".") + "."


def render_entity_card(profile_name: str) -> str:
    """Carte pour l'étape « entités » : types et règles d'entités seulement (aucune relation)."""
    profile = PROFILES[profile_name]
    lines = "\n".join(f"- {t} : {_first_sentence(OBJECT_TYPES[t].definition)}" for t in profile.entity_types)
    rules = "\n".join(f"{i}. {r}" for i, r in enumerate(ENTITY_RULES, 1))
    return f"TYPES D'ENTITÉS (n'utilise que ceux-ci) :\n{lines}\n\nRÈGLES :\n{rules}"


def render_relation_card(profile_name: str) -> str:
    """Carte pour l'étape « relations » : relations autorisées avec leur définition, et les règles de relation."""
    profile = PROFILES[profile_name]
    rules = "\n".join(f"{i}. {r}" for i, r in enumerate(RELATION_RULES, 1))
    return f"RELATIONS AUTORISÉES (aucune autre) :\n{_relation_lines(profile)}\n\nRÈGLES :\n{rules}"


def render_prompt_card(profile_name: str) -> str:
    """Description de l'ontologie, prête à injecter dans le prompt d'extraction du profil."""
    profile = PROFILES[profile_name]
    extra = []
    if profile.sightings:
        extra.append(
            "OBSERVATIONS (sightings) : pour chaque malware, outil ou technique effectivement VU dans l'incident décrit, "
            "ajoute une observation {sighting_of, where_sighted (victime), first_seen, last_seen}. `uses` est la "
            "connaissance générale ; la sighting est l'observation datée."
        )
    if profile.attack_flow:
        extra.append(
            "SÉQUENCE (Attack Flow) : ordonne les actions de l'adversaire dans le temps (attack-action : "
            "technique_id, dates, actifs ; `effect_refs` = action suivante)."
        )
    rules = "\n".join(f"{i}. {r}" for i, r in enumerate(EXTRACTION_RULES, 1))
    return (
        f"ONTOLOGIE STIX 2.1, profil « {profile.name} »\n{profile.focus}\n\n"
        f"TYPES D'ENTITÉS (n'utilise que ceux-ci) :\n{_entity_lines(profile)}\n\n"
        f"RELATIONS AUTORISÉES (aucune autre) :\n{_relation_lines(profile)}\n\n"
        + ("\n".join(extra) + "\n\n" if extra else "")
        + f"RÈGLES :\n{rules}"
    )


def _check_profiles() -> None:
    """Garde-fou à l'import : un profil ne peut pas déclarer un type inconnu ni une relation sans paire valide."""
    for p in PROFILES.values():
        for t in p.entity_types:
            assert t in OBJECT_TYPES and OBJECT_TYPES[t].extraction == "llm", (p.name, t)
        for spec in p.relations:
            assert spec.relationship in SEMANTICS, (p.name, spec.relationship)
            assert spec.pairs(), (p.name, spec)
            for s, t in spec.pairs():
                assert s in p.entity_types and t in p.entity_types, (p.name, s, spec.relationship, t)


_check_profiles()
