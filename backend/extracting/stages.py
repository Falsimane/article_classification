"""Les deux étapes LLM de l'extraction : entités, puis relations. Sorties volontairement minimales.

Étape 1 (entités), par passe : le modèle liste `type|Nom|alias;alias`, une courte chaîne par entité.
Étape 2 (relations), par passe : le modèle écrit `numéro_de_phrase|E3|relation|E7`. Les identifiants d'entité et
les types de relation viennent de listes fermées et la preuve est le NUMÉRO d'une phrase : aucune citation à recopier.

Entre les deux, tout le reste est déterministe : rapprochement avec ATT&CK, fusion des alias, filtrage des phrases
utiles, vérification que chaque relation est valide en STIX et étayée par la phrase citée (`ontology.stix.validate`).
"""

import re
from dataclasses import dataclass
from functools import lru_cache

from backend.ontology.stix import PROFILES, get_reference_kb
from backend.ontology.stix.profiles import render_entity_card, render_relation_card
from backend.ontology.stix.validate import mentions_prepared, prepare_text

from .segment import Pass, Unit

# Types demandés au modèle. `indicator` (le motif d'une règle) et `course-of-action` exigent de recopier un contenu
# long : hors de cette première version, qui vise la rapidité (voir README).
SKIPPED_TYPES = frozenset({"indicator", "course-of-action"})
ADVERSARY = frozenset({"threat-actor", "intrusion-set", "campaign"})
MAX_ENTITY_TOKENS = 450
MAX_RELATION_TOKENS = 550


def llm_entity_types(profile_name: str) -> tuple[str, ...]:
    return tuple(t for t in PROFILES[profile_name].entity_types if t not in SKIPPED_TYPES)


# --- Étape 1 : entités ---------------------------------------------------------------------------------------------
ENTITY_SCHEMA = {
    "type": "object",
    "properties": {"entities": {"type": "array", "items": {"type": "string"}}},
    "required": ["entities"],
}

_ENTITY_FORMAT = (
    "FORMAT DE RÉPONSE : un objet JSON {\"entities\": [...]} dont chaque élément est UNE chaîne "
    "\"type|Nom|alias1;alias2\" (alias facultatifs). Exemples : \"malware|Qakbot|QBot\", \"intrusion-set|APT29\", "
    "\"vulnerability|CVE-2023-4966\", \"tool|PsExec\". Chaque entité une seule fois. Aucun commentaire."
)


def entity_system(profile_name: str) -> str:
    return (
        "Tu es analyste en renseignement sur la menace (CTI). Tu lis un extrait numéroté d'un rapport et tu listes "
        "les ENTITÉS précises qui y sont nommées, selon l'ontologie STIX 2.1 ci-dessous.\n\n"
        + render_entity_card(profile_name)
        + "\n\n"
        + _ENTITY_FORMAT
    )


@lru_cache(maxsize=1)
def _kb_labels() -> dict[str, tuple[str, str]]:
    """{libellé exact: (nom canonique, type STIX)} des groupes, logiciels et campagnes ATT&CK actifs. Le libellé est
    comparé avec sa casse : « Net » (commande) et « net group » ne se confondent pas avec un acteur."""
    kb = get_reference_kb()
    labels: dict[str, tuple[str, str]] = {}
    for matches in kb._by_name.values():
        for m in matches:
            if m.status != "active":
                continue
            for label in (m.name, *m.aliases):
                if len(label) >= 4 and not label.islower():
                    labels.setdefault(label, (m.name, m.stix_type))
    return labels


_WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.\-+#]*[A-Za-z0-9]|[A-Za-z0-9]")


def kb_hints(units: tuple[Unit, ...] | list[Unit]) -> list[tuple[str, str]]:
    """Candidats ATT&CK repérés dans les phrases, par correspondance exacte (casse comprise) : [(nom, type)].
    Ce sont des INDICES soumis au modèle, jamais des entités acceptées d'office."""
    labels = _kb_labels()
    found: dict[str, str] = {}
    for u in units:
        if u.kind in ("code", "table"):
            continue
        words = _WORD.findall(u.text)
        for i in range(len(words)):
            for n in (3, 2, 1):
                if i + n <= len(words):
                    surface = " ".join(words[i : i + n])
                    if surface in labels:
                        name, stix_type = labels[surface]
                        found.setdefault(name, stix_type)
                        break
    return sorted(found.items())


def entity_user(title: str, category: str, pass_: Pass, hints: list[tuple[str, str]]) -> str:
    hint = ""
    if hints:
        hint = (
            "\nCANDIDATS REPÉRÉS DANS LA BASE ATT&CK (à confirmer par le contexte, ignore-les s'ils ne désignent pas "
            "une menace ici) :\n" + "\n".join(f"- {n} ({t})" for n, t in hints) + "\n"
        )
    return f"RAPPORT : {title}\nCATÉGORIE : {category}\n{hint}\nEXTRAIT :\n{pass_.render()}"


def parse_entities(items: list, allowed: tuple[str, ...]) -> tuple[list[dict], int]:
    """Entités depuis les chaînes du modèle. Retourne (entités, nombre de chaînes illisibles ou hors type)."""
    out, dropped = [], 0
    for item in items or []:
        parts = [p.strip() for p in str(item).split("|")]
        if len(parts) < 2 or parts[0] not in allowed or len(parts[1]) < 2:
            dropped += 1
            continue
        ent = {"type": parts[0], "name": parts[1]}
        if len(parts) > 2 and parts[2]:
            ent["aliases"] = [a.strip() for a in re.split(r"[;,]", parts[2]) if a.strip()]
        out.append(ent)
    return out, dropped


# --- Étape 2 : relations ---------------------------------------------------------------------------------------------
def relation_schema(relations: tuple[str, ...]) -> dict:
    """Chaque relation est une chaîne `uid|Ea|relation|Eb` dont le motif impose un type de relation autorisé."""
    names = "|".join(re.escape(r) for r in relations)
    return {
        "type": "object",
        "properties": {"relations": {"type": "array", "items": {"type": "string", "pattern": rf"^[0-9]{{1,5}}\|E[0-9]{{1,3}}\|({names})\|E[0-9]{{1,3}}$"}}},
        "required": ["relations"],
    }


def relation_system(profile_name: str) -> str:
    return (
        "Tu es analyste en renseignement sur la menace (CTI). On te donne des ENTITÉS numérotées (E1, E2…) et un extrait "
        "dont les phrases sont numérotées. Tu écris les relations STIX 2.1 que ces phrases établissent entre les "
        "entités.\n\n"
        + render_relation_card(profile_name)
        + "\n\nFORMAT DE RÉPONSE : un objet JSON {\"relations\": [...]} dont chaque élément est UNE chaîne "
        "\"numéro_de_phrase|E3|relation|E7\" : la phrase qui étaye la relation, l'entité source, la relation, "
        "l'entité cible. Exemple : \"12|E3|uses|E7\". Aucune autre entité que celles listées. Aucun commentaire."
    )


@dataclass(frozen=True)
class EntityRow:
    eid: str  # "E1"
    stix_type: str
    name: str
    terms: tuple[str, ...]  # nom + alias, pour repérer l'entité dans une phrase


def relation_user(title: str, category: str, rows: list[EntityRow], units: list[Unit]) -> str:
    table = "\n".join(f"{r.eid} {r.stix_type} {r.name}" for r in rows)
    body = "\n".join(
        f"[{u.uid}] ({u.kind})\n{u.prompt_text}" if u.kind in ("code", "table") else f"[{u.uid}] {u.prompt_text}" for u in units
    )
    return f"RAPPORT : {title}\nCATÉGORIE : {category}\n\nENTITÉS :\n{table}\n\nEXTRAIT :\n{body}"


def entity_hits(units: tuple[Unit, ...] | list[Unit], rows: list[EntityRow]) -> dict[int, set[str]]:
    """{numéro de phrase: identifiants des entités nommées dedans}. Chaque phrase n'est tokenisée qu'une fois."""
    hits: dict[int, set[str]] = {}
    for u in units:
        prepared = prepare_text(u.text)
        found = {r.eid for r in rows if mentions_prepared(prepared, r.terms)}
        if found:
            hits[u.uid] = found
    return hits


_RELATION_LINE = re.compile(r"^\s*(\d+)\s*\|\s*(E\d+)\s*\|\s*([a-z\-]+)\s*\|\s*(E\d+)\s*$")


def parse_relations(items: list, valid_ids: set[str], unit_ids: set[int]) -> tuple[list[tuple[int, str, str, str]], int]:
    """Relations (uid, source, relation, cible) depuis les chaînes du modèle ; retire ce qui cite une phrase ou une
    entité inexistante. Retourne aussi le nombre de chaînes écartées."""
    out, dropped = [], 0
    for item in items or []:
        m = _RELATION_LINE.match(str(item))
        if not m or int(m.group(1)) not in unit_ids or m.group(2) not in valid_ids or m.group(4) not in valid_ids:
            dropped += 1
            continue
        out.append((int(m.group(1)), m.group(2), m.group(3), m.group(4)))
    return out, dropped
