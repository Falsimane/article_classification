"""Schémas JSON imposés au décodage (xgrammar). Ils sont générés depuis le registre STIX et l'article : un type, une relation
ou une extrémité hors table ne peut pas être écrit. Une branche dont une liste serait vide est omise (xgrammar refuse
`enum: []`)."""

from collections import defaultdict

from backend.extracting.stix.objects import ALLOWED_RELATIONS, ENTITY_CLASSES

CARRIER_TYPES = ("campaign", "intrusion-set", "threat-actor", "malware", "tool")
MAX_SENTENCES = 6


def _sentences(min_items: int = 1) -> dict:
    return {"type": "array", "items": {"type": "integer"}, "minItems": min_items, "maxItems": MAX_SENTENCES}


def _array(item: dict, min_items: int = 0, max_items: int | None = None) -> dict:
    out = {"type": "array", "items": item, "minItems": min_items}
    if max_items:
        out["maxItems"] = max_items
    return out


def _object(props: dict) -> dict:
    return {"type": "object", "properties": props, "required": list(props), "additionalProperties": False}


def entity_schema() -> dict:
    """Entités de l'article : type STIX du registre, nom tel que le texte l'écrit, alias, et le troisième champ de la forme."""
    item = _object({
        "type": {"type": "string", "enum": list(ENTITY_CLASSES)},
        "name": {"type": "string"},
        "aliases": _array({"type": "string"}, max_items=6),
        "detail": {"type": "string"},
    })  # fmt: skip
    return _object({"entities": _array(item, min_items=1, max_items=80)})


def relation_schema(types: list[str], sources: set[str] | None = None) -> dict | None:
    """Relations entre entités numérotées 1..n (`types[i-1]` = type STIX de l'entité i) : une branche par (type source,
    relation), la source parmi les entités de ce type, la cible parmi celles des types admis par la table STIX. `sources`
    restreint les types de source (relations des seules techniques)."""
    targets: dict[tuple[str, str], set[str]] = defaultdict(set)
    for s, r, t in ALLOWED_RELATIONS:
        if sources is None or s in sources:
            targets[(s, r)].add(t)
    by_type: dict[str, list[int]] = defaultdict(list)
    for i, t in enumerate(types, 1):
        by_type[t].append(i)
    branches = []
    for (s, r), allowed in sorted(targets.items()):
        sources = by_type.get(s, [])
        dests = sorted(i for t in allowed for i in by_type.get(t, []))
        if not sources or not dests:
            continue
        branches.append(_object({
            "source": {"type": "integer", "enum": sources},
            "relation": {"type": "string", "enum": [r]},
            "target": {"type": "integer", "enum": dests},
            "sentences": _sentences(),
        }))  # fmt: skip
    if not branches:
        return None
    return _object({"relations": _array({"anyOf": branches}, max_items=150)})


def cluster_schema(n_carriers: int) -> dict:
    """Grappes : centre = numéro d'un porteur (1..n) ou 0 pour « non nommé » ; portée incident / contexte ; phrases."""
    item = _object({
        "center": {"type": "integer", "enum": list(range(0, n_carriers + 1))},
        "scope": {"type": "string", "enum": ["incident", "background"]},
        "sentences": _array({"type": "integer"}, min_items=1, max_items=80),
    })  # fmt: skip
    return _object({"clusters": _array(item, min_items=1, max_items=20)})


def grid_schema(tactics: list[str]) -> dict:
    """Une case par tactique ATT&CK : les procédures du centre pour cette tactique, ou une liste vide."""
    proc = _object({"procedure": {"type": "string"}, "sentences": _sentences()})
    return _object({t: _array(proc, max_items=6) for t in tactics})


def choice_schema(n_procedures: int, ids: list[str]) -> dict:
    """Technique de chaque procédure, dans la liste fermée de la tactique (ou « none »)."""
    item = _object({
        "procedure": {"type": "integer", "enum": list(range(1, n_procedures + 1))},
        "technique": {"type": "string", "enum": [*ids, "none"]},
    })  # fmt: skip
    return _object({"choices": _array(item, max_items=2 * n_procedures + 2)})


def label_schema(n_items: int) -> dict:
    """Un libellé par entité refusée (numérotée) : la correction ne peut ni en oublier ni en ajouter."""
    item = _object({"item": {"type": "integer", "enum": list(range(1, n_items + 1))}, "name": {"type": "string"}})
    return _object({"labels": _array(item, min_items=n_items, max_items=n_items)})
