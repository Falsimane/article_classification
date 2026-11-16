"""Graphe d'un bundle STIX (gold ou prédiction) en données pures pour l'interface de révision : nœuds du périmètre scoré
(sans IOC ni éditeur), arêtes typées, déplacements et fusions de la révision du gold marqués."""

from backend.evaluation.score import load_bundle
from backend.extracting.stix.attack import get_attack_kb


def graph_of(bundle: dict, gold: bool) -> dict:
    kb = get_attack_kb()
    ents, rels = load_bundle(bundle, kb, gold=gold)
    objs = {o["id"]: o for o in bundle.get("objects", [])}
    nodes = [
        {"id": sid, "type": e.stix_type, "name": e.name, "technique": e.technique,
         "tactics": (kb.get(e.technique) or {}).get("tactics", []) if e.technique else []}
        for sid, e in ents.items()
    ]  # fmt: skip
    edges = []
    for r in rels:
        o = objs.get(r.sid, {})
        edges.append({"id": r.sid, "source": r.source, "target": r.target, "rel": r.rel, "quotes": r.quotes[:2],
                      "moved_from": o.get("x_gold_revised_from"), "merged_from": o.get("x_gold_merged_from", [])})  # fmt: skip
    return {"nodes": nodes, "edges": edges, "tactic_order": [t for t, _, _ in kb.tactic_rows()]}
