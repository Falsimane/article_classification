"""Graphe d'un bundle pour l'interface de révision (noms inventés)."""
import copy

from backend.evaluation.gold_carriers import apply_rows, update_row, worksheet
from backend.evaluation.graph_view import graph_of
from tests.evaluation.test_gold_carriers import BUNDLE, CAMP, MAL, T1

import pytest


def test_graph_nodes_and_edges():
    g = graph_of(BUNDLE, gold=True)
    nodes = {n["id"]: n for n in g["nodes"]}
    assert nodes[MAL]["type"] == "malware" and nodes[MAL]["name"] == "Alpha-Loader"
    assert nodes[T1]["technique"] == "T1027"
    assert nodes[T1]["tactics"]  # tactiques ATT&CK v20 de T1027
    assert {(e["source"], e["rel"], e["target"]) for e in g["edges"]} >= {(CAMP, "uses", T1), (MAL, "uses", T1)}


def test_moved_and_merged_edges_are_marked():
    rows = worksheet(BUNDLE)
    for r in rows:
        if r["source"].startswith("campaign") and r["technique"] == "T1027":
            r.update(decision="move", new_source=MAL)
    out, _ = apply_rows(copy.deepcopy(BUNDLE), rows)
    edge = next(e for e in graph_of(out, gold=True)["edges"] if e["source"] == MAL and e["target"] == T1)
    assert edge["merged_from"] == [CAMP]


def test_update_row_move_requires_allowed_source():
    rows = worksheet(BUNDLE)
    rid = rows[0]["relation_id"]
    with pytest.raises(ValueError):
        update_row(rows, rid, "move", "malware--00000000-0000-4000-8000-000000000000", "", allowed={MAL, CAMP})
    out = update_row(rows, rid, "move", MAL, "le code le fait", allowed={MAL, CAMP})
    row = next(r for r in out if r["relation_id"] == rid)
    assert (row["decision"], row["new_source"], row["reason"]) == ("move", MAL, "le code le fait")


def test_update_row_keep_clears_source():
    rows = worksheet(BUNDLE)
    rid = rows[0]["relation_id"]
    out = update_row(update_row(rows, rid, "move", MAL, "x", allowed={MAL}), rid, "keep", None, "", allowed={MAL})
    assert next(r for r in out if r["relation_id"] == rid)["new_source"] is None


def test_update_row_unknown_decision():
    rows = worksheet(BUNDLE)
    with pytest.raises(ValueError):
        update_row(rows, rows[0]["relation_id"], "maybe", None, "", allowed=set())
