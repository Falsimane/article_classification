"""Feuille de révision des porteurs du gold (noms inventés)."""
import copy

import pytest

from backend.evaluation.gold_carriers import apply_rows, worksheet

CAMP = "campaign--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
MAL = "malware--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
LOC = "location--cccccccc-cccc-4ccc-8ccc-cccccccccccc"
T1 = "attack-pattern--dddddddd-dddd-4ddd-8ddd-dddddddddddd"
T2 = "attack-pattern--eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"


def _ap(sid, tid, name):
    return {"type": "attack-pattern", "id": sid, "name": name, "labels": ["gold:required"],
            "external_references": [{"source_name": "mitre-attack", "external_id": tid}]}  # fmt: skip


def _rel(rid, src, tgt, quote, rel="uses"):
    return {"type": "relationship", "id": f"relationship--{rid * 8}-{rid * 4}-4{rid * 3}-8{rid * 3}-{rid * 12}", "relationship_type": rel,
            "source_ref": src, "target_ref": tgt, "labels": ["gold:required"], "x_gold_evidence_quote": quote}  # fmt: skip


BUNDLE = {"type": "bundle", "id": "bundle--ffffffff-ffff-4fff-8fff-ffffffffffff", "objects": [
    {"type": "campaign", "id": CAMP, "name": "Wave campaign", "labels": ["gold:required"]},
    {"type": "malware", "id": MAL, "name": "Alpha-Loader", "is_family": True, "labels": ["gold:required"]},
    {"type": "location", "id": LOC, "name": "Nowhere", "country": "ZZ", "labels": ["gold:required"]},
    _ap(T1, "T1027", "Obfuscated Files or Information"), _ap(T2, "T1566.001", "Spearphishing Attachment"),
    _rel("1", CAMP, T1, "Alpha-Loader decrypts its strings"),
    _rel("2", CAMP, T2, "the operators sent emails"),
    _rel("3", CAMP, MAL, "the campaign used Alpha-Loader"),
    _rel("4", MAL, T1, "the loader XORs its payload"),
]}  # fmt: skip


def test_worksheet_lists_only_uses_to_technique():
    rows = worksheet(BUNDLE)
    assert sorted(r["technique"] for r in rows) == ["T1027", "T1027", "T1566.001"]
    row = next(r for r in rows if r["source"] == "campaign:Wave campaign" and r["technique"] == "T1027")
    assert set(row["candidates"]) == {CAMP, MAL}
    assert row["decision"] == "keep" and row["new_source"] is None


def test_apply_moves_source_and_merges_duplicate():
    rows = worksheet(BUNDLE)
    for r in rows:
        if r["source"].startswith("campaign") and r["technique"] == "T1027":
            r.update(decision="move", new_source=MAL, reason="Alpha-Loader decrypts its strings")
    out, moved = apply_rows(copy.deepcopy(BUNDLE), rows)
    uses_t1 = [o for o in out["objects"] if o.get("relationship_type") == "uses" and o["target_ref"] == T1]
    assert moved == 1 and len(uses_t1) == 1 and uses_t1[0]["source_ref"] == MAL
    assert "Alpha-Loader decrypts its strings" in uses_t1[0]["description"]


def test_apply_moves_without_duplicate_keeps_trace():
    rows = worksheet(BUNDLE)
    for r in rows:
        if r["technique"] == "T1566.001":
            r.update(decision="move", new_source=MAL, reason="x")
    out, moved = apply_rows(copy.deepcopy(BUNDLE), rows)
    rel = next(o for o in out["objects"] if o.get("target_ref") == T2)
    assert moved == 1 and rel["source_ref"] == MAL and rel["x_gold_revised_from"] == CAMP


def test_apply_refuses_disallowed_relation():
    rows = worksheet(BUNDLE)
    rows[0].update(decision="move", new_source=LOC, reason="x")
    original = copy.deepcopy(BUNDLE)
    with pytest.raises(ValueError):
        apply_rows(original, rows)
    assert original == BUNDLE


TOOL = "tool--99999999-9999-4999-8999-999999999999"


def test_move_to_tool_writes_stix_direction():
    bundle = copy.deepcopy(BUNDLE)
    bundle["objects"].append({"type": "tool", "id": TOOL, "name": "Beta-Tool", "labels": ["gold:required"]})
    bundle["objects"].append(_rel("5", CAMP, TOOL, "the campaign used Beta-Tool"))
    bundle["objects"].append(_rel("6", T2, TOOL, "Beta-Tool sends the emails"))  # déjà présent, sens de la norme
    rows = worksheet(bundle)
    for r in rows:
        if r["source"].startswith("campaign") and r["technique"] in ("T1027", "T1566.001"):
            r.update(decision="move", new_source=TOOL, reason="x")
    out, _ = apply_rows(bundle, rows)
    tool_rels = [o for o in out["objects"] if o.get("type") == "relationship" and TOOL in (o["source_ref"], o["target_ref"]) and o["source_ref"] != CAMP]
    assert all(o["source_ref"].startswith("attack-pattern--") and o["target_ref"] == TOOL for o in tool_rels)
    assert sorted(o["source_ref"] for o in tool_rels) == sorted([T1, T2])  # T2 fusionnée, pas dupliquée
