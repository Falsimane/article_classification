"""Audit des faux positifs étendu aux entités et aux relations (noms inventés)."""
from backend.evaluation.fp_audit import entity_items, relation_items, summary_line
from backend.preprocessing.cleaning.text.segment import segment

TEXT = "Alpha-Loader decrypts its configuration.\n\nThe operators of Group-Nine sent spearphishing emails.\n\nNothing else here."
UNITS = segment(TEXT)


def test_entity_items_skip_techniques_and_cite_sentences():
    items = entity_items(7, "t", ["malware:Alpha-Loader", "attack-pattern:PowerShell [T1059.001]"], UNITS)
    assert [i["key"] for i in items] == ["7:E:malware:Alpha-Loader"]
    assert items[0]["kind"] == "entity"
    assert any("decrypts" in q for q in items[0]["quotes"])


def test_entity_key_strips_hallucination_note():
    items = entity_items(7, "t", ["attack-pattern:X [T9999] (hallucination T9999)", "tool:Beta (hallucination x)"], UNITS)
    assert [i["key"] for i in items] == ["7:E:tool:Beta"]


def test_relation_items_skip_already_judged_technique():
    rels = [
        {"relation": "malware:Alpha-Loader --uses--> attack-pattern:Obfuscated Files or Information [T1027]", "quote": "q1"},
        {"relation": "intrusion-set:Group-Nine --uses--> malware:Alpha-Loader", "quote": "q2"},
    ]
    items = relation_items(7, "t", rels, judged={"T1027"})
    assert [i["key"] for i in items] == ["7:R:intrusion-set:Group-Nine --uses--> malware:Alpha-Loader"]
    assert items[0]["kind"] == "relation" and items[0]["quotes"] == ["q2"]


def _data():
    return {
        "run": "x", "stats": {"gold": 1, "gold_event": 1, "pred": 10, "pred_family": 8, "pred_event": 8},
        "items": [{"key": "1:T1005", "kind": "technique"}, {"key": "1:E:tool:Beta", "kind": "entity"},
                  {"key": "1:R:a --uses--> b", "kind": "relation"}],
        "kinds": {"entity": {"pred": 5, "matched": 4}, "relation": {"pred": 4, "matched": 2, "inherited": {"1:R:c": "1:T1005"}}},
    }  # fmt: skip


def test_legacy_keys_still_count():
    line = summary_line(_data(), {"1:T1005": {"verdict": "F", "comment": ""}})
    assert "J 0 · D 0 · F 1" in line


def test_entity_corrected_precision():
    line = summary_line(_data(), {"1:E:tool:Beta": {"verdict": "J", "comment": ""}})
    assert "entités" in line and "100.0 %" in line  # (4 appariées + 1 J) / 5


def test_relation_inherits_technique_verdict():
    # relation propre « a uses b » : J ; relation héritée de T1005 (F) : non comptée comme juste → (2 + 1) / 4
    line = summary_line(_data(), {"1:R:a --uses--> b": {"verdict": "J"}, "1:T1005": {"verdict": "F"}})
    assert "relations" in line and " 75.0 %" in line
