"""Migration du gold vers STIX 2.1 strict (bundles inventés), puis contrôle des vrais golds."""
import copy
import json

import pytest

from backend.evaluation.cti_eval import load_manifest
from backend.evaluation.gold_strict import drop_native_tools, invert_tool_techniques, strip_software, violations
from backend.extracting.stix.attack import get_attack_kb

CAMP = "campaign--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
VULN = "vulnerability--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
SOFT = "software--cccccccc-cccc-4ccc-8ccc-cccccccccccc"
NATIVE = "tool--dddddddd-dddd-4ddd-8ddd-dddddddddddd"
ATTACK_TOOL = "tool--eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
T1 = "attack-pattern--ffffffff-ffff-4fff-8fff-ffffffffffff"


def _rel(n, src, rel, tgt, quote, label="gold:required"):
    return {"type": "relationship", "id": f"relationship--{n * 8}-{n * 4}-4{n * 3}-8{n * 3}-{n * 12}", "relationship_type": rel,
            "source_ref": src, "target_ref": tgt, "labels": [label], "x_gold_evidence_quote": quote}  # fmt: skip


def _bundle(*extra):
    return {"type": "bundle", "id": "bundle--11111111-1111-4111-8111-111111111111", "objects": [
        {"type": "campaign", "id": CAMP, "name": "Wave campaign", "labels": ["gold:required"]},
        {"type": "vulnerability", "id": VULN, "name": "CVE-2000-0001", "labels": ["gold:required"]},
        {"type": "attack-pattern", "id": T1, "name": "Obfuscated Files or Information", "labels": ["gold:required"],
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1027"}]},
        *extra,
    ]}  # fmt: skip


@pytest.fixture(scope="module")
def kb():
    return get_attack_kb()


def _rels(bundle):
    return [o for o in bundle["objects"] if o["type"] == "relationship"]


def test_strip_software_keeps_product_in_description():
    b = _bundle({"type": "software", "id": SOFT, "name": "Alpha-Product", "vendor": "Beta-Vendor", "labels": ["gold:required"]},
                _rel("2", SOFT, "has", VULN, "q"), _rel("3", CAMP, "targets", SOFT, "q"))  # fmt: skip
    out, n = strip_software(b)
    objs = {o["id"]: o for o in out["objects"]}
    assert n == 1 and SOFT not in objs and not _rels(out)
    assert "Produit visé : Alpha-Product (Beta-Vendor)" in objs[VULN]["description"]
    assert "Produit visé : Alpha-Product (Beta-Vendor)" in objs[CAMP]["description"]


def test_strip_software_drops_orphaned_vendor():
    vendor = "identity--33333333-3333-4333-8333-333333333333"
    b = _bundle({"type": "software", "id": SOFT, "name": "Alpha-Product", "labels": ["gold:required"]},
                {"type": "identity", "id": vendor, "name": "Beta-Vendor", "labels": ["gold:required"]},
                _rel("2", SOFT, "related-to", vendor, "q"))  # fmt: skip
    out, _ = strip_software(b)
    assert vendor not in {o["id"] for o in out["objects"]}


def test_drop_native_tool_rewires_technique(kb):
    b = _bundle({"type": "tool", "id": NATIVE, "name": "odbcconf", "labels": ["gold:required"]},
                _rel("2", CAMP, "uses", NATIVE, "q0"), _rel("3", NATIVE, "uses", T1, "q1"))  # fmt: skip
    out, n = drop_native_tools(b, kb)
    rels = _rels(out)
    assert n == 1 and NATIVE not in {o["id"] for o in out["objects"]}
    assert len(rels) == 1 and (rels[0]["source_ref"], rels[0]["target_ref"]) == (CAMP, T1)
    assert rels[0]["x_gold_evidence_quote"] == "q1" and "via odbcconf" in rels[0]["x_gold_context"]


def test_drop_native_tool_merges_existing(kb):
    b = _bundle({"type": "tool", "id": NATIVE, "name": "odbcconf", "labels": ["gold:required"]},
                _rel("2", CAMP, "uses", NATIVE, "q0"), _rel("3", NATIVE, "uses", T1, "q1"),
                _rel("4", CAMP, "uses", T1, "q2", label="gold:acceptable"))  # fmt: skip
    out, _ = drop_native_tools(b, kb)
    rels = _rels(out)
    assert len(rels) == 1 and rels[0]["labels"] == ["gold:required"]
    assert "q1" in rels[0]["description"] and NATIVE in rels[0]["x_gold_merged_from"]


def test_drop_native_tool_no_rewire_when_technique_carried(kb):
    mal = "malware--44444444-4444-4444-8444-444444444444"
    b = _bundle({"type": "tool", "id": NATIVE, "name": "odbcconf", "labels": ["gold:required"]},
                {"type": "malware", "id": mal, "name": "Alpha-Loader", "is_family": True, "labels": ["gold:required"]},
                _rel("2", CAMP, "uses", NATIVE, "q0"), _rel("3", NATIVE, "uses", T1, "q1"), _rel("4", mal, "uses", T1, "q2"))  # fmt: skip
    out, _ = drop_native_tools(b, kb)
    assert [(r["source_ref"], r["target_ref"]) for r in _rels(out)] == [(mal, T1)]


def test_invert_tool_technique(kb):
    b = _bundle({"type": "tool", "id": ATTACK_TOOL, "name": "bitsadmin", "labels": ["gold:required"]},
                _rel("2", ATTACK_TOOL, "uses", T1, "q1"))  # fmt: skip
    kept, n_drop = drop_native_tools(b, kb)
    out, n = invert_tool_techniques(kept)
    rel = _rels(out)[0]
    assert n_drop == 0 and n == 1 and (rel["source_ref"], rel["target_ref"]) == (T1, ATTACK_TOOL) and rel["x_gold_inverted"] is True


def test_input_bundle_untouched(kb):
    b = _bundle({"type": "tool", "id": NATIVE, "name": "odbcconf", "labels": ["gold:required"]},
                {"type": "software", "id": SOFT, "name": "Alpha-Product", "labels": ["gold:required"]},
                _rel("2", CAMP, "uses", NATIVE, "q0"), _rel("3", NATIVE, "uses", T1, "q1"), _rel("4", SOFT, "has", VULN, "q"))  # fmt: skip
    before = copy.deepcopy(b)
    strip_software(invert_tool_techniques(drop_native_tools(b, kb)[0])[0])
    assert b == before


def test_violations_flag_each_rule(kb):
    b = _bundle({"type": "tool", "id": NATIVE, "name": "odbcconf", "labels": ["gold:required"]},
                {"type": "software", "id": SOFT, "name": "Alpha-Product", "labels": ["gold:required"]},
                {"type": "malware", "id": "malware--22222222-2222-4222-8222-222222222222", "name": "alpha.dll", "is_family": False},
                _rel("3", NATIVE, "uses", T1, "q1"))  # fmt: skip
    text = " ".join(violations(b, kb))
    assert "software" in text and "odbcconf" in text and "alpha.dll" in text and "tool uses attack-pattern" in text


@pytest.mark.parametrize("entry", load_manifest(), ids=lambda e: str(e["article_id"]))
def test_all_golds_strict(entry, kb):
    assert violations(json.loads(entry["gold_path"].read_text(encoding="utf-8")), kb) == []


# --- Ajouts validés par l'audit (tâche 5) -----------------------------------------------------------------------------------
from backend.evaluation.gold_strict import additions_for_article, apply_additions  # noqa: E402

PRED_TOOL = "tool--55555555-5555-4555-8555-555555555555"
PRED_T = "attack-pattern--66666666-6666-4666-8666-666666666666"


def _pred(*extra):
    return {"type": "bundle", "id": "bundle--77777777-7777-4777-8777-777777777777", "objects": [
        {"type": "campaign", "id": "campaign--88888888-8888-4888-8888-888888888888", "name": "Wave campaign"},
        {"type": "tool", "id": PRED_TOOL, "name": "Beta-Tool"},
        {"type": "attack-pattern", "id": PRED_T, "name": "Obfuscated Files or Information",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1027"}]},
        *extra,
    ]}  # fmt: skip


def test_additions_skip_violations(kb):
    pred = _pred({"type": "software", "id": SOFT, "name": "Alpha-Product"})
    assert additions_for_article(_bundle(), pred, ["E:software:Alpha-Product"], kb) == []


def test_additions_relation_maps_endpoints_and_writes_stix_direction(kb):
    rel = {"type": "relationship", "id": RID_PRED, "relationship_type": "uses", "source_ref": PRED_TOOL, "target_ref": PRED_T,
           "external_references": [{"source_name": "test", "description": "Beta-Tool obfuscates the payload"}]}  # fmt: skip
    items = additions_for_article(_bundle(), _pred(rel), ["E:tool:Beta-Tool", "R:tool:Beta-Tool --uses--> attack-pattern:Obfuscated Files or Information [T1027]"], kb)
    objs = [i["object"] for i in items]
    new_rel = next(o for o in objs if o["type"] == "relationship")
    assert (new_rel["source_ref"], new_rel["target_ref"]) == (T1, PRED_TOOL)  # technique du gold, sens de la norme
    assert new_rel["labels"] == ["gold:acceptable"] and new_rel["x_gold_evidence_quote"] == "Beta-Tool obfuscates the payload"


def test_apply_additions_rename():
    out, n = apply_additions(_bundle(), [{"rename": CAMP, "name": "Wave delivery campaign (Group-Nine, 2020)"}])
    camp = next(o for o in out["objects"] if o["id"] == CAMP)
    assert n == 1 and camp["name"] == "Wave delivery campaign (Group-Nine, 2020)" and camp["x_gold_renamed_from"] == "Wave campaign"


RID_PRED = "relationship--99999999-9999-4999-8999-999999999990"


def test_additions_skip_other_carrier_in_group(kb):
    mal = "malware--12121212-1212-4121-8121-121212121212"
    gold = _bundle({"type": "malware", "id": mal, "name": "Alpha-Loader", "is_family": True, "labels": ["gold:required"]},
                   _rel("2", CAMP, "uses", mal, "q"), _rel("3", mal, "uses", T1, "q"))  # fmt: skip
    pred_camp = "campaign--88888888-8888-4888-8888-888888888888"
    rel = {"type": "relationship", "id": RID_PRED, "relationship_type": "uses", "source_ref": pred_camp, "target_ref": PRED_T}
    key = "R:campaign:Wave campaign --uses--> attack-pattern:Obfuscated Files or Information [T1027]"
    assert additions_for_article(gold, _pred(rel), [key], kb) == []


def test_additions_no_orphan_technique(kb):
    other = "malware--13131313-1313-4131-8131-131313131313"
    t2 = "attack-pattern--14141414-1414-4141-8141-141414141414"
    pred = _pred({"type": "malware", "id": other, "name": "Gamma-Loader", "is_family": True},
                 {"type": "attack-pattern", "id": t2, "name": "Command and Scripting Interpreter",
                  "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}]},
                 {"type": "relationship", "id": RID_PRED, "relationship_type": "uses", "source_ref": other, "target_ref": t2})  # fmt: skip
    assert additions_for_article(_bundle(), pred, ["T1059"], kb) == []


def test_additions_skip_technique_already_carried(kb):
    mal = "malware--15151515-1515-4151-8151-151515151515"
    gold = _bundle({"type": "malware", "id": mal, "name": "Alpha-Loader", "is_family": True, "labels": ["gold:required"]},
                   _rel("2", mal, "uses", T1, "q"))  # fmt: skip
    other = "campaign--16161616-1616-4161-8161-161616161616"
    pred = _pred({"type": "campaign", "id": other, "name": "Other wave campaign"},
                 {"type": "relationship", "id": RID_PRED, "relationship_type": "uses", "source_ref": other, "target_ref": PRED_T})  # fmt: skip
    items = additions_for_article(gold, pred, ["E:campaign:Other wave campaign",
                                               "R:campaign:Other wave campaign --uses--> attack-pattern:Obfuscated Files or Information [T1027]"], kb)
    assert [i["object"]["type"] for i in items] == ["campaign"]


def test_apply_additions_rename_of_added_object():
    new = {"type": "campaign", "id": "campaign--17171717-1717-4171-8171-171717171717", "name": "Other wave campaign", "labels": ["gold:acceptable"]}
    out, _ = apply_additions(_bundle(), [{"rename": new["id"], "name": "Other wave campaign (Group-Nine, 2021)"}, {"key": "E", "object": new}])
    assert next(o for o in out["objects"] if o["id"] == new["id"])["name"] == "Other wave campaign (Group-Nine, 2021)"
