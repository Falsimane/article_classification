"""Score STIX strict : outil → technique lu dans les deux sens, software hors périmètre (noms inventés)."""
from backend.evaluation.score import score_article

TOOL = "tool--11111111-1111-4111-8111-111111111111"
SW = "software--22222222-2222-4222-8222-222222222222"
T1 = "attack-pattern--33333333-3333-4333-8333-333333333333"
RID = "relationship--44444444-4444-4444-8444-444444444444"


def _bundle(objects):
    return {"type": "bundle", "id": "bundle--55555555-5555-4555-8555-555555555555", "objects": objects}


def _base(gold: bool):
    label = {"labels": ["gold:required"]} if gold else {}
    return [
        {"type": "tool", "id": TOOL, "name": "Beta-Tool", **label},
        {"type": "attack-pattern", "id": T1, "name": "Obfuscated Files or Information", **label,
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1027"}]},
    ]  # fmt: skip


def _uses(src, tgt, gold: bool):
    label = {"labels": ["gold:required"], "x_gold_evidence_quote": "q"} if gold else {"description": "q"}
    return {"type": "relationship", "id": RID, "relationship_type": "uses", "source_ref": src, "target_ref": tgt, **label}


def test_tool_technique_matches_both_directions():
    gold = _bundle(_base(True) + [_uses(T1, TOOL, True)])  # sens de la norme
    pred = _bundle(_base(False) + [_uses(TOOL, T1, False)])  # ancien bundle
    assert score_article(1, gold, pred).relations.found_required == 1


def test_software_ignored():
    gold = _bundle(_base(True))
    pred = _bundle(_base(False) + [{"type": "software", "id": SW, "name": "Alpha-Product"}])
    assert score_article(1, gold, pred).entities.predicted == 2
