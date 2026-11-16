"""Appariement sémantique de l'évaluation : deux libellés différents du même composant sont appariés par un juge, jamais
deux entités déjà appariées par leur nom, jamais deux types différents (noms inventés)."""
from backend.evaluation.score import score_article
from backend.evaluation.semantic_match import match_article, pending
from backend.extracting.stix.attack import get_attack_kb

T1 = "attack-pattern--33333333-3333-4333-8333-333333333333"
G_MAL, P_MAL = "malware--11111111-1111-4111-8111-111111111111", "malware--22222222-2222-4222-8222-222222222222"
P_OTHER = "malware--66666666-6666-4666-8666-666666666666"
P_ID = "identity--77777777-7777-4777-8777-777777777777"


def _bundle(objects):
    return {"type": "bundle", "id": "bundle--55555555-5555-4555-8555-555555555555", "objects": objects}


def _technique(gold):
    return {"type": "attack-pattern", "id": T1, "name": "Obfuscated Files or Information", **({"labels": ["gold:required"]} if gold else {}),
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1027"}]}  # fmt: skip


def _uses(rid, src, gold):
    extra = {"labels": ["gold:required"], "x_gold_evidence_quote": "The second-stage loader hides its strings."} if gold else {"description": "The second-stage loader hides its strings."}
    return {"type": "relationship", "id": f"relationship--{rid * 8}-4444-4444-8444-444444444444", "relationship_type": "uses", "source_ref": src, "target_ref": T1, **extra}


GOLD = _bundle([{"type": "malware", "id": G_MAL, "name": "Beta-stage loader", "labels": ["gold:required"]}, _technique(True), _uses("4", G_MAL, True)])
PRED = _bundle([
    {"type": "malware", "id": P_MAL, "name": "second stage implant"},
    {"type": "malware", "id": P_OTHER, "name": "Gamma stealer"},
    {"type": "identity", "id": P_ID, "name": "Beta-stage vendor"},
    _technique(False), _uses("9", P_MAL, False),
])  # fmt: skip


def test_pending_lists_unmatched_entities_of_the_same_class():
    groups = pending(GOLD, PRED, get_attack_kb())
    assert len(groups) == 1 and [g["name"] for g in groups[0]["gold"]] == ["Beta-stage loader"]
    assert [p["name"] for p in groups[0]["pred"]] == ["second stage implant", "Gamma stealer"]
    assert "hides its strings" in groups[0]["pred"][0]["context"]


def test_judge_answer_becomes_a_pair_and_credits_entity_and_relation():
    pairs = match_article(GOLD, PRED, get_attack_kb(), judge=lambda group: {1: 1})
    assert pairs == [{"gold": G_MAL, "pred": P_MAL, "gold_name": "Beta-stage loader", "pred_name": "second stage implant"}]
    without, with_ = score_article(1, GOLD, PRED), score_article(1, GOLD, PRED, semantic=pairs)
    assert without.relations.found_required == 0 and with_.relations.found_required == 1
    assert with_.entities.found_required == without.entities.found_required + 1


def test_judge_saying_none_gives_no_pair():
    assert match_article(GOLD, PRED, get_attack_kb(), judge=lambda group: {1: 0}) == []


def test_out_of_range_answer_ignored():
    assert match_article(GOLD, PRED, get_attack_kb(), judge=lambda group: {1: 7, 3: 1}) == []


def test_judged_pair_cannot_displace_a_name_match():
    named = _bundle([{"type": "malware", "id": P_MAL, "name": "Beta-stage loader"}, {"type": "malware", "id": P_OTHER, "name": "Gamma stealer"}])
    stale = [{"gold": G_MAL, "pred": P_OTHER, "gold_name": "Beta-stage loader", "pred_name": "Gamma stealer"}]
    score = score_article(1, GOLD, named, semantic=stale)
    assert score.entities.found_required == score_article(1, GOLD, named).entities.found_required
    assert score.entities.predicted == 2
