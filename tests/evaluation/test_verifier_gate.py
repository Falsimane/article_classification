"""Barrière hors ligne du vérificateur : seuils F rejetés ≥ 2/3 et vrais positifs gardés ≥ 95 %."""
from backend.evaluation.verifier_gate import gate


def test_gate_passes_on_thresholds():
    rows = [("f", "drop")] * 2 + [("f", "keep")] + [("tp", "keep")] * 19 + [("tp", "drop")]
    assert gate(rows)["verdict"] == "PASSE"


def test_gate_fails_on_false_rejections():
    rows = [("f", "drop")] * 3 + [("tp", "keep")] * 18 + [("tp", "drop")] * 2
    assert gate(rows)["verdict"] == "ÉCHOUE"


def test_gate_fails_when_errors_kept():
    rows = [("f", "drop")] + [("f", "keep")] * 2 + [("tp", "keep")] * 20
    assert gate(rows)["verdict"] == "ÉCHOUE"


def test_to_parent_counts_as_kept_for_d():
    out = gate([("jd", "to_parent"), ("jd", "reassign"), ("jd", "drop")])
    assert out["jd_kept"] == 2 and out["jd"] == 3


def test_reassigned_true_positive_is_not_kept():
    out = gate([("tp", "reassign"), ("tp", "keep")])
    assert out["tp_kept"] == 1 and out["tp_modified"] == 1


def test_no_audited_error_is_undetermined():
    assert gate([("tp", "keep")] * 5)["verdict"] == "INDÉTERMINÉ"
