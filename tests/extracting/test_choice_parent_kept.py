"""Choix en deux temps : quand le modèle garde la technique parente à l'étape des sous-techniques, elle reste retenue."""
from types import SimpleNamespace

from backend.extracting.cascade.clusters import Cluster
from backend.extracting.cascade.techniques import _children, choose_global

PARENT = "T1498"  # technique ATT&CK avec sous-techniques


def _choose(sub_answer):
    assert _children(PARENT)
    answers = {"choice:parent": {"choices": [{"procedure": 1, "technique": PARENT}]}, "choice:sub": sub_answer}
    draft = SimpleNamespace()
    procs = [("impact", {"procedure": "floods the public services of the victim with traffic", "sentences": [1]})]
    return choose_global(draft, Cluster(None, "incident", [1]), procs, lambda stage, *a: answers[stage])


def test_parent_itself_is_kept():
    assert _choose({"choices": [{"procedure": 1, "technique": PARENT}]}) == {1: [PARENT]}


def test_sub_technique_replaces_parent():
    assert _choose({"choices": [{"procedure": 1, "technique": f"{PARENT}.001"}]}) == {1: [f"{PARENT}.001"]}


def test_no_sub_answer_keeps_parent():
    assert _choose({"choices": []}) == {1: [PARENT]}
