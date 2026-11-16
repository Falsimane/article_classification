"""Profil d'acteur : commanditaire lu à travers le threat-actor parent (noms inventés)."""
from backend.dashboard.stix_dashboard import _profile

GROUP = {"id": "intrusion-set--1", "type": "intrusion-set", "name": "Group-Nine", "tactics": []}
STATE = {"id": "threat-actor--2", "type": "threat-actor", "name": "Alpha-State", "tactics": []}
GOV = {"id": "identity--3", "type": "identity", "name": "Alpha-Government", "tactics": []}


def _e(src, dst):
    return {"source": src["id"], "target": dst["id"], "type": "attributed-to", "confidence": 60, "evidence": []}


def test_sponsor_through_parent():
    nodes = {n["id"]: n for n in (GROUP, STATE, GOV)}
    out = _profile(GROUP, nodes, [_e(GROUP, STATE), _e(STATE, GOV)])
    assert [p["node"]["id"] for p in out["parents"]] == [STATE["id"]]
    assert out["sponsors"][0]["node"]["id"] == GOV["id"] and out["sponsors"][0]["via"] == STATE["id"]
