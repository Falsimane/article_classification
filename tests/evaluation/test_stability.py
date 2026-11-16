"""Stabilité entre deux exécutions : Jaccard des entités, techniques et relations (noms inventés)."""
import json

from backend.evaluation.stability import bundle_keys, jaccard, stability
from backend.extracting.stix.attack import get_attack_kb
from backend.preprocessing.cleaning.text.evidence import normalize_name

MAL = "malware--11111111-1111-4111-8111-111111111111"
TECH = "attack-pattern--22222222-2222-4222-8222-222222222222"
BUNDLE = {
    "type": "bundle", "id": "bundle--33333333-3333-4333-8333-333333333333",
    "objects": [
        {"type": "malware", "id": MAL, "name": "Alpha-Loader", "is_family": True},
        {"type": "attack-pattern", "id": TECH, "name": "PowerShell",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001"}]},
        {"type": "relationship", "id": "relationship--44444444-4444-4444-8444-444444444444", "relationship_type": "uses",
         "source_ref": MAL, "target_ref": TECH},
    ],
}  # fmt: skip


def test_jaccard_empty_is_one():
    assert jaccard(set(), set()) == 1.0


def test_jaccard_partial():
    assert jaccard({1, 2}, {2, 3}) == 1 / 3


def test_bundle_keys_uses_technique_id_and_normalized_name():
    ents, techs, rels = bundle_keys(BUNDLE, get_attack_kb())
    assert ("attack-pattern", "T1059.001") in techs
    assert ("malware", normalize_name("Alpha-Loader")) in ents
    assert ("malware", normalize_name("Alpha-Loader"), "uses", "attack-pattern", "T1059.001") in rels


def test_stability_identical_runs(tmp_path):
    for run in ("a", "b"):
        (tmp_path / run).mkdir()
        (tmp_path / run / "article_1.json").write_text(json.dumps(BUNDLE))
        (tmp_path / run / "article_1.iocs.json").write_text("{}")  # couche observable : ignorée
    assert stability(tmp_path / "a", tmp_path / "b") == {"entities": 1.0, "techniques": 1.0, "relations": 1.0}
