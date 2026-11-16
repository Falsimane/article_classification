"""Passe dédiée après les entités : victimes oubliées (secteurs, organisations, pays visés) et composants sans nom de
famille (is_family faux). Noms inventés."""
from types import SimpleNamespace

from backend.extracting.cascade.graph import build_graph
from backend.extracting.graph.draft import DraftGraph
from backend.extracting.stix.objects import ArticleContext
from backend.preprocessing.cleaning.text.segment import segment

TEXT = "# Report\n\nAlpha Group targeted logistics companies with a custom kernel driver and with BetaRAT.\n"


def _run(context_answer):
    draft = DraftGraph(segment(TEXT), ArticleContext(1, "test-source", None, "t"))
    result = SimpleNamespace(refused=0, accepted=0, refused_entities=[], refused_relations=[])
    entities = {"entities": [
        {"type": "intrusion-set", "name": "Alpha Group", "aliases": [], "detail": ""},
        {"type": "malware", "name": "custom kernel driver", "aliases": [], "detail": ""},
        {"type": "malware", "name": "BetaRAT", "aliases": [], "detail": ""},
    ]}  # fmt: skip
    prompts = {}

    def call(stage, system, prompt, schema, tokens):
        prompts[stage] = (prompt, schema)
        return {"entities": entities, "entities:context": context_answer}.get(stage, {})

    sids = build_graph(draft, TEXT, "s", result, call)
    return draft, sids, prompts


def test_victim_found_by_the_dedicated_pass_is_declared():
    draft, sids, prompts = _run({"victims": [{"type": "identity", "name": "logistics companies", "detail": "transportation;class"}], "components": []})
    assert "logistics companies" in [draft.name_of(s) for s in sids]
    assert "2. malware: custom kernel driver" in prompts["entities:context"][0]


def test_unnamed_component_is_not_a_family():
    draft, sids, _ = _run({"victims": [], "components": [2]})
    by_name = {draft.name_of(s): draft.objects[s] for s in sids}
    assert by_name["custom kernel driver"]["is_family"] is False and by_name["BetaRAT"]["is_family"] is True


def test_component_numbers_are_limited_to_malware():
    _, _, prompts = _run({"victims": [], "components": []})
    assert prompts["entities:context"][1]["properties"]["components"]["items"]["enum"] == [2, 3]
