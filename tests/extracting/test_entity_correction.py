"""Une entité refusée parce que nommée par un fichier est redemandée une fois au modèle (noms inventés)."""
from types import SimpleNamespace

from backend.extracting.cascade.graph import build_graph
from backend.extracting.graph.draft import DraftGraph
from backend.extracting.stix.objects import ArticleContext
from backend.preprocessing.cleaning.text.segment import segment

TEXT = "# Report\n\nThe first-stage loader alpha_loader.dll starts the implant.\n"


def _run(answers):
    draft = DraftGraph(segment(TEXT), ArticleContext(1, "test-source", None, "t"))
    result = SimpleNamespace(refused=0, accepted=0, refused_entities=[], refused_relations=[])
    stages = []

    def call(stage, system, prompt, schema, tokens):
        stages.append(stage)
        return answers.get(stage, {})

    sids = build_graph(draft, TEXT, "s", result, call)
    return draft, sids, stages


def _entity(name):
    return {"entities": [{"type": "malware", "name": name, "aliases": [], "detail": ""}]}


def test_file_named_malware_is_asked_again():
    draft, sids, stages = _run({"entities": _entity("alpha_loader.dll"), "entities:corrections": {"labels": [{"item": 1, "name": "first-stage loader"}]}})
    assert "entities:corrections" in stages and [draft.name_of(s) for s in sids] == ["first-stage loader"]


def test_no_correction_call_without_file_refusal():
    _, sids, stages = _run({"entities": _entity("first-stage loader")})
    assert "entities:corrections" not in stages and len(sids) == 1


def test_correction_asks_one_label_per_refused_component():
    two = {"entities": _entity("alpha_loader.dll")["entities"] + _entity("beta_stage.dll")["entities"]}
    fix = {"labels": [{"item": 1, "name": "first-stage loader"}, {"item": 2, "name": "second-stage downloader"}]}
    draft, sids, _ = _run({"entities": two, "entities:corrections": fix})
    assert [draft.name_of(s) for s in sids] == ["first-stage loader", "second-stage downloader"]
