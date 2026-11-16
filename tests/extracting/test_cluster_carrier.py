"""Règle du porteur appliquée aux grappes : une campagne attribuée à un seul groupe nommé lui cède ses passages."""
from types import SimpleNamespace

from backend.extracting.cascade.clusters import build_clusters
from backend.extracting.graph.draft import DraftGraph
from backend.extracting.stix.objects import ArticleContext
from backend.preprocessing.cleaning.text.segment import segment

TEXT = "# Report\n\nAlpha Group ran the Winter Wave campaign.\n\nThe operators sent phishing emails.\n\nBeta Group is another actor.\n"


def _clusters(lines, relations, answer):
    draft = DraftGraph(segment(TEXT), ArticleContext(1, "test-source", None, "t"))
    sids = [draft.declare(line)[0] for line in lines]
    for rel in relations:
        assert draft.relate(rel) is None
    result = SimpleNamespace()
    return draft, sids, build_clusters(draft, TEXT, "s", sids, result, lambda *a: answer)


def _answer(*rows):
    return {"clusters": [{"center": c, "scope": "incident", "sentences": s} for c, s in rows]}


def test_attributed_campaign_gives_its_passages_to_the_group():
    first = next(u.uid for u in segment(TEXT) if "Winter Wave" in u.text)
    draft, sids, clusters = _clusters(
        ["intrusion-set|Alpha Group", "campaign|Winter Wave"], [f"Winter Wave|attributed-to|Alpha Group|{first}"], _answer((1, [first]), (2, [first + 1]))
    )
    assert [(c.center, c.sentences) for c in clusters] == [(sids[0], [first, first + 1])]


def test_campaign_without_group_keeps_its_passages():
    first = next(u.uid for u in segment(TEXT) if "Winter Wave" in u.text)
    draft, sids, clusters = _clusters(["campaign|Winter Wave"], [], _answer((1, [first])))
    assert [c.center for c in clusters] == [sids[0]]


def test_campaign_attributed_to_two_groups_keeps_its_passages():
    units = segment(TEXT)
    first = next(u.uid for u in units if "Winter Wave" in u.text)
    last = next(u.uid for u in units if "Beta Group" in u.text)
    draft, sids, clusters = _clusters(
        ["intrusion-set|Alpha Group", "intrusion-set|Beta Group", "campaign|Winter Wave"],
        [f"Winter Wave|attributed-to|Alpha Group|{first}", f"Winter Wave|attributed-to|Beta Group|{first},{last}"],
        _answer((3, [first])),
    )
    assert [c.center for c in clusters] == [sids[2]]
