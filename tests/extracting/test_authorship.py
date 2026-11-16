"""« authored-by » exige une preuve propre : la phrase qui montre seulement que le groupe emploie le malware ne dit pas
qu'il l'a écrit (noms inventés)."""
from backend.extracting.graph.draft import DraftGraph
from backend.extracting.stix.objects import ArticleContext
from backend.preprocessing.cleaning.text.segment import segment

TEXT = "# Report\n\nAlpha Group deployed AlphaLoader on the host.\n\nAlpha Group developed AlphaLoader in 2020.\n"


def _draft():
    units = segment(TEXT)
    draft = DraftGraph(units, ArticleContext(1, "test-source", None, "t"))
    draft.declare("intrusion-set|Alpha Group")
    draft.declare("malware|AlphaLoader")
    return draft, [u.uid for u in units if "AlphaLoader" in u.text]


def test_authorship_on_the_sentence_of_use_is_dropped():
    draft, (use, _) = _draft()
    assert draft.relate(f"Alpha Group|uses|AlphaLoader|{use}") is None and draft.relate(f"AlphaLoader|authored-by|Alpha Group|{use}") is None
    draft.prune_unsupported_authorship()
    assert [rel for (_, rel, _) in draft.evidence] == ["uses"]


def test_authorship_with_its_own_sentence_is_kept():
    draft, (use, wrote) = _draft()
    assert draft.relate(f"Alpha Group|uses|AlphaLoader|{use}") is None and draft.relate(f"AlphaLoader|authored-by|Alpha Group|{wrote}") is None
    draft.prune_unsupported_authorship()
    assert sorted(rel for (_, rel, _) in draft.evidence) == ["authored-by", "uses"]


def test_authorship_without_use_is_kept():
    draft, (_, wrote) = _draft()
    assert draft.relate(f"AlphaLoader|authored-by|Alpha Group|{wrote}") is None
    draft.prune_unsupported_authorship()
    assert len(draft.evidence) == 1
