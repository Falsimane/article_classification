"""Une technique parente n'est pas gardée à côté de sa sous-technique sur le même porteur, même citée ailleurs."""
from backend.extracting.graph.draft import DraftGraph
from backend.extracting.stix.objects import ArticleContext
from backend.preprocessing.cleaning.text.segment import segment

TEXT = "# Report\n\nAlphaLoader hides its strings.\n\nAlphaLoader is packed with a commercial packer.\n\nBetaTool hides its strings.\n"


def _draft():
    units = segment(TEXT)
    draft = DraftGraph(units, ArticleContext(1, "test-source", None, "t"))
    draft.declare("malware|AlphaLoader")
    draft.declare("malware|BetaTool")
    n = [u.uid for u in units if "AlphaLoader" in u.text]
    m = next(u.uid for u in units if "BetaTool" in u.text)
    return draft, n, m


def test_parent_dropped_when_carrier_has_sub_technique_elsewhere():
    draft, n, m = _draft()
    assert draft.relate(f"AlphaLoader|uses|T1027|{n[0]}") is None and draft.relate(f"AlphaLoader|uses|T1027.002|{n[1]}") is None
    draft.prune_subsumed_techniques()
    assert {draft.name_of(t) for (s, r, t) in draft.evidence} == {draft.name_of(draft.names["T1027.002"])}


def test_parent_kept_on_another_carrier():
    draft, n, m = _draft()
    assert draft.relate(f"BetaTool|uses|T1027|{m}") is None and draft.relate(f"AlphaLoader|uses|T1027.002|{n[1]}") is None
    draft.prune_subsumed_techniques()
    assert len(draft.evidence) == 2
