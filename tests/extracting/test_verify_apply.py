"""Application des décisions du vérificateur sur un vrai DraftGraph (texte et noms inventés)."""
import pytest

from backend.extracting.cascade.verify import Claim, Decision, apply, collect_claims
from backend.extracting.graph.draft import DraftGraph
from backend.extracting.pipeline import ExtractionResult
from backend.extracting.stix.objects import ArticleContext
from backend.preprocessing.cleaning.text.segment import segment

TEXT = (
    "# Report\n\n"
    "Group-Nine deploys Alpha-Loader, which decrypts its strings with a hardcoded XOR key.\n\n"
    "## Second stage\n\n"
    "Alpha-Loader then runs PowerShell scripts to fetch the next stage.\n\n"
    "Alpha-Loader also executes commands through a script interpreter.\n"
)


def uid(draft, needle):
    return next(u.uid for u in draft.units if needle in u.text)


@pytest.fixture
def setup():
    units = segment(TEXT)
    draft = DraftGraph(units, ArticleContext(1, "test-source", None, "t"))
    mal, _ = draft.declare("malware|Alpha-Loader")
    grp, _ = draft.declare("intrusion-set|Group-Nine")
    result = ExtractionResult(article_id=1, draft=draft, n_units=len(units))
    return draft, mal, grp, result


def key_of(draft, src, aid):
    return (src, "uses", draft.names[aid])


def test_reassign_moves_relation(setup):
    draft, mal, grp, result = setup
    assert draft.relate(f"Group-Nine|uses|T1027|{uid(draft, 'XOR')}") is None
    claim = next(c for c in collect_claims(draft, []) if c.key[0] == grp)
    apply(draft, claim, Decision("reassign", mal, 85, "porteur corrigé"), result)
    assert key_of(draft, mal, "T1027") in draft.evidence and key_of(draft, grp, "T1027") not in draft.evidence


def test_reassign_unnamed_agent_drops_with_reason(setup):
    draft, mal, grp, result = setup
    assert draft.relate(f"Alpha-Loader|uses|T1059.001|{uid(draft, 'PowerShell')}") is None
    tool, _ = draft.declare("tool|Beta-Tool")  # un outil doit être nommé par la phrase (un groupe est implicite)
    claim = next(c for c in collect_claims(draft, []) if c.technique == "T1059.001")
    apply(draft, claim, Decision("reassign", tool, 85, "porteur corrigé"), result)
    assert not any(k[2] == draft.names["T1059.001"] for k in draft.evidence)
    assert result.refused_relations[-1][3].startswith("porteur contesté")


def test_to_parent_merges_existing(setup):
    draft, mal, grp, result = setup
    assert draft.relate(f"Alpha-Loader|uses|T1059.001|{uid(draft, 'PowerShell')}") is None
    assert draft.relate(f"Alpha-Loader|uses|T1059|{uid(draft, 'interpreter')}") is None
    draft.procedures[draft.names["T1059.001"]] = ["runs PowerShell scripts"]
    claim = next(c for c in collect_claims(draft, []) if c.technique == "T1059.001")
    apply(draft, claim, Decision("to_parent", None, 85, "parente"), result)
    uses = [k for k in draft.evidence if k[0] == mal]
    assert uses == [key_of(draft, mal, "T1059")]
    assert len(draft.evidence[uses[0]]) == 2
    assert "runs PowerShell scripts" in draft.procedures[draft.names["T1059"]]


def test_drop_records_refusal(setup):
    draft, mal, grp, result = setup
    assert draft.relate(f"Alpha-Loader|uses|T1027|{uid(draft, 'XOR')}") is None
    claim = collect_claims(draft, [])[0]
    apply(draft, claim, Decision("drop", reason="hors de l'incident (general)"), result)
    assert draft.evidence == {}
    assert result.refused_relations[-1] == (mal, "uses", draft.names["T1027"], "hors de l'incident (general)")


def test_confidence_written_to_bundle(setup):
    draft, mal, grp, result = setup
    assert draft.relate(f"Alpha-Loader|uses|T1027|{uid(draft, 'XOR')}") is None
    claim = collect_claims(draft, [])[0]
    apply(draft, claim, Decision("keep", confidence=60), result)
    assert draft.relationships()[0]["confidence"] == 60


def test_kept_technique_claim_from_behaviors(setup):
    draft, mal, grp, result = setup
    sid, _ = draft.technique("T1027")
    draft.kept.add(sid)
    claims = collect_claims(draft, [{"uids": [uid(draft, "XOR")], "chosen": ["T1027"], "center": None, "text": "decrypts"}])
    assert claims and claims[0].key == ("", "uses", sid) and "XOR" in claims[0].quotes[0]
    apply(draft, claims[0], Decision("drop", reason="hypothèse"), result)
    assert sid not in draft.kept
