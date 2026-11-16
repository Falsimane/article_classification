"""Table des relations égale à STIX 2.1 (docs/stix-v2.1-os.pdf, sections 4.x.2) et orientation outil → technique.
Texte et noms inventés."""
import pytest

from backend.extracting.graph.draft import DraftGraph
from backend.extracting.stix.objects import ALLOWED_RELATIONS, ArticleContext
from backend.preprocessing.cleaning.text.segment import segment


def _rows(source, rels, targets):
    return {(source, r, t) for r in rels for t in targets}


OFFICIAL = (
    # 4.1.2 attack-pattern (p. 50)
    _rows("attack-pattern", ["delivers"], ["malware"])
    | _rows("attack-pattern", ["targets"], ["identity", "location", "vulnerability"])
    | _rows("attack-pattern", ["uses"], ["malware", "tool"])
    # 4.2.2 campaign (p. 55)
    | _rows("campaign", ["attributed-to"], ["intrusion-set", "threat-actor"])
    | _rows("campaign", ["compromises"], ["infrastructure"])
    | _rows("campaign", ["originates-from"], ["location"])
    | _rows("campaign", ["targets"], ["identity", "location", "vulnerability"])
    | _rows("campaign", ["uses"], ["attack-pattern", "infrastructure", "malware", "tool"])
    # 4.3.2 course-of-action (p. 58) ; investigates → indicator : couche observable, hors registre
    | _rows("course-of-action", ["mitigates"], ["attack-pattern", "malware", "tool", "vulnerability"])
    | _rows("course-of-action", ["remediates"], ["malware", "vulnerability"])
    # 4.5.2 identity (p. 63)
    | _rows("identity", ["located-at"], ["location"])
    # 4.8.2 infrastructure (p. 72) ; cibles SCO et observed-data : couche observable
    | _rows("infrastructure", ["communicates-with", "consists-of", "uses"], ["infrastructure"])
    | _rows("infrastructure", ["controls"], ["infrastructure", "malware"])
    | _rows("infrastructure", ["delivers"], ["malware"])
    | _rows("infrastructure", ["has"], ["vulnerability"])
    | _rows("infrastructure", ["hosts"], ["tool", "malware"])
    | _rows("infrastructure", ["located-at"], ["location"])
    # 4.9.2 intrusion-set (p. 79)
    | _rows("intrusion-set", ["attributed-to"], ["threat-actor"])
    | _rows("intrusion-set", ["compromises", "hosts", "owns"], ["infrastructure"])
    | _rows("intrusion-set", ["originates-from"], ["location"])
    | _rows("intrusion-set", ["targets"], ["identity", "location", "vulnerability"])
    | _rows("intrusion-set", ["uses"], ["attack-pattern", "infrastructure", "malware", "tool"])
    # 4.11.2 malware (p. 89) ; communicates-with → SCO, downloads/drops → file : couche observable
    | _rows("malware", ["authored-by"], ["threat-actor", "intrusion-set"])
    | _rows("malware", ["beacons-to", "exfiltrates-to"], ["infrastructure"])
    | _rows("malware", ["controls"], ["malware"])
    | _rows("malware", ["downloads", "drops"], ["malware", "tool"])
    | _rows("malware", ["exploits"], ["vulnerability"])
    | _rows("malware", ["originates-from"], ["location"])
    | _rows("malware", ["targets"], ["identity", "infrastructure", "location", "vulnerability"])
    | _rows("malware", ["uses"], ["attack-pattern", "infrastructure", "malware", "tool"])
    | _rows("malware", ["variant-of"], ["malware"])
    # 4.12.2 malware-analysis (p. 100)
    | _rows("malware-analysis", ["analysis-of", "characterizes", "static-analysis-of", "dynamic-analysis-of"], ["malware"])
    # 4.17.2 threat-actor (p. 114)
    | _rows("threat-actor", ["attributed-to", "impersonates"], ["identity"])
    | _rows("threat-actor", ["compromises", "hosts", "owns"], ["infrastructure"])
    | _rows("threat-actor", ["located-at"], ["location"])
    | _rows("threat-actor", ["targets"], ["identity", "location", "vulnerability"])
    | _rows("threat-actor", ["uses"], ["attack-pattern", "infrastructure", "malware", "tool"])
    # 4.18.2 tool (p. 118)
    | _rows("tool", ["delivers", "drops"], ["malware"])
    | _rows("tool", ["has"], ["vulnerability"])
    | _rows("tool", ["targets"], ["identity", "infrastructure", "location", "vulnerability"])
    | _rows("tool", ["uses"], ["infrastructure"])
)

TEXT = (
    "# Report\n\n"
    "Alpha-Loader obfuscates its configuration with Beta-Tool before delivery.\n\n"
    "Alpha-Loader then talks to the Alpha relay every hour.\n"
)


def uid(draft, needle):
    return next(u.uid for u in draft.units if needle in u.text)


@pytest.fixture
def draft():
    d = DraftGraph(segment(TEXT), ArticleContext(1, "test-source", None, "t"))
    d.declare("malware|Alpha-Loader")
    return d


def test_relations_are_stix21():
    assert ALLOWED_RELATIONS == OFFICIAL


def test_software_not_declarable(draft):
    sid, err = draft.declare("software|Alpha-Product|Beta-Vendor")
    assert sid is None and err


def test_tool_technique_written_in_stix_direction(draft):
    tool, _ = draft.declare("tool|Beta-Tool")
    assert draft.relate(f"Beta-Tool|uses|T1027|{uid(draft, 'Beta-Tool')}") is None
    rel = next(r for r in draft.relationships() if tool in (r["source_ref"], r["target_ref"]))
    assert rel["relationship_type"] == "uses" and rel["target_ref"] == tool
    assert rel["source_ref"].startswith("attack-pattern--")


def test_malware_communicates_with_infrastructure_refused(draft):
    draft.declare("infrastructure|Alpha relay")
    assert draft.relate(f"Alpha-Loader|communicates-with|Alpha relay|{uid(draft, 'relay')}") is not None
