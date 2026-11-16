"""Vérificateur par questions fermées : décision pure (identifiants inventés)."""
from backend.extracting.cascade.verify import (
    CONFIDENCE, Claim, Verdict, batches, decide, parse_verdicts, verify_schema,
)  # fmt: skip

AGENTS = ["malware--11111111-1111-4111-8111-111111111111", "intrusion-set--22222222-2222-4222-8222-222222222222"]
TECH = "attack-pattern--33333333-3333-4333-8333-333333333333"
CAMP = "campaign--44444444-4444-4444-8444-444444444444"
CLAIM_TECH = Claim(key=(AGENTS[0], "uses", TECH), kind="technique", quotes=["it xors its strings"], procedure="xors strings", technique="T1027")
CLAIM_SUBTECH = Claim(key=(AGENTS[0], "uses", TECH), kind="technique", quotes=["runs a script"], procedure="runs", technique="T1059.001")
CLAIM_KEPT = Claim(key=("", "uses", TECH), kind="technique", quotes=["someone ran a script"], procedure="runs", technique="T1059")
CLAIM_REL = Claim(key=(CAMP, "attributed-to", AGENTS[1]), kind="relation", quotes=["the campaign is attributed to the group"])
OK = dict(scope="incident", mechanism="technique", status="established")


def test_missing_verdict_keeps_claim():
    assert decide(CLAIM_TECH, None, AGENTS).action == "keep"


def test_out_of_range_agent_is_no_verdict():
    v = parse_verdicts({"verdicts": [{"claim": 1, "agent": 9, **OK}]}, 1, 2)
    assert 1 not in v


def test_unknown_enum_value_is_no_verdict():
    assert parse_verdicts({"verdicts": [{"claim": 1, "agent": 1, **{**OK, "scope": "maybe"}}]}, 1, 2) == {}


def test_valid_verdict_parsed():
    v = parse_verdicts({"verdicts": [{"claim": 1, "agent": 2, **OK}]}, 1, 2)
    assert v[1] == Verdict(2, "incident", "technique", "established")


def test_speculative_dropped():
    assert decide(CLAIM_TECH, Verdict(1, "incident", "technique", "speculative"), AGENTS).action == "drop"


def test_refuted_dropped():
    assert decide(CLAIM_REL, Verdict(0, "incident", "none", "refuted"), AGENTS).action == "drop"


def test_past_event_dropped():
    assert decide(CLAIM_REL, Verdict(1, "past_event", "technique", "established"), AGENTS).action == "drop"


def test_generic_dropped():
    assert decide(CLAIM_TECH, Verdict(1, "generic", "technique", "established"), AGENTS).action == "drop"


GROUP_TARGETS = Claim(key=(AGENTS[1], "targets", "identity--55555555-5555-4555-8555-555555555555"), kind="action", quotes=["the group regularly targets banks"])
CAMP_TARGETS = Claim(key=(CAMP, "targets", "identity--55555555-5555-4555-8555-555555555555"), kind="action", quotes=["the group regularly targets banks"])


def test_actor_general_fact_kept_on_actor_with_confidence():
    d = decide(GROUP_TARGETS, Verdict(2, "actor_general", "technique", "established"), AGENTS)
    assert (d.action, d.confidence) == ("keep", 85)


def test_actor_general_fact_on_campaign_moves_to_actor():
    d = decide(CAMP_TARGETS, Verdict(2, "actor_general", "technique", "assessed"), AGENTS + [CAMP])
    assert (d.action, d.new_source, d.confidence) == ("reassign", AGENTS[1], 60)


def test_actor_general_fact_on_campaign_without_actor_dropped():
    assert decide(CAMP_TARGETS, Verdict(3, "actor_general", "technique", "established"), AGENTS + [CAMP]).action == "drop"
    assert decide(CAMP_TARGETS, Verdict(0, "actor_general", "technique", "established"), AGENTS + [CAMP]).action == "drop"


def test_mechanism_none_drops_technique():
    assert decide(CLAIM_TECH, Verdict(1, "incident", "none", "established"), AGENTS).action == "drop"


def test_mechanism_ignored_for_relation():
    assert decide(CLAIM_REL, Verdict(0, "incident", "none", "established"), AGENTS).action == "keep"


def test_parent_on_subtechnique():
    assert decide(CLAIM_SUBTECH, Verdict(1, "incident", "parent", "established"), AGENTS).action == "to_parent"


def test_parent_on_parent_technique_keeps():
    assert decide(CLAIM_TECH, Verdict(1, "incident", "parent", "established"), AGENTS).action == "keep"


def test_other_agent_reassigns():
    d = decide(CLAIM_TECH, Verdict(2, "incident", "technique", "established"), AGENTS)
    assert (d.action, d.new_source) == ("reassign", AGENTS[1])


def test_unstated_agent_drops_carried_technique():
    assert decide(CLAIM_TECH, Verdict(0, "incident", "technique", "established"), AGENTS).action == "drop"


def test_unstated_agent_keeps_report_level_technique():
    assert decide(CLAIM_KEPT, Verdict(0, "incident", "technique", "established"), AGENTS).action == "keep"


def test_assessed_confidence_60():
    assert decide(CLAIM_REL, Verdict(1, "incident", "technique", "assessed"), AGENTS).confidence == 60 == CONFIDENCE["assessed"]


def test_established_confidence_85():
    assert decide(CLAIM_TECH, Verdict(1, "incident", "technique", "established"), AGENTS).confidence == 85


def test_no_claims_no_batches():
    assert batches([]) == []


def test_batches_split():
    assert [len(b) for b in batches([CLAIM_TECH] * 30, size=25)] == [25, 5]


def test_schema_with_no_agents_is_valid():
    schema = verify_schema(3, 0)
    item = schema["properties"]["verdicts"]["items"]["properties"]
    assert item["agent"]["enum"] == [0] and item["claim"]["enum"] == [1, 2, 3]
