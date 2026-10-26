"""Agent d'extraction (vérification STIX des soumissions, boucle d'outils avec faux modèle, bundle) :
`uv run python -m unittest tests.test_stix_agent -v`."""

import json
import unittest
from unittest import mock

from backend.extracting import llm, stix_agent
from backend.extracting.agent_tools import DraftGraph, parse_relation, search_attack
from backend.extracting.segment import segment
from tests.attack_fixture import mini_kb

ARTICLE = """# Axios compromise

STARDUST CHOLLIMA compromised the npm package. The campaign targeted fintech companies.

## ZshBucket

ZshBucket runs systeminfo to collect host details. It then executes commands with cmd.exe.
"""


def draft(kb) -> DraftGraph:
    return DraftGraph(segment(ARTICLE), publishers=("crowdstrike",), attack=kb)


def uid(units, needle: str) -> int:
    return next(u.uid for u in units if needle in u.text)


class Verification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kb = mini_kb()

    def setUp(self):
        self.g = draft(self.kb)
        self.zsh = uid(self.g.units, "ZshBucket runs")
        self.cmd = uid(self.g.units, "cmd.exe")

    def test_parse_relation_tolerates_interleaved_types(self):
        self.assertEqual(parse_relation("software|FortiOS|has|vulnerability|CVE-2018-13379|1,9"), ("FortiOS", "has", "CVE-2018-13379", "1,9"))
        self.assertEqual(parse_relation("C# downloader|uses|T1071.001|42, 43"), ("C# downloader", "uses", "T1071.001", "42, 43"))
        self.assertIsNone(parse_relation("ZshBucket|uses|T1082"))

    def test_valid_relation_accepted_with_exact_evidence(self):
        report, accepted, refused = self.g.submit(["malware|ZshBucket"], [f"ZshBucket|uses|T1082|{self.zsh}"])
        self.assertEqual((accepted, refused), (2, 0), report)
        rel = next(iter(self.g.relationships.values()))
        self.assertEqual(rel["_evidence"][0]["quote"], "ZshBucket runs systeminfo to collect host details.")
        technique = self.g.entities[rel["target_ref"]]
        self.assertEqual(technique["external_references"][0]["external_id"], "T1082")

    def test_unknown_and_revoked_attack_ids(self):
        _, _, refused = self.g.submit(["malware|ZshBucket"], [f"ZshBucket|uses|T1999|{self.zsh}"])
        self.assertEqual(refused, 1)
        self.assertEqual(self.g.hallucinated, ["T1999"])
        sid, err = self.g.technique("T1086")  # révoqué : remplacé par T1059.001
        self.assertIsNone(err)
        self.assertEqual(self.g.entities[sid]["external_references"][0]["external_id"], "T1059.001")

    def test_invalid_stix_relation_refused_with_alternatives(self):
        report, _, refused = self.g.submit(["malware|ZshBucket", "identity|fintech companies"], [f"ZshBucket|attributed-to|fintech companies|{self.zsh}"])
        self.assertEqual(refused, 1)
        self.assertIn("admises : targets", report)

    def test_cited_sentence_must_name_the_software_pronoun_window_allowed(self):
        _, _, refused = self.g.submit(["malware|ZshBucket"], ["ZshBucket|uses|T1082|1"])
        self.assertEqual(refused, 1)  # la phrase 1 (titre) ne nomme pas ZshBucket
        _, _, refused = self.g.submit([], [f"ZshBucket|uses|T1059.003|{self.cmd}"])  # « It » : ZshBucket est dans la phrase précédente
        self.assertEqual(refused, 0)

    def test_direction_fixed_and_attack_names_auto_declared(self):
        _, _, refused = self.g.submit([], [f"T1059.003|uses|cmd|{self.cmd}"])
        self.assertEqual(refused, 0)
        rel = next(iter(self.g.relationships.values()))
        self.assertEqual(self.g.entities[rel["source_ref"]]["type"], "tool")  # « cmd » connu d'ATT&CK (S0106), sens corrigé

    def test_publisher_and_iocs_refused(self):
        _, _, refused = self.g.submit(["intrusion-set|crowdstrike", "infrastructure|evil.example.com"], [])
        self.assertEqual(refused, 2)

    def test_search_tool_output(self):
        self.assertIn("T1082", search_attack(self.kb, "runs systeminfo"))
        self.assertIn("inconnue", search_attack(self.kb, "runs systeminfo", tactic="nope"))


def _call(name: str, **arguments) -> dict:
    return {"function": {"name": name, "arguments": arguments}}


class AgentLoop(unittest.TestCase):
    def test_tool_loop_corrects_refusal_and_builds_valid_bundle(self):
        kb = mini_kb()
        units = segment(ARTICLE)
        zsh = uid(units, "ZshBucket runs")
        script = [
            [_call("search_attack", query="collect host details with systeminfo")],
            [_call("submit", entities=["malware|ZshBucket", "intrusion-set|STARDUST CHOLLIMA", "campaign|Campagne Axios"],
                   relations=[f"ZshBucket|uses|T1999|{zsh}", "Campagne Axios|attributed-to|STARDUST CHOLLIMA|1"])],  # fmt: skip
            [_call("submit", entities=[], relations=[f"ZshBucket|uses|T1082|{zsh}", "Campagne Axios|uses|ZshBucket|1"])],
        ]
        seen: list[list[dict]] = []

        def fake_chat(messages, tools, **_):
            seen.append([dict(m) for m in messages])
            calls = script.pop(0) if script else []
            msg = {"role": "assistant", "content": "" if calls else "FIN", **({"tool_calls": calls} if calls else {})}
            return llm.ChatResult(msg, msg["content"], [c["function"] for c in calls], 100, 20, 0.1)

        with mock.patch.object(llm, "chat", side_effect=fake_chat), mock.patch.object(stix_agent, "get_attack_kb", return_value=kb), \
                mock.patch("backend.extracting.agent_tools.get_attack_kb", return_value=kb), mock.patch.object(stix_agent, "DraftGraph", lambda units, publishers: DraftGraph(units, publishers, kb)):  # fmt: skip
            result = stix_agent.extract_article(7, "Axios compromise", ARTICLE, "crowdstrike")
        self.assertEqual(result.refused, 2)  # T1999 inconnu ; « Campagne Axios|uses|ZshBucket|1 » : la phrase 1 ne nomme pas ZshBucket
        self.assertIn("T1999 n'existe pas", seen[2][-1]["content"])  # le refus revient au modèle
        self.assertEqual(len(result.draft.relationships), 2)
        bundle = json.loads(stix_agent.build_bundle(result, {"source_id": 7, "title": "Axios compromise", "site_name": "crowdstrike", "category": "tactical"}))
        types = sorted(o["type"] for o in bundle["objects"])
        self.assertEqual(types.count("relationship"), 2)
        self.assertIn("attack-pattern", types)


if __name__ == "__main__":
    unittest.main()
