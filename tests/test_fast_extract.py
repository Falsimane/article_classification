"""Extraction rapide (deux appels contraints par partie, techniques choisies parmi les candidates du code), avec faux modèle :
`uv run python -m unittest tests.test_fast_extract -v`."""

import unittest
from unittest import mock

from backend.extracting import fast_extract, llm
from backend.extracting.agent_tools import DraftGraph
from backend.extracting.segment import segment
from tests.attack_fixture import mini_kb

# Noms fictifs : aucun article réel, et aucun article évalué
ARTICLE = """# Report

GLASSWORM compromised a software package. The operation is attributed to GLASSWORM.

## ByteMole

ByteMole runs systeminfo to collect host details. The weather was nice.
"""


class FastExtraction(unittest.TestCase):
    def test_calls_share_their_prefix_keep_candidate_techniques_and_correct_refusals_once(self):
        kb = mini_kb()
        units = segment(ARTICLE)
        mole = next(u.uid for u in units if "systeminfo" in u.text)
        replies = [
            {"entities": "intrusion-set|GLASSWORM\nmalware|ByteMole\ncampaign|Campagne GLASSWORM\nattack-pattern|T1082", "behaviors": f"{mole}, 999"},
            {"techniques": f"{mole}|2|T1082\n{mole}|2|T1059.001\n{mole}|9|T1082", "relations": "3|attributed-to|1|2\n3|uses|2|1"},
            {"techniques": "", "relations": f"3|uses|2|{mole}"},  # correction : la phrase qui nomme ByteMole
        ]  # fmt: skip
        prompts: list[str] = []

        def fake_generate(system, prompt, schema, **_):
            prompts.append(prompt)
            return llm.LLMResult(parsed=replies[len(prompts) - 1], raw="", prompt_tokens=100, output_tokens=30)

        art = {"id": 7, "title": "Report", "site_name": "example-vendor", "url": None, "clean_markdown": ARTICLE}
        with mock.patch.object(llm, "generate", side_effect=fake_generate), mock.patch.object(fast_extract, "DraftGraph", lambda u, ctx: DraftGraph(u, ctx, kb)):
            result = fast_extract.extract_article(art, with_iocs=False, with_rules=False)

        self.assertEqual(len(prompts), 3)
        text = prompts[0].split("\n\n---\n")[0]
        self.assertTrue(prompts[1].startswith(text))  # même début : le serveur relit le texte depuis son cache
        self.assertTrue(prompts[2].startswith(prompts[1]))
        self.assertIn("ne nomment pas ByteMole", prompts[2])  # la raison du refus revient au modèle
        self.assertIn("T1082 System Information Discovery", prompts[1])  # candidates calculées par le code
        triples = {(result.draft.name_of(s), r, result.draft.name_of(t)) for s, r, t in result.draft.evidence}
        self.assertEqual(triples, {
            ("ByteMole", "uses", "System Information Discovery"), ("Campagne GLASSWORM", "attributed-to", "GLASSWORM"), ("Campagne GLASSWORM", "uses", "ByteMole"),
        })  # fmt: skip
        # T1059.001 hors des candidates ; entité 9 inexistante ; « campagne uses ByteMole » : la phrase 1 ne nomme pas ByteMole
        self.assertEqual(result.refused, 3)
        self.assertEqual([t.tool_calls for t in result.turns], [["inventory"], ["relations"], ["corrections"]])


if __name__ == "__main__":
    unittest.main()
