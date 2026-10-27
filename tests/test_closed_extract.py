"""Extraction à questions fermées : candidats du code, pipeline complet avec un faux modèle."""

import unittest
from unittest import mock

from backend.extracting import closed_extract as ce
from backend.extracting import llm
from backend.extracting.segment import segment
from backend.stix.attack import get_attack_kb

TEXT = """# Rapport

Le groupe TA999 a été observé en 2024 contre des organisations en Norway.

## Analyse

Le chargeur Zorblax lance une commande PowerShell encodée pour télécharger la charge suivante. Le chargeur Zorblax contacte ensuite son serveur de commande toutes les dix minutes.
"""


def fake_generate(system, prompt, schema, **_):
    """Répond comme un petit modèle docile : types par mot, première technique, lien « utilise »."""
    if system == ce.TYPING_SYSTEM:
        answer = "malware" if "Zorblax" in prompt.split("Que désigne")[1] else "group" if "TA999" in prompt.split("Que désigne")[1] else "none"
        return llm.LLMResult({"answer": answer}, "", 100, 3)
    if system == ce.TECHNIQUE_SYSTEM:
        return llm.LLMResult({"answer": "1" if "PowerShell" in prompt else "0"}, "", 100, 2)
    if system == ce.CAMPAIGN_SYSTEM:
        return llm.LLMResult({"campaign": "Campagne TA999 contre la Norvège, 2024"}, "", 100, 12)
    if system == ce.ACTOR_SYSTEM:
        return llm.LLMResult({"answer": "1"}, "", 100, 2)
    if system == ce.CAMPAIGN_LINK_SYSTEM:
        return llm.LLMResult({"answer": "1"}, "", 100, 2)
    if system == ce.PAIR_SYSTEM:
        return llm.LLMResult({"answer": "1" if "uses" in prompt or "attributed-to" in prompt else "0"}, "", 100, 2)
    raise AssertionError(system)


class Candidates(unittest.TestCase):
    def test_patterns_locations_and_cves(self):
        units = segment("# R\n\nTA505 exploited CVE-2021-44228 against Norway and used the loader dubbed Zorblax. It then ran certutil.exe on hosts.")
        found = {c.name: c for c in ce.find_candidates(units, get_attack_kb())}
        self.assertEqual(found["CVE-2021-44228"].stix_type, "vulnerability")
        self.assertEqual(found["Norway"].stix_type, "location")
        self.assertEqual(found["Norway"].extra, "NO")
        self.assertIn("TA505", found)
        self.assertIn("Zorblax", found)
        self.assertIn("certutil.exe", found)
        self.assertNotIn("It", found)

    def test_publisher_is_never_a_candidate(self):
        units = segment("# R\n\nAcmeLabs researchers observed TA505 in 2024.")
        self.assertNotIn("AcmeLabs", {c.name for c in ce.find_candidates(units, get_attack_kb(), publisher="acmelabs")})


class Pipeline(unittest.TestCase):
    def test_closed_pipeline_builds_verified_relations(self):
        art = {"id": 1, "title": "Rapport", "site_name": "Acme", "url": "http://x", "publication_date": "2024-01-01", "clean_markdown": TEXT}
        with mock.patch.object(llm, "generate", side_effect=fake_generate):
            result = ce.extract_article(art, with_iocs=False, with_rules=False)
        draft = result.draft
        rels = {(draft.name_of(s), r, draft.name_of(t)) for (s, r, t) in draft.evidence}
        names = {draft.name_of(s) for s in draft.objects}
        self.assertTrue({"Zorblax", "TA999"} <= names, names)
        self.assertTrue(any(s == "Zorblax" and r == "uses" and t.startswith("PowerShell") for s, r, t in rels) or any(r == "uses" for _, r, _ in rels), rels)
        self.assertTrue(result.turns and not result.failed_passages)
        for quotes in draft.evidence.values():
            self.assertTrue(all(q in TEXT for q in quotes))  # preuves relues dans le texte : exactes par construction


class Evidence(unittest.TestCase):
    def test_best_evidence_keeps_first_mention_and_the_busiest_sentences(self):
        mentioned = {1: ["a"], 2: [], 5: ["a", "b", "c"], 6: ["a", "b"], 9: ["a"]}
        self.assertEqual(ce.best_evidence([1, 2, 5, 6, 9], mentioned, k=3), [1, 5, 6])
        self.assertEqual(ce.best_evidence([2, 1], mentioned, k=3), [1, 2])


if __name__ == "__main__":
    unittest.main()
