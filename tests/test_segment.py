"""Découpage d'un article en phrases numérotées et en passages, titre sans éditeur : `uv run python -m unittest tests.test_segment -v`."""

import unittest

from backend.extracting import segment
from backend.extracting.stix_agent import clean_title

ARTICLE = """# Report

## Initial access

In October 2024, the cluster UNC3944 exploited the vulnerability CVE-2023-4966 on a Citrix appliance. The group then deployed BlackCat on the victim network.

## Lateral movement

The threat actor used PsExec to move laterally. Mandiant observed rclone.exe and taskkill during the exfiltration. Enable Sensor Tampering Protection on all hosts. SABOTAGE: BlackCat also uses PsExec.

```
rclone copy C:\\data remote:bucket
```

## References

[1] Mandiant, Some Report, 2024. UNC3944 was cited here.
"""


class Segmentation(unittest.TestCase):
    def test_units_are_numbered_sentences_with_heading_paths(self):
        units = segment.segment(ARTICLE)
        self.assertEqual([u.uid for u in units], list(range(1, len(units) + 1)))
        self.assertEqual({u.kind for u in units}, {"sentence", "code"})
        self.assertEqual(units[0].heading_path, "Report > Initial access")
        self.assertTrue(units[0].text.startswith("In October 2024"))

    def test_sentence_splitter_keeps_filenames_versions_and_abbreviations(self):
        parts = segment.split_sentences("Le binaire cmd.exe lance v1.2.3 de l'outil (e.g. PsExec). Puis le groupe agit. Il part en 2024. Fin.")
        self.assertEqual(len(parts), 4, parts)
        self.assertIn("cmd.exe", parts[0])
        self.assertIn("e.g. PsExec", parts[0])

    def test_passes_never_split_a_unit_and_respect_budget(self):
        units = segment.segment(ARTICLE * 6)
        passes = segment.make_passes(units, max_chars=700)
        self.assertGreater(len(passes), 1)
        self.assertEqual([u.uid for p in passes for u in p.units], [u.uid for u in units])

    def test_code_references_and_indicators_cannot_be_evidence(self):
        text = (
            "# R\n\n## S\n\n" + "A normal sentence about the intrusion that is long enough to count.\n\n"
            + "rule X { meta: description = \"y\" author = \"z\" strings: $a = \"b\" condition: any of them }\n\n"
            + "[9] Some Vendor, Title of the cited report, 2024\n\n"
            + "1ebb6bb49ac1077c5e7eba4d56f6a3a1 1a37bb789c7bdda44330fd55aa292f5f76dada5d\n"
        )
        units = segment.segment(text)
        eligible = [u for u in units if u.is_evidence_eligible]
        self.assertTrue(any("normal sentence" in u.text for u in eligible))
        for u in units:
            if any(k in u.text for k in ("rule X", "[9]", "1ebb6bb4")):
                self.assertFalse(u.is_evidence_eligible, u.text)
        self.assertIn("omise", [u for u in units if "[9]" in u.text][0].prompt_text)

    def test_a_rule_inventory_line_is_not_evidence(self):
        units = segment.segment("# R\n\n## S\n\n5cc90652-4cbd-4241-aa3b-4b462fa5a248 : Potential Recon Activity Via Nltest.EXE\n\nThe actor ran nltest on the domain controller.\n")
        self.assertEqual([u.is_evidence_eligible for u in units], [False, True])


    def test_an_attack_mapping_line_is_shown_to_the_agent_and_can_be_cited(self):
        units = segment.segment("# R\n\n## MITRE ATT&CK\n\n- Lateral Tool Transfer - T1570\n\nThe actor relied on process injection (T1055).\n")
        self.assertTrue(all(u.is_evidence_eligible and "T1" in u.prompt_text for u in units))


class Titles(unittest.TestCase):
    def test_publisher_suffix_is_removed_only_when_it_is_the_publisher(self):
        self.assertEqual(clean_title("Bissa Scanner Exposed - The DFIR Report", "dfir-report"), "Bissa Scanner Exposed")
        self.assertEqual(clean_title("Rapport | Sekoia", "sekoia"), "Rapport")
        self.assertEqual(clean_title("Lazarus - Part 2", "sekoia"), "Lazarus - Part 2")
        self.assertEqual(clean_title("Sans suffixe", None), "Sans suffixe")


if __name__ == "__main__":
    unittest.main()
