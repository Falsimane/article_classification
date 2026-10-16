"""Tests de l'extraction avec un faux modèle : `uv run python -m unittest tests.test_extraction_pipeline -v`.

Le faux modèle répond aux quatre types d'appels et commet volontairement des erreurs : chaque garde-fou doit les rattraper.
"""

import re
import unittest
from unittest import mock

from backend.extracting import llm, pipeline, segment, stages

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


def fake_generate(system, prompt, schema, **kw):
    props = schema["properties"]
    if "entities" in props:  # étape 1 : le modèle liste aussi des erreurs
        items = ["intrusion-set|UNC3944", "malware|BlackCat", "tool|PsExec", "tool|rclone.exe", "tool|Sensor Tampering Protection",
                 "threat-actor|Mandiant", "malware|malware", "threat-actor|Threat actor", "ligne illisible", "tool|closeapps.bat",
                 "malware|" + "a" * 64, "vulnerability|CVE-2023-4966", "tool|Entité Inventée"]  # fmt: skip
        return llm.LLMResult({"entities": items}, "", 800, 60, 1.0, {"generate": 1.0})
    if "verdicts" in props and "entités" in system:  # vérification d'entités : rejette le paramètre de défense
        out = [f"{m.group(1)}:{'n' if 'Sensor Tampering' in m.group(0) else 'o'}" for m in re.finditer(r"^(\d+)\. .*$", prompt, re.M)]
        return llm.LLMResult({"verdicts": out}, "", 300, 20, 0.5, {"generate": 0.5})
    if "verdicts" in props:  # vérification de relations : rejette la phrase piégée
        blocks = re.findall(r"^(\d+)\. PHRASE : (.*)$", prompt, re.M)
        out = [f"{n}:{'n' if 'SABOTAGE' in sentence else 'o'}" for n, sentence in blocks]
        return llm.LLMResult({"verdicts": out}, "", 300, 20, 0.5, {"generate": 0.5})
    # étape 2 : le modèle accepte tous les candidats `uses` ou `targets` (y compris ceux de la phrase piégée)
    enum = props["relations"]["items"]["enum"]
    chosen, seen = [], set()
    for answer in enum:
        cid, rel = answer.split(":")
        if rel in ("uses", "targets") and cid not in seen:
            seen.add(cid)
            chosen.append(answer)
    return llm.LLMResult({"relations": chosen}, "", 1500, 90, 2.0, {"generate": 2.0})


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


class Titles(unittest.TestCase):
    def test_publisher_suffix_is_removed_only_when_it_is_the_publisher(self):
        self.assertEqual(pipeline.clean_title("Bissa Scanner Exposed - The DFIR Report", "dfir-report"), "Bissa Scanner Exposed")
        self.assertEqual(pipeline.clean_title("Rapport | Sekoia", "sekoia"), "Rapport")
        self.assertEqual(pipeline.clean_title("Lazarus - Part 2", "sekoia"), "Lazarus - Part 2")
        self.assertEqual(pipeline.clean_title("Sans suffixe", None), "Sans suffixe")


class Stages(unittest.TestCase):
    def test_entity_lines(self):
        ents, dropped = stages.parse_entities(["malware|Qakbot|QBot;Pinkslipbot", "tool|PsExec", "bizarre", "location|", "unknown|X|Y", "malware|a"], ("malware", "tool", "location"))
        self.assertEqual([(e["type"], e["name"]) for e in ents], [("malware", "Qakbot"), ("tool", "PsExec")])
        self.assertEqual(ents[0]["aliases"], ["QBot", "Pinkslipbot"])
        self.assertEqual(dropped, 4)

    def test_kb_hints_use_exact_case_and_ignore_commands(self):
        units = segment.segment("Le groupe Scattered Spider utilise Cobalt Strike. La commande net group et le shell sont courants. Impacket aussi.")
        names = [n for n, _ in stages.kb_hints(units)]
        self.assertTrue({"Scattered Spider", "Cobalt Strike", "Impacket"} <= set(names))
        self.assertFalse([n for n in names if n.lower() in ("net", "shell", "page")])

    def _rows(self):
        return [
            stages.EntityRow("E1", "intrusion-set", "Scattered Spider", ("Scattered Spider", "UNC3944")),
            stages.EntityRow("E2", "tool", "PsExec", ("PsExec",)),
            stages.EntityRow("E3", "malware", "BlackCat", ("BlackCat",)),
            stages.EntityRow("E4", "incident", "Rapport", ()),
        ]

    def test_candidates_are_valid_by_construction_and_closed(self):
        text = "# R\n\n## A\n\nUNC3944 used PsExec to drop BlackCat on the network of the victim.\n"
        cands = stages.build_candidates(segment.segment(text), self._rows(), "tactical")
        pairs = {(c.source, c.target): c.options for _, cs in cands for c in cs}
        self.assertIn(("E1", "E2"), pairs)
        self.assertEqual(pairs[("E2", "E3")], ("delivers", "drops"))  # tool -> malware : seules relations STIX autorisées
        self.assertNotIn(("E2", "E1"), pairs)  # un outil n'« emploie » pas un acteur
        schema = stages.relation_schema(cands)
        self.assertIn("1a:uses", schema["properties"]["relations"]["items"]["enum"])

    def test_section_subject_never_crosses_sections(self):
        text = "# R\n\n## A\n\nUNC3944 compromised the network. The attackers used PsExec.\n\n## B\n\nThe attackers used BlackCat.\n"
        by_section = {}
        for u, cs in stages.build_candidates(segment.segment(text), self._rows(), "tactical"):
            by_section.setdefault(u.heading_path.split(" > ")[-1], []).extend((c.source, c.target) for c in cs)
        self.assertIn(("E1", "E2"), by_section["A"])  # sujet de section : UNC3944 -> PsExec
        self.assertNotIn("B", by_section)  # aucun acteur nommé dans la section B, pas d'incident hors profil opérationnel

    def test_incident_is_the_implicit_subject_of_an_operational_report(self):
        text = "# R\n\n## B\n\nThe attackers used PsExec.\n"
        cands = stages.build_candidates(segment.segment(text), self._rows(), "operational", implicit=self._rows()[3])
        self.assertIn(("E4", "E2"), {(c.source, c.target) for _, cs in cands for c in cs})

    def test_two_sentence_window_when_endpoints_are_in_different_sentences(self):
        text = "# R\n\n## A\n\nUNC3944 compromised the network. Then PsExec was deployed there.\n"
        cands = [c for _, cs in stages.build_candidates(segment.segment(text), self._rows(), "tactical") for c in cs]
        windowed = [c for c in cands if c.prev_uid]
        self.assertTrue(windowed or any((c.source, c.target) == ("E1", "E2") for c in cands))

    def test_answers_are_parsed_leniently_and_checked_against_the_options(self):
        group = stages.build_candidates(segment.segment("# R\n\n## A\n\nUNC3944 used PsExec.\n"), self._rows(), "tactical")
        answers, dropped = stages.parse_answers(["1a:uses", "1a:uses", "1a:E1 -> E2:uses", "1a:drops", "9z:uses", "n'importe quoi"], group)
        self.assertEqual([(c.cid, rel) for _, c, rel in answers], [("1a", "uses")])
        self.assertEqual(dropped, 3)

    def test_verdicts(self):
        self.assertEqual(stages.parse_verdicts(["1:o", "2:n", "3:o", "9:o", "x"], [1, 2, 3]), {1, 3})


class FullPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with mock.patch.object(llm, "generate", side_effect=fake_generate):
            cls.op = pipeline.extract_article(1, "Operation Report", "operational", ARTICLE, site_name="mandiant")
            cls.tac = pipeline.extract_article(2, "Operation Report", "tactical", ARTICLE, site_name="mandiant")
            cls.noverify = pipeline.extract_article(3, "Operation Report", "operational", ARTICLE, site_name="mandiant", verify=False)

    @staticmethod
    def triples(result):
        names = {e["id"]: e["name"] for e in result.graph.entities}
        return {(names[r["source_ref"]], r["relationship_type"], names[r["target_ref"]]) for r in result.graph.relationships}

    def codes(self, result):
        return {i.code for i in result.graph.issues}

    def test_every_entity_error_is_caught_before_relations(self):
        names = {e["name"] for e in self.op.graph.entities}
        for bad in ("Mandiant", "malware", "Threat actor", "closeapps.bat", "Entité Inventée"):
            self.assertNotIn(bad, names)
        self.assertFalse([n for n in names if len(n) >= 32])  # le hachage n'est pas une entité
        self.assertTrue({"PUBLISHER_AS_ADVERSARY", "GENERIC_TERM", "FILE_NAME_AS_ENTITY", "OBSERVABLE_AS_ENTITY",
                         "ENTITY_VERIFICATION_REJECTED", "ENTITY_NOT_IN_TEXT"} <= self.codes(self.op))  # fmt: skip

    def test_defensive_setting_is_never_an_attacker_tool(self):
        self.assertNotIn("Sensor Tampering Protection", {e["name"] for e in self.op.graph.entities})
        self.assertNotIn("Sensor Tampering Protection", {t[2] for t in self.triples(self.op)})

    def test_aliases_converge_on_the_reference_object(self):
        actor = next(e for e in self.op.graph.entities if e["type"] == "intrusion-set")
        self.assertEqual(actor["name"], "Scattered Spider")
        self.assertIn("UNC3944", actor["aliases"])

    def test_supported_relations_survive_with_the_sentence_as_evidence(self):
        triples = self.triples(self.op)
        self.assertIn(("Scattered Spider", "targets", "CVE-2023-4966"), triples)
        self.assertIn(("Scattered Spider", "uses", "BlackCat"), triples)  # sujet de section
        self.assertIn(("Operation Report", "uses", "PsExec"), triples)  # sujet implicite : l'incident
        for r in self.op.graph.relationships:
            self.assertTrue(r["_evidence"][0]["quote"] and r["_evidence"][0]["section"].startswith("Report"))

    def test_verification_removes_what_the_model_proposed_wrongly(self):
        sabotage = [t for t in self.triples(self.noverify) if t[0] == "BlackCat"]
        self.assertTrue(sabotage, "sans vérification, la relation piégée passe")
        self.assertFalse([t for t in self.triples(self.op) if t[0] == "BlackCat"])
        self.assertIn("VERIFICATION_REJECTED", self.codes(self.op))
        self.assertGreater(self.op.n_proposed, self.op.n_verified)

    def test_section_subject_and_incident_depend_on_the_profile(self):
        self.assertIn(("Scattered Spider", "uses", "BlackCat"), self.triples(self.tac))
        self.assertNotIn("Operation Report", {e["name"] for e in self.tac.graph.entities})  # pas d'incident hors opérationnel
        self.assertFalse([t for t in self.triples(self.tac) if t[2] == "PsExec"])  # PsExec : section sans acteur nommé

    def test_stats_are_collected_and_output_stays_small(self):
        self.assertEqual({c.stage for c in self.op.calls}, {"entities", "entity-check", "relations", "verification"})
        self.assertLess(self.op.output_tokens, 400)

    def test_unknown_category_is_refused(self):
        with self.assertRaises(ValueError):
            pipeline.extract_article(1, "t", "out_of_scope", ARTICLE)


if __name__ == "__main__":
    unittest.main()
