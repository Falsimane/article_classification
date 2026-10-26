"""Tests des règles de détection (analyse YARA et Sigma, étape LLM avec faux modèle, objets STIX) : `uv run python -m unittest tests.test_rules -v`."""

import unittest
from unittest import mock

import stix2

from backend.extracting import rules as ex
from backend.stix.objects import ArticleContext, bundle, deterministic_id, report
from backend.stix.rules import build_rule_objects

QAKBOT = deterministic_id("malware", name="qakbot")
INCIDENT = deterministic_id("incident", name="intrusionreport")
ENTITIES = [
    {"id": QAKBOT, "type": "malware", "name": "Qakbot", "aliases": ["QBot"]},
    {"id": deterministic_id("infrastructure", name="staging"), "type": "infrastructure", "name": "Staging"},  # `indicates` ne l'admet pas
    {"id": INCIDENT, "type": "incident", "name": "Intrusion report"},
]

YARA_OK = '''    rule qbot_loader_dll : loader {
       meta:
          description = "Qakbot loader { not a brace }"
          hash1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
       strings:
          $s1 = "rundll32.exe \\"%s\\"" fullword ascii /* } dans un commentaire */
          $h1 = { 4D 5A ?? 00 }
          // } commentaire de fin de ligne
       condition:
          uint16(0) == 0x5a4d and all of them
    }'''
YARA_PE = '''    import "pe"

    rule anydesk_dropper {
       condition:
          pe.number_of_sections > 2
    }'''
YARA_DAMAGED = '''    rule damaged_by_scraping {
       strings:
          $s1 = ")..\\..\\Windows" fullword wide
       condition:
          all of them
    }'''
YARA_TRUNCATED = '''    rule truncated_rule {
       condition:
          8 of the'''
SIGMA_OK = '''    title: QBot WmiPrvSE execution pattern
    id: 1620db43-fde5-45f3-b4d9-45ca6e79e047
    description: Detects QBot child processes
    logsource:
      category: process_creation
      product: windows
    detection:
      selection_image:
        Image|endswith:
          - 'regsvr32.exe'

      selection_parent:
        ParentImage|endswith: 'WmiPrvSE.exe'
      condition: selection_image and selection_parent
    level: high'''
SIGMA_FLATTENED = '''    title: AdFind Recon
    logsource:
    category: process_creation
    detection:
    selection:
    CommandLine|contains: adfind
    condition: selection'''

ARTICLE = f"""# Intrusion report

title: not a rule at all
author: someone

## Detections

### YARA

{YARA_OK}

{YARA_PE}

{YARA_DAMAGED}

### Sigma

{SIGMA_OK}

Sigma rule for AdFind:

{SIGMA_FLATTENED}

## Annex

{YARA_TRUNCATED}
"""


class Parsing(unittest.TestCase):
    def setUp(self):
        self.rules, dropped = ex.find_rules(ARTICLE)
        self.by_name = {r.name: r for r in self.rules}
        self.dropped = {d.name: d.reason for d in dropped}

    def test_valid_rules_are_kept_with_their_section_and_description(self):
        self.assertEqual(set(self.by_name), {"qbot_loader_dll", "anydesk_dropper", "QBot WmiPrvSE execution pattern"})
        yara_rule = self.by_name["qbot_loader_dll"]
        self.assertEqual((yara_rule.kind, yara_rule.heading, yara_rule.description), ("yara", "Intrusion report > Detections > YARA", "Qakbot loader { not a brace }"))
        self.assertTrue(yara_rule.source.startswith("rule qbot_loader_dll") and yara_rule.source.endswith("}"))  # désindentée, entière
        sigma = self.by_name["QBot WmiPrvSE execution pattern"]
        self.assertEqual((sigma.kind, sigma.heading, sigma.description), ("sigma", "Intrusion report > Detections > Sigma", "Detects QBot child processes"))
        self.assertIn("condition: selection_image and selection_parent", sigma.source)  # la ligne vide n'arrête pas le document
        self.assertIn("level: high", sigma.source)

    def test_braces_in_strings_comments_and_hex_strings_do_not_end_the_rule(self):
        self.assertIn("all of them", self.by_name["qbot_loader_dll"].source)

    def test_used_import_is_prepended_so_the_rule_compiles_alone(self):
        self.assertTrue(self.by_name["anydesk_dropper"].source.startswith('import "pe"\n'))

    def test_damaged_rules_are_dropped_with_a_reason_never_repaired(self):
        self.assertTrue(self.dropped["damaged_by_scraping"].startswith("does-not-compile"))
        self.assertEqual(self.dropped["truncated_rule"], "unclosed")
        self.assertEqual(self.dropped["AdFind Recon"], "missing-title-logsource-or-condition")  # indentation perdue : structure changée

    def test_a_title_key_in_prose_is_not_a_sigma_rule(self):
        self.assertNotIn("not a rule at all", self.dropped)
        self.assertNotIn("not a rule at all", self.by_name)

    def test_same_rule_twice_is_kept_once(self):
        rules, _ = ex.find_rules(ARTICLE + "\n## Copy\n\n" + YARA_OK + "\n")
        self.assertEqual(sum(r.name == "qbot_loader_dll" for r in rules), 1)


def fake_generate(answers):
    def generate(system, prompt, schema, **kw):
        return mock.Mock(parsed={"answers": answers(prompt, schema)}, prompt_tokens=1, output_tokens=1, seconds=0.0, tokens_per_second=0.0)

    return generate


class Stage(unittest.TestCase):
    def test_rule_naming_an_entity_is_attached_by_the_model_others_to_the_incident(self):
        prompts = []

        def answers(prompt, schema):
            prompts.append(prompt)
            self.assertNotIn("Staging", prompt)  # une infrastructure ne peut pas être la cible d'`indicates`
            return [{"rule": "1", "to": "E1"}, {"rule": "2", "to": "E1"}]

        with mock.patch.object(ex.llm, "generate", side_effect=fake_generate(answers)):
            res = ex.extract_rules("Intrusion report", ARTICLE, ENTITIES)
        by = {r.name: r for r in res.rules}
        self.assertEqual(len(prompts), 1)
        self.assertEqual((by["qbot_loader_dll"].attach_name, by["qbot_loader_dll"].confidence), ("Qakbot", 75))
        self.assertEqual(by["QBot WmiPrvSE execution pattern"].attach_name, "Qakbot")  # alias QBot
        self.assertEqual((by["anydesk_dropper"].attach_type, by["anydesk_dropper"].confidence), ("incident", 55))  # ne nomme rien : sans appel

    def test_none_unanswered_and_unproposed_answers_leave_the_rule_unattached(self):
        with mock.patch.object(ex.llm, "generate", side_effect=fake_generate(lambda p, s: [{"rule": "1", "to": "none"}, {"rule": "2", "to": "E9"}])):
            res = ex.extract_rules("Intrusion report", ARTICLE, ENTITIES)
        by = {r.name: r for r in res.rules}
        self.assertIsNone(by["qbot_loader_dll"].attach_id)
        self.assertIsNone(by["QBot WmiPrvSE execution pattern"].attach_id)
        self.assertEqual(len(res.rules), 3)  # aucune règle perdue

    def test_a_failed_call_keeps_the_rules_unattached(self):
        with mock.patch.object(ex.llm, "generate", side_effect=TimeoutError("délai")):
            res = ex.extract_rules("Intrusion report", ARTICLE, ENTITIES)
        self.assertTrue(res.calls and all(c.error for c in res.calls))
        by = {r.name: r for r in res.rules}
        self.assertIsNone(by["qbot_loader_dll"].attach_id)
        self.assertEqual(by["anydesk_dropper"].attach_type, "incident")  # rattachée sans appel : non concernée

    def test_no_rule_no_call(self):
        with mock.patch.object(ex.llm, "generate") as gen:
            res = ex.extract_rules("Intrusion report", "# Title\n\nNothing to detect here.", ENTITIES)
        self.assertEqual((res.rules, gen.call_count), ([], 0))


class Objects(unittest.TestCase):
    def build(self, source_id=5):
        rules, _ = ex.find_rules(ARTICLE)
        for r in rules:
            if r.name == "qbot_loader_dll":
                r.attach_id, r.attach_type, r.attach_name, r.confidence = QAKBOT, "malware", "Qakbot", 75
        ctx = ArticleContext(source_id, "x", "https://x.org/a", "Report")
        objs = [ctx.publisher, *build_rule_objects(rules, ctx, None)]
        return [report(ctx, "Report", None, [o["id"] for o in objs if o["id"] != ctx.publisher.id]), *objs]

    def test_rules_are_strict_stix_indicators_listed_by_the_report(self):
        objects = self.build()
        stix2.parse(bundle(objects).serialize())  # relu par stix2 en mode strict
        indicators = {o["name"]: o for o in objects if o["type"] == "indicator"}
        self.assertEqual(indicators["qbot_loader_dll"]["pattern_type"], "yara")
        self.assertEqual(indicators["QBot WmiPrvSE execution pattern"]["pattern_type"], "sigma")
        self.assertTrue(indicators["qbot_loader_dll"]["pattern"].startswith("rule qbot_loader_dll"))
        report = next(o for o in objects if o["type"] == "report")
        self.assertTrue({o["id"] for o in indicators.values()} <= set(report["object_refs"]))
        self.assertFalse(any(o["type"] == "sighting" for o in objects))  # une règle n'est pas une observation

    def test_attached_rule_indicates_the_entity(self):
        objects = self.build()
        rule_id = next(o["id"] for o in objects if o["type"] == "indicator" and o["name"] == "qbot_loader_dll")
        rels = {(o["relationship_type"], o["source_ref"], o["target_ref"]) for o in objects if o["type"] == "relationship"}
        self.assertEqual(rels, {("indicates", rule_id, QAKBOT)})

    def test_same_rule_in_two_articles_is_one_indicator(self):
        ids = lambda objs: {o["id"] for o in objs if o["type"] == "indicator"}  # noqa: E731
        self.assertEqual(ids(self.build(5)), ids(self.build(6)))


if __name__ == "__main__":
    unittest.main()
