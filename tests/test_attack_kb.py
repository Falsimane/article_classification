"""Index ATT&CK v20.0 construit par stix2 (recherche, fiches, objets officiels, alias, statuts) : `uv run python -m unittest tests.test_attack_kb -v`."""

import tempfile
import unittest
from pathlib import Path

from stix2 import AttackPattern

from backend.stix.attack import build_index, clean_description, fts_query, load_store
from tests.attack_fixture import OBJECTS, mini_kb


class Index(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kb = mini_kb()

    def test_version_is_pinned(self):
        self.assertEqual(self.kb.version, "20.0")
        bad = [{**o, "x_mitre_version": "19.1"} if o["type"] == "x-mitre-collection" else o for o in OBJECTS]
        with self.assertRaises(ValueError):
            build_index(load_store(bad), Path(tempfile.mkdtemp()) / "kb.sqlite")

    def test_procedure_examples_bridge_commands_to_techniques(self):
        hits = self.kb.search_techniques("the implant ran systeminfo on the host")
        self.assertEqual(hits[0].attack_id, "T1082")

    def test_subtechnique_named_with_parent_and_tactic_filter(self):
        hits = self.kb.search_techniques("windows command shell")
        self.assertEqual(hits[0].attack_id, "T1059.003")
        self.assertEqual(hits[0].name, "Command and Scripting Interpreter: Windows Command Shell")
        self.assertEqual(self.kb.search_techniques("windows command shell", tactic="discovery"), [])

    def test_revoked_techniques_are_not_suggested_but_resolve(self):
        self.assertNotIn("T1086", [h.attack_id for h in self.kb.search_techniques("PowerShell")])
        self.assertEqual(self.kb.status("T1086"), ("revoked", "T1059.001"))
        self.assertEqual(self.kb.status("T9999"), ("unknown", None))

    def test_technique_is_not_shadowed_by_a_mitigation_with_its_id(self):
        self.assertEqual((self.kb.get("T1082")["type"], self.kb.get("T1082")["name"]), ("attack-pattern", "System Information Discovery"))
        self.assertEqual(self.kb.status("T1082"), ("active", None))
        self.assertEqual(self.kb.search_techniques("System Information Discovery")[0].attack_id, "T1082")

    def test_alias_lookup_and_known_uses(self):
        self.assertEqual([h["attack_id"] for h in self.kb.lookup("Stardust Chollima")], ["G0082"])
        self.assertEqual([h["attack_id"] for h in self.kb.lookup("cmd.exe")], ["S0106"])
        self.assertEqual(self.kb.known_uses("G0082", "malware"), [("S0154", "Cobalt Strike")])
        self.assertEqual([i for i, _ in self.kb.subtechniques("T1059")], ["T1059.001", "T1059.003"])

    def test_official_object_is_returned_by_stix2_with_its_mitre_id(self):
        obj = self.kb.stix_object("T1059.003")
        self.assertIsInstance(obj, AttackPattern)
        self.assertEqual(obj.id, next(o["id"] for o in OBJECTS if o.get("name") == "Windows Command Shell"))
        self.assertEqual([type(o).__name__ for o in self.kb.support_objects({obj.created_by_ref})], ["Identity"])

    def test_id_query_and_description_cleaning(self):
        self.assertEqual([h.attack_id for h in self.kb.search_techniques("T1059.001")], ["T1059.001"])
        self.assertEqual(clean_description("Use [cmd](https://x) here.(Citation: A B)"), "Use cmd here.")
        self.assertEqual(fts_query('the "cmd" OR NEAR('), '"cmd" OR "near"')


if __name__ == "__main__":
    unittest.main()
