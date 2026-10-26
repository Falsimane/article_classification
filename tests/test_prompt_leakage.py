"""Aucun texte envoyé au modèle ne reprend un article évalué (noms, alias, identifiants du gold) : `uv run python -m unittest tests.test_prompt_leakage -v`."""

import json
import re
import unittest
from pathlib import Path

from backend.extracting.iocs import ioc_system
from backend.extracting.rules import rule_system
from backend.extracting.stix_agent import system_prompt, tool_specs
from backend.stix.objects import ENTITY_CLASSES

ANNOTATIONS = Path(__file__).resolve().parents[1] / "Annotations"
# Les noms de type STIX (« Tool » est aussi la technique T1588.002) font partie du vocabulaire des prompts
_TYPE_WORDS = {t.casefold() for t in (*ENTITY_CLASSES, "attack-pattern")}


def gold_terms() -> set[str]:
    manifest = json.loads((ANNOTATIONS / "manifest.json").read_text(encoding="utf-8"))
    terms = set()
    for art in manifest["articles"]:
        for o in json.loads((ANNOTATIONS / art["gold"]).read_text(encoding="utf-8"))["objects"]:
            terms |= {o.get("name") or "", *(o.get("aliases") or []), *(o.get("x_gold_name_variants") or []), *(o.get("x_mitre_aliases") or [])}
            terms |= {r["external_id"] for r in o.get("external_references", []) if r.get("external_id")}
    return {t for t in terms if len(t) >= 3 and t.casefold() not in _TYPE_WORDS}


@unittest.skipUnless((ANNOTATIONS / "manifest.json").exists(), "pas d'articles annotés")
class NoEvaluatedArticleInPrompts(unittest.TestCase):
    def test_prompts_name_nothing_from_the_gold(self):
        prompts = {
            "agent (système)": system_prompt(),
            "agent (outils)": json.dumps(tool_specs(), ensure_ascii=False),
            "IOC": ioc_system(),
            "règles": rule_system(),
        }
        terms = gold_terms()
        for name, text in prompts.items():
            leaked = sorted(t for t in terms if re.search(rf"(?<![\w-]){re.escape(t)}(?![\w-])", text, re.I))
            self.assertEqual(leaked, [], f"prompt {name}")


if __name__ == "__main__":
    unittest.main()
