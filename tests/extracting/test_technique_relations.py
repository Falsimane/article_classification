"""Relations des techniques : le modèle voit la procédure et les phrases de chaque technique (le texte ne nomme jamais une
technique ATT&CK, il ne peut donc pas citer une phrase qui la « nomme »)."""
from types import SimpleNamespace

from backend.extracting.cascade.graph import technique_relations
from backend.extracting.graph.draft import DraftGraph
from backend.extracting.stix.objects import ArticleContext
from backend.preprocessing.cleaning.text.segment import segment

TEXT = "# Report\n\nAlpha Group exploited CVE-2099-0001 in the exposed gateway to get in.\n"


def test_prompt_shows_procedure_and_relation_is_written():
    units = segment(TEXT)
    n = next(u.uid for u in units if "CVE-2099-0001" in u.text)
    draft = DraftGraph(units, ArticleContext(1, "test-source", None, "t"))
    group, _ = draft.declare("intrusion-set|Alpha Group")
    cve, _ = draft.declare("vulnerability|CVE-2099-0001")
    assert draft.relate(f"Alpha Group|uses|T1190|{n}") is None
    tech = draft.names["T1190"]
    draft.procedures[tech] = ["exploits the exposed gateway"]
    result = SimpleNamespace(refused=0, accepted=0, refused_relations=[], behaviors=[{"uids": [n], "chosen": ["T1190"]}])
    prompts = []

    def call(stage, system, prompt, schema, tokens):
        prompts.append(prompt)
        return {"relations": [{"source": 3, "relation": "targets", "target": 2, "sentences": [n]}]}

    technique_relations(draft, TEXT, "s", [group, cve], result, call)
    assert f"« exploits the exposed gateway » [{n}]" in prompts[0] and "nomme ses deux extrémités" not in prompts[0]
    assert (tech, "targets", cve) in draft.evidence
