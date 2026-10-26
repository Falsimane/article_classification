"""Score contre un gold (méthode Annotations/methode_annotation.md) : `uv run python -m unittest tests.test_evaluation -v`."""

import unittest

from backend.evaluation.score import grounding_status, score_article, total
from tests.attack_fixture import mini_kb

TEXT = "The operators ran systeminfo through cmd.exe. ZshBucket then collected the host name. Contact evil.example.com."


def ap(n: int, aid: str, label="gold:required") -> dict:
    return {"type": "attack-pattern", "id": f"attack-pattern--{n:08d}-0000-4000-8000-000000000000", "name": aid, "labels": [label],
            "external_references": [{"source_name": "mitre-attack", "external_id": aid}]}  # fmt: skip


def obj(stix_type: str, n: int, name: str, label="gold:required", **extra) -> dict:
    return {"type": stix_type, "id": f"{stix_type}--{n:08d}-0000-4000-8000-000000000000", "name": name, "labels": [label], **extra}


def rel(n: int, src: dict, rtype: str, dst: dict, label="gold:required", quote: str | None = None) -> dict:
    out = {"type": "relationship", "id": f"relationship--{n:08d}-0000-4000-8000-000000000000", "relationship_type": rtype,
           "source_ref": src["id"], "target_ref": dst["id"], "labels": [label]}  # fmt: skip
    if quote:
        out["description"] = quote
    return out


CAMPAIGN = obj("campaign", 1, "Campagne Axios (mars 2026)")
ACTOR = obj("intrusion-set", 2, "STARDUST CHOLLIMA")
ZSH = obj("malware", 3, "ZshBucket")
T1082 = ap(4, "T1082")
T1059_003 = ap(5, "T1059.003")
CMD = obj("tool", 6, "cmd", "gold:acceptable", x_gold_name_variants=["cmd.exe"])
GOLD = {"objects": [
    {"type": "report", "id": "report--00000000-0000-4000-8000-000000000000", "name": "r", "labels": ["gold:required"]},
    CAMPAIGN, ACTOR, ZSH, T1082, T1059_003, CMD,
    rel(10, CAMPAIGN, "attributed-to", ACTOR),
    rel(11, ZSH, "uses", T1082),
    rel(12, CAMPAIGN, "uses", T1059_003),
    rel(13, CAMPAIGN, "uses", CMD, "gold:acceptable"),
]}  # fmt: skip


def predicted(*extra: dict) -> dict:
    publisher = obj("identity", 90, "crowdstrike", identity_class="organization")
    incident = obj("incident", 91, "STARDUST CHOLLIMA Likely Compromises Axios npm Package", created_by_ref=publisher["id"])
    apt38 = obj("intrusion-set", 92, "APT38", created_by_ref=publisher["id"])  # alias ATT&CK de Stardust Chollima (G0082)
    zsh = obj("malware", 93, "ZshBucket")
    t1059 = ap(94, "T1059")  # technique parente de T1059.003 : crédit 0,5
    t1082 = ap(95, "T1082")
    fake = ap(96, "T1999")  # absent de la v20.0
    cmd = obj("tool", 97, "cmd.exe")
    domain = {"type": "domain-name", "id": "domain-name--00000098-0000-4000-8000-000000000000", "value": "evil.example.com"}
    objs = [publisher, incident, apt38, zsh, t1059, t1082, fake, cmd, domain,
            rel(30, incident, "attributed-to", apt38, quote="The operators ran systeminfo through cmd.exe."),
            rel(31, zsh, "uses", t1082, quote="ZshBucket then collected the host name."),
            rel(32, incident, "uses", t1059, quote="The operators ran systeminfo through cmd.exe."),
            rel(33, incident, "uses", cmd, quote="ran systeminfo through cmd"),
            rel(34, zsh, "uses", fake, quote="This sentence is not in the article at all."),
            rel(35, zsh, "communicates-with", domain, quote="Contact evil.example.com.")]  # fmt: skip
    for o in extra:
        objs.append(o)
    return {"objects": [{**o, "labels": []} if "labels" in o else o for o in objs]}


class Scoring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kb = mini_kb()
        cls.score = score_article(1, GOLD, predicted(), TEXT, kb=cls.kb)

    def test_entities_partial_credit_alias_and_operation_alignment(self):
        e = self.score.entities
        # required : campagne (incident), acteur (alias G0082), ZshBucket, T1082 (1) ; T1059.003 par sa parente (0,5)
        self.assertEqual((e.gold_required, e.found_required), (5, 4.5))
        self.assertEqual(e.found_acceptable, 1.0)  # cmd.exe = cmd (variante de nom)
        # prédits dans le périmètre : sans l'éditeur ni le domaine (IOC) ; T1999 est un faux positif
        self.assertEqual(e.predicted, 7)
        self.assertAlmostEqual(e.precision, 5.5 / 7)
        self.assertEqual(self.score.hallucinations, ["T1999"])

    def test_relations_matched_after_normalization(self):
        r = self.score.relations
        self.assertEqual((r.gold_required, r.found_required, r.found_acceptable), (3, 2.5, 1.0))
        self.assertEqual(r.predicted, 5)  # la relation vers le domaine (IOC) est hors périmètre
        self.assertEqual(len(self.score.review_relations), 1)

    def test_grounding_exact_approximate_missing(self):
        g = self.score.grounding
        self.assertEqual((g["with_quote"], g["exact"], g["missing"]), (5, 4, 1))
        self.assertEqual(grounding_status("operators ran systeminfo through the cmd.exe shell", "The operators ran systeminfo through cmd.exe shell"), "approximate")
        self.assertEqual(grounding_status("the loader encrypted every file with AES", "The operators ran systeminfo through cmd.exe shell"), "missing")
        long ="The operators ran systeminfo through cmd.exe and then collected the host name from the beachhead"
        self.assertEqual(grounding_status(long.replace("then ", ""), long), "approximate")

    def test_invalid_gold_relations_are_reported(self):
        software = obj("software", 50, "Axios")
        gold = {"objects": [*GOLD["objects"], software, rel(51, CAMPAIGN, "targets", software)]}
        s = score_article(1, gold, predicted(), TEXT, kb=self.kb)
        self.assertEqual(len(s.invalid_gold_relations), 1)

    def test_total_is_micro_average(self):
        summary = total([self.score, self.score])
        self.assertEqual(summary["entities"]["gold_required"], 10)
        self.assertAlmostEqual(summary["entities"]["recall"], 0.9)


if __name__ == "__main__":
    unittest.main()
