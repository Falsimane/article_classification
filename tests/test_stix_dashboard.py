"""Tests de l'API de données du tableau de bord STIX (sans Neo4j) : `uv run python -m unittest tests.test_stix_dashboard -v`."""

import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from backend import stix_dashboard as sd

def ev(article, quote):
    return json.dumps({"article": article, "quote": quote})


def sighting(article, first, quote="vu"):
    return {"article": article, "first": first, "last": first, "quote": quote}


def ioc_record(kind, value, role, *sightings, targets=(), labels=None):
    obs = {"type": kind, "value": value}
    return {"indicator": {"id": f"indicator--{value}", "labels": labels or [role], "confidence": 75}, "observable": obs, "sightings": list(sightings),
            "targets": [{"id": f"x--{n}", "name": n, "type": t} for n, t in targets]}  # fmt: skip


class FakeStore:
    def article_ioc_counts(self, article_id):
        return {"malware--2": 3}

    def article_iocs(self, article_id):
        return [
            ioc_record("ipv4-addr", "8.8.4.4", "c2", sighting(7, "2026-10-01T00:00:00.000Z", "C2 <b>at</b> 8.8.4.4"), sighting(8, "2026-10-10T00:00:00.000Z", "again"), targets=[("Bissa", "infrastructure")]),
            ioc_record("file", "a" * 64, "malware-sample", sighting(7, "2025-01-01T00:00:00.000Z")),
            ioc_record("domain-name", "old.example.org", "c2", sighting(7, "2025-01-01T00:00:00.000Z")),
            ioc_record("url", "http://x.test/a", "unknown", {"article": 7, "first": None}),
        ]

    def actor_iocs(self, actor_id):
        return self.article_iocs(7)[:1]

    def article_rules(self, article_id):
        yara_src = 'rule Bumble_ISO {\n  strings:\n    $a = "<b>x</b>"\n  condition:\n    $a\n}\n'
        return [
            {"rule": {"id": "indicator--y", "pattern_type": "yara", "name": "Bumble_ISO", "pattern": yara_src, "confidence": 75, "article_ids": [7]},
             "targets": [{"id": "malware--2", "name": "BumbleBee", "type": "malware"}]},
            {"rule": {"id": "indicator--s", "pattern_type": "sigma", "name": "Suspicious Rundll32", "pattern": "title: Suspicious Rundll32\n", "description": "Lancement", "confidence": 50, "article_ids": [7]},
             "targets": [{"id": None, "name": None, "type": None}]},
        ]  # fmt: skip

    def reports(self):
        return [{"id": 7, "title": "Rapport <b>test</b>", "url": "https://x.org/a", "site_name": "x", "published": "2026-04-22T00:00:00.000Z",
                 "category": "operational", "model": "m", "duration": 12.0, "extracted_at": "2026-10-16T19:00:00", "entities_count": 5, "relations_count": 3}]  # fmt: skip

    def totals(self):
        return {"nodes": {"malware": 2, "tool": 1}, "edges": {"COMMUNICATES_WITH": 2, "USES": 1}, "reports": 1, "lolbins": 1, "iocs": 2}

    def dashboard_graph(self, article_id):
        nodes = [
            {"id": "intrusion-set--1", "type": "intrusion-set", "name": "APT <img src=x onerror=alert(1)>", "aliases": ["Cozy"]},
            {"id": "malware--2", "type": "malware", "name": "A" * 90, "is_family": True},
            {"id": "tool--3", "type": "tool", "name": "PsExec", "labels": ["living-off-the-land"]},
            {"id": "attack-pattern--4", "type": "attack-pattern", "name": "PowerShell",
             "kill_chain_phases_json": json.dumps([{"kill_chain_name": "mitre-attack", "phase_name": "execution"}]),
             "external_references_json": json.dumps([{"source_name": "mitre-attack", "external_id": "T1059.001"}])},
            {"id": "identity--5", "type": "identity", "name": "retail", "sectors": ["retail"]},
            {"id": "location--6", "type": "location", "name": "Orphelin"},
        ]  # fmt: skip
        edges = [
            {"source": "intrusion-set--1", "target": "malware--2", "type": "USES", "id": "relationship--a", "confidence": 85,
             "evidence": [ev(7, "Quote <script>alert(1)</script> de cet article"), ev(8, "Citation d'un AUTRE article")]},
            {"source": "intrusion-set--1", "target": "attack-pattern--4", "type": "USES", "id": "relationship--b", "confidence": 70, "evidence": [ev(7, "PowerShell was used")]},
            {"source": "malware--2", "target": "intrusion-set--1", "type": "COMMUNICATES_WITH", "id": "relationship--c", "confidence": 50, "evidence": []},
            {"source": "tool--3", "target": "ghost--9", "type": "USES", "id": "relationship--d", "evidence": []},  # extrémité absente
            {"source": "tool--3", "target": "attack-pattern--4", "type": "USES", "id": "relationship--e", "confidence": 85, "evidence": [ev(7, "PsExec was run")]},
            {"source": "intrusion-set--1", "target": "identity--5", "type": "TARGETS", "id": "relationship--f", "confidence": 85, "evidence": [ev(7, "They targeted retail")]},
        ]  # fmt: skip
        return {"nodes": nodes, "edges": edges}


class Dashboard(unittest.TestCase):
    def graph(self, **params):
        return sd.graph(7, {k: [v] for k, v in params.items()}, FakeStore())

    def test_articles_and_stats_match_the_shapes_the_frontend_reads(self):
        art = sd.articles(FakeStore())["articles"][0]
        self.assertEqual((art["id"], art["publication_date"], art["category"], art["entities_count"], art["relations_count"]), (7, "2026-04-22", "operational", 5, 3))
        stats = sd.stats(FakeStore())
        self.assertEqual((stats["articles_count"], stats["entities_count"], stats["relations_count"], stats["dual_use_count"]), (1, 3, 3, 1))
        self.assertIn("communicates-with", stats["relation_types"])

    def test_api_returns_data_only_no_presentation(self):
        g = self.graph()
        for n in g["nodes"]:
            self.assertTrue({"id", "label", "type", "family", "degree"} <= n.keys())
            self.assertFalse({"color", "title", "group"} & n.keys())  # couleurs et infobulles : affaire du frontend
        self.assertEqual({n["type"] for n in g["nodes"]}, {"intrusion-set", "malware", "tool", "attack-pattern", "identity"})

    def test_article_text_is_returned_verbatim_for_react_to_escape(self):
        g = self.graph()
        actor = next(n for n in g["nodes"] if n["type"] == "intrusion-set")
        self.assertIn("<img", actor["label"])  # pas d'échappement côté serveur : un double échappement s'afficherait tel quel
        first = next(e for e in g["edges"] if e["id"] == "relationship--a")
        self.assertEqual(first["evidence"][0]["quote"], "Quote <script>alert(1)</script> de cet article")
        self.assertEqual(g["article"]["title"], "Rapport <b>test</b>")
        self.assertEqual(len(next(n for n in g["nodes"] if n["type"] == "malware")["label"]), 90)  # pas de troncature

    def test_evidence_is_this_articles_and_edges_have_ids_and_confidence(self):
        g = self.graph()
        first = next(e for e in g["edges"] if e["id"] == "relationship--a")
        self.assertEqual([x["quote"] for x in first["evidence"]], ["Quote <script>alert(1)</script> de cet article"])
        self.assertEqual(first["confidence"], 85)
        self.assertTrue(all(e["source"] and e["target"] and e["id"] for e in g["edges"]))
        self.assertNotIn("ghost--9", {e["target"] for e in g["edges"]})  # arête sans extrémité : écartée

    def test_attack_tactic_and_reference_are_structured(self):
        e = next(e for e in self.graph()["edges"] if e["id"] == "relationship--b")
        self.assertEqual(e["tactic"], "execution")
        node = next(n for n in self.graph()["nodes"] if n["type"] == "attack-pattern")
        self.assertEqual(node["references"], [{"source": "mitre-attack", "id": "T1059.001"}])
        self.assertEqual(node["tactics"], ["execution"])

    def test_lolbin_label_makes_a_tool_dual_use(self):
        tool = next(n for n in self.graph()["nodes"] if n["type"] == "tool")
        self.assertTrue(tool["is_dual_use"])
        self.assertEqual([n["label"] for n in self.graph(dual_use_only="1")["nodes"]], ["PsExec"])

    def test_filters_and_orphans(self):
        names = lambda **p: sorted(n["label"] for n in self.graph(**p)["nodes"])  # noqa: E731
        self.assertNotIn("Orphelin", names())  # degré 0 : masqué par défaut
        self.assertIn("Orphelin", names(hide_orphans="0"))
        self.assertEqual(names(type="malware"), ["A" * 90])
        self.assertEqual(len(names(type="actor")), 1)  # la famille regroupe threat-actor, intrusion-set, campaign
        self.assertEqual(names(search="psexec"), ["PsExec"])

    def test_unknown_article_falls_back_to_an_extracted_one(self):
        self.assertEqual(sd.graph(999, {}, FakeStore())["article_id"], 7)

    def test_techniques_stay_in_the_entity_graph(self):
        self.assertIn("PowerShell", {n["label"] for n in sd.graph(7, {}, FakeStore())["nodes"]})


NOW = datetime(2026, 10, 16, tzinfo=timezone.utc)


class Iocs(unittest.TestCase):
    def rows(self):
        return {r["value"]: r for r in sd.iocs_of_article(7, FakeStore(), NOW)["iocs"]}

    def test_first_and_last_seen_come_from_all_sightings(self):
        r = self.rows()["8.8.4.4"]
        self.assertEqual((r["first_seen"], r["last_seen"], r["sources"], r["article_ids"]), ("2026-10-01", "2026-10-10", 2, [7, 8]))

    def test_status_is_computed_at_read_time_from_the_last_sighting(self):
        rows = self.rows()
        self.assertEqual(rows["8.8.4.4"]["status"], "active")  # 6 jours
        self.assertEqual(rows["old.example.org"]["status"], "stale")  # > 365 jours pour un domaine
        self.assertEqual(rows["a" * 64]["status"], "aging")  # 1 an : un hachage reste actif 365 jours
        self.assertEqual(sd.iocs_of_article(7, FakeStore(), datetime(2026, 12, 1, tzinfo=timezone.utc))["iocs"][0]["status"], "aging")  # même IOC, plus tard
        self.assertEqual(rows["http://x.test/a"]["status"], "unknown")  # aucune observation datée : jamais « actif »

    def test_role_attachment_and_evidence_text_is_verbatim(self):
        r = self.rows()["8.8.4.4"]
        self.assertEqual((r["role"], r["attached_to"][0]["name"]), ("c2", "Bissa"))
        self.assertEqual(r["evidence"][0]["quote"], "C2 <b>at</b> 8.8.4.4")  # React échappe ; le serveur ne touche pas au texte

    def test_graph_nodes_carry_their_ioc_count_and_stats_the_total(self):
        g = sd.graph(7, {}, FakeStore())
        self.assertEqual({n["id"]: n["ioc_count"] for n in g["nodes"]}["malware--2"], 3)
        self.assertEqual(sd.stats(FakeStore())["iocs_count"], 2)

    def test_actor_profile_carries_its_iocs(self):
        class S(Actors.Store):
            def actor_iocs(self, actor_id):
                return FakeStore().actor_iocs(actor_id)

        self.assertEqual([r["value"] for r in sd.actor_graph("intrusion-set--1", S(), NOW)["iocs"]], ["8.8.4.4"])


class Rules(unittest.TestCase):
    def rows(self):
        return {r["kind"]: r for r in sd.rules_of_article(7, FakeStore())["rules"]}

    def test_rule_text_is_returned_verbatim_with_its_language(self):
        r = self.rows()["yara"]
        self.assertEqual((r["name"], r["source"]), ("Bumble_ISO", FakeStore().article_rules(7)[0]["rule"]["pattern"]))

    def test_detected_entity_or_none(self):
        rows = self.rows()
        self.assertEqual([t["name"] for t in rows["yara"]["detects"]], ["BumbleBee"])
        self.assertEqual((rows["sigma"]["detects"], rows["sigma"]["description"]), ([], "Lancement"))  # règle sans rattachement : liste vide

    def test_rules_are_kept_out_of_the_entity_graph(self):
        from backend.database.stix_store import _is_ioc

        self.assertIn("'yara', 'sigma'", _is_ioc("n"))


class Actors(unittest.TestCase):
    class Store(FakeStore):
        def actors(self):
            return [{"id": "intrusion-set--1", "type": "intrusion-set", "name": "APT29", "aliases": ["Cozy Bear"], "relations": 3, "reports": 2}]

        def actor_subgraph(self, actor_id):
            if actor_id != "intrusion-set--1":
                return None
            g = FakeStore().dashboard_graph(7)
            nodes = {n["id"]: n for n in g["nodes"]}
            return {"actor": nodes["intrusion-set--1"], "nodes": [nodes["malware--2"], nodes["attack-pattern--4"]],
                    "edges": [e for e in g["edges"] if e["id"] in ("relationship--a", "relationship--b")],
                    "reports": [{"id": 7, "title": "T", "url": "u", "site_name": "x", "category": "operational", "published": "2026-04-22T00:00:00Z"}]}  # fmt: skip

    def test_actor_list_carries_counts(self):
        row = sd.actors(self.Store())["actors"][0]
        self.assertEqual((row["label"], row["family"], row["relations"], row["reports"]), ("APT29", "actor", 3, 2))

    def test_profile_keeps_evidence_from_every_article(self):
        p = sd.actor_graph("intrusion-set--1", self.Store())
        first = next(e for e in p["edges"] if e["id"] == "relationship--a")
        self.assertEqual(len(first["evidence"]), 2)  # contrairement à la vue d'un rapport : tous les articles
        self.assertEqual(p["actor"]["id"], "intrusion-set--1")
        self.assertEqual(p["reports"][0]["published"], "2026-04-22")

    def test_profile_is_read_from_direct_edges_and_leaves_gaps_empty(self):
        node = lambda i, t, n, **k: {"id": i, "type": t, "name": n, **k}  # noqa: E731
        edge = lambda i, s, r, t: {"id": i, "source": s, "target": t, "type": r, "confidence": 80, "evidence": []}  # noqa: E731
        nodes = [node("loc", "location", "Russie"), node("tt", "attack-pattern", "PowerShell", kill_chain_phases_json=json.dumps([{"kill_chain_name": "mitre-attack", "phase_name": "execution"}])),
                 node("m", "malware", "WellMess"), node("t", "tool", "PsExec"), node("i", "infrastructure", "C2"), node("v", "vulnerability", "CVE-1"),
                 node("sub", "campaign", "SolarStorm"), node("id", "identity", "SVR"), node("tg", "identity", "Santé")]
        edges = [edge("1", "a", "originates-from", "loc"), edge("2", "a", "uses", "tt"), edge("3", "a", "uses", "m"), edge("4", "a", "uses", "t"),
                 edge("5", "a", "uses", "i"), edge("6", "a", "targets", "v"), edge("7", "sub", "attributed-to", "a"), edge("8", "a", "attributed-to", "id"),
                 edge("9", "a", "targets", "tg")]  # fmt: skip

        class S(Actors.Store):
            def actor_subgraph(self, actor_id):
                return {"actor": {"id": "a", "type": "intrusion-set", "name": "APT29"}, "nodes": nodes, "edges": edges, "reports": []}

        p = sd.actor_graph("a", S())["profile"]
        names = lambda k: [x["node"]["label"] for x in p[k]]  # noqa: E731
        self.assertEqual((names("origin"), names("malware"), names("tools"), names("infrastructure"), names("vulnerabilities")), (["Russie"], ["WellMess"], ["PsExec"], ["C2"], ["CVE-1"]))
        self.assertEqual((names("divisions"), names("sponsors"), names("targets"), names("parents")), (["SolarStorm"], ["SVR"], ["Santé"], []))
        self.assertEqual({k: [x["node"]["label"] for x in v] for k, v in p["techniques"].items()}, {"execution": ["PowerShell"]})

    def test_unknown_actor(self):
        self.assertIsNone(sd.actor_graph("nope", self.Store()))


class ArticleSource(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_article_text_is_the_clean_markdown_verbatim(self):
        db = self.dir / "articles.db"
        with sqlite3.connect(db) as conn:
            conn.execute("CREATE TABLE knowledge (id INTEGER, title TEXT, url TEXT, site_name TEXT, publication_date TEXT)")
            conn.execute("CREATE TABLE article_classifications (knowledge_id INTEGER, primary_category TEXT, clean_markdown TEXT)")
            conn.execute("INSERT INTO knowledge VALUES (7, 'Rapport', 'https://x.org/a', 'x', '2026-04-22T00:00:00')")
            conn.execute("INSERT INTO article_classifications VALUES (7, 'operational', '## Titre\n\n<script>alert(1)</script> texte')")
        text = sd.article_text(7, db)
        self.assertEqual((text["title"], text["published"], text["category"]), ("Rapport", "2026-04-22", "operational"))
        self.assertEqual(text["markdown"], "## Titre\n\n<script>alert(1)</script> texte")  # échappé par le frontend, pas ici
        self.assertIsNone(sd.article_text(8, db))

    def test_bundle_is_served_as_written_and_checked_against_the_graph(self):
        graph = FakeStore().dashboard_graph(7)
        objects = [{"id": x["id"]} for x in graph["nodes"] + graph["edges"]]
        (self.dir / "article_7.json").write_text(json.dumps({"type": "bundle", "objects": objects}))
        raw, matches = sd.article_bundle(7, FakeStore(), self.dir)
        self.assertEqual(json.loads(raw)["objects"], objects)
        self.assertTrue(matches)
        (self.dir / "article_7.json").write_text(json.dumps({"type": "bundle", "objects": objects[1:]}))  # ré-extraction en --dry-run
        self.assertFalse(sd.article_bundle(7, FakeStore(), self.dir)[1])
        self.assertIsNone(sd.article_bundle(8, FakeStore(), self.dir))


if __name__ == "__main__":
    unittest.main()
