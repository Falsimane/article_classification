"""Tests de l'ontologie STIX : `uv run python -m unittest tests.test_stix_ontology -v`."""

import json
import unittest

import stix2

from backend.ontology.stix import (
    OBJECT_TYPES, PROFILES, SEMANTICS, allowed_relationships, build_stix_objects, confidence_from_text,
    classify_identifier, get_reference_kb, is_valid_relationship, neo4j_label, neo4j_relationship_type, normalize_name,
    ontology_turtle, render_prompt_card, sanitize_extraction, stix_id, to_bundle,
)  # fmt: skip
from backend.ontology.stix.relationships import ALL_RELATIONSHIP_TYPES
from backend.ontology.stix.validate import evidence_in_source, mentions
from backend.ontology.stix.vocab import OPEN_VOCABULARIES, allowed_values

SOURCE = (
    "En octobre 2024, le cluster d'activité suspecté UNC3944 a compromis l'infrastructure périphérique d'un opérateur "
    "de télécommunications. L'accès initial a été obtenu par l'exploitation de la vulnérabilité critique CVE-2023-4966 "
    "(dite « Citrix Bleed »). Muni de cette session légitime, l'acteur a invoqué l'interpréteur natif powershell.exe "
    "pour exécuter la technique ATT&CK T1059.001. Depuis PowerShell, l'attaquant a exécuté l'utilitaire "
    "d'administration légitime PsExec.exe afin d'obtenir des privilèges complets. UNC3944 a déposé un binaire "
    "malveillant dédié nommé BlackCat_Locker.exe. L'acteur a détourné l'outil de synchronisation cloud rclone.exe "
    "pour transférer les archives vers un bucket externe situé sur l'infrastructure C2 Storage Sync."
)


class RelationshipTable(unittest.TestCase):
    def test_covers_every_relationship_published_in_attack_data(self):
        triplets = get_reference_kb().meta["relationship_triplets"]
        self.assertGreater(len(triplets), 10)
        for src, rel, dst, n in triplets:
            self.assertTrue(is_valid_relationship(src, rel, dst), f"ATT&CK publie {n}× {src} --{rel}--> {dst}")

    def test_stix_semantics(self):
        ok = [("intrusion-set", "uses", "attack-pattern"), ("malware", "exploits", "vulnerability"),
              ("threat-actor", "targets", "vulnerability"), ("campaign", "attributed-to", "threat-actor"),
              ("malware", "exfiltrate-to", "infrastructure"), ("malware", "exfiltrates-to", "infrastructure"),
              ("tool", "uses", "attack-pattern"), ("indicator", "indicates", "malware"), ("tool", "related-to", "identity")]  # fmt: skip
        ko = [("threat-actor", "uses", "vulnerability"), ("intrusion-set", "exploits", "vulnerability"),
              ("tool", "exfiltrates-to", "infrastructure"), ("threat-actor", "attributed-to", "campaign"),
              ("malware", "derived-from", "tool"), ("identity", "uses", "malware")]  # fmt: skip
        for t in ok:
            self.assertTrue(is_valid_relationship(*t), t)
        for t in ko:
            self.assertFalse(is_valid_relationship(*t), t)

    def test_every_relationship_type_is_defined_for_prompts(self):
        used = {r for p in PROFILES.values() for _, r, _ in p.pairs()}
        self.assertLessEqual(used, set(SEMANTICS))
        self.assertLessEqual(used, ALL_RELATIONSHIP_TYPES)

    def test_suggestions(self):
        self.assertEqual(allowed_relationships("intrusion-set", "vulnerability"), ["related-to", "targets"])


class Vocabularies(unittest.TestCase):
    def test_come_from_stix2_and_are_complete(self):
        self.assertIn("ransomware", OPEN_VOCABULARIES["malware-type-ov"])
        self.assertIn("yara", OPEN_VOCABULARIES["pattern-type-ov"])
        self.assertIn("nation-state", allowed_values("threat-actor", "threat_actor_types"))
        self.assertIsNone(allowed_values("malware", "name"))

    def test_attack_tactics_follow_the_reference_data(self):
        kb = get_reference_kb()
        self.assertEqual(kb.normalize_tactic("defense-evasion"), ("stealth", "defense-impairment"))
        self.assertEqual(kb.normalize_tactic("Initial Access"), ("initial-access",))
        self.assertEqual(kb.normalize_tactic("n'importe quoi"), ())


class Identity(unittest.TestCase):
    def test_deterministic_ids_converge_on_aliases_of_the_same_name(self):
        self.assertEqual(stix_id("intrusion-set", {"name": "APT 29"}), stix_id("intrusion-set", {"name": "apt29"}))
        self.assertEqual(stix_id("intrusion-set", {"name": "Lazarus Group"}), stix_id("intrusion-set", {"name": "lazarus"}))
        self.assertNotEqual(stix_id("malware", {"name": "A"}), stix_id("tool", {"name": "A"}))
        self.assertEqual(
            stix_id("vulnerability", {"cve": "cve-2023-4966", "name": "Citrix Bleed"}),
            stix_id("vulnerability", {"name": "CVE-2023-4966", "cve": "CVE-2023-4966"}),
        )
        self.assertTrue(stix_id("malware", {"name": "x"}).startswith("malware--"))
        with self.assertRaises(ValueError):
            stix_id("malware", {})

    def test_normalize_name(self):
        for raw, norm in [("The DFIR Report", "dfirreport"), ("Lazarus Group", "lazarus"), ("Équipe Café", "equipecafe"), ("APT-29", "apt29")]:
            self.assertEqual(normalize_name(raw), norm)

    def test_normative_identifiers(self):
        cases = {"CVE-2023-4966": "cve", "cwe-79": "cwe", "T1059.001": "attack-technique", "G0016": "attack-group",
                 "S0154": "attack-software", "C0001": "attack-campaign", "TA0001": "attack-tactic", "M1017": "attack-mitigation",
                 "CAPEC-112": "capec", "APT29": None, "UNC2452": None, "Storm-0558": None}  # fmt: skip
        for text, kind in cases.items():
            self.assertEqual(classify_identifier(text), kind, text)

    def test_vendor_naming_conventions_are_not_interpreted(self):
        """Les noms d'acteurs sont des conventions propriétaires qui changent : aucune information n'en est déduite."""
        import backend.ontology.stix as stix
        import backend.ontology.stix.identity as identity

        self.assertFalse(hasattr(stix, "identify_name") or hasattr(identity, "NAMING_SCHEMES"))
        raw = {
            "entities": [
                {"ref": "a", "type": "threat-actor", "name": "Zéphyr Typhoon"},  # forme « Microsoft », absent d'ATT&CK
                {"ref": "b", "type": "malware", "name": "Qakbot"},
            ],
            "relationships": [{"source": "a", "type": "uses", "target": "b", "evidence": "Zéphyr Typhoon déploie Qakbot"}],
        }
        g = sanitize_extraction(raw, "tactical", "texte : Zéphyr Typhoon déploie Qakbot. fin")
        actor = next(e for e in g.entities if e["name"] == "Zéphyr Typhoon")
        self.assertEqual(actor["type"], "threat-actor")  # pas reclassé d'après la forme du nom
        self.assertFalse([k for k in actor if k.startswith("x_cti_origin") or k.startswith("x_cti_motivation")])
        # à l'inverse, un groupe CONNU d'ATT&CK prend le type de la donnée de référence (intrusion-set)
        raw["entities"][0]["name"] = "Volt Typhoon"
        raw["relationships"][0]["evidence"] = "Volt Typhoon déploie Qakbot"
        known = sanitize_extraction(raw, "tactical", "texte : Volt Typhoon déploie Qakbot. fin")
        self.assertEqual(next(e for e in known.entities if "Volt" in e["name"])["type"], "intrusion-set")

    def test_confidence_follows_stix_scales(self):
        cases = [("We assess with moderate confidence", 50), ("with high confidence", 85), ("low confidence", 15),
                 ("highly likely", 90), ("likely operated by", 70), ("unlikely", 30), ("allegedly stolen", 30),
                 ("pourrait être lié", 50), ("The actor deployed", 85)]  # fmt: skip
        for text, value in cases:
            self.assertEqual(confidence_from_text(text), value, text)


class ReferenceKB(unittest.TestCase):
    def setUp(self):
        self.kb = get_reference_kb()

    def test_aliases_converge_on_one_object(self):
        for name in ("Cozy Bear", "NOBELIUM", "Midnight Blizzard", "APT 29", "UNC2452"):
            g = self.kb.ground("intrusion-set", name)
            self.assertEqual((g.status, g.match.attack_id), ("grounded", "G0016"), name)

    def test_same_name_resolves_by_type(self):
        self.assertEqual(self.kb.ground("malware", "Cozy Bear").match.attack_id, "S0046")  # le malware CozyCar
        self.assertEqual(self.kb.ground("intrusion-set", "Cozy Bear").match.attack_id, "G0016")

    def test_unknown_names_are_not_invented(self):
        self.assertEqual(self.kb.ground("intrusion-set", "Équipe Fictive Zéta").status, "unknown")

    def test_type_conflict(self):
        self.assertEqual(self.kb.type_conflict("threat-actor", "Cobalt Strike").stix_type, "malware")
        self.assertIsNone(self.kb.type_conflict("tool", "Cobalt Strike"))  # malware/tool : frontière d'usage

    def test_revoked_technique_is_replaced_not_rejected(self):
        r = self.kb.resolve_technique("T1086")
        self.assertEqual((r.attack_id, r.status, r.original_id), ("T1059.001", "revoked", "T1086"))
        r = self.kb.resolve_technique("T1059.001", "Scheduled Task")
        self.assertTrue(r.name_conflict)
        self.assertEqual(r.name, "PowerShell")
        self.assertEqual(self.kb.resolve_technique("T9999").status, "unknown")
        self.assertEqual(self.kb.resolve_technique(None, "Process Injection").attack_id, "T1055")


class Profiles(unittest.TestCase):
    def test_profiles_are_narrower_than_the_ontology(self):
        self.assertTrue(PROFILES["operational"].sightings and PROFILES["operational"].attack_flow)
        self.assertFalse(PROFILES["strategic"].sightings)
        self.assertLess(len(PROFILES["strategic"].pairs()), len(PROFILES["tactical"].pairs()))
        self.assertNotIn("attack-pattern", PROFILES["strategic"].entity_types)

    def test_observables_are_never_extracted_by_the_llm(self):
        for p in PROFILES.values():
            self.assertFalse({"ipv4-addr", "domain-name", "url", "file"} & set(p.entity_types))
            self.assertEqual(OBJECT_TYPES["ipv4-addr"].extraction, "deterministic")

    def test_prompt_card_mentions_rules_and_only_profile_content(self):
        card = render_prompt_card("strategic")
        self.assertIn("attributed-to", card)
        self.assertNotIn("beacons-to", card)
        self.assertIn("auteur du rapport", card)
        for vendor_term in ("Typhoon", "CrowdStrike", "Mandiant", "Microsoft", "NOMMAGE"):
            self.assertNotIn(vendor_term, card)
        self.assertIn("Attack Flow", render_prompt_card("operational"))


class Evidence(unittest.TestCase):
    def test_quotes_tolerate_formatting_and_cuts(self):
        self.assertTrue(evidence_in_source("l'exploitation de la vulnérabilité critique CVE-2023-4966", SOURCE))
        self.assertTrue(evidence_in_source("a invoqué l'interpréteur natif [...] la technique ATT&CK T1059.001", SOURCE))
        self.assertFalse(evidence_in_source("Le groupe a certainement chiffré toutes les données du client", SOURCE))
        self.assertFalse(evidence_in_source("PsExec", SOURCE))  # trop courte pour être probante

    def test_sector_stems_match_the_words_articles_use(self):
        from backend.ontology.stix.validate import mentions

        self.assertTrue(mentions("victims in the financial, cryptocurrency and retail sectors", ["financial-services", "~financ"]))
        self.assertTrue(mentions("attacks against telecom operators", ["telecommunications", "~teleco"]))
        self.assertTrue(mentions("the finance team of the victim", ["~financ"]))  # « finance » commence bien par « financ »
        self.assertFalse(mentions("nothing relevant here", ["~financ"]))

    def test_mentions_use_whole_words(self):
        self.assertTrue(mentions("a exécuté PsExec.exe sur le contrôleur", ["PsExec"]))
        self.assertTrue(mentions("le cluster APT 29 a ciblé", ["APT29"]))
        self.assertFalse(mentions("psexecuted nothing", ["PsExec"]))
        self.assertFalse(mentions("le groupe apt290 a ciblé", ["APT29"]))


def _scenario() -> dict:
    ev = lambda s: s  # noqa: E731
    return {
        "entities": [
            {"ref": "e1", "type": "threat-actor", "name": "UNC3944"},
            {"ref": "e2", "type": "vulnerability", "name": "Citrix Bleed", "cve": "cve-2023-4966"},
            {"ref": "e3", "type": "malware", "name": "BlackCat"},
            {"ref": "e4", "type": "tool", "name": "PsExec", "labels": ["lolbin"]},
            {"ref": "e5", "type": "tool", "name": "powershell.exe"},
            {"ref": "e6", "type": "tool", "name": "rclone"},
            {"ref": "e7", "type": "attack-pattern", "name": "PowerShell Scripting", "attack_id": "T1059.001"},
            {"ref": "e8", "type": "attack-pattern", "name": "Impair Defenses", "attack_id": "T1562.001"},
            {"ref": "e9", "type": "threat-actor", "name": "Mandiant"},
            {"ref": "e10", "type": "threat-actor", "name": "Cobalt Strike"},
            {"ref": "e11", "type": "malware", "name": "malware"},
            {"ref": "e12", "type": "infrastructure", "name": "Storage Sync C2", "infrastructure_types": ["command-and-control", "inventé"]},
            {"ref": "e13", "type": "vulnerability", "name": "Citrix NetScaler Gateway"},
        ],
        "relationships": [
            {"source": "e1", "type": "exploits", "target": "e2", "evidence": ev("l'exploitation de la vulnérabilité critique CVE-2023-4966")},
            {"source": "e1", "type": "targets", "target": "e2", "evidence": ev("l'exploitation de la vulnérabilité critique CVE-2023-4966")},
            {"source": "e4", "type": "drops", "target": "e3", "evidence": ev("UNC3944 a déposé un binaire malveillant dédié nommé BlackCat_Locker.exe")},
            {"source": "e6", "type": "exfiltrates-to", "target": "e12", "evidence": ev("transférer les archives vers un bucket externe situé sur l'infrastructure C2 Storage Sync")},
            {"source": "e1", "type": "uses", "target": "e3", "evidence": ev("Le groupe a certainement chiffré toutes les données du client")},
            {"source": "e1", "type": "uses", "target": "e4", "evidence": ev("PsExec")},
            {"source": "e4", "type": "uses", "target": "e1", "evidence": ev("l'attaquant a exécuté l'utilitaire d'administration légitime PsExec.exe")},
            {"source": "e1", "type": "uses", "target": "e7", "evidence": ev("pour exécuter la technique ATT&CK T1059.001")},
            {"source": "e1", "type": "uses", "target": "e8", "evidence": ev("pour exécuter la technique ATT&CK T1059.001")},
            {"source": "e1", "type": "uses", "target": "e6", "evidence": ev("l'acteur a détourné l'outil de synchronisation cloud rclone.exe")},
            {"source": "e6", "type": "uses", "target": "e12", "evidence": ev("transférer les archives vers un bucket externe situé sur l'infrastructure C2 Storage Sync")},
            {"source": "e9", "type": "uses", "target": "e5", "evidence": ev("Mandiant a observé powershell.exe")},
            {"source": "e1", "type": "communicates-with", "target": "e3", "evidence": ev("UNC3944 a déposé un binaire malveillant dédié nommé BlackCat_Locker.exe")},
        ],
    }  # fmt: skip


class Sanitizer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.graph = sanitize_extraction(_scenario(), "operational", SOURCE, publisher_names=["Mandiant", "dfir-report"])
        cls.codes = [i.code for i in cls.graph.issues]
        cls.names = {e["id"]: e["name"] for e in cls.graph.entities}
        cls.triples = {(cls.names[r["source_ref"]], r["relationship_type"], cls.names[r["target_ref"]]) for r in cls.graph.relationships}

    def test_entity_resolution_and_type_correction(self):
        by_name = {e["name"]: e for e in self.graph.entities}
        actor = by_name["Scattered Spider"]  # UNC3944 résolu par ATT&CK
        self.assertEqual(actor["type"], "intrusion-set")
        self.assertIn("UNC3944", actor["aliases"])
        self.assertEqual(actor["external_references"][0], {"source_name": "mitre-attack", "external_id": "G1015"})
        self.assertIn("TYPE_CORRECTED", self.codes)  # ATT&CK range G1015 en intrusion-set : le type suit la donnée de référence
        self.assertIn("CANONICAL_NAME", self.codes)
        self.assertTrue(any("ATT&CK range G1015" in i.message for i in self.graph.issues))

    def test_publisher_generic_and_conflicting_entities_are_rejected(self):
        self.assertIn("PUBLISHER_AS_ADVERSARY", self.codes)
        self.assertIn("GENERIC_TERM", self.codes)
        self.assertNotIn("Mandiant", self.names.values())

    def test_attack_ids_are_corrected_from_the_reference(self):
        self.assertIn("ATTACK_ID_REPLACED", self.codes)
        self.assertIn("ATTACK_NAME_CORRECTED", self.codes)
        self.assertIn("PowerShell", self.names.values())

    def test_only_supported_relationships_survive(self):
        self.assertEqual(
            self.triples,
            {
                ("Scattered Spider", "targets", "CVE-2023-4966"),
                ("Scattered Spider", "uses", "PsExec"),  # écrite à l'envers par le modèle : sens corrigé
                ("Scattered Spider", "uses", "PowerShell"),
                ("Scattered Spider", "uses", "Rclone"),
            },
        )

    def test_each_rejection_has_the_right_reason(self):
        reasons = {i.subject.split(" ")[0] + "|" + i.code for i in self.graph.rejected()}
        # un acteur ne peut pas « exploiter » une CVE, seul un malware le peut
        self.assertIn("e1|INVALID_RELATIONSHIP", reasons)
        # un outil n'« exfiltre » pas : seul un malware exfiltre
        self.assertIn("e6|INVALID_RELATIONSHIP", reasons)
        self.assertIn("EVIDENCE_NOT_IN_SOURCE", self.codes)  # citation inventée
        self.assertIn("NO_EVIDENCE", self.codes)
        self.assertIn("DIRECTION_FIXED", self.codes)

    def test_evidence_must_talk_about_the_linked_entities(self):
        # la phrase citée dit que UNC3944 a déposé BlackCat, pas que PsExec l'a fait
        self.assertNotIn(("PsExec", "drops", "BlackCat"), self.triples)
        # la citation parle de T1059.001, pas de défense : la technique T1685 ne doit pas être liée
        self.assertNotIn("Disable or Modify Tools", {t[2] for t in self.triples})
        self.assertIn("EVIDENCE_NOT_ABOUT_ENTITIES", self.codes)

    def test_orphans_are_dropped_and_vocabularies_enforced(self):
        self.assertIn("ORPHAN", self.codes)
        self.assertNotIn("Storm", " ".join(self.names.values()))
        self.assertIn("VOCAB", self.codes)

    def test_confidence_and_evidence_are_kept_on_every_relationship(self):
        for r in self.graph.relationships:
            self.assertTrue(0 <= r["confidence"] <= 100)
            self.assertTrue(r["_evidence"][0]["quote"])

    def test_profile_limits_relations(self):
        raw = {
            "entities": [{"ref": "a", "type": "malware", "name": "QakBot"}, {"ref": "b", "type": "infrastructure", "name": "Storage Sync C2"}],
            "relationships": [{"source": "a", "type": "beacons-to", "target": "b", "evidence": "l'infrastructure C2 Storage Sync QakBot"}],
        }
        strategic = sanitize_extraction(raw, "strategic", None)
        self.assertIn("TYPE_NOT_IN_PROFILE", [i.code for i in strategic.issues])  # l'infrastructure n'est pas extraite en stratégique
        tactical = sanitize_extraction(raw, "tactical", "texte : l'infrastructure C2 Storage Sync QakBot fin")
        self.assertEqual(len(tactical.relationships), 1)

    def test_sanitizing_twice_gives_the_same_ids(self):
        again = sanitize_extraction(_scenario(), "operational", SOURCE, publisher_names=["Mandiant"])
        self.assertEqual({e["id"] for e in again.entities}, {e["id"] for e in self.graph.entities})
        self.assertEqual({r["id"] for r in again.relationships}, {r["id"] for r in self.graph.relationships})


class Locations(unittest.TestCase):
    def _sanitize(self, *names):
        source = " ".join(f"{n} est mentionné." for n in names) + " UNC3944 cible les victimes."
        raw = {"entities": [{"type": "location", "name": n} for n in names] + [{"type": "intrusion-set", "name": "UNC3944"}], "relationships": []}
        return sanitize_extraction(raw, "operational", source, keep_orphans=True)

    def test_country_and_region_names_are_resolved(self):
        graph = self._sanitize("Russia", "Russie", "Eastern Europe", "Middle East")  # noqa
        by_name = {e["name"]: e for e in graph.entities if e["type"] == "location"}
        self.assertEqual(by_name["Russia"]["country"], "RU")
        self.assertEqual(len([e for e in graph.entities if e["type"] == "location" and e.get("country") == "RU"]), 1)  # Russie et Russia fusionnent
        self.assertEqual(by_name["Eastern Europe"]["region"], "eastern-europe")
        self.assertEqual(by_name["Middle East"]["region"], "western-asia")

    def test_unknown_place_is_rejected_and_export_never_raises(self):
        graph = self._sanitize("Atlantis", "Kyiv Oblast")
        self.assertFalse([e for e in graph.entities if e["type"] == "location"])
        self.assertEqual([i.code for i in graph.issues].count("UNRESOLVED_LOCATION"), 2)
        report = {"source_id": 1, "title": "t", "url": "https://exemple.org/a", "site_name": "exemple", "published": "2026-08-24", "category": "operational"}
        json.loads(to_bundle(build_stix_objects(self._sanitize("Atlantis", "France"), report)))  # stix2 valide en mode strict

    def test_invalid_model_values_are_dropped(self):
        raw = {"entities": [{"type": "location", "name": "Germany", "country": "Deutschland!"}, {"type": "intrusion-set", "name": "UNC3944"}], "relationships": []}
        graph = sanitize_extraction(raw, "operational", "Germany UNC3944", keep_orphans=True)
        loc = next(e for e in graph.entities if e["type"] == "location")
        self.assertEqual(loc["country"], "DE")


class Export(unittest.TestCase):
    def test_bundle_is_valid_stix_with_provenance(self):
        graph = sanitize_extraction(_scenario(), "operational", SOURCE, publisher_names=["Mandiant"], keep_orphans=True)
        report = {"source_id": 597, "title": "Rapport de test", "url": "https://exemple.org/a", "site_name": "exemple", "published": "2026-08-24", "category": "operational"}
        objects = build_stix_objects(graph, report)
        bundle = json.loads(to_bundle(objects))  # stix2 valide chaque objet : lève une exception sinon
        ids = {o["id"] for o in bundle["objects"]}
        by_type = {}
        for o in bundle["objects"]:
            by_type.setdefault(o["type"], []).append(o)
        self.assertEqual(len(by_type["report"]), 1)
        rep = by_type["report"][0]
        self.assertTrue(set(rep["object_refs"]) <= ids)
        self.assertEqual(len(rep["object_refs"]), len(graph.entities) + len(graph.relationships))
        for rel in by_type["relationship"]:
            self.assertIn(rel["source_ref"], ids)
            self.assertIn(rel["target_ref"], ids)
            self.assertEqual(rel["external_references"][0]["url"], "https://exemple.org/a")
            self.assertTrue(rel["external_references"][0]["description"])  # la citation, en champ STIX standard
            self.assertTrue(rel["description"])
        # l'éditeur est l'auteur de l'information, pas un nœud de l'attaque
        publisher = next(o for o in by_type["identity"] if o["name"] == "exemple")
        self.assertTrue(all(o["created_by_ref"] == publisher["id"] for o in bundle["objects"] if o["type"] != "identity"))
        self.assertNotIn(publisher["id"], rep["object_refs"])
        self.assertTrue(by_type["malware"] and all(m["is_family"] is True for m in by_type["malware"]))

    def test_bundle_contains_no_custom_property(self):
        """Un bundle ne doit contenir que des propriétés STIX 2.1 : le mode strict de stix2 le garantit."""
        graph = sanitize_extraction(_scenario(), "operational", SOURCE, publisher_names=["Mandiant"], keep_orphans=True)
        objects = build_stix_objects(graph, {"source_id": 1, "title": "t", "url": "https://exemple.org/a", "site_name": "exemple", "category": "operational"})
        text = to_bundle(objects)  # lève une exception si une propriété hors norme est présente
        self.assertNotIn('"x_', text)
        self.assertNotIn('"_', text)
        techniques = [o for o in json.loads(text)["objects"] if o["type"] == "attack-pattern"]
        self.assertTrue(techniques and all(t["kill_chain_phases"][0]["kill_chain_name"] == "mitre-attack" for t in techniques))

    def test_publication_dates_in_every_format_of_the_database(self):
        from backend.ontology.stix.export import parse_date

        for raw in ("2020-08-03", "April 22, 2026", "Dec 17, 2025", "2026-08-24T10:11:12", "24 August 2026"):
            self.assertIsNotNone(parse_date(raw), raw)
        self.assertIsNone(parse_date("hier"))
        self.assertIsNone(parse_date(None))
        graph = sanitize_extraction(_scenario(), "operational", SOURCE, publisher_names=["Mandiant"], keep_orphans=True)
        for raw in ("April 22, 2026", "2020-08-03", "date inconnue", None):
            objects = build_stix_objects(graph, {"source_id": 1, "title": "t", "site_name": "s", "published": raw})
            to_bundle(objects)  # doit rester du STIX valide, quelle que soit la date fournie

    def test_stix2_rejects_what_the_ontology_would_reject(self):
        with self.assertRaises(Exception):
            stix2.parse({"type": "relationship", "spec_version": "2.1", "id": "relationship--" + "0" * 8 + "-0000-4000-8000-" + "0" * 12}, version="2.1")

    def test_neo4j_mapping(self):
        self.assertEqual(neo4j_label("threat-actor"), "ThreatActor")
        self.assertEqual(neo4j_label("ipv4-addr"), "IPv4Address")
        self.assertEqual(neo4j_relationship_type("attributed-to"), "ATTRIBUTED_TO")

    def test_turtle_schema(self):
        ttl = ontology_turtle()
        self.assertIn("cti:IntrusionSet a owl:Class", ttl)
        self.assertIn("cti:ATTRIBUTED_TO a owl:ObjectProperty", ttl)


if __name__ == "__main__":
    unittest.main()
