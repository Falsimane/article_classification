"""Persistance Neo4j des objets STIX 2.1 extraits.

Modèle de propriétés (objets créés par `stix2`, voir `backend/stix/`) :
- chaque objet STIX est un nœud `(:Stix:<Type>)` identifié par son `id` STIX déterministe, donc ré-extraire le même
  fait met à jour le même nœud : le graphe ne se fragmente pas d'un article à l'autre ;
- chaque relation STIX est une arête typée `(:Stix)-[:USES]->(:Stix)` portant `confidence`, `description` et une
  entrée de preuve par article ;
- l'article est un nœud `(:Stix:Report)` relié à ce qu'il a fourni par `OBJECT_REF` et à son éditeur par `CREATED_BY`.

Provenance : `article_ids` liste les articles qui ont établi un nœud ou une arête. Retirer un article
(`purge_article`) ne supprime que ce qu'aucun autre article n'étaye.
"""

import json
import re
from typing import Any

from backend.stix.iocs import HASH_PRIORITY, IOC_OBJECT_TYPES
from backend.stix.rules import RULE_KINDS

from .neo4j_store import Neo4jStore

_LABEL_OVERRIDES = {"ipv4-addr": "IPv4Address", "ipv6-addr": "IPv6Address", "url": "URL", "x509-certificate": "X509Certificate"}


def neo4j_label(stix_type: str) -> str:
    """Étiquette de nœud : `threat-actor` -> `ThreatActor`."""
    return _LABEL_OVERRIDES.get(stix_type) or "".join(part.capitalize() for part in stix_type.split("-"))


def neo4j_relationship_type(relationship_type: str) -> str:
    """Type de relation Neo4j : `attributed-to` -> `ATTRIBUTED_TO`."""
    return relationship_type.upper().replace("-", "_")


def to_neo4j_properties(obj: dict) -> dict:
    """Propriétés plates d'un objet STIX (forme JSON) : Neo4j n'accepte pas de structures imbriquées, elles sont sérialisées en JSON."""
    flat: dict = {}
    for key, value in obj.items():
        if key in ("source_ref", "target_ref", "type"):
            continue
        if isinstance(value, dict) or (isinstance(value, list) and any(isinstance(v, (dict, list)) for v in value)):
            flat[f"{key}_json"] = json.dumps(value, ensure_ascii=False, sort_keys=True)
        else:
            flat[key] = value
    if obj.get("type") == "file" and isinstance(obj.get("hashes"), dict) and obj["hashes"]:
        algo = next((a for a in HASH_PRIORITY if a in obj["hashes"]), next(iter(obj["hashes"])))
        flat["value"], flat["hash_algo"] = obj["hashes"][algo], algo  # lisible dans une requête sans décoder `hashes_json`
    return flat


_SAFE = re.compile(r"^[A-Za-z0-9_]+$")
_LIST_KEYS = ("aliases", "labels", "sectors")


# Nœuds d'IOC : observables, indicateurs réseau/fichier (pattern STIX) et observations. Ils ne font pas partie du graphe d'entités
# d'un rapport (des centaines par article l'étoufferaient) : ils ont leur propre tableau.
_IOC_TYPES = repr(sorted(IOC_OBJECT_TYPES - {"indicator"}))
# Indicateurs hors du graphe : IOC (pattern STIX, tableau des indicateurs) et règles de détection (onglet Détection)
_PATTERN_TYPES = repr(["stix", *RULE_KINDS])


def _is_ioc(var: str) -> str:
    """Vrai pour ce qui n'est PAS une entité du graphe d'un rapport : IOC (leur tableau), règles YARA et Sigma (onglet
    Détection)."""
    return f"({var}.type IN {_IOC_TYPES} OR ({var}.type = 'indicator' AND {var}.pattern_type IN {_PATTERN_TYPES}))"


def _safe(identifier: str) -> str:
    if not _SAFE.match(identifier):
        raise ValueError(f"identifiant Cypher refusé : {identifier!r}")
    return identifier


class StixStore:
    def __init__(self, store: Neo4jStore | None = None):
        self._store = store or Neo4jStore.get_instance()

    @property
    def driver(self):
        return self._store.driver

    def init_schema(self) -> None:
        with self.driver.session() as session:
            session.run("CREATE CONSTRAINT stix_id_unique IF NOT EXISTS FOR (n:Stix) REQUIRE n.id IS UNIQUE")
            session.run("CREATE INDEX stix_type_idx IF NOT EXISTS FOR (n:Stix) ON (n.type)")
            session.run("CREATE INDEX stix_name_idx IF NOT EXISTS FOR (n:Stix) ON (n.name)")

    # --- écriture ---------------------------------------------------------------------------------------------------
    def save_article(self, objects: list[dict], article_id: int, meta: dict[str, Any] | None = None) -> dict[str, int]:
        """Enregistre les objets d'un article (forme JSON des objets `stix2` d'un article) : [identity éditeur, report, entités…,
        relations…]. Retourne les effectifs écrits. Idempotent : un article déjà présent perd d'abord son ancienne contribution,
        dans la même transaction (sans balayer le graphe pour un article nouveau)."""
        nodes = [o for o in objects if o["type"] != "relationship"]
        edges = [o for o in objects if o["type"] == "relationship"]
        report = next(o for o in nodes if o["type"] == "report")
        publisher_id = report["created_by_ref"]
        meta = meta or {}
        with self.driver.session() as session:
            session.execute_write(self._replace, nodes, edges, article_id, report, publisher_id, meta)
        return {"nodes": len(nodes), "edges": len(edges)}

    def _replace(self, tx, nodes: list[dict], edges: list[dict], article_id: int, report: dict, publisher_id: str, meta: dict) -> None:
        if tx.run("MATCH (r:Stix:Report {source_id: $a}) RETURN count(r) > 0 AS seen", a=article_id).single()["seen"]:
            self._purge(tx, article_id)
        self._write(tx, nodes, edges, article_id, report, publisher_id, meta)

    @staticmethod
    def _merge_lists(existing: dict | None, incoming: dict, keys=_LIST_KEYS) -> dict:
        merged = dict(incoming)
        for key in keys:
            values = list((existing or {}).get(key) or []) + list(incoming.get(key) or [])
            if values:
                merged[key] = list(dict.fromkeys(values))
        return merged

    def _write(self, tx, nodes: list[dict], edges: list[dict], article_id: int, report: dict, publisher_id: str, meta: dict) -> None:
        ids = [n["id"] for n in nodes]
        existing = {
            r["id"]: r["props"]
            for r in tx.run("MATCH (n:Stix) WHERE n.id IN $ids RETURN n.id AS id, properties(n) AS props", ids=ids)
        }
        by_label: dict[str, list[dict]] = {}
        for node in nodes:
            props = self._merge_lists(existing.get(node["id"]), to_neo4j_properties(node))
            articles = list(dict.fromkeys(list((existing.get(node["id"]) or {}).get("article_ids") or []) + [article_id]))
            props["article_ids"] = articles
            props["type"] = node["type"]
            old_from = (existing.get(node["id"]) or {}).get("valid_from")
            if node["type"] == "indicator" and old_from and old_from < props.get("valid_from", "9"):
                props["valid_from"] = old_from  # la première observation reste la première
            if node["type"] == "report":
                props.update({"source_id": article_id, **{k: v for k, v in meta.items() if v is not None}})
            by_label.setdefault(_safe(neo4j_label(node["type"])), []).append({"id": node["id"], "props": props})
        for label, rows in by_label.items():
            tx.run(f"UNWIND $rows AS r MERGE (n:Stix {{id: r.id}}) SET n:{label} SET n += r.props", rows=rows)

        sightings = [{"sid": n["id"], "iid": n["sighting_of_ref"], "pid": publisher_id} for n in nodes if n["type"] == "sighting"]
        if sightings:
            tx.run("UNWIND $rows AS r MATCH (s:Stix {id: r.sid}), (i:Stix {id: r.iid}) MERGE (s)-[:SIGHTING_OF]->(i)", rows=sightings)
            tx.run("UNWIND $rows AS r MATCH (s:Stix {id: r.sid}), (p:Stix {id: r.pid}) MERGE (s)-[:SIGHTED_AT]->(p)", rows=sightings)

        # Rattachement de l'article : ce qu'il a fourni et son éditeur
        provided = [n["id"] for n in nodes if n["type"] not in ("report", "identity") or n["id"] != publisher_id]
        tx.run(
            "MATCH (rep:Stix {id: $rid}) UNWIND $ids AS oid MATCH (o:Stix {id: oid}) "
            "WHERE o.id <> rep.id AND o.id <> $pid MERGE (rep)-[:OBJECT_REF]->(o)",
            rid=report["id"], ids=provided, pid=publisher_id,
        )
        tx.run("MATCH (rep:Stix {id: $rid}), (p:Stix {id: $pid}) MERGE (rep)-[:CREATED_BY]->(p)", rid=report["id"], pid=publisher_id)

        by_type: dict[str, list[dict]] = {}
        for edge in edges:
            props = to_neo4j_properties({k: v for k, v in edge.items() if k not in ("created_by_ref", "object_marking_refs")})
            props.pop("relationship_type", None)
            props.pop("external_references_json", None)  # les preuves sont portées par `evidence`
            evidence = [json.dumps({"article": article_id, "quote": ref.get("description", "")}, ensure_ascii=False) for ref in edge.get("external_references", [])]
            by_type.setdefault(_safe(neo4j_relationship_type(edge["relationship_type"])), []).append(
                {"id": edge["id"], "src": edge["source_ref"], "dst": edge["target_ref"], "props": props, "evidence": evidence, "article": article_id}
            )
        for rel_type, rows in by_type.items():
            tx.run(
                f"UNWIND $rows AS r MATCH (a:Stix {{id: r.src}}), (b:Stix {{id: r.dst}}) "
                f"MERGE (a)-[x:{rel_type} {{id: r.id}}]->(b) "
                f"SET x += r.props "
                f"SET x.article_ids = CASE WHEN r.article IN coalesce(x.article_ids, []) THEN x.article_ids ELSE coalesce(x.article_ids, []) + r.article END "
                f"SET x.evidence = reduce(acc = [], e IN coalesce(x.evidence, []) + r.evidence | CASE WHEN e IN acc THEN acc ELSE acc + e END)",
                rows=rows,
            )

    def purge_article(self, article_id: int) -> dict[str, int]:
        """Retire la contribution d'un article. Un nœud ou une arête étayé par d'autres articles est conservé."""
        with self.driver.session() as session:
            return session.execute_write(self._purge, article_id)

    @staticmethod
    def _purge(tx, article_id: int) -> dict[str, int]:
        prefix = f'{{"article": {article_id},'  # les preuves sont des JSON `{"article": <id>, "quote": …}`
        rels = tx.run(
            "MATCH ()-[x]->() WHERE x.article_ids IS NOT NULL AND $a IN x.article_ids "
            "SET x.article_ids = [i IN x.article_ids WHERE i <> $a], "
            "    x.evidence = [e IN coalesce(x.evidence, []) WHERE NOT e STARTS WITH $prefix] "
            "WITH x WHERE size(x.article_ids) = 0 DELETE x RETURN count(*) AS n",
            a=article_id, prefix=prefix,
        ).single()["n"]
        nodes = tx.run(
            "MATCH (n:Stix) WHERE n.article_ids IS NOT NULL AND $a IN n.article_ids "
            "SET n.article_ids = [i IN n.article_ids WHERE i <> $a] "
            "WITH n WHERE size(n.article_ids) = 0 DETACH DELETE n RETURN count(*) AS n",
            a=article_id,
        ).single()["n"]
        return {"edges_deleted": rels, "nodes_deleted": nodes}

    # --- lecture ----------------------------------------------------------------------------------------------------
    def extracted_article_ids(self) -> set[int]:
        """Articles extraits en entier : un article dont une étape LLM a échoué (`llm_failures` > 0) sera repris."""
        query = "MATCH (r:Stix:Report) WHERE r.source_id IS NOT NULL AND coalesce(r.llm_failures, 0) = 0 RETURN r.source_id AS id"
        with self.driver.session() as session:
            return {r["id"] for r in session.run(query)}

    def stats(self) -> dict[str, Any]:
        with self.driver.session() as session:
            nodes = {r["type"]: r["n"] for r in session.run("MATCH (n:Stix) RETURN n.type AS type, count(*) AS n ORDER BY n DESC")}
            edges = {r["type"]: r["n"] for r in session.run("MATCH (:Stix)-[x]->(:Stix) WHERE x.id IS NOT NULL RETURN type(x) AS type, count(*) AS n ORDER BY n DESC")}
            articles = session.run("MATCH (r:Stix:Report) RETURN count(r) AS n").single()["n"]
        return {"nodes": nodes, "edges": edges, "articles": articles}

    # --- lecture pour le tableau de bord ---------------------------------------------------------------------------
    def reports(self) -> list[dict]:
        """Articles extraits : un enregistrement par rapport STIX, avec ses effectifs, du plus récent au plus ancien."""
        query = f"""
            MATCH (r:Stix:Report) WHERE r.source_id IS NOT NULL
            OPTIONAL MATCH (r)-[:OBJECT_REF]->(o:Stix) WHERE NOT {_is_ioc("o")}
            WITH r, collect(o) AS objs
            OPTIONAL MATCH (a:Stix)-[x]->(b:Stix) WHERE x.id IS NOT NULL AND r.source_id IN x.article_ids AND NOT {_is_ioc("a")} AND NOT {_is_ioc("b")}
            RETURN r.source_id AS id, r.title AS title, r.url AS url, r.site_name AS site_name, r.published AS published,
                   r.category AS category, r.model AS model, r.extraction_seconds AS duration, r.extracted_at AS extracted_at,
                   size(objs) AS entities_count, count(x) AS relations_count
            ORDER BY r.extracted_at DESC, r.source_id ASC
        """
        with self.driver.session() as session:
            return [dict(r) for r in session.run(query)]

    def dashboard_graph(self, article_id: int) -> dict[str, list[dict]]:
        """Nœuds et arêtes d'un article AVEC identifiants, sans l'article lui-même ni son éditeur (ils portent la
        provenance, ils ne font pas partie de l'attaque décrite)."""
        node_query = f"""
            MATCH (r:Stix:Report {{source_id: $a}})-[:OBJECT_REF]->(n:Stix) WHERE NOT {_is_ioc("n")}
            RETURN properties(n) AS p
        """
        edge_query = f"""
            MATCH (a:Stix)-[x]->(b:Stix) WHERE x.id IS NOT NULL AND $a IN x.article_ids AND NOT {_is_ioc("a")} AND NOT {_is_ioc("b")}
            RETURN a.id AS source, b.id AS target, type(x) AS type, properties(x) AS p
        """
        with self.driver.session() as session:
            nodes = [dict(r["p"]) for r in session.run(node_query, a=article_id)]
            edges = [{"source": r["source"], "target": r["target"], "type": r["type"], **dict(r["p"])} for r in session.run(edge_query, a=article_id)]
        return {"nodes": nodes, "edges": edges}

    def totals(self) -> dict[str, Any]:
        """Effectifs globaux pour les compteurs du tableau de bord (hors rapports et éditeurs)."""
        with self.driver.session() as session:
            nodes = {
                r["type"]: r["n"]
                for r in session.run(
                    f"MATCH (r:Stix:Report)-[:OBJECT_REF]->(n:Stix) WHERE NOT {_is_ioc('n')} RETURN n.type AS type, count(DISTINCT n) AS n ORDER BY n DESC"
                )
            }
            edges = {
                r["type"]: r["n"]
                for r in session.run(
                    f"MATCH (a:Stix)-[x]->(b:Stix) WHERE x.id IS NOT NULL AND NOT {_is_ioc('a')} AND NOT {_is_ioc('b')} RETURN type(x) AS type, count(*) AS n ORDER BY n DESC"
                )
            }
            reports = session.run("MATCH (r:Stix:Report) WHERE r.source_id IS NOT NULL RETURN count(r) AS n").single()["n"]
            lolbins = session.run("MATCH (n:Stix:Tool) WHERE 'living-off-the-land' IN coalesce(n.labels, []) RETURN count(n) AS n").single()["n"]
            iocs = session.run("MATCH (i:Stix:Indicator {pattern_type: 'stix'}) RETURN count(i) AS n").single()["n"]
        return {"nodes": nodes, "edges": edges, "reports": reports, "lolbins": lolbins, "iocs": iocs}

    def actors(self) -> list[dict]:
        """Acteurs, ensembles d'intrusion et campagnes de tous les articles, du plus relié au moins relié."""
        query = """
            MATCH (a:Stix) WHERE a.type IN ['threat-actor', 'intrusion-set', 'campaign']
            OPTIONAL MATCH (a)-[x]-(:Stix) WHERE x.id IS NOT NULL
            WITH a, count(DISTINCT x) AS relations
            OPTIONAL MATCH (r:Stix:Report)-[:OBJECT_REF]->(a)
            RETURN properties(a) AS p, relations, count(DISTINCT r) AS reports
            ORDER BY relations DESC, p.name ASC
        """
        with self.driver.session() as session:
            return [{**dict(r["p"]), "relations": r["relations"], "reports": r["reports"]} for r in session.run(query)]

    def actor_subgraph(self, actor_id: str) -> dict[str, Any] | None:
        """L'acteur, ses voisins directs, les arêtes qui les relient à lui (tous articles confondus) et ses rapports."""
        with self.driver.session() as session:
            head = session.run("MATCH (a:Stix {id: $id}) RETURN properties(a) AS p", id=actor_id).single()
            if head is None:
                return None
            rels = session.run(
                "MATCH (a:Stix {id: $id})-[x]-(n:Stix) WHERE x.id IS NOT NULL "
                "RETURN startNode(x).id AS source, endNode(x).id AS target, type(x) AS type, properties(x) AS p, properties(n) AS n",
                id=actor_id,
            )
            edges, nodes = [], {}
            for r in rels:
                edges.append({"source": r["source"], "target": r["target"], "type": r["type"], **dict(r["p"])})
                nodes[r["n"]["id"]] = dict(r["n"])
            reports = [
                dict(r)
                for r in session.run(
                    "MATCH (r:Stix:Report)-[:OBJECT_REF]->(a:Stix {id: $id}) "
                    "RETURN r.source_id AS id, r.title AS title, r.url AS url, r.site_name AS site_name, r.category AS category, r.published AS published "
                    "ORDER BY r.published DESC",
                    id=actor_id,
                )
            ]
        return {"actor": dict(head["p"]), "nodes": list(nodes.values()), "edges": edges, "reports": reports}

    # --- IOC ------------------------------------------------------------------------------------------------------
    _IOC_QUERY = """
        MATCH (i:Stix:Indicator {pattern_type: 'stix'})-[:BASED_ON]->(o:Stix)
        WHERE %s
        OPTIONAL MATCH (s:Stix:Sighting)-[:SIGHTING_OF]->(i)
        OPTIONAL MATCH (i)-[:INDICATES]->(t:Stix)
        WITH i, o, collect(DISTINCT {article: head(s.article_ids), first: s.first_seen, last: s.last_seen, quote: s.description}) AS sightings,
             collect(DISTINCT {id: t.id, name: t.name, type: t.type}) AS targets
        RETURN properties(i) AS indicator, properties(o) AS observable, sightings, targets
        ORDER BY o.type, o.value
    """

    def _ioc_rows(self, where: str, **params: Any) -> list[dict]:
        with self.driver.session() as session:
            return [dict(r) for r in session.run(self._IOC_QUERY % where, **params)]

    def article_iocs(self, article_id: int) -> list[dict]:
        """IOC cités par un article. `sightings` couvre TOUS les articles : première et dernière observation sont globales."""
        return self._ioc_rows("$a IN i.article_ids", a=article_id)

    def article_ioc_counts(self, article_id: int) -> dict[str, int]:
        """Nombre d'observables par infrastructure de l'article (pastille du graphe)."""
        with self.driver.session() as session:
            return {
                r["id"]: r["n"]
                for r in session.run(
                    "MATCH (r:Stix:Report {source_id: $a})-[:OBJECT_REF]->(f:Stix:Infrastructure)-[:CONSISTS_OF]->(o:Stix) "
                    "WHERE $a IN o.article_ids RETURN f.id AS id, count(DISTINCT o) AS n", a=article_id,
                )
            }

    # --- Règles de détection ----------------------------------------------------------------------------------------
    def article_rules(self, article_id: int) -> list[dict]:
        """Règles YARA et Sigma citées par un article, et l'entité que chacune détecte selon CET article."""
        query = """
            MATCH (:Stix:Report {source_id: $a})-[:OBJECT_REF]->(i:Stix:Indicator) WHERE i.pattern_type IN ['yara', 'sigma']
            OPTIONAL MATCH (i)-[x:INDICATES]->(t:Stix) WHERE $a IN x.article_ids
            WITH i, collect(DISTINCT {id: t.id, name: t.name, type: t.type}) AS targets
            RETURN properties(i) AS rule, targets
            ORDER BY i.pattern_type, toLower(i.name)
        """
        with self.driver.session() as session:
            return [dict(r) for r in session.run(query, a=article_id)]

    def actor_iocs(self, actor_id: str) -> list[dict]:
        """IOC de l'acteur : ceux dont l'indicateur désigne une infrastructure, un malware ou un outil qu'il utilise, directement,
        par l'intermédiaire d'un malware, ou dans une intrusion qui lui est attribuée."""
        with self.driver.session() as session:
            carriers = {
                r["id"]
                for r in session.run(
                    """
                    MATCH (a:Stix {id: $id})
                    OPTIONAL MATCH (a)-[:USES]->(d:Stix)
                    OPTIONAL MATCH (a)-[:USES]->(:Stix)-[:USES]->(d2:Stix:Infrastructure)
                    OPTIONAL MATCH (inc:Stix:Incident)-[:ATTRIBUTED_TO]->(a)
                    OPTIONAL MATCH (inc)-[:USES]->(d3:Stix)
                    UNWIND [x IN [d, d2, d3] WHERE x IS NOT NULL] AS c
                    RETURN DISTINCT c.id AS id
                    """,
                    id=actor_id,
                )
            }
        if not carriers:
            return []
        return self._ioc_rows("EXISTS { MATCH (i)-[:INDICATES]->(c:Stix) WHERE c.id IN $carriers }", carriers=sorted(carriers))
