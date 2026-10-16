"""
Module de persistance Neo4j pour le Cyber Threat Intelligence (CTI) Knowledge Graph.
Remplace le stockage statique SQLite par un Property Graph dynamique et interconnecté,
compatible avec l'ontologie CTI V2, Neosemantics (n10s) et APOC.
"""

from datetime import datetime
import os
from pathlib import Path
import re
import sqlite3
from typing import Any, Dict, List, Optional, Set, Tuple

from neo4j import GraphDatabase, Driver, Session
from rich.console import Console

try:
    from backend.ontology import (
        normalize_entity_type,
        normalize_predicate,
        clean_uri_fragment,
        SNAKE_TO_PREFIXED_TYPE,
        TYPE_TO_ID_PREFIX,
    )
except ImportError:
    from ontology import (
        normalize_entity_type,
        normalize_predicate,
        clean_uri_fragment,
        SNAKE_TO_PREFIXED_TYPE,
        TYPE_TO_ID_PREFIX,
    )

console = Console()

DEFAULT_NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
DEFAULT_NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
DEFAULT_NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password123")


def to_pascal_case(snake_str: str) -> str:
    """Convertit snake_case en PascalCase pour les labels de nœuds Neo4j."""
    if not snake_str:
        return "Unknown"
    return "".join(part.capitalize() for part in snake_str.split("_"))


def sanitize_relationship_type(rel_type: str) -> str:
    """Normalise le type de relation en MAJUSCULES_CYPHER."""
    if not rel_type:
        return "RELATED_TO"
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", rel_type.strip()).upper()
    return cleaned if cleaned else "RELATED_TO"


class Neo4jStore:
    """Gestionnaire de connexion et de transactions pour le CTI Knowledge Graph dans Neo4j."""

    _instance: Optional["Neo4jStore"] = None

    def __init__(
        self,
        uri: str = DEFAULT_NEO4J_URI,
        user: str = DEFAULT_NEO4J_USER,
        password: str = DEFAULT_NEO4J_PASSWORD,
    ) -> None:
        self.uri = uri
        self.user = user
        self.password = password
        self._driver: Optional[Driver] = None

    @classmethod
    def get_instance(cls) -> "Neo4jStore":
        """Singleton d'accès au store Neo4j."""
        if cls._instance is None:
            cls._instance = Neo4jStore()
        return cls._instance

    @property
    def driver(self) -> Driver:
        """Initialise ou retourne le driver Neo4j thread-safe."""
        if self._driver is None:
            self._driver = GraphDatabase.driver(
                self.uri,
                auth=(self.user, self.password),
                max_connection_lifetime=3600,
                max_connection_pool_size=50,
                connection_acquisition_timeout=30.0,
            )
        return self._driver

    def close(self) -> None:
        """Ferme les connexions du driver."""
        if self._driver is not None:
            self._driver.close()
            self._driver = None

    def check_connection(self) -> Tuple[bool, Optional[str]]:
        """Vérifie la disponibilité du conteneur et du serveur Neo4j."""
        try:
            with self.driver.session() as session:
                result = session.run("RETURN 1 AS ping").single()
                if result and result["ping"] == 1:
                    return True, None
                return False, "Réponse inattendue de Neo4j"
        except Exception as e:
            return False, str(e)

    def init_schema(self) -> None:
        """Initialise les contraintes d'unicité et les index pour accélérer le Knowledge Graph."""
        queries = [
            # Unicité des entités par nom
            "CREATE CONSTRAINT entity_name_unique IF NOT EXISTS FOR (e:Entity) REQUIRE e.name IS UNIQUE;",
            # Index sur le type d'entité ontologique
            "CREATE INDEX entity_type_idx IF NOT EXISTS FOR (e:Entity) ON (e.entity_type);",
            # Unicité de l'article source
            "CREATE CONSTRAINT article_id_unique IF NOT EXISTS FOR (a:Article) REQUIRE a.id IS UNIQUE;",
        ]
        with self.driver.session() as session:
            for q in queries:
                session.run(q)

    def save_extraction(
        self,
        knowledge_id: int,
        entities: List[Dict[str, Any]],
        relations: List[Dict[str, Any]],
        duration: float,
        model_version: str,
        status: str = "success",
        error_message: Optional[str] = None,
        title: Optional[str] = None,
    ) -> None:
        """
        Persiste atomiquement les entités, relations, postures et transitions d'Attack Graph
        extraites d'un article dans Neo4j.
        """
        prepared_entities = []
        for ent in entities:
            etype = ent.get("type", "software_system")
            snake_type = normalize_entity_type(etype)
            eid = ent.get("id") or f"{TYPE_TO_ID_PREFIX.get(snake_type, 'entity')}:{clean_uri_fragment(ent.get('name', ''))}"
            prepared_entities.append({
                "id": eid,
                "name": ent["name"],
                "type": SNAKE_TO_PREFIXED_TYPE.get(snake_type, f"cti:{snake_type}"),
                "label": to_pascal_case(snake_type),
                "is_dual_use": bool(ent.get("is_dual_use", False)),
                "cpe": ent.get("cpe23Uri") or ent.get("cpe", "") or "",
                "cpe23Uri": ent.get("cpe23Uri") or ent.get("cpe", "") or "",
                "cveId": ent.get("cveId", "") or "",
                "mitreId": ent.get("mitreId", "") or "",
                "requiresPrecondition": ent.get("requiresPrecondition", "") or "",
                "yieldsPostcondition": ent.get("yieldsPostcondition", "") or "",
                "confidenceScore": int(ent.get("confidenceScore") or ent.get("confidence") or 85),
                "description": ent.get("description", "") or "",
            })

        prepared_relations = []
        for rel in relations:
            s_ref = str(rel.get("subject") or rel.get("source_name", "")).strip()
            t_ref = str(rel.get("object") or rel.get("target_name", "")).strip()
            raw_rtype = rel.get("predicate") or rel.get("relation_type", "RELATED_TO")
            norm_pred = normalize_predicate(raw_rtype)
            full_pred = f"ag:{norm_pred}" if norm_pred == "leads_to_step" else f"cti:{norm_pred}"

            qual = rel.get("qualification", {}) or {}
            src_posture = qual.get("source_posture") or rel.get("source_posture", "")
            tgt_posture = qual.get("target_posture") or rel.get("target_posture", "")
            mod = qual.get("modality") or rel.get("modality", "cti:ObservedInIncident")

            prepared_relations.append({
                "source_ref": s_ref,
                "target_ref": t_ref,
                "source_name": rel.get("source_name", s_ref),
                "target_name": rel.get("target_name", t_ref),
                "source_type": rel.get("source_type", ""),
                "target_type": rel.get("target_type", ""),
                "source_posture": src_posture or "",
                "target_posture": tgt_posture or "",
                "predicate": full_pred,
                "cypher_type": sanitize_relationship_type(norm_pred),
                "kill_chain_phase": rel.get("kill_chain_phase", "execution"),
                "modality": mod,
                "confidence": int(rel.get("confidence", 85)),
                "precondition_state": rel.get("precondition_state", "") or "",
                "postcondition_state": rel.get("postcondition_state", "") or "",
                "evidence": rel.get("evidence", "") or "",
            })

        with self.driver.session() as session:
            session.execute_write(
                self._save_extraction_tx,
                knowledge_id=knowledge_id,
                title=title or f"Article #{knowledge_id}",
                incident_id=f"INC-ARTICLE-{knowledge_id}",
                entities=prepared_entities,
                relations=prepared_relations,
                duration=duration,
                model_version=model_version,
                status=status,
                error_message=error_message or "",
            )

    @staticmethod
    def _save_extraction_tx(
        tx,
        knowledge_id: int,
        title: str,
        incident_id: str,
        entities: List[Dict[str, Any]],
        relations: List[Dict[str, Any]],
        duration: float,
        model_version: str,
        status: str,
        error_message: str,
    ) -> None:
        # 1. Création / Mise à jour du nœud Article
        tx.run(
            """
            MERGE (a:Article {id: $kid})
            SET a.title = $title,
                a.incident_id = $incident_id,
                a.status = $status,
                a.duration = $duration,
                a.model_version = $model_version,
                a.entities_count = $ent_count,
                a.relations_count = $rel_count,
                a.extracted_at = datetime(),
                a.error_message = $error_message
            """,
            kid=knowledge_id,
            title=title,
            incident_id=incident_id,
            status=status,
            duration=duration,
            model_version=model_version,
            ent_count=len(entities),
            rel_count=len(relations),
            error_message=error_message,
        )

        # 2. Nettoyage des anciennes relations pour cet article (idempotence en cas de re-run)
        tx.run(
            """
            MATCH (a:Article {id: $kid})-[r:MENTIONS]->() DELETE r;
            """,
            kid=knowledge_id,
        )
        tx.run(
            """
            MATCH ()-[r]->() WHERE r.knowledge_id = $kid AND type(r) <> 'MENTIONS' DELETE r;
            """,
            kid=knowledge_id,
        )

        # 3. Insertion / Mise à jour des Nœuds Entités
        if entities:
            tx.run(
                """
                UNWIND $entities AS ent
                MERGE (e:Entity {name: ent.name})
                ON CREATE SET
                    e.id = ent.id,
                    e.entity_type = ent.type,
                    e.is_dual_use = ent.is_dual_use,
                    e.cpe = ent.cpe,
                    e.cpe23Uri = ent.cpe23Uri,
                    e.cveId = ent.cveId,
                    e.mitreId = ent.mitreId,
                    e.requiresPrecondition = ent.requiresPrecondition,
                    e.yieldsPostcondition = ent.yieldsPostcondition,
                    e.confidenceScore = ent.confidenceScore,
                    e.description = ent.description,
                    e.created_at = datetime()
                ON MATCH SET
                    e.id = CASE WHEN ent.id <> '' THEN ent.id ELSE e.id END,
                    e.is_dual_use = CASE WHEN ent.is_dual_use THEN true ELSE e.is_dual_use END,
                    e.cpe = CASE WHEN ent.cpe <> '' THEN ent.cpe ELSE e.cpe END,
                    e.cpe23Uri = CASE WHEN ent.cpe23Uri <> '' THEN ent.cpe23Uri ELSE e.cpe23Uri END,
                    e.cveId = CASE WHEN ent.cveId <> '' THEN ent.cveId ELSE e.cveId END,
                    e.mitreId = CASE WHEN ent.mitreId <> '' THEN ent.mitreId ELSE e.mitreId END,
                    e.requiresPrecondition = CASE WHEN ent.requiresPrecondition <> '' THEN ent.requiresPrecondition ELSE e.requiresPrecondition END,
                    e.yieldsPostcondition = CASE WHEN ent.yieldsPostcondition <> '' THEN ent.yieldsPostcondition ELSE e.yieldsPostcondition END,
                    e.confidenceScore = ent.confidenceScore,
                    e.description = CASE WHEN size(ent.description) > size(coalesce(e.description, ''))
                                         THEN ent.description ELSE e.description END
                WITH e, ent
                CALL apoc.create.addLabels(e, [ent.label]) YIELD node
                RETURN count(*);
                """,
                entities=entities,
            )

            # Liaison Article -> Entité (Provenance & Traçabilité)
            tx.run(
                """
                MATCH (a:Article {id: $kid})
                UNWIND $entities AS ent
                MATCH (e:Entity {name: ent.name})
                MERGE (a)-[:MENTIONS]->(e);
                """,
                kid=knowledge_id,
                entities=entities,
            )

        # 4. Insertion des Relations CTI & Transitions d'Attack Graph via APOC
        if relations:
            tx.run(
                """
                UNWIND $relations AS rel
                MATCH (s:Entity) WHERE s.id = rel.source_ref OR s.name = rel.source_ref OR s.name = rel.source_name
                MATCH (t:Entity) WHERE t.id = rel.target_ref OR t.name = rel.target_ref OR t.name = rel.target_name
                CALL apoc.merge.relationship(
                    s,
                    rel.cypher_type,
                    {knowledge_id: $kid},
                    {
                        predicate: rel.predicate,
                        kill_chain_phase: rel.kill_chain_phase,
                        modality: rel.modality,
                        confidence: rel.confidence,
                        source_type: rel.source_type,
                        source_posture: rel.source_posture,
                        target_type: rel.target_type,
                        target_posture: rel.target_posture,
                        precondition_state: rel.precondition_state,
                        postcondition_state: rel.postcondition_state,
                        evidence: rel.evidence
                    },
                    t
                ) YIELD rel AS created_rel
                RETURN count(*);
                """,
                kid=knowledge_id,
                relations=relations,
            )

    def get_incident_graph(self, knowledge_id: int) -> Dict[str, Any]:
        """
        Reconstruit le Knowledge Graph de l'article au format exact JSON CTI demandé :
        { graph_metadata: {...}, entities: [...], relationships: [...] }
        """
        with self.driver.session() as session:
            art_res = session.run("MATCH (a:Article {id: $kid}) RETURN a.title AS title, a.incident_id AS inc_id;", kid=knowledge_id).single()
            inc_id = (art_res["inc_id"] if art_res and art_res.get("inc_id") else None) or f"INC-ARTICLE-{knowledge_id}"

            ent_res = session.run("""
                MATCH (a:Article {id: $kid})-[:MENTIONS]->(e:Entity)
                RETURN DISTINCT e.id AS id,
                                e.name AS name,
                                e.entity_type AS type,
                                coalesce(e.cpe23Uri, e.cpe, '') AS cpe23Uri,
                                coalesce(e.cveId, '') AS cveId,
                                coalesce(e.mitreId, '') AS mitreId,
                                coalesce(e.requiresPrecondition, '') AS requiresPrecondition,
                                coalesce(e.yieldsPostcondition, '') AS yieldsPostcondition,
                                coalesce(e.confidenceScore, 85) AS confidenceScore;
            """, kid=knowledge_id)

            entities = []
            for r in ent_res:
                eid = r["id"] or f"entity:{clean_uri_fragment(r['name'])}"
                etype = r["type"] or "cti:SoftwareSystem"
                if not etype.startswith("cti:"):
                    snake = normalize_entity_type(etype)
                    etype = SNAKE_TO_PREFIXED_TYPE.get(snake, f"cti:{to_pascal_case(snake)}")

                ent_dict: Dict[str, Any] = {
                    "id": eid,
                    "type": etype,
                    "name": r["name"],
                }
                if r["confidenceScore"]:
                    ent_dict["confidenceScore"] = int(r["confidenceScore"])
                if r["cpe23Uri"]:
                    ent_dict["cpe23Uri"] = r["cpe23Uri"]
                if r["cveId"]:
                    ent_dict["cveId"] = r["cveId"]
                if r["mitreId"]:
                    ent_dict["mitreId"] = r["mitreId"]
                if r["requiresPrecondition"]:
                    ent_dict["requiresPrecondition"] = r["requiresPrecondition"]
                if r["yieldsPostcondition"]:
                    ent_dict["yieldsPostcondition"] = r["yieldsPostcondition"]
                entities.append(ent_dict)

            rel_res = session.run("""
                MATCH (s:Entity)-[r]->(t:Entity)
                WHERE r.knowledge_id = $kid AND type(r) <> 'MENTIONS'
                RETURN s.id AS s_id, s.name AS s_name,
                       t.id AS t_id, t.name AS t_name,
                       r.predicate AS predicate,
                       type(r) AS cypher_type,
                       r.source_posture AS source_posture,
                       r.target_posture AS target_posture,
                       r.modality AS modality,
                       r.evidence AS evidence;
            """, kid=knowledge_id)

            relationships = []
            for r in rel_res:
                pred = r["predicate"]
                if not pred:
                    norm = r["cypher_type"].lower()
                    pred = f"ag:{norm}" if norm == "leads_to_step" else f"cti:{norm}"

                rel_dict: Dict[str, Any] = {
                    "subject": r["s_id"] or r["s_name"],
                    "predicate": pred,
                    "object": r["t_id"] or r["t_name"],
                }
                qual: Dict[str, Any] = {}
                if r["source_posture"]:
                    qual["source_posture"] = r["source_posture"]
                if r["target_posture"]:
                    qual["target_posture"] = r["target_posture"]
                if r["modality"]:
                    qual["modality"] = r["modality"]
                if qual:
                    rel_dict["qualification"] = qual
                rel_dict["evidence"] = r["evidence"] or ""
                relationships.append(rel_dict)

            return {
                "graph_metadata": {
                    "ontology_uri": "https://w3id.org/cti/ontology#",
                    "version": "2.0.0",
                    "incident_id": inc_id,
                },
                "entities": entities,
                "relationships": relationships,
            }

    def get_extracted_article_ids(self) -> Set[int]:
        """Retourne l'ensemble des IDs d'articles déjà extraits avec succès dans Neo4j."""
        with self.driver.session() as session:
            result = session.run("MATCH (a:Article) WHERE a.status = 'success' RETURN a.id AS id;")
            return {record["id"] for record in result}

    def get_summary_stats(self) -> Dict[str, Any]:
        """Récupère les statistiques globales du Knowledge Graph depuis Neo4j."""
        stats: Dict[str, Any] = {
            "entities": [],
            "relations": [],
            "kill_chain": [],
            "article_count": 0,
            "total_entities": 0,
            "total_relations": 0,
        }

        with self.driver.session() as session:
            # 1. Entités par type
            ent_res = session.run("""
                MATCH (e:Entity)
                RETURN e.entity_type AS entity_type,
                       count(e) AS count,
                       sum(CASE WHEN e.is_dual_use THEN 1 ELSE 0 END) AS dual_cnt,
                       sum(CASE WHEN e.cpe <> '' AND e.cpe IS NOT NULL THEN 1 ELSE 0 END) AS cpe_cnt
                ORDER BY count DESC;
            """)
            stats["entities"] = [
                (r["entity_type"] or "unknown", r["count"], r["dual_cnt"], r["cpe_cnt"])
                for r in ent_res
            ]
            stats["total_entities"] = sum(cnt for _, cnt, _, _ in stats["entities"])

            # 2. Relations par type
            rel_res = session.run("""
                MATCH ()-[r]->()
                WHERE type(r) <> 'MENTIONS'
                RETURN type(r) AS relation_type, count(r) AS count
                ORDER BY count DESC LIMIT 15;
            """)
            stats["relations"] = [(r["relation_type"], r["count"]) for r in rel_res]
            stats["total_relations"] = sum(cnt for _, cnt in stats["relations"])

            # 3. Distribution Kill Chain
            kc_res = session.run("""
                MATCH ()-[r]->()
                WHERE type(r) <> 'MENTIONS' AND r.kill_chain_phase IS NOT NULL AND r.kill_chain_phase <> ''
                RETURN r.kill_chain_phase AS kill_chain_phase, count(r) AS count
                ORDER BY count DESC;
            """)
            stats["kill_chain"] = [(r["kill_chain_phase"], r["count"]) for r in kc_res]

            # 4. Nombre d'articles extraits
            art_res = session.run("MATCH (a:Article) WHERE a.status = 'success' RETURN count(a) AS art_count;").single()
            stats["article_count"] = art_res["art_count"] if art_res else 0

        return stats

    def fetch_entities_and_relations(
        self, article_id: Optional[int] = None
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Extrait les entités et relations depuis Neo4j (pour affichage ou export RDF/OWL)."""
        with self.driver.session() as session:
            if article_id is not None:
                ent_query = """
                    MATCH (a:Article {id: $kid})-[:MENTIONS]->(e:Entity)
                    RETURN DISTINCT e.name AS name,
                                    e.entity_type AS type,
                                    coalesce(e.is_dual_use, false) AS is_dual_use,
                                    coalesce(e.cpe, '') AS cpe,
                                    coalesce(e.description, '') AS description;
                """
                rel_query = """
                    MATCH (s:Entity)-[r]->(t:Entity)
                    WHERE r.knowledge_id = $kid AND type(r) <> 'MENTIONS'
                    RETURN s.name AS source_name,
                           coalesce(r.source_type, s.entity_type) AS source_type,
                           coalesce(r.source_posture, '') AS source_posture,
                           toLower(type(r)) AS relation_type,
                           t.name AS target_name,
                           coalesce(r.target_type, t.entity_type) AS target_type,
                           coalesce(r.target_posture, '') AS target_posture,
                           coalesce(r.kill_chain_phase, 'execution') AS kill_chain_phase,
                           coalesce(r.modality, 'observed') AS modality,
                           coalesce(r.confidence, 85) AS confidence,
                           coalesce(r.precondition_state, '') AS precondition_state,
                           coalesce(r.postcondition_state, '') AS postcondition_state,
                           coalesce(r.evidence, '') AS evidence;
                """
                ent_records = session.run(ent_query, kid=article_id)
                rel_records = session.run(rel_query, kid=article_id)
            else:
                ent_query = """
                    MATCH (e:Entity)
                    RETURN DISTINCT e.name AS name,
                                    e.entity_type AS type,
                                    coalesce(e.is_dual_use, false) AS is_dual_use,
                                    coalesce(e.cpe, '') AS cpe,
                                    coalesce(e.description, '') AS description;
                """
                rel_query = """
                    MATCH (s:Entity)-[r]->(t:Entity)
                    WHERE type(r) <> 'MENTIONS'
                    RETURN DISTINCT s.name AS source_name,
                           coalesce(r.source_type, s.entity_type) AS source_type,
                           coalesce(r.source_posture, '') AS source_posture,
                           toLower(type(r)) AS relation_type,
                           t.name AS target_name,
                           coalesce(r.target_type, t.entity_type) AS target_type,
                           coalesce(r.target_posture, '') AS target_posture,
                           coalesce(r.kill_chain_phase, 'execution') AS kill_chain_phase,
                           coalesce(r.modality, 'observed') AS modality,
                           coalesce(r.confidence, 85) AS confidence,
                           coalesce(r.precondition_state, '') AS precondition_state,
                           coalesce(r.postcondition_state, '') AS postcondition_state,
                           coalesce(r.evidence, '') AS evidence;
                """
                ent_records = session.run(ent_query)
                rel_records = session.run(rel_query)

            entities = [dict(record) for record in ent_records]
            relations = [dict(record) for record in rel_records]
            return entities, relations

    def migrate_from_sqlite(self, sqlite_path: Path) -> int:
        """Migre les extractions existantes de SQLite vers Neo4j."""
        if not sqlite_path.exists():
            console.print(f"[yellow]Fichier SQLite introuvable : {sqlite_path}[/]")
            return 0

        self.init_schema()
        migrated_count = 0

        with sqlite3.connect(sqlite_path) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()

            # Vérifier si la table article_kg_extractions existe
            tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()}
            if "article_kg_extractions" not in tables:
                return 0

            extractions = c.execute("SELECT * FROM article_kg_extractions;").fetchall()
            for ext in extractions:
                kid = ext["knowledge_id"]
                # Récupérer le titre
                title_row = c.execute("SELECT title FROM knowledge WHERE id = ?;", (kid,)).fetchone()
                title = title_row["title"] if title_row else f"Article #{kid}"

                # Récupérer les entités
                ent_rows = c.execute("SELECT * FROM kg_entities WHERE knowledge_id = ?;", (kid,)).fetchall()
                entities = [
                    {
                        "name": r["name"],
                        "type": r["entity_type"],
                        "is_dual_use": bool(r["is_dual_use"]),
                        "cpe": r["cpe"] if "cpe" in r.keys() else "",
                        "description": r["description"] or "",
                    }
                    for r in ent_rows
                ]

                # Récupérer les relations
                rel_rows = c.execute("SELECT * FROM kg_relations WHERE knowledge_id = ?;", (kid,)).fetchall()
                relations = []
                for r in rel_rows:
                    rel_dict = dict(r)
                    relations.append({
                        "source_name": rel_dict["source_name"],
                        "source_type": rel_dict.get("source_type", ""),
                        "source_posture": rel_dict.get("source_posture", ""),
                        "relation_type": rel_dict["relation_type"],
                        "target_name": rel_dict["target_name"],
                        "target_type": rel_dict.get("target_type", ""),
                        "target_posture": rel_dict.get("target_posture", ""),
                        "kill_chain_phase": rel_dict.get("kill_chain_phase", "execution"),
                        "modality": rel_dict.get("modality", "observed"),
                        "confidence": rel_dict.get("confidence", 85),
                        "precondition_state": rel_dict.get("precondition_state", "") or "",
                        "postcondition_state": rel_dict.get("postcondition_state", "") or "",
                        "evidence": rel_dict.get("evidence", "") or "",
                    })

                self.save_extraction(
                    knowledge_id=kid,
                    entities=entities,
                    relations=relations,
                    duration=ext["extraction_duration_seconds"],
                    model_version=ext["model_version"],
                    status=ext["status"],
                    error_message=ext["error_message"],
                    title=title,
                )
                migrated_count += 1

        return migrated_count
