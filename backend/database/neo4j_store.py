"""
Module de persistance Neo4j pour le Cyber Threat Intelligence (CTI) Knowledge Graph.
Remplace le stockage statique SQLite par un Property Graph dynamique et interconnecté,
compatible avec l'ontologie CTI V2, Neosemantics (n10s) et APOC.
"""

import os
from typing import Any, Dict, Optional, Tuple

from neo4j import GraphDatabase, Driver

DEFAULT_NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
DEFAULT_NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
DEFAULT_NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password123")


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
