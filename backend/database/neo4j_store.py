"""Connexion Neo4j du Knowledge Graph CTI (singleton), réutilisée par `stix_store`."""

import os
from typing import Optional, Tuple

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
