"""Module de persistance et de requêtage pour les bases de données (Neo4j, SQLite)."""
from .neo4j_store import Neo4jStore

__all__ = ["Neo4jStore"]
