"""
Package Backend pour la plateforme CTI Knowledge Graph.
Structure modulaire étanche :
- preprocessing : Assainissement universel, fast-reject, segmentation & classification.
- extracting : Extraction du Knowledge Graph LLM avec Structured Outputs & Reflexion.
- database : Couche de persistance et de requêtage (Neo4j, SQLite).
- ontology : Ontologie CTI Kill Chain, normalisation et filtrage anti-bruit.
"""
