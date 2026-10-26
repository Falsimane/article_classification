"""
Package Backend pour la plateforme CTI Knowledge Graph.
Structure modulaire étanche :
- preprocessing : Assainissement universel, fast-reject, segmentation & classification.
- extracting : Agent d'extraction du Knowledge Graph (outils ATT&CK v20.0, vérification par stix2), IOC et règles.
- database : Couche de persistance et de requêtage (Neo4j, SQLite).
- stix : Objets STIX 2.1 créés par la bibliothèque stix2 ; ATT&CK v20.0 (bundle officiel lu par stix2, index de recherche).
- evaluation : Score de l'extraction contre les articles annotés à la main.
"""
