"""
Package Backend pour la plateforme CTI Knowledge Graph.
Structure modulaire étanche :
- preprocessing : Assainissement universel (moteur Rust cti_core), fast-reject, segmentation & classification ;
  text/ (noms normalisés, ancrage, phrases numérotées) est partagé par l'extraction et l'évaluation.
- extracting : Agent d'extraction du Knowledge Graph (outils ATT&CK v20.0, vérification par stix2), IOC et règles ;
  extracting/stix : Objets STIX 2.1 créés par la bibliothèque stix2 ; ATT&CK v20.0 (bundle officiel lu par stix2, index de recherche).
- database : Couche de persistance et de requêtage (Neo4j, SQLite).
- evaluation : Score de l'extraction contre les articles annotés à la main.
"""
