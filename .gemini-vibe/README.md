# Gemini Vibe — Configuration & Context

Ce dossier est réservé aux configurations, styles et règles d'ambiance / vibe de développement.
- **Architecture :** Modulaire étanche `backend/` et `frontend/`.
- **Backend :**
  - `backend/preprocessing/` : Nettoyage déterministe, refanging universel, fast-reject, segmentation AST et classification.
  - `backend/extracting/` : Extraction du Knowledge Graph CTI (Structured Outputs & Reflexion).
  - `backend/database/` : Couche de persistance Property Graph Neo4j et lecture SQLite.
  - `backend/ontology/` : Ontologie CTI Kill Chain RDF/OWL et filtres anti-bruit.
  - `backend/server.py` : Serveur API REST et distribution du frontend.
- **Frontend :**
  - `frontend/src/` : Composants sources React Flow et calculateurs de disposition Dagre.
  - `frontend/` : Interface OpenCTI, bundles JS/CSS et assets graphiques.
