[Rapport Brut]
       │
       ▼
1. Extraction d'entités & d'actions (LLM) ──► Détecte : acteurs, malwares, outils, CVEs, phrases clés
       │
       ▼
2. Normalisation MITRE (Tool Search)     ──► Match chaque phrase clé -> ID ATT&CK officiel
       │
       ▼
3. Modélisation du graphe (LLM)          ──► Relie les entités aux techniques via triplets STIX
       │
       ▼
4. Validation & Bundling (Tool STIX)     ──► Vérification des contraintes relationnelles & export JSON
       │
       ▼
[STIX 2.1 Bundle Valide]