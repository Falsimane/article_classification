# Projet CTI Knowledge Graph — Référence Projet (CLAUDE.md)

---

## 1. But du Projet

Ce projet a pour objectif d'ingérer des articles bruts de Cyber Threat Intelligence (CTI), d'en assainir le contenu, et de construire automatiquement un **Knowledge Graph sémantique** fiable, interconnecté et validé par ontologie dans **Neo4j**.

Le pipeline permet de :
1. **Prétraiter et classifier** les articles CTI (tactique, opérationnel, stratégique, hors-sujet) en éliminant le bruit web (bannières, boutons sociaux, disclaimers).
2. **Extraire** les entités CTI (Threat Actors, Malwares, LOLBins, Infrastructures, TTPs MITRE ATT&CK, Vulnérabilités, IOCs) avec leurs relations et citations textuelles exactes (Grounding).
3. **Explorer visuellement** les renseignements via un tableau de bord Web (OpenCTI-like) :
   - **Rapports CTI** : Visualisation du graphe unitaire par incident (Vis-Network).
   - **Threat Actors** : Profiling hiérarchique interactif sous forme d'arborescence (React Flow) reliant le sponsor étatique, l'acteur, ses infrastructures C2, ses TTPs et son arsenal.

---

## 2. Infrastructure & LLM Distant (Ollama)

> [!IMPORTANT]
> **Ollama s'exécute sur un SERVEUR DISTANT (ou accessible via tunnel sur `http://localhost:11434`).**
> - **Ne JAMAIS exécuter de commandes shell locales** comme `ollama list`, `ollama run`, `ollama pull` ou `systemctl restart ollama`.
> - Les scripts Python interagissent avec le LLM (`qwen3:32b`) **uniquement via des requêtes HTTP REST** (`POST http://localhost:11434/api/generate`).
> - La variable d'environnement `NO_PROXY="localhost,127.0.0.1"` est appliquée pour éviter tout détournement de trafic.

---

## 3. Architecture du Projet

Le projet sépare strictement le backend Python/Rust, le frontend Web/React Flow et la persistance.

```text
├── backend/
│   ├── preprocessing/            # Ingestion, refanging universel, fast-reject & classification
│   │   ├── __init__.py
│   │   ├── cleaner.py            # UniversalCTICleaner appelant le moteur Rust cti_core (gabarit par source, découpage atomique)
│   │   ├── evaluate_cleaning.py  # Rapport qualité du preprocessing (fidélité IOC, résidus, source inconnue)
│   │   ├── cti_classifier.py     # Pipeline de classification & triage LLM (Qwen)
│   │   └── audit_classifier.py   # Interface TUI (Textual) pour l'audit et la validation humaine
│   │
│   ├── extracting/               # Construction sémantique du Knowledge Graph CTI
│   │   ├── __init__.py
│   │   └── cti_extractor.py      # Extracteur d'entités, relations, postures & preuves
│   │
│   ├── database/                 # Couche de persistance et de requêtage
│   │   ├── __init__.py
│   │   └── neo4j_store.py        # Driver Neo4j, contraintes d'unicité, labels dynamiques
│   │
│   ├── ontology/                 # Ontologie CTI
│   │   ├── stix/                 # Ontologie STIX 2.1 (source de vérité, voir stix/README.md) : types, relations,
│   │   │                         #   profils d'extraction, validation, base ATT&CK, export bundle/Neo4j/RDF
│   │   ├── ontology.py           # DÉPRÉCIÉ : ancienne ontologie maison, utilisée tant que l'extracteur n'a pas migré
│   │   └── cti_killchain_ontology.ttl  # DÉPRÉCIÉ
│   │
│   ├── cti_core/                 # Moteur déterministe natif Rust (PyO3) : nettoyage, sections, découpage
│   ├── server.py                 # Serveur Web HTTP & API REST (sert frontend/)
│   └── __init__.py
│
├── frontend/                     # Interface Web OpenCTI & Visualisation
│   ├── index.html                # Page d'accueil (Rapports CTI & Threat Actor)
│   ├── style.css                 # Thème sombre moderne et tokens CSS
│   ├── app.js                    # Logique frontend (Vis-Network, sélection d'articles, APIs)
│   ├── threat_actor_flow.bundle.js   # Bundle React Flow autonome (hors-ligne)
│   ├── threat_actor_flow.bundle.css  # Styles du bundle React Flow
│   ├── build.js                  # Script de compilation esbuild pour React Flow
│   └── src/                      # Sources React 18 + React Flow 11
│       ├── CustomNodes.jsx       # Nœuds CTI personnalisés (Sponsor, Actor, Category, SubCategory)
│       ├── ThreatActorFlow.jsx   # Composant React Flow avec MiniMap et contrôles
│       ├── treeLayout.js         # Algorithme de disposition arborescente symétrique (Dagre)
│       └── index.jsx             # Point d'entrée montant React Flow dans le DOM
│
├── .gemini-vibe/                 # Directives de vibe, contexte et style
│   └── README.md
│
├── db_outputs/                   # Base relationnelle SQLite source (cti_knowledge.db)
├── tests/                        # Tests unitaires
│   └── test_extractor.py
└── pyproject.toml                # Configuration du package, dépendances uv et scripts CLI
```

---

## 4. Rôles Stricts des Bases de Données

| Base de Données | Rôle | Politique d'accès |
| :--- | :--- | :--- |
| **Neo4j** (`bolt://localhost:7687`) | **L'UNIQUE base de persistance du Knowledge Graph CTI** (nœuds d'entités, relations typées, postures d'usage, articles indexés). | Lecture / Écriture via `backend/database/neo4j_store.py`. |
| **SQLite** (`db_outputs/cti_knowledge.db`) | Contient les articles bruts scrappés (`knowledge`) et les résultats de classification (`article_classifications`). | **STRICTEMENT LECTURE SEULE** pour le pipeline d'extraction et le dashboard. Aucune entité de graphe n'y est enregistrée. |

---

## 5. Commandes à Connaître

Toutes les commandes Python s'exécutent avec `uv` :

### A. Preprocessing & Classification LLM
```bash
# Lancer le pipeline de nettoyage et de classification des articles
uv run cti-classifier

# Lancer l'interface TUI d'audit terminal (validation humaine)
uv run cti-audit
```

### B. Extraction du Knowledge Graph vers Neo4j
```bash
# Extraire les 10 prochains articles éligibles vers Neo4j
uv run cti-extractor --limit 10

# Extraire un article spécifique et afficher les triplets extraits
uv run cti-extractor --article-id 597 --show-triples

# Afficher les statistiques actuelles du graphe Neo4j
uv run cti-extractor --stats

# Forcer le re-traitement d'articles déjà extraits
uv run cti-extractor --limit 5 --force
```

### C. Serveur Web & Dashboard CTI
```bash
# Démarrer le serveur Web sur le port 8080 (http://localhost:8080)
uv run cti-dashboard --port 8080

# Ou directement avec Python
.venv/bin/python backend/server.py --port 8080
```

### D. Compilation Frontend (React Flow)
```bash
# Recompiler le bundle React Flow après modification de frontend/src/
node frontend/build.js
```

### E. Moteur Rust (`cti_core`)
```bash
# Recompiler l'extension Rust dans l'environnement virtuel Python
cd backend/cti_core
cargo test
maturin develop --release
cd ../..

# Rapport qualité du preprocessing (à lancer avant d'ingérer une nouvelle source)
uv run python backend/preprocessing/evaluate_cleaning.py [--site <source>]
```

### F. Tests Unitaires
```bash
# Ontologie STIX (relations contre les données ATT&CK, validateur, export)
uv run python -m unittest tests.test_stix_ontology -v

# Lancer les tests unitaires du pipeline d'extraction et de l'ontologie
uv run python tests/test_extractor.py
```

---

## 6. Règles Métier & Invariants CTI

1. **Isolation par Article :** Le dashboard ne présente plus aucun graphe global agrégé. Chaque rapport CTI affiche exclusivement son propre sous-graphe d'incident.
2. **Arborescence Threat Actor (React Flow) :**
   - **Niveau 0 (Haut) :** Sponsor Étatique / Pays d'attribution (ex: *Armée populaire de Chine*).
   - **Niveau 1 :** Threat Actor (ex: *APT1*).
   - **Niveau 2 :** 3 branches principales : *Infrastructure*, *TTPs Kill Chain*, *Outils*.
   - **Niveau 3 :** Sous-branches dédiées : *Serveurs C2* (avec IOCs copiables 📋), *Localisation*, *Malwares Dédiés* et *LOLBins / Utilitaires détournés* (en violet néon).
3. **Preprocessing universel :** aucune liste d'éditeurs, d'acteurs ou d'outils dans Rust. Le bruit est détecté par structure (densité de liens, tête/queue de document) puis par apprentissage du gabarit de chaque source sur le corpus (`site_boilerplate`, relu à chaque lancement de `cti-classifier`). Les IOC restent à leur place dans le récit.
4. **Anti-Bruit :** Les chercheurs en sécurité, éditeurs CTI et entreprises victimes ne doivent jamais être labellisés en `cti:ThreatActor`. Les utilitaires natifs (`powershell.exe`, `certutil.exe`) sont catégorisés en outils à double usage, jamais en infrastructure C2.
