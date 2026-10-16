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
│   │   ├── cti_extractor.py      # CLI d'extraction STIX (articles classifiés -> objets STIX validés -> Neo4j)
│   │   ├── pipeline.py           # Extraction d'un article : entités, vérification, relations par candidats, validation
│   │   ├── stages.py             # Prompts, schémas de sortie fermés et analyse des réponses de chaque étape LLM
│   │   ├── segment.py            # Phrases numérotées (la preuve d'une relation est un numéro de phrase)
│   │   ├── llm.py                # Client Ollama : sortie contrainte, durées et tokens mesurés par le serveur
│   │   └── cti_extractor_legacy.py  # DÉPRÉCIÉ : ancien extracteur, tant que le tableau de bord lit l'ancien graphe
│   │
│   ├── database/                 # Couche de persistance et de requêtage
│   │   ├── __init__.py
│   │   ├── neo4j_store.py        # Ancien graphe (Entity/Article) lu par le tableau de bord, bientôt déprécié
│   │   └── stix_store.py         # Graphe STIX : nœuds (:Stix:<Type>), arêtes typées, provenance par article
│   │
│   ├── ontology/                 # Ontologie CTI
│   │   ├── stix/                 # Ontologie STIX 2.1 (source de vérité, voir stix/README.md) : types, relations,
│   │   │                         #   profils d'extraction, validation, base ATT&CK, export bundle/Neo4j/RDF
│   │   ├── ontology.py           # DÉPRÉCIÉ : ancienne ontologie maison, utilisée tant que l'extracteur n'a pas migré
│   │   └── cti_killchain_ontology.ttl  # DÉPRÉCIÉ
│   │
│   ├── cti_core/                 # Moteur déterministe natif Rust (PyO3) : nettoyage, sections, découpage
│   ├── server.py                 # Serveur Web HTTP & API REST (sert frontend/) ; /api/stats|articles|graph servent le graphe STIX
│   ├── stix_dashboard.py         # Graphe STIX (Neo4j) -> JSON de données pures (pas de couleurs ni de HTML) ; /api/actors pour les profils
│   └── __init__.py
│
├── frontend/                     # Interface Web : React 18 + TypeScript + Tailwind CSS 3 + React Flow 12 (Vite)
│   ├── src/
│   │   ├── components/           # Shell, ReportsView (rapport = graphe d'un article : nœuds ronds + icône, acteurs en rectangles,
│   │   │                         #   flèches flottantes), ActorsView (onglets) + OrgChart (organigramme React Flow), EntryTable,
│   │   │                         #   GraphCanvas, Inspector (attributs, relations, preuves), FamilyFilter
│   │   ├── lib/                  # api.ts (client REST), layout.ts (d3-force), org.ts (organigramme), icons.ts (icône par type STIX), theme.ts
│   │   └── types.ts              # Formes JSON de l'API (miroir de backend/stix_dashboard.py)
│   ├── tailwind.config.js        # Palette sobre inspirée de Blueprint (Palantir) : aucun dégradé, une seule couleur d'accent
│   ├── dist/                     # Build servi par backend/server.py (non versionné : `npm run build`)
│   └── legacy/                   # Ancienne interface HTML/CSS/Vis-Network/React Flow 11, archivée, plus servie
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
# Extraire les 10 prochains articles éligibles vers Neo4j (graphe STIX)
uv run cti-extractor --limit 10

# Un article, avec les relations et leur phrase de preuve, sans écrire dans Neo4j, bundle STIX 2.1 en fichier
uv run cti-extractor --article-id 686 --show-triples --dry-run --out /tmp/bundles

# Statistiques du graphe STIX
uv run cti-extractor --stats

# Re-traiter des articles déjà extraits (retire d'abord leur ancienne contribution)
uv run cti-extractor --limit 5 --force
```

### C. Serveur Web & Dashboard CTI
```bash
# Démarrer le serveur Web sur le port 8080 (http://localhost:8080). Le graphe STIX est servi dès qu'un article est
# extrait ; ?model=legacy force l'ancien graphe (Entity/Article), ?model=stix force le nouveau.
uv run cti-dashboard --port 8080

# Ou directement avec Python
.venv/bin/python backend/server.py --port 8080
```

### D. Frontend (React + Tailwind + React Flow)
```bash
cd frontend
npm install
npm run build        # typecheck + build Vite vers frontend/dist, servi par `uv run cti-dashboard`
npm run dev          # serveur de développement :5173, l'API est proxifiée vers :8080
npm test             # layouts du graphe, aucun innerHTML sur du texte d'article
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

# Extraction (faux modèle : segmentation, candidats, vérifications, pipeline complet)
uv run python -m unittest tests.test_extraction_pipeline -v

# API de données du tableau de bord STIX (formes JSON, filtres, preuves par article, profils d'acteurs)
uv run python -m unittest tests.test_stix_dashboard -v

```

---

## 6. Règles Métier & Invariants CTI

1. **Isolation par Article :** Le dashboard ne présente plus aucun graphe global agrégé. Chaque rapport CTI affiche exclusivement son propre sous-graphe d'incident.
2. **Profil d'acteur (onglet Acteurs) :** ce n'est PAS un graphe de connaissances mais un organigramme en rectangles (identité/pays en haut, acteur, divisions, puis Arsenal / Techniques / Infrastructure / Cibles) avec des onglets Organigramme, Arsenal, Techniques (par tactique ATT&CK), Infrastructure, Cibles, Références. Calculé côté serveur (`stix_dashboard._profile`) à partir des arêtes directes ; une rubrique sans donnée reste vide (« origine non établie »), jamais déduite. Seule vue qui agrège plusieurs articles. Dans un graphe de rapport : nœuds ronds avec icône par type, rectangles réservés aux acteurs de la menace.
3. **Débit du serveur Ollama :** il traite les requêtes l'une après l'autre (mesuré : 1, 2, 3, 4 requêtes simultanées durent 5, 10, 15, 21 s, débit constant de 38 tokens/s). Lancer des appels en parallèle n'accélère rien ; l'extraction est rapide parce qu'elle fait GÉNÉRER très peu de tokens (chaque réponse est un identifiant de candidat, pas du texte).
4. **Preprocessing universel :** aucune liste d'éditeurs, d'acteurs ou d'outils dans Rust. Le bruit est détecté par structure (densité de liens, tête/queue de document) puis par apprentissage du gabarit de chaque source sur le corpus (`site_boilerplate`, relu à chaque lancement de `cti-classifier`). Les IOC restent à leur place dans le récit.
5. **Anti-Bruit :** Les chercheurs en sécurité, éditeurs CTI et entreprises victimes ne doivent jamais être labellisés en `cti:ThreatActor`. Les utilitaires natifs (`powershell.exe`, `certutil.exe`) sont catégorisés en outils à double usage, jamais en infrastructure C2.
