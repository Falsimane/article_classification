# CTI Knowledge Graph

Ce projet transforme des articles bruts de **Cyber Threat Intelligence** (rapports d'éditeurs, blogs de recherche) en un
**graphe de connaissances STIX 2.1** stocké dans **Neo4j**, puis l'expose dans un tableau de bord Web.

Le principe directeur : **le code vérifie, le modèle de langage décide du sens, la bibliothèque `stix2` valide.** Un LLM
local (famille Qwen, servi par vLLM pour l'extraction, par Ollama pour la classification) répond en lignes courtes sous schéma
JSON : entités, techniques ATT&CK, relations entre éléments numérotés, preuves par numéro de phrase. Tout ce qu'il propose est
créé par `stix2` en mode strict, confronté à MITRE ATT&CK v20.0 et au texte de l'article avant d'entrer dans le graphe.

```text
 articles scrappés            nettoyage + triage                 extraction STIX                    persistance + visualisation
┌──────────────────┐   ┌──────────────────────────────┐   ┌───────────────────────────────┐   ┌─────────────────────────────┐
│ SQLite           │   │ cti_core (Rust) : bruit web,  │   │ phrases numérotées            │   │ Neo4j (:Stix:<Type>)        │
│ table `knowledge`│──▶│ gabarit appris par source,    │──▶│ entités, techniques ATT&CK,   │──▶│ bundle STIX 2.1 par article │
│                  │   │ refang des IOC                │   │ relations (preuve = n° phrase)│   │ tableau de bord React       │
│                  │   │ LLM : tactique / opérationnel │   │ IOC et règles YARA/Sigma      │   │ (rapports, acteurs)         │
│                  │   │ / stratégique / hors sujet    │   │ vérification stix2 + ATT&CK   │   │                             │
└──────────────────┘   └──────────────────────────────┘   └───────────────────────────────┘   └─────────────────────────────┘
                          uv run cti-classifier              uv run cti-extract                  scripts/dashboard.sh
```

Le dépôt contient aussi un **jeu d'articles annotés à la main** (`Annotations/`) et un outil de score (`cti-eval`) pour
mesurer rappel, précision et hallucinations de l'extraction.

---

## Sommaire

1. [Architecture](#architecture)
2. [Prérequis](#prérequis)
3. [Installation](#installation)
4. [Reproduire le pipeline de bout en bout](#reproduire-le-pipeline-de-bout-en-bout)
5. [Commandes essentielles](#commandes-essentielles)
6. [Configuration](#configuration)
7. [Données et sorties](#données-et-sorties)
8. [Tests](#tests)
9. [Règles métier](#règles-métier)

---

## Architecture

```text
.
├── backend/                 # Python : preprocessing, extraction, STIX, Neo4j, évaluation, API Web   → backend/README.md
│   ├── preprocessing/       #   nettoyage, classification LLM, audit humain (TUI)
│   │   ├── classifying/     #     classification LLM, audit humain (TUI), rapport qualité du nettoyage
│   │   └── cleaning/        #     cleaner.py, façade Python du moteur Rust
│   │       ├── cti_core/    #       moteur de nettoyage natif en Rust (PyO3), compilé par uv à l'installation
│   │       └── text/        #       noms normalisés, ancrage, dates, phrases numérotées (partagé par extraction, STIX, évaluation)
│   ├── extracting/          #   extraction STIX en trois étapes (graph/ : entités, techniques vérifiées, relations), observables/ : IOC, règles
│   │   └── stix/            #     objets STIX 2.1 (stix2), index ATT&CK v20.0
│   ├── database/            #   persistance Neo4j
│   ├── evaluation/          #   score contre le gold annoté ; eval/ (hors git) : un dossier par exécution de cti-eval
│   ├── dashboard/           #   serveur HTTP (API REST + build du frontend), graphe Neo4j → JSON pour l'interface
│   └── data/                #   données hors git : sources/ (SQLite), bundles/, raw/, archive/ (CTI_DATA_DIR)
├── frontend/                # React 18 + TypeScript + Tailwind + React Flow 12 (Vite)                 → frontend/README.md
├── Annotations/             # articles annotés à la main (gold STIX), manifest.json, méthode d'annotation
├── scripts/dashboard.sh     # build du frontend si besoin + lancement du serveur
├── docker-compose.yml       # Neo4j 5 (APOC, n10s)
├── Dockerfile               # image Neo4j utilisée par docker-compose
├── .env.example             # variables du client LLM
└── pyproject.toml           # dépendances Python et commandes CLI (uv)
```

| Documentation détaillée | Contenu |
| :--- | :--- |
| [backend/README.md](backend/README.md) | Flux de données, rôle de chaque module, étapes de l'extraction, modèle Neo4j, API REST, évaluation |
| [frontend/README.md](frontend/README.md) | Vues, composants, contrat d'API, conventions visuelles et de sécurité, développement |
| [Annotations/methode_annotation.md](Annotations/methode_annotation.md) | Méthode d'annotation du gold et règles de score |

---

## Prérequis

| Outil | Version | Usage |
| :--- | :--- | :--- |
| [uv](https://docs.astral.sh/uv/) | récente | environnement Python 3.12 et dépendances |
| Rust (`cargo`) | stable | compilation de l'extension `cti_core` (faite par `uv sync`) |
| Node.js + npm | ≥ 20 | build du frontend |
| Docker + Docker Compose | — | base Neo4j |
| Serveurs LLM | — | extraction : serveur compatible OpenAI (**vLLM**, **SGLang**) lancé avec un analyseur d'appels d'outils ; classification : **Ollama** |

**Données d'entrée.** Le pipeline lit les articles dans `backend/data/sources/cti_knowledge.db` (SQLite, table `knowledge` :
`id, site_name, url, title, publication_date, content`). Cette base est produite par le scraping, qui n'est pas dans ce
dépôt, et `backend/data/` n'est pas versionné : elle doit être fournie séparément.

**Serveurs LLM distants.** Les modèles tournent sur une machine distante, jointe par un tunnel SSH sur `localhost`. Les
scripts n'envoient que des requêtes HTTP.

```bash
# vLLM / SGLang distant (API OpenAI sur le port 8010) : extraction
ssh -N -L 8010:127.0.0.1:8010 <utilisateur>@<serveur>
# Ollama distant : classification
ssh -N -L 11434:127.0.0.1:11434 <utilisateur>@<serveur>
```

L'extraction envoie l'article entier en un appel : le contexte du serveur (`--max-model-len`) doit le contenir (32 768 tokens
suffisent pour les articles annotés). L'étape de correction des techniques appelle des outils : vLLM doit être lancé avec
`--enable-auto-tool-choice --tool-call-parser qwen3_coder` (Qwen3.5).

---

## Installation

```bash
git clone <url-du-dépôt> article_classification && cd article_classification

# Dépendances Python + compilation de cti_core (Rust)
uv sync

# Variables du client LLM (lues dans l'environnement : aucun chargement automatique du fichier)
cp .env.example .env            # puis adapter
set -a && source .env && set +a

# Base Neo4j (http://localhost:7474, bolt://localhost:7687, neo4j / password123 par défaut)
docker compose up -d neo4j

# Frontend (fait aussi automatiquement par scripts/dashboard.sh)
cd frontend && npm install && npm run build && cd ..
```

L'index ATT&CK v20.0 (`backend/extracting/stix/reference/attack_v20.sqlite`) est versionné : il n'y a rien à construire pour
commencer. Pour le reconstruire, voir [backend/README.md](backend/README.md#stix--objets-stix-21-et-bases-de-référence).

Après une modification du code Rust :

```bash
cd backend/preprocessing/cleaning/cti_core && cargo test && maturin develop --release && cd ../../../..
```

---

## Reproduire le pipeline de bout en bout

```bash
# 0. Neo4j démarré, tunnel LLM ouvert, variables exportées (voir Installation)

# 1. Nettoyer et classifier les articles de la table `knowledge`
#    (apprend le gabarit de chaque source, puis écrit article_classifications dans SQLite)
uv run cti-classifier

# 1 bis. (facultatif) Vérifier et corriger les classifications à la main
uv run cti-audit

# 2. Extraire les 10 prochains articles CTI vers Neo4j (bundle STIX écrit dans backend/data/bundles/)
uv run cti-extract --limit 10

# 3. Ouvrir le tableau de bord sur http://localhost:8095
scripts/dashboard.sh

# 4. Mesurer la qualité de l'extraction sur les articles annotés
uv run cti-eval --run --workers 4
```

---

## Commandes essentielles

### Preprocessing et classification

```bash
uv run cti-classifier                                   # nettoyage Rust + classification LLM des articles non classés
CTI_CLASSIFIER_WORKERS=3 uv run cti-classifier          # classifications en parallèle (défaut : 2)
uv run cti-audit                                        # interface terminal (Textual) de validation humaine
uv run python backend/preprocessing/classifying/evaluate_cleaning.py [--site <source>]   # qualité du nettoyage, sans LLM
```

### Extraction STIX vers Neo4j

`cti-extract` choisit les articles classés *tactical*, *operational* ou *strategic* et pas encore extraits.

```bash
uv run cti-extract --limit 10                           # 10 articles vers Neo4j
uv run cti-extract --article-id 1553 --dry-run          # un article, sans écrire dans Neo4j (le bundle est écrit)
uv run cti-extract --article-id 1553 --dry-run --show-log   # chaque refus de la vérification, chaque appel d'outil
uv run cti-extract --limit 5 --force                    # ré-extraire des articles déjà présents dans Neo4j
uv run cti-extract --limit 20 --workers 2               # deux articles à la fois (Neo4j reste écrit par un seul fil)
uv run cti-extract --stats                              # nœuds et relations du graphe par type STIX
```

Chaque article passe par trois étapes sur le texte entier : un appel pour les entités et les techniques ATT&CK, une
vérification des techniques (les refusées sont corrigées par le modèle avec les outils `search_attack` / `get_attack`), un
appel pour les relations entre les éléments numérotés retenus (plus un appel de correction). Le détail est dans
[backend/README.md](backend/README.md#extracting--extraction-stix).

### Évaluation contre le gold

```bash
uv run cti-eval --run --workers 4                       # extrait les articles de Annotations/manifest.json (4 à la fois) puis score
uv run cti-eval --run --bundles backend/evaluation/eval/<nom>   # dans un dossier nommé, pour comparer deux versions
uv run cti-eval --bundles backend/evaluation/eval/<nom>         # re-score des bundles existants, sans appel au modèle
uv run cti-eval --article-id 1553 --bundles <dossier>   # limiter à un article
```

Le rapport est écrit dans le dossier des bundles : `report.md` (lisible) et `report.json` (manques, prédictions à revoir).

### Tableau de bord

```bash
scripts/dashboard.sh                    # npm install / build si besoin, puis serveur sur http://localhost:8095
scripts/dashboard.sh --dev              # backend :8095 + Vite à rechargement à chaud sur http://localhost:5173
scripts/dashboard.sh --port 8096        # autre port (8080 et 8090 sont pris par une pile OpenCTI locale)
uv run cti-dashboard --port 8095        # serveur seul (sert frontend/dist)
```

### Données de référence

```bash
uv run python -m backend.extracting.stix.attack [chemin/enterprise-attack-20.0.json]   # reconstruire l'index ATT&CK v20.0
uv run python -m backend.extracting.observables.update_reference                     # TLD IANA et domaines populaires (Tranco)
```

---

## Configuration

Toutes les variables sont lues dans l'environnement du processus (voir `backend/config.py` et `.env.example`).

| Variable | Défaut | Rôle |
| :--- | :--- | :--- |
| `CTI_OPENAI_URL` | `http://127.0.0.1:8010/v1` | serveur de l'extraction (vLLM, SGLang : `/v1/chat/completions`) |
| `CTI_OPENAI_MODEL` | `cti-qwen` | nom servi (`--served-model-name`) |
| `CTI_LLM_SLOTS` | `10` | requêtes en vol (le `--max-running-requests` du serveur) |
| `CTI_LLM_TIMEOUT` | `180` | délai d'un appel d'extraction, en secondes |
| `CTI_THINKING` | `off` | réflexion de Qwen pendant l'extraction |
| `OLLAMA_API_URL` | `http://127.0.0.1:11434/api/generate` | serveur de la classification |
| `OLLAMA_MODEL` | `qwen3.8:27b` | modèle de la classification |
| `OLLAMA_NUM_CTX` | `12288` | contexte de **chaque** requête de classification (une autre valeur ferait recharger le modèle) |
| `CTI_CLASSIFIER_WORKERS` | `2` | classifications en parallèle |
| `NEO4J_URI` / `NEO4J_USER` / `NEO4J_PASSWORD` | `bolt://localhost:7687` / `neo4j` / `password123` | connexion Neo4j |

---

## Données et sorties

| Emplacement | Contenu | Accès |
| :--- | :--- | :--- |
| `backend/data/sources/cti_knowledge.db` | `knowledge` (articles bruts), `article_classifications` (catégorie, markdown nettoyé), `site_boilerplate` (gabarits appris) | écrit par `cti-classifier` et `cti-audit` ; **lecture seule** pour l'extraction et le tableau de bord |
| Neo4j `bolt://localhost:7687` | graphe STIX : nœuds `(:Stix:<Type>)`, arêtes typées, provenance par article | **seule** base du graphe de connaissances |
| `backend/data/bundles/article_<id>.json` | bundle STIX 2.1 complet de chaque extraction (IOC bénins compris) | réécrit à chaque extraction, même en `--dry-run` |
| `backend/evaluation/eval/<nom>/` | bundles de l'évaluation, `runs.json`, `report.md`, `report.json` (défaut : `latest`) | écrit par `cti-eval` |
| `backend/extracting/stix/reference/` | index ATT&CK v20.0 (SQLite FTS5) | versionné / reconstruit à la demande |

---

## Tests

Le backend Python n'a pas de tests unitaires : la qualité de l'extraction se mesure contre les articles annotés
(`cti-eval`, voir plus haut).

```bash
# Frontend : layouts, organigramme, filtres, aucun innerHTML sur du texte d'article
cd frontend && npm test

# Moteur Rust
cd backend/preprocessing/cleaning/cti_core && cargo test
```

---

## Règles métier

1. **Un graphe par article.** Le tableau de bord n'affiche aucun graphe global : chaque rapport montre son propre
   sous-graphe. Seule la vue *Acteurs* agrège ce que plusieurs articles disent d'un même acteur.
2. **Ancrage.** Une relation cite des numéros de phrases ; le texte de la preuve est relu par le code, jamais recopié
   par le modèle.
3. **Pas d'invention.** Un identifiant ATT&CK absent de la v20.0 est refusé ; un lieu non résolu en pays ISO ou en
   région STIX est refusé ; une rubrique de profil sans donnée reste vide.
4. **Anti-bruit.** Chercheurs, éditeurs de sécurité et victimes ne sont jamais des acteurs de la menace ; les binaires
   natifs (`powershell.exe`, `certutil.exe`) sont des outils détournés, jamais de l'infrastructure C2.
5. **Preprocessing universel.** Aucune liste d'éditeurs, d'acteurs ou d'outils dans le moteur Rust : le bruit est détecté
   par structure puis par apprentissage du gabarit de chaque source. Les IOC restent à leur place dans le texte.
6. **IOC par règles.** Les valeurs (IP, domaines, hachages…) ne sont jamais générées par le modèle ; il n'en choisit
   que le rôle et l'entité de rattachement.
