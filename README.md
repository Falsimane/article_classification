# CTI Knowledge Graph

Ce projet transforme des articles bruts de **Cyber Threat Intelligence** (rapports d'éditeurs, blogs de recherche) en un
**graphe de connaissances STIX 2.1** stocké dans **Neo4j**, puis l'expose dans un tableau de bord Web.

Le principe directeur : **le code propose, le modèle de langage choisit, la bibliothèque `stix2` valide.** Un LLM local
(famille Qwen, servi par Ollama ou vLLM/SGLang) ne génère presque jamais de texte libre. Il répond par un numéro de phrase,
un identifiant de candidat ou un mot d'une liste fermée. Tout ce qu'il propose est créé par `stix2` en mode strict, confronté
à MITRE ATT&CK v20.0 et au texte de l'article avant d'entrer dans le graphe.

```text
 articles scrappés            nettoyage + triage                 extraction STIX                    persistance + visualisation
┌──────────────────┐   ┌──────────────────────────────┐   ┌───────────────────────────────┐   ┌─────────────────────────────┐
│ SQLite           │   │ cti_core (Rust) : bruit web,  │   │ phrases numérotées            │   │ Neo4j (:Stix:<Type>)        │
│ table `knowledge`│──▶│ gabarit appris par source,    │──▶│ entités, techniques ATT&CK,   │──▶│ bundle STIX 2.1 par article │
│                  │   │ refang des IOC                │   │ relations (preuve = n° phrase)│   │ tableau de bord React       │
│                  │   │ LLM : tactique / opérationnel │   │ IOC et règles YARA/Sigma      │   │ (rapports, acteurs)         │
│                  │   │ / stratégique / hors sujet    │   │ vérification stix2 + ATT&CK   │   │                             │
└──────────────────┘   └──────────────────────────────┘   └───────────────────────────────┘   └─────────────────────────────┘
                          uv run cti-classifier              uv run cti-agent                    scripts/dashboard.sh
```

Le dépôt contient aussi un **jeu d'articles annotés à la main** (`Annotations/`) et un outil de score (`cti-eval`) pour
mesurer rappel, précision et hallucinations de chaque méthode d'extraction.

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
│   ├── cti_core/            #   moteur de nettoyage natif en Rust (PyO3), compilé par uv à l'installation
│   ├── preprocessing/       #   nettoyage, classification LLM, audit humain (TUI)
│   ├── extracting/          #   extraction STIX : agent à outils, méthodes fast / closed / oneshot, IOC, règles
│   ├── stix/                #   objets STIX 2.1 (stix2), index ATT&CK v20.0, MISP Galaxy
│   ├── database/            #   persistance Neo4j
│   ├── evaluation/          #   score contre le gold annoté
│   ├── server.py            #   serveur HTTP : API REST + build du frontend
│   └── stix_dashboard.py    #   graphe Neo4j → JSON pour l'interface
├── frontend/                # React 18 + TypeScript + Tailwind + React Flow 12 (Vite)                 → frontend/README.md
├── Annotations/             # articles annotés à la main (gold STIX), manifest.json, méthode d'annotation
├── tests/                   # tests unitaires Python (faux modèle, aucun appel réseau)
├── scripts/dashboard.sh     # build du frontend si besoin + lancement du serveur
├── docker-compose.yml       # Neo4j 5 (APOC, n10s)
├── Dockerfile               # image Neo4j utilisée par docker-compose
├── .env.example             # variables du client LLM
└── pyproject.toml           # dépendances Python et commandes CLI (uv)
```

| Documentation détaillée | Contenu |
| :--- | :--- |
| [backend/README.md](backend/README.md) | Flux de données, rôle de chaque module, méthodes d'extraction, modèle Neo4j, API REST, évaluation |
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
| Serveur LLM | — | **Ollama** (`/api/generate`, `/api/chat`) ou serveur compatible OpenAI (**vLLM**, **SGLang**) avec un modèle Qwen |

**Données d'entrée.** Le pipeline lit les articles dans `db_outputs/cti_knowledge.db` (SQLite, table `knowledge` :
`id, site_name, url, title, publication_date, content`). Cette base est produite par le scraping, qui n'est pas dans ce
dépôt, et `db_outputs/` n'est pas versionné : elle doit être fournie séparément.

**Serveur LLM distant.** Le modèle tourne sur une machine distante, jointe par un tunnel SSH sur `localhost`. Les scripts
ne lancent jamais `ollama` en local : ils n'envoient que des requêtes HTTP.

```bash
# Ollama distant
ssh -N -L 11434:127.0.0.1:11434 <utilisateur>@<serveur>
# vLLM / SGLang distant (API OpenAI sur le port 8010)
ssh -N -L 8010:127.0.0.1:8010 <utilisateur>@<serveur>
```

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

L'index ATT&CK v20.0 (`backend/stix/reference/attack_v20.sqlite`) est versionné : il n'y a rien à construire pour
commencer. Pour le reconstruire, voir [backend/README.md](backend/README.md#stix--objets-stix-21-et-bases-de-référence).

Après une modification du code Rust :

```bash
cd backend/cti_core && cargo test && maturin develop --release && cd ../..
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

# 2. Extraire les 10 prochains articles CTI vers Neo4j (bundle STIX écrit dans db_outputs/stix_bundles/)
uv run cti-agent --limit 10

# 3. Ouvrir le tableau de bord sur http://localhost:8095
scripts/dashboard.sh

# 4. Mesurer la qualité de l'extraction sur les articles annotés
uv run cti-eval --system agent --run
```

---

## Commandes essentielles

### Preprocessing et classification

```bash
uv run cti-classifier                                   # nettoyage Rust + classification LLM des articles non classés
CTI_CLASSIFIER_WORKERS=3 uv run cti-classifier          # classifications en parallèle (défaut : 2)
uv run cti-audit                                        # interface terminal (Textual) de validation humaine
uv run python backend/preprocessing/evaluate_cleaning.py [--site <source>]   # qualité du nettoyage, sans LLM
```

### Extraction STIX vers Neo4j

`cti-agent` choisit les articles classés *tactical*, *operational* ou *strategic* et pas encore extraits.

```bash
uv run cti-agent --limit 10                             # 10 articles, méthode par défaut (agent à outils)
uv run cti-agent --article-id 1553 --dry-run            # un article, sans écrire dans Neo4j (le bundle est écrit)
uv run cti-agent --article-id 1553 --show-tools --show-log   # chaque appel d'outil, chaque refus de la vérification
uv run cti-agent --closed --article-id 1553 --dry-run   # questions fermées (petits modèles)
uv run cti-agent --fast --article-id 854 --dry-run      # deux appels contraints par partie d'article
uv run cti-agent --limit 5 --force                      # ré-extraire des articles déjà présents dans Neo4j
uv run cti-agent --stats                                # nœuds et relations du graphe par type STIX
```

| Méthode | Option | Principe | Appels au modèle |
| :--- | :--- | :--- | :--- |
| Agent | *(défaut)* | conversation avec outils `search_attack`, `get_attack`, `lookup_name`, `submit` | quelques dizaines de tours par article |
| Fast | `--fast` | le code calcule les techniques candidates, le modèle choisit | 2 par partie (+1 de correction) |
| Closed | `--closed` | questions fermées très courtes, indépendantes, parallélisables | des centaines de petits appels |
| Oneshot | `cti-eval --system oneshot` | l'article entier en un appel, sans décomposition (référence) | 1 (+1 de correction) |

Toutes les méthodes passent par la même vérification STIX et produisent le même format de bundle. Le détail est dans
[backend/README.md](backend/README.md#extracting--extraction-stix).

### Évaluation contre le gold

```bash
uv run cti-eval --system agent --run                    # extrait les articles de Annotations/manifest.json puis score
uv run cti-eval --system closed --run --workers 4       # plusieurs articles à la fois (utile avec vLLM/SGLang)
uv run cti-eval --bundles db_outputs/eval/agent         # re-score des bundles existants, sans appel au modèle
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
uv run python -m backend.stix.attack [chemin/enterprise-attack-20.0.json]   # reconstruire l'index ATT&CK v20.0
uv run python -m backend.stix.galaxy                                         # télécharger l'index MISP Galaxy
uv run python -m backend.extracting.update_ioc_reference                     # TLD IANA et domaines populaires (Tranco)
```

---

## Configuration

Toutes les variables sont lues dans l'environnement du processus (voir `backend/config.py` et `.env.example`).

| Variable | Défaut | Rôle |
| :--- | :--- | :--- |
| `CTI_LLM_BACKEND` | `ollama` | `ollama` ou `openai` (vLLM, SGLang : `/v1/chat/completions`) |
| `OLLAMA_API_URL` | `http://127.0.0.1:11434/api/generate` | point d'entrée Ollama |
| `OLLAMA_MODEL` | `qwen3.8:27b` | modèle Ollama |
| `OLLAMA_NUM_CTX` | `12288` | contexte de **chaque** requête, identique pour tous les clients (sinon Ollama recharge le modèle) |
| `OLLAMA_NUM_PARALLEL` | `1` | slots du serveur Ollama : le client n'envoie jamais plus de requêtes simultanées |
| `CTI_OPENAI_URL` | `http://127.0.0.1:8010/v1` | serveur compatible OpenAI |
| `CTI_OPENAI_MODEL` | `cti-qwen` | nom servi (`--served-model-name`) |
| `CTI_LLM_SLOTS` | `10` | requêtes en vol avec le moteur `openai` |
| `CTI_LLM_TIMEOUT` | `55` (Ollama) / `180` (openai) | délai d'un appel, compté à partir de l'envoi |
| `CTI_THINKING` | `off` | réflexion de Qwen (moteur `openai` seulement) |
| `CTI_CLASSIFIER_WORKERS` | `2` | classifications en parallèle |
| `NEO4J_URI` / `NEO4J_USER` / `NEO4J_PASSWORD` | `bolt://localhost:7687` / `neo4j` / `password123` | connexion Neo4j |

Le débit d'Ollama est constant quel que soit le nombre de requêtes simultanées (il les traite l'une après l'autre) : le
parallélisme n'accélère que les serveurs à traitement par lots (vLLM, SGLang).

---

## Données et sorties

| Emplacement | Contenu | Accès |
| :--- | :--- | :--- |
| `db_outputs/cti_knowledge.db` | `knowledge` (articles bruts), `article_classifications` (catégorie, markdown nettoyé), `site_boilerplate` (gabarits appris) | écrit par `cti-classifier` et `cti-audit` ; **lecture seule** pour l'extraction et le tableau de bord |
| Neo4j `bolt://localhost:7687` | graphe STIX : nœuds `(:Stix:<Type>)`, arêtes typées, provenance par article | **seule** base du graphe de connaissances |
| `db_outputs/stix_bundles/article_<id>.json` | bundle STIX 2.1 complet de chaque extraction (IOC bénins compris) | réécrit à chaque extraction, même en `--dry-run` |
| `db_outputs/eval/<système>/` | bundles de l'évaluation, `report.md`, `report.json` | écrit par `cti-eval` |
| `backend/stix/reference/` | index ATT&CK v20.0 (SQLite FTS5), MISP Galaxy | versionné / reconstruit à la demande |

---

## Tests

```bash
# Python : tous les modules (faux modèle, aucun appel au LLM ni à Neo4j)
uv run python -m unittest tests.test_segment tests.test_iocs tests.test_rules tests.test_attack_kb \
  tests.test_stix_agent tests.test_fast_extract tests.test_closed_extract tests.test_llm tests.test_llm_openai \
  tests.test_evaluation tests.test_stix_dashboard tests.test_prompt_leakage

# Frontend : layouts, organigramme, filtres, aucun innerHTML sur du texte d'article
cd frontend && npm test

# Moteur Rust
cd backend/cti_core && cargo test
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
