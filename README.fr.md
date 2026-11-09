# CTI Knowledge Graph

Ce projet transforme des articles bruts de **Cyber Threat Intelligence** (rapports d'éditeurs, blogs de recherche) en un
**graphe de connaissances STIX 2.1** stocké dans **Neo4j**, puis l'expose dans un tableau de bord Web.

Le principe directeur : **le code vérifie, le modèle de langage décide du sens, la bibliothèque `stix2` valide.** Un LLM
local (famille Qwen) répond en lignes courtes sous schéma JSON : entités, techniques ATT&CK, relations entre éléments
numérotés, preuves par numéro de phrase. Tout ce qu'il propose est créé par `stix2` en mode strict, confronté à
MITRE ATT&CK v20.0 et au texte de l'article avant d'entrer dans le graphe. Les valeurs d'IOC (IP, domaines, hachages) ne
sont jamais générées par le modèle : elles sont lues par des règles.

```text
 articles scrappés            nettoyage + triage                 extraction STIX                    persistance + visualisation
┌──────────────────┐   ┌──────────────────────────────┐   ┌───────────────────────────────┐   ┌─────────────────────────────┐
│ SQLite           │   │ cti_core (Rust) : bruit web,  │   │ phrases numérotées            │   │ Neo4j (:Stix:<Type>)        │
│ table `knowledge`│──▶│ gabarit appris par source,    │──▶│ entités, techniques ATT&CK,   │──▶│ bundle STIX 2.1 par article │
│ + page HTML brute│   │ refang des IOC                │   │ relations (preuve = n° phrase)│   │ tableau de bord React       │
│                  │   │ LLM : tactique / opérationnel │   │ IOC et règles YARA/Sigma      │   │ (rapports, acteurs, graphe  │
│                  │   │ / stratégique / hors sujet    │   │ vérification stix2 + ATT&CK   │   │  global, questions au LLM)  │
└──────────────────┘   └──────────────────────────────┘   └───────────────────────────────┘   └─────────────────────────────┘
                          uv run cti-classifier              uv run cti-extract                  scripts/dashboard.sh
```

Le dépôt contient aussi un **jeu d'articles annotés à la main** (`Annotations/`) et un outil de score (`cti-eval`) pour
mesurer rappel, précision et hallucinations de l'extraction.

---

## Sommaire

1. [Architecture du dépôt](#1-architecture-du-dépôt)
2. [Installation complète depuis zéro](#2-installation-complète-depuis-zéro)
3. [Le nettoyage (preprocessing) en détail](#3-le-nettoyage-preprocessing-en-détail)
4. [L'extraction STIX en détail](#4-lextraction-stix-en-détail)
5. [Persistance, tableau de bord et évaluation](#5-persistance-tableau-de-bord-et-évaluation)
6. [Commandes essentielles](#6-commandes-essentielles)
7. [Configuration (variables d'environnement)](#7-configuration-variables-denvironnement)
8. [Données et sorties](#8-données-et-sorties)
9. [Dépannage](#9-dépannage)
10. [Règles métier](#10-règles-métier)

| Documentation détaillée | Contenu |
| :--- | :--- |
| [backend/README.md](backend/README.md) | Flux de données, rôle de chaque module, modèle Neo4j, API REST, évaluation |
| [frontend/README.md](frontend/README.md) | Vues, composants, contrat d'API, conventions visuelles et de sécurité |
| [Annotations/methode_annotation.md](Annotations/methode_annotation.md) | Méthode d'annotation du gold et règles de score |

---

## 1. Architecture du dépôt

```text
.
├── backend/
│   ├── preprocessing/
│   │   ├── cleaning/
│   │   │   ├── cleaner.py          # façade Python de cti_core : gabarit par source, découpage, contexte du classifieur
│   │   │   ├── cti_core/           # moteur déterministe en Rust (PyO3) : HTML -> Markdown canonique
│   │   │   │   └── src/{lib.rs, html.rs, tests.rs}
│   │   │   └── text/               # partagé par extraction, STIX et évaluation
│   │   │       ├── evidence.py     #   noms normalisés, ancrage des citations, confiance, dates
│   │   │       └── segment.py      #   phrases numérotées (la preuve d'une relation est un numéro de phrase)
│   │   └── classifying/
│   │       ├── cti_classifier.py   # nettoyage + classification LLM (Ollama)
│   │       ├── audit_classifier.py # interface terminal (Textual) de validation humaine
│   │       └── evaluate_cleaning.py# rapport qualité du nettoyage, sans LLM
│   ├── extracting/
│   │   ├── cli.py                  # `cti-extract`
│   │   ├── runner.py               # lot d'articles (cti-extract et cti-eval) : --workers, un seul fil écrit Neo4j
│   │   ├── pipeline.py             # extraction d'un article, de la phrase numérotée au graphe vérifié
│   │   ├── agents.py               # micro-agents de perception (menace, cibles, TTP, porteur, relations)
│   │   ├── llm.py                  # client vLLM : sortie contrainte, slots, journal des appels
│   │   ├── graph/                  # draft.py (DraftGraph : vérification stix2 + ATT&CK), places.py (lieux -> ISO 3166-1)
│   │   ├── observables/            # iocs.py (IOC), rules.py (YARA/Sigma), update_reference.py (TLD, domaines populaires)
│   │   └── stix/                   # objets STIX 2.1, index SQLite FTS5 d'ATT&CK v20.0
│   ├── evaluation/                 # score.py, cti_eval.py ; eval/ (hors git) : un dossier par exécution
│   ├── database/                   # neo4j_store.py (connexion), stix_store.py (graphe STIX, provenance par article)
│   ├── dashboard/                  # server.py (API REST + SSE), stix_dashboard.py (Neo4j -> JSON), ask.py (questions au graphe)
│   ├── config.py                   # seul endroit qui définit chemins de données et serveurs LLM
│   └── data/                       # hors git : sources/, raw/html_pages/, cleaned/, bundles/
├── frontend/                       # React 18 + TypeScript + Tailwind + React Flow 12 + sigma.js (Vite)
├── Annotations/                    # gold STIX annoté à la main, manifest.json, méthode d'annotation, holdout/
├── scripts/dashboard.sh            # build du frontend si besoin + lancement du serveur
├── docker-compose.yml, Dockerfile  # Neo4j 5 Community (APOC, n10s)
├── .env.example                    # variables des clients LLM
└── pyproject.toml                  # dépendances Python et commandes CLI (uv)
```

---

## 2. Installation complète depuis zéro

Le système a **trois briques** à installer : (A) la machine de développement qui exécute ce dépôt, (B) la base Neo4j,
(C) les serveurs d'inférence LLM, qui tournent en général sur une **autre machine** (un serveur GPU) jointe par tunnel SSH.

```text
 poste de travail (ce dépôt)                          serveur GPU
┌────────────────────────────────┐   tunnel SSH   ┌──────────────────────────────────────┐
│ cti-classifier ───────────────────:11434 ───────▶│ Ollama  qwen3.8:27b   (classification)│
│ cti-extract / cti-eval / dashboard ─:8010 ───────▶│ vLLM    cti-qwen      (extraction)    │
│ Neo4j (Docker) :7687               │               └──────────────────────────────────────┘
│ dashboard :8095                    │
└────────────────────────────────┘
```

### 2.1 Matériel et logiciels requis

| Brique | Minimum | Remarques |
| :--- | :--- | :--- |
| Poste de travail | Linux/macOS, 8 Go de RAM, ~5 Go de disque | Python 3.12, Rust, Node.js ≥ 20, Docker |
| Serveur GPU (extraction) | 1 GPU NVIDIA, **≥ 40 Go de VRAM** (A100 40 Go validé), pilote CUDA récent | le modèle INT4 (~15-20 Go) + le cache KV pour des articles de 32k tokens |
| Serveur GPU (classification) | peut être le même GPU | Ollama et vLLM partagent la machine, pas forcément le GPU : voir 2.5 |
| Données | une base SQLite d'articles + leurs pages HTML | produites par le scraping, **qui n'est pas dans ce dépôt** (voir 2.7) |

### 2.2 Poste de travail : dépôt, Python, Rust, Node

```bash
# Outils système (exemple Debian/Ubuntu)
sudo apt install -y build-essential pkg-config libssl-dev git curl

# uv (gestionnaire Python), Rust (compilation de cti_core), Node.js >= 20
curl -LsSf https://astral.sh/uv/install.sh | sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# Node.js : via nvm, fnm ou le gestionnaire de paquets de votre système (version >= 20)

git clone https://github.com/Falsimane/article_classification.git
cd article_classification

# Dépendances Python (3.12) + compilation de l'extension Rust cti_core (installée en mode éditable)
uv sync

# Vérification du moteur de nettoyage
uv run python -c "import cti_core; print(cti_core.CtiEngine())"
```

`uv sync` compile `backend/preprocessing/cleaning/cti_core` (PyO3) : si `cargo` est absent, la compilation échoue. Après
une modification du code Rust :

```bash
cd backend/preprocessing/cleaning/cti_core
cargo test
maturin develop --release
cd ../../../..
```

### 2.3 Neo4j (Docker)

```bash
docker compose up -d neo4j        # Neo4j 5 Community + plugins APOC et n10s
docker compose ps                 # attendre « healthy »
```

- Neo4j Browser : <http://localhost:7474>, Bolt : `bolt://localhost:7687`.
- Identifiants par défaut : `neo4j` / `password123`. Pour les changer, exporter `NEO4J_AUTH=neo4j/<mot_de_passe>` **avant**
  le premier `docker compose up`, puis `NEO4J_PASSWORD=<mot_de_passe>` pour le code Python.
- Les données vivent dans les volumes Docker `cti_neo4j_data`, `cti_neo4j_logs`, `cti_neo4j_plugins`.

### 2.4 Serveur GPU : vLLM pour l'extraction

C'est le serveur qui fait **tout le travail d'extraction** (entités, techniques, relations, vérification). Il doit
exposer l'API OpenAI (`/v1/chat/completions`) sur le port `8010`.

**Modèle utilisé.** `ukisai/Swift-1.5-Qwen3.8-27b-W4A16-AWQ` : un dérivé de **Qwen3.8-27B** à réflexion bridée, quantifié
en INT4 (W4A16, AWQ), qui tient sur un A100 40 Go avec un grand cache KV (~238 000 tokens, soit environ 7 articles de 32k
tokens en parallèle). Il est servi sous le nom `cti-qwen`, que le client attend par défaut. Les scores de référence du
dépôt (voir section 5) sont mesurés avec ce modèle.

| Modèle | Rôle | Remarque |
| :--- | :--- | :--- |
| `ukisai/Swift-1.5-Qwen3.8-27b-W4A16-AWQ` | **extraction (référence actuelle)** | licence gratuite sous 1 M$ de chiffre d'affaires ; ~7 requêtes de 32k simultanées |
| `Qwen/Qwen3.8-27B-FP8` | alternative officielle | poids FP8 via Marlin sur A100 ; seulement ~49 000 tokens de cache KV sur 40 Go : 2 requêtes à la fois au plus |
| un modèle 9B | écarté | jugé trop faible pour l'extraction |

**Installation de vLLM** (sans droits administrateur, dans un environnement isolé) :

```bash
# Sur le serveur GPU
python3 -m venv ~/vllm-env            # ou : uv venv ~/vllm-env --python 3.12
source ~/vllm-env/bin/activate
pip install --upgrade pip
pip install vllm                       # version validée : 0.32.0 ; installe aussi torch, flashinfer…
nvidia-smi                             # vérifier le pilote et choisir le GPU libre (son numéro sert plus bas)
```

**Lancement** (à adapter : le numéro de GPU, le port s'il est pris) :

```bash
source ~/vllm-env/bin/activate

CUDA_VISIBLE_DEVICES=1 vllm serve ukisai/Swift-1.5-Qwen3.8-27b-W4A16-AWQ \
  --served-model-name cti-qwen \
  --host 127.0.0.1 --port 8010 \
  --language-model-only \
  --max-model-len 32768 \
  --gpu-memory-utilization 0.92 \
  --max-num-seqs 8 \
  --reasoning-parser qwen3 \
  --enable-auto-tool-choice --tool-call-parser qwen3_coder
```

Ce que fait chaque option, et pourquoi elle est obligatoire ou recommandée :

| Option | Rôle |
| :--- | :--- |
| `CUDA_VISIBLE_DEVICES=1` | **à toujours fixer** : sans elle vLLM prend le GPU 0, parfois occupé par quelqu'un d'autre, et le moteur échoue à l'initialisation. Ne jamais utiliser le GPU d'un tiers sans son accord. |
| `--served-model-name cti-qwen` | nom que le client envoie (`CTI_OPENAI_MODEL`) |
| `--port 8010` | port attendu par défaut (`CTI_OPENAI_URL`) ; à changer des deux côtés si le 8010 est pris |
| `--host 127.0.0.1` | le serveur n'est joignable que par le tunnel SSH, jamais exposé sur le réseau |
| `--language-model-only` | ne charge pas la partie vision du modèle (VRAM économisée) |
| `--max-model-len 32768` | **l'article entier est envoyé en un appel** : le contexte doit le contenir. Un article plus long est refusé par le serveur et marqué en échec avec sa raison. |
| `--gpu-memory-utilization 0.92` | part de la VRAM réservée aux poids et au cache KV |
| `--max-num-seqs 8` | requêtes simultanées du serveur ; `CTI_LLM_SLOTS` côté client doit être **égal ou inférieur** |
| `--reasoning-parser qwen3` | sépare le texte de réflexion de la réponse (la réflexion est coupée par défaut côté client) |
| `--enable-auto-tool-choice --tool-call-parser qwen3_coder` | **obligatoires** : l'analyseur d'appels d'outils de la famille Qwen ; sans eux, les tours avec outils sont refusés (erreur HTTP) |

Le préfixe de cache (`enable-prefix-caching`) est actif par défaut dans vLLM : les appels d'extraction d'un même article
commencent tous par le même texte, que le serveur relit depuis le cache au lieu de le recalculer. C'est ce qui rend les
étapes successives presque gratuites en lecture.

**Premier démarrage** : compter environ 4 minutes (téléchargement des poids Hugging Face, `torch.compile`, JIT de
flashinfer). Si la compilation de flashinfer pose problème :

```bash
export VLLM_USE_FLASHINFER_SAMPLER=0
```

Lancer le serveur dans `tmux`/`screen` (ou un service systemd) pour qu'il survive à la déconnexion SSH.

**Test de cohérence à faire avant tout benchmark** (un modèle mal chargé répond sans erreur mais ne lit pas le texte) :

```bash
curl -s http://127.0.0.1:8010/v1/chat/completions -H 'Content-Type: application/json' -d '{
  "model": "cti-qwen",
  "messages": [{"role": "user", "content": "Combien font 17 x 23 ? Réponds par le nombre seul."}],
  "max_tokens": 16, "temperature": 0
}'
# attendu : 391
```

**Alternative : serveur Hugging Face derrière un proxy ou hors ligne.** Télécharger le modèle une fois
(`huggingface-cli download ukisai/Swift-1.5-Qwen3.8-27b-W4A16-AWQ`) puis lancer `HF_HUB_OFFLINE=1 vllm serve …`.

### 2.5 Serveur GPU : Ollama pour la classification

La classification (`cti-classifier`) utilise Ollama, avec un seul modèle et **un seul contexte**.

```bash
# Sur le serveur GPU
curl -fsSL https://ollama.com/install.sh | sh        # ou l'installation sans root de votre site
ollama pull qwen3.8:27b

# Un seul num_ctx pour toutes les requêtes : deux valeurs différentes forcent Ollama à recharger le modèle
OLLAMA_CONTEXT_LENGTH=12288 OLLAMA_HOST=127.0.0.1:11434 ollama serve
```

Le client envoie `num_ctx` = `OLLAMA_NUM_CTX` (12288 par défaut) : `OLLAMA_CONTEXT_LENGTH` du serveur doit avoir la **même**
valeur. Un contexte dépassé fait tronquer le *début* du prompt par Ollama, donc le prompt système.

> **Mémoire GPU.** vLLM (réservation de 92 % de la VRAM) et Ollama ne tiennent pas ensemble sur un même GPU de 40 Go.
> Soit les deux tournent sur des GPU différents (`CUDA_VISIBLE_DEVICES`), soit on classe d'abord (Ollama), on l'arrête
> (`ollama stop qwen3.8:27b`), puis on lance vLLM pour l'extraction. Les deux étapes ne sont pas simultanées.

### 2.6 Tunnels SSH et variables d'environnement

Les scripts n'envoient que des requêtes HTTP sur `localhost` ; les serveurs sont joints par tunnel. **Ne jamais exécuter
`ollama`, `vllm` ou `systemctl` depuis le poste de travail** : ce sont des commandes du serveur.

```bash
# Poste de travail : deux tunnels, un par serveur (laisser tourner, ou ajouter -f pour l'arrière-plan)
ssh -N -L 8010:127.0.0.1:8010   <utilisateur>@<serveur-gpu>     # vLLM : extraction
ssh -N -L 11434:127.0.0.1:11434 <utilisateur>@<serveur-gpu>     # Ollama : classification

curl -s http://127.0.0.1:8010/v1/models | head -c 300          # doit lister « cti-qwen »
curl -s http://127.0.0.1:11434/api/tags | head -c 300          # doit lister « qwen3.8:27b »
```

Variables d'environnement (aucun chargement automatique d'un fichier `.env` : il faut l'exporter) :

```bash
cp .env.example .env            # puis adapter
set -a && source .env && set +a
```

Valeurs importantes, déjà par défaut dans `.env.example` :

```bash
CTI_OPENAI_URL=http://127.0.0.1:8010/v1
CTI_OPENAI_MODEL=cti-qwen
CTI_LLM_SLOTS=8                 # <= --max-num-seqs de vLLM (le défaut du code est 10 : le baisser à 8 avec le serveur ci-dessus)
OLLAMA_API_URL=http://127.0.0.1:11434/api/generate
OLLAMA_MODEL=qwen3.8:27b
OLLAMA_NUM_CTX=12288
```

> **Règle des slots.** Ne jamais envoyer plus de requêtes simultanées que de slots : derrière un tunnel SSH, une requête
> abandonnée par le client continue d'occuper le serveur. `llm.py` attend un slot libre avant d'envoyer. Même règle pour
> `--workers` des CLI : chaque article en parallèle consomme plusieurs slots.

### 2.7 Données d'entrée

Le pipeline attend deux choses sous `backend/data/` (dossier hors git, déplaçable avec `CTI_DATA_DIR=/chemin`) :

```text
backend/data/
├── sources/cti_knowledge.db          # SQLite : table `knowledge` (id, site_name, url, title, publication_date, content)
└── raw/html_pages/<site>/<sha1(url)[:16]>.html   # la page HTML brute de chaque article
```

Le **nettoyage lit la page HTML, jamais le champ `content`** (un export Markdown a déjà perdu les liens, les blocs de code
et ce qui est caché). Le nom du fichier est `sha1(url)[:16]` ; `cleaner.page_id()` le calcule. Le scraping qui remplit ces
deux emplacements n'est pas dans ce dépôt.

### 2.8 Index ATT&CK et frontend

```bash
# L'index ATT&CK v20.0 (SQLite FTS5) est versionné : rien à faire pour commencer.
# Reconstruction, seulement depuis le bundle officiel enterprise-attack-20.0.json (52 Mo, hors git) :
uv run python -m backend.extracting.stix.attack Annotations/enterprise-attack-20.0.json

# Frontend (fait aussi automatiquement par scripts/dashboard.sh)
cd frontend && npm install && npm run build && cd ..
```

### 2.9 Vérification de bout en bout

```bash
uv run cti-extract --stats                       # Neo4j joignable : compteurs (vides au début)
uv run python backend/preprocessing/classifying/evaluate_cleaning.py   # nettoyage sans LLM, sur le corpus présent
uv run cti-classifier --reclean                  # (si des articles sont déjà classés) recalcule le texte nettoyé, sans LLM
uv run cti-extract --limit 1 --dry-run --show-log   # extraction d'un article sans écrire dans Neo4j
scripts/dashboard.sh                             # http://localhost:8095
```

---

## 3. Le nettoyage (preprocessing) en détail

**But :** passer d'une page HTML brute (menus, bannières, boutons sociaux, formulaires, cookies, pieds de page) à un
**Markdown canonique** qui ne contient que l'article, avec ses blocs de code, ses tables et ses IOC intacts et à leur
place. Puis classer l'article (tactique, opérationnel, stratégique, hors sujet).

```text
page HTML ──▶ cti_core.process_html ──▶ Markdown canonique ──▶ découpage en blocs ──▶ contexte budgété ──▶ LLM (Ollama)
 (disque)      (Rust, structurel)        + sections             (atomiques)                                  │
     ▲                │                                                                                     ▼
     │      gabarit appris par source                                                       article_classifications (SQLite)
     └───── site_boilerplate (corpus entier) ◀── learn_site_boilerplate                      clean_markdown, catégorie, scores
```

### 3.1 Principes

- **Universel.** Aucune liste d'éditeurs, d'acteurs ou d'outils dans le moteur. Le bruit est reconnu par **structure** dans le
  DOM, puis par **apprentissage du gabarit de chaque source** sur le corpus.
- **Atomique.** Un bloc de code, une table ou un paragraphe n'est jamais déplacé ni coupé.
- **Fidèle.** Aucune extraction d'entités ni d'IOC dans cette étape : les IOC restent dans le récit, à leur place.
- **Déterministe.** Le moteur est du Rust sans modèle : le même HTML donne toujours le même texte.

### 3.2 Le moteur Rust `cti_core` (`backend/preprocessing/cleaning/cti_core/`)

Extension Python native (PyO3, compilée par `uv sync`) exposant la classe `CtiEngine`. `html.rs` fait le DOM, `lib.rs` le
Markdown, les sections et le découpage ; `tests.rs` contient les tests (`cargo test`).

**Étape 1 : fast-reject** (`check_viability`). Une page vide, une coquille ou une **page d'erreur de scraping** (document
court contenant « access denied », « 403 forbidden », « just a moment », « enable javascript », captcha, etc.) est refusée
avec une raison (`reject_reason`) et ne coûte aucun appel au LLM.

**Étape 2 : HTML vers blocs** (`html.rs`). Le DOM porte ce qu'un export Markdown perdait : ce qui est un lien et où il
pointe, ce qui est du code, une table, un titre, un élément caché. Le bruit est retiré ainsi :

| Mécanisme | Ce qui est retiré ou décidé |
| :--- | :--- |
| Éléments jamais lus | `script`, `style`, formulaires, navigation, médias… |
| Éléments cachés | attributs `hidden`, styles `display:none`, etc. |
| Frontières de streaming React | `<template id="B:n">` est remplacé par le contenu de `<div hidden id="S:n">` (la page est rendue côté serveur par morceaux) |
| Navigation | un bloc fait de liens internes sans prose ; un titre qui est un lien vers une autre page du site |
| Racine du contenu | on descend vers l'enfant qui porte au moins 85 % du texte hors liens, tant que ce qui est laissé de côté ne porte rien de technique (code, table, IOC) ; un frère avec ≥ 12 mots de prose bloque la descente |
| Gabarits d'écriture non échappés | `cmd /c <command>`, `.[<victim_id>]` : une balise inconnue sans tiret est rendue **telle qu'écrite**, pas supprimée |
| Ancres d'IOC | une ancre d'au plus 4 mots qui porte un IOC **est** l'indicateur lui-même |
| Shortcodes | `[nom clé="…"]…[/nom]` laissés par un constructeur de pages |

**Étape 3 : passes communes** (`finish`). Doublons, métadonnées d'en-tête, rognage de la tête et de la queue, titres
orphelins ; puis rendu du Markdown canonique (titres `#`, paragraphes, listes `- `, code clôturé, tables `|`) et découpage
en **sections** (`ArticleSection` : titre, niveau, contenu, `heading_path` « H1 > H2 > H3 », blocs atomiques,
`is_appendix_ioc`).

**Étape 4 : dé-neutralisation** (`refang`). Les IOC défanguées sont rétablies, hors blocs de code : `hxxp` → `http`,
`example[.]com`, `example(dot)com`, `user[at]example.com`, `domaine.]com`, `domaine[.com`.

### 3.3 Le gabarit appris par source (`cleaner.py`)

Un menu, une bannière ou un appel à l'action reviennent identiques d'une page à l'autre d'un même éditeur. Le moteur les
repère **par le corpus**, sans liste :

- `html_template_keys` : chaque page donne des clés « chemin de balises + texte normalisé » pour ses blocs feuilles
  (jamais un titre, du code, une table ni un texte portant un IOC).
- Une clé présente dans **≥ 40 %** des pages d'une source (au moins **5 pages**) est du gabarit.
- Une **phrase entière** (≥ 6 mots) reprise mot pour mot dans **≥ 15 %** des articles l'est aussi (encart promotionnel d'une
  période) ; un texte plus court peut être un intitulé de section (« Indicators of compromise ») et garde le seuil de 40 %.
- Les clés apprises sont persistées dans la table `site_boilerplate` de SQLite et **relues à chaque lancement** de
  `cti-classifier` ; `learn_site_boilerplate` les ré-apprend sur tout le corpus.
- Tant qu'une source a moins de 5 pages, son gabarit est vide : seule la détection structurelle agit.
- Une source sans `site_name` est identifiée par le domaine de l'URL (`site_key`).

### 3.4 Découpage et sections

- `split_blocks` : blocs du document dans l'ordre (`heading`, `code`, `table`, `text`) avec leur chemin de titres. C'est ce
  qui permet à l'extraction de **numéroter des phrases** sans réimplémenter l'analyse Markdown.
- `chunk` / `chunk_markdown(max_chars)` : segments **sans recouvrement** (donc aucun IOC dupliqué), jamais coupés dans un bloc
  de code, une table ou un paragraphe ; chaque titre reste avec son premier bloc ; `oversized` signale un bloc seul plus grand
  que le budget.
- Les phases d'intrusion sont déduites des titres de section par mot entier (`KNOWN_PHASES` : initial access, execution,
  persistence… détection YARA/Sigma, indicateurs).

### 3.5 Classification (`cti_classifier.py`)

Le classifieur n'envoie **jamais l'article entier** : `build_classifier_context` construit une vue compacte et budgétée,
qui garde le prompt court et stable :

```text
TITLE: …
STRUCTURE: <n> sections, <n> chars, <n> code blocks, <n> tables [, <n> indicator-list sections]
OUTLINE: plan complet (titres)
TEXT (excerpts, in reading order): introduction + un échantillon de prose par section + conclusion
                                   [omitted: code×2, table×1]   ← le code et les tables ne sont pas envoyés, seulement signalés
```

Si l'article a trop de sections pour le budget, un sous-ensemble réparti sur tout le document est échantillonné plutôt que de
couper la fin. Le modèle (Ollama, `qwen3.8:27b`, 160 tokens de sortie maximum) répond en JSON :

```json
{"evidence": "<= 20 mots, l'indice principal", "category": "operational|tactical|strategic|out_of_scope", "confidence": "high|medium|low"}
```

| Catégorie | Contenu |
| :--- | :--- |
| `operational` | une intrusion ou campagne concrète racontée dans l'ordre (rapports DFIR, chronologie) |
| `tactical` | comment fonctionne ou se détecte une technique, un outil, un malware, une vulnérabilité |
| `strategic` | tendances, géopolitique, rapports de secteur ou annuels, peu de détail technique |
| `out_of_scope` | pas de CTI : marketing, webinaires, offres d'emploi, conseils génériques, pages vides ou d'erreur |

La confiance devient un score (`high` 0,9, `medium` 0,7, `low` 0,5) ; la catégorie retenue reçoit ce score, les autres 0.
Tout est écrit dans la table **`article_classifications`** (`primary_category`, `score_*`, `rationale`, **`clean_markdown`**,
`sections_meta`, `is_processable`, `reject_reason`, `human_category`). **`clean_markdown` en SQLite est la source du texte
nettoyé** ; `backend/data/cleaned/<site>/<hash>.md` n'en est qu'une copie lisible.

Seuls les articles `tactical`, `operational` et `strategic` sont éligibles à l'extraction.

### 3.6 Audit humain et qualité

```bash
uv run cti-audit                                                       # interface terminal (Textual) : corriger la catégorie (human_category)
uv run python backend/preprocessing/classifying/evaluate_cleaning.py [--site <source>]
```

`evaluate_cleaning.py` mesure, **sans LLM**, la fidélité des IOC (tous ceux du texte visible de la page sont-ils dans le
texte nettoyé ?), les résidus de bruit et les sources sans gabarit connu. **À lancer avant d'ingérer une nouvelle source.**

### 3.7 Commandes

```bash
uv run cti-classifier                           # nettoie (depuis la page HTML) et classe les articles non classés
CTI_CLASSIFIER_WORKERS=3 uv run cti-classifier  # classifications en parallèle (défaut 2)
uv run cti-classifier --reclean                 # recalcule seulement le texte nettoyé des articles déjà classés, sans LLM
```

Après un changement du moteur Rust ou du gabarit, `--reclean` met à jour la base et `data/cleaned/` sans reclasser.

---

## 4. L'extraction STIX en détail

**But :** à partir du texte nettoyé, produire un **bundle STIX 2.1** fiable : entités (acteurs, malwares, outils, victimes,
lieux, vulnérabilités), techniques MITRE ATT&CK, relations typées, IOC et règles de détection. Chaque relation est **prouvée
par des numéros de phrases** dont le texte est relu par le code.

### 4.1 Idées de conception

1. **Le modèle écrit peu, le code vérifie tout.** Le coût est dominé par les tokens **générés** ; la lecture du prompt est
   quasi gratuite quand il commence comme le précédent (cache de préfixe). Tous les appels commencent donc par le **même
   texte d'article**, et le modèle n'écrit que des lignes courtes.
2. **Sortie contrainte.** `llm.generate` impose un schéma JSON ; chaque réponse est une ou plusieurs lignes `a|b|c`.
3. **Preuve = numéro de phrase.** `segment.py` découpe l'article en unités numérotées. Une relation cite `12,13` au lieu de
   recopier une phrase : le texte de la preuve est exact par construction (zéro token, zéro hallucination de citation).
   Les blocs de code et tables restent des unités entières mais seul un extrait (8 lignes de code, 14 lignes de table,
   700 caractères par phrase) est montré au modèle ; le texte complet reste disponible comme preuve.
4. **Une technique ATT&CK existe toujours.** Elle n'est jamais écrite de mémoire : le code propose des candidates, le modèle
   choisit par lettres.
5. **Le LLM décide du sens, jamais une règle** : pas de règle déterministe pour typer ou juger un nom ; le code propose,
   borne et informe.
6. **Les IOC sont lus par des règles.** Le modèle ne choisit que leur rôle et l'entité de rattachement.

### 4.2 Vue d'ensemble du pipeline (`pipeline.py`, `extract_article`)

```text
clean_markdown
  │ segment.py : phrases numérotées (Unit)
  ▼
1. PERCEPTION, en parallèle (micro-agents, agents.py)             préfixe commun : l'article entier
   ├─ ThreatModelerAgent     acteurs, campagnes, malwares, outils
   ├─ TargetSpecialistAgent  victimes, secteurs, pays, logiciels visés, CVE
   └─ TTPHunterAgent         comportements : « phrases | outil | action et but | tactique | T#### présumé »
  ▼
   declare_entities : registre canonique des entités (DraftGraph) ; CVE relues par règle dans le texte
  ▼
2. TECHNIQUES : find_candidates (recherche ATT&CK FTS5) ─▶ appel de choix par lots (lettres) ─▶ accept_choices
   │ porteur de chaque technique : CarrierDisambiguationAgent (malware > outil > campagne > groupe)
  ▼
3. RELATIONS : RelationWeaverAgent (numéro source|relation|numéro cible|phrases)
   │ appel de correction pour les lignes refusées ; appel pour relier les « îlots » (composantes isolées)
  ▼
4. VÉRIFICATION : le modèle juge chaque relation contre le texte (o / n) ; les non étayées sont retirées,
   │ avec les entités qui n'ont plus aucune relation
  ▼
5. OBSERVABLES : IOC (règles + rôle/rattachement par le modèle) et règles YARA / Sigma (analyse syntaxique)
  ▼
DraftGraph ─▶ bundle sémantique article_<id>.json  +  bundle observables article_<id>.iocs.json ─▶ Neo4j
```

Les étapes sont des **appels contraints** séparés ; une étape qui échoue marque l'article `llm_failures > 0` dans Neo4j, et
il est **repris au lancement suivant**.

### 4.3 Étape 1 : entités et comportements

Trois micro-agents (`CTI_MULTI_AGENT=on`, défaut) lisent l'article en parallèle, avec le même préfixe de prompt :

| Agent | Extrait |
| :--- | :--- |
| `ThreatModelerAgent` | `intrusion-set`, `threat-actor`, `campaign`, `malware`, `tool` |
| `TargetSpecialistAgent` | `identity` (victimes, secteurs), `location` (pays visés), `software` (produit visé), `vulnerability` (CVE) |
| `TTPHunterAgent` | un comportement de l'attaquant par ligne, décrit en anglais, avec les numéros de phrases et un identifiant ATT&CK présumé. `CTI_MULTI_TEMP` : union de générations à T=0,2 et T=0,7 pour le rappel |

Les entités déclarées passent par `DraftGraph.declare` : nom normalisé (`« <malware> (<fichier> ) »` devient nom + alias),
type STIX vérifié par `stix2`, doublons fusionnés. Les lieux sont résolus en **code ISO 3166-1 ou région STIX** (`places.py`) ;
un lieu non résolu est refusé. Les CVE sont relues **par règle** dans le texte, pas par le modèle.

### 4.4 Étape 2 : techniques ATT&CK choisies, jamais inventées

1. **Recherche** (`find_candidates`, `stix/attack.py`) : pour chaque comportement, SQLite **FTS5** interroge l'index ATT&CK
   v20.0 par deux recherches BM25 fusionnées (RRF) : l'une sur le nom et la description des techniques, l'autre sur leurs
   **17 636 exemples de procédures** (« APT29 used systeminfo to… »), meilleur pont lexical entre un article et ATT&CK. Les
   procédures citant **l'article lui-même** (`report_key`) sont écartées : sinon la recherche retrouverait une paraphrase de
   l'article. `CTI_CANDIDATES` (6 par défaut) fixe le nombre de candidates, plus l'identifiant présumé et sa technique parente.
2. **Choix** : un appel contraint par lot (`CHOICE_BATCH`) montre à chaque comportement ses candidates avec leur définition ;
   le modèle répond par lettres. Une technique retenue existe donc toujours dans ATT&CK, avec son identifiant et son nom.
3. **Porteur** : `CarrierDisambiguationAgent` désigne l'entité qui exécute le comportement, avec une convention stricte :
   un malware ou un outil nommé d'abord, puis une campagne, et un groupe seulement si aucune entité d'exécution n'est
   mentionnée. Le code crée la relation `uses`, dont la description est le comportement décrit en anglais (la procédure).

### 4.5 Étape 3 : relations

`RelationWeaverAgent` reçoit l'article et la **liste numérotée** des entités et techniques retenues (« registre canonique ») et
répond `numéro source|relation|numéro cible|numéros de phrases`. Chaque ligne passe par `DraftGraph.relate` :

- le type de relation doit exister dans la table `RELATIONS` (`stix/objects.py`) pour ce couple de types STIX ;
- `stix2` crée l'objet en mode strict ; les phrases citées doivent exister et mentionner les deux extrémités quand c'est exigé ;
- les lignes refusées sont renvoyées au modèle **une fois** avec la raison du refus ; un dernier appel relie les **îlots**
  (composantes sans lien) : le modèle relie, le code ne fait que repérer.

### 4.6 Étape 4 : vérification

Le modèle juge chaque relation acceptée contre les phrases citées (`o` / `n`, par lots de 40). Les relations non étayées sont
retirées, et avec elles les entités qui n'ont plus de relation (sauf `CTI_KEEP_ORPHANS=on`). Mesuré : le vérificateur retire
environ 30 relations par exécution, presque toutes absentes du gold.

### 4.7 Étape 5 : observables (couche détection)

Séparée de la couche sémantique et de son évaluation :

- **IOC** (`observables/iocs.py`) : hachages, IP, domaines (TLD réels de la liste IANA, pas une extension de fichier),
  URL, courriels, lus **par règles** dans le texte, en place. Sont écartés : les hôtes de l'éditeur de l'article, les domaines
  populaires (Tranco), les URL non malveillantes. Le modèle ne choisit que le **rôle** et l'**entité de rattachement** ;
  un IOC jugé non malveillant est écarté. Chaque IOC reçoit la date d'observation de son unité de texte si elle est unique et
  plausible.
- **Règles** (`observables/rules.py`) : règles **YARA** (`yara-python`, analyse syntaxique) et **Sigma** (YAML) copiées telles
  qu'écrites ; le modèle ne choisit que l'entité détectée. Le texte d'une règle n'est jamais compté comme liste d'IOC.
- Mise à jour des listes de référence : `uv run python -m backend.extracting.observables.update_reference`.

### 4.8 Le client LLM (`llm.py`)

- **Sortie contrainte** par schéma JSON (`generate`), décodage **déterministe** par défaut (température 0, `top_k` 1, graine
  fixe), réflexion coupée par défaut (`CTI_THINKING=off`).
- **Slots** : `CTI_LLM_SLOTS` requêtes en vol au plus ; `map_parallel` attend un slot libre avant d'envoyer.
- **Délai** par appel : `CTI_LLM_TIMEOUT` (180 s) ; la connexion est fermée au-delà pour que le serveur abandonne la génération.
- **Journal** : `--llm-log` écrit chaque échange dans `article_<id>.llm.jsonl` (et la génération en direct dans
  `.live.log`) ; `cti-eval` l'écrit toujours.
- **Tokens** comptés par le serveur lui-même.

### 4.9 Sorties d'un article

| Fichier / base | Contenu |
| :--- | :--- |
| `backend/data/bundles/article_<id>.json` | **couche sémantique** : rapport, entités, techniques, relations ; ce que décrivent les gold, ce que note `cti-eval` |
| `backend/data/bundles/article_<id>.iocs.json` | **couche observables** : observables, indicateurs, observations, infrastructures dérivées, règles |
| Neo4j | les deux bundles ; nœuds `(:Stix:<Type>)`, arêtes typées, provenance par article |

Les bundles sont **toujours écrits**, même en `--dry-run` ; une ré-extraction les écrase (annoter une copie, pas l'original).

### 4.10 Variantes expérimentales

| Variable | Effet |
| :--- | :--- |
| `CTI_MULTI_AGENT` (`on`) | micro-agents en parallèle (défaut) ; `off` : l'appel unique « entités + comportements » |
| `CTI_MULTI_TEMP` | TTPHunter à plusieurs températures |
| `CTI_SECTION_PASS=on` | comportements relevés aussi par blocs d'environ 1 500 tokens (gains sur les articles longs ; +57 % de durée) |
| `CTI_CARRIER=on` | porteur choisi avec la technique |
| `CTI_OPERATIONS=on` | campagnes décidées par un appel à part (non mesurée) |
| `CTI_SECOND_LOOK`, `CTI_VICTIMS`, `CTI_MENTIONS` | passes de relecture, de victimes et de mentions manquantes |
| `CTI_KEEP_ORPHANS=on` | garde les entités sans relation |

> Toute retouche du prompt système peut faire disparaître une campagne à la marge : la mesurer comme un changement de
> méthode, sur au moins **deux exécutions** (vLLM sous requêtes concurrentes n'est pas strictement déterministe).

---

## 5. Persistance, tableau de bord et évaluation

### 5.1 Neo4j (`backend/database/`)

Neo4j est **l'unique base de persistance du graphe**. `stix_store.py` écrit des nœuds `(:Stix:<Type>)`, des arêtes typées et
la **provenance par article** : chaque nœud et chaque arête porte la liste des articles qui l'étayent. Retirer un article
retire sa contribution, sans toucher à ce qu'un autre article étaye. SQLite, lui, reste en **lecture seule** pour
l'extraction et le tableau de bord.

### 5.2 Tableau de bord (`scripts/dashboard.sh`)

| Vue | Contenu |
| :--- | :--- |
| **Rapports CTI** | graphe unitaire d'un incident, ses IOC, ses règles, la chronologie ; bouton de suppression de l'article |
| **Threat Actors** | profil hiérarchique (organigramme React Flow) : pays/identité, acteur, divisions, puis Arsenal / Techniques / Infrastructure / Cibles |
| **Graphe global** | tous les nœuds de tous les articles (sigma.js, WebGL), filtrables par nombre d'articles sources ; panneau qui **interroge le graphe par LLM** |

Le panneau de questions (`dashboard/ask.py`) n'écrit **aucun Cypher** : le modèle dispose d'outils en lecture seule et
bornés, cite des repères courts `[[E3]]`, et les citations inconnues sont retirées. `CTI_ASK_SLOTS` (1) borne les questions
simultanées.

### 5.3 Évaluation contre le gold (`cti-eval`)

Les articles annotés à la main (`Annotations/manifest.json` : `article_id` → gold) servent à **mesurer** toute modification de
l'extraction. Le backend Python n'a pas de tests unitaires : c'est `cti-eval` qui tient lieu de test de non-régression.

```bash
uv run cti-eval --run --workers 4 --bundles backend/evaluation/eval/<nom>   # extrait puis score
uv run cti-eval --bundles backend/evaluation/eval/<nom>                     # re-score sans appel au modèle
uv run cti-eval --compare v5_base_1,v5_base_2 <a>,<b>                       # écart et IC 95 % par bootstrap sur les articles
```

Le rapport (`report.md`, `report.json`) donne rappel, précision, crédit partiel, hallucinations, ancrage, un score strict, un
score relâché, les pertes par étape pour les techniques (aucun comportement / absente des candidates / non retenue) et les
relations retirées par le vérificateur. **Référence** (`v5_base_1` / `v5_base_2`, couche sémantique seule) : entités R 63,1 /
63,7 %, P 68,8 / 68,7 % ; relations R 30,7 / 30,3 %, P 38,7 / 35,5 %.

> **Pas de fuite du gold.** Aucun nom propre ni identifiant tiré des articles annotés ne doit apparaître dans les prompts ou le
> code (exemples avec des gabarits : `<malware>`, `T####.###`). `Annotations/holdout/` est tenu à l'écart : ne pas s'en servir
> pour régler l'extraction.

---

## 6. Commandes essentielles

```bash
# Nettoyage et classification
uv run cti-classifier                    # articles non classés
uv run cti-classifier --reclean          # texte nettoyé seulement, sans LLM
uv run cti-audit                         # validation humaine (TUI)

# Extraction vers Neo4j
uv run cti-extract --limit 10                               # les 10 prochains articles éligibles
uv run cti-extract --article-id 1553 --dry-run --show-log   # un article, sans Neo4j, avec les refus et les appels
uv run cti-extract --limit 5 --force                        # ré-extraire (retire d'abord l'ancienne contribution)
uv run cti-extract --limit 20 --workers 2                   # deux articles à la fois (un seul fil écrit Neo4j)
uv run cti-extract --limit 1 --llm-log                      # + journal de chaque échange avec le modèle
uv run cti-extract --stats                                  # statistiques du graphe

# Évaluation
uv run cti-eval --run --workers 4

# Tableau de bord
scripts/dashboard.sh                     # http://localhost:8095
scripts/dashboard.sh --dev               # backend :8095 + Vite à rechargement à chaud :5173
uv run cti-dashboard --port 8095         # serveur seul (sert frontend/dist)

# Tests
cd frontend && npm test                  # layouts du graphe, aucun innerHTML sur du texte d'article
cd backend/preprocessing/cleaning/cti_core && cargo test
```

Un article **supprimé** depuis le tableau de bord est marqué `(:DeletedArticle)` : `cti-extract` le saute, sauf avec
`--article-id` ou `--force`.

---

## 7. Configuration (variables d'environnement)

Toutes les variables sont lues dans l'environnement du processus (`backend/config.py`, `.env.example`).

| Variable | Défaut | Rôle |
| :--- | :--- | :--- |
| `CTI_DATA_DIR` | `backend/data` | déplace tout le dossier de données |
| `CTI_OPENAI_URL` | `http://127.0.0.1:8010/v1` | serveur d'extraction (vLLM) |
| `CTI_OPENAI_MODEL` | `cti-qwen` | nom servi (`--served-model-name`) |
| `CTI_LLM_SLOTS` | `10` | requêtes en vol ; **≤ `--max-num-seqs`** du serveur |
| `CTI_LLM_TIMEOUT` | `180` | délai d'un appel, en secondes |
| `CTI_MAX_MODEL_LEN` | `32768` | contexte supposé du serveur (doit égaler `--max-model-len`) |
| `CTI_THINKING` | `off` | réflexion de Qwen pendant l'extraction ; `CTI_REASONING_EFFORT` (`xhigh`/`medium`/`low`) et `CTI_THINKING_TOKENS` (8192) la règlent |
| `CTI_ASK_SLOTS` | `1` | questions du tableau de bord traitées à la fois |
| `OLLAMA_API_URL` | `http://127.0.0.1:11434/api/generate` | serveur de classification |
| `OLLAMA_MODEL` | `qwen3.8:27b` | modèle de classification |
| `OLLAMA_NUM_CTX` | `12288` | contexte de **chaque** requête (une autre valeur ferait recharger le modèle) |
| `CTI_CLASSIFIER_WORKERS` | `2` | classifications en parallèle |
| `NEO4J_URI` / `NEO4J_USER` / `NEO4J_PASSWORD` | `bolt://localhost:7687` / `neo4j` / `password123` | connexion Neo4j |
| `NO_PROXY` | `localhost,127.0.0.1` | posé par `config.py` : les serveurs ne passent jamais par un proxy |

---

## 8. Données et sorties

| Emplacement | Contenu | Accès |
| :--- | :--- | :--- |
| `backend/data/sources/cti_knowledge.db` | `knowledge` (articles bruts), `article_classifications` (catégorie, `clean_markdown`), `site_boilerplate` (gabarits appris) | écrit par `cti-classifier` et `cti-audit` ; **lecture seule** pour l'extraction et le tableau de bord |
| `backend/data/raw/html_pages/<site>/<hash>.html` | page HTML brute de chaque article : **seule entrée du nettoyage** | fournie par le scraping |
| `backend/data/cleaned/<site>/<hash>.md` | copie lisible du texte nettoyé (la source est SQLite) | écrit par `cti-classifier` |
| `backend/data/bundles/` | `article_<id>.json`, `article_<id>.iocs.json`, éventuellement `.llm.jsonl` | écrit par `cti-extract` |
| Neo4j `bolt://localhost:7687` | graphe STIX, provenance par article | **seule** base du graphe |
| `backend/evaluation/eval/<nom>/` | bundles, `runs.json`, `report.md`, `report.json` | écrit par `cti-eval` |
| `backend/extracting/stix/reference/` | index ATT&CK v20.0 (SQLite FTS5), listes TLD / domaines populaires | versionné / reconstruit à la demande |

---

## 9. Dépannage

| Symptôme | Cause probable et remède |
| :--- | :--- |
| `uv sync` échoue sur `cti_core` | `cargo` absent ou trop ancien : installer Rust (`rustup`), relancer |
| `import cti_core` introuvable | `uv sync` non lancé, ou code Rust modifié sans `maturin develop --release` |
| vLLM : le moteur échoue à l'initialisation | mauvais GPU (occupé) : fixer `CUDA_VISIBLE_DEVICES` ; ou VRAM insuffisante : baisser `--max-model-len` / `--max-num-seqs` |
| Erreur HTTP sur les appels d'extraction | serveur lancé **sans** `--enable-auto-tool-choice --tool-call-parser qwen3_coder` |
| Article « en échec » avec raison « context length » | l'article dépasse `--max-model-len` : l'augmenter si la VRAM le permet |
| Délais d'attente, requêtes lentes | `CTI_LLM_SLOTS` ou `--workers` > `--max-num-seqs` : la file du serveur s'allonge, des préemptions apparaissent dans `/metrics` |
| Le modèle répond mais ignore le texte | poids mal chargés : refaire le test de cohérence (§2.4) avant toute mesure |
| Ollama recharge le modèle à chaque requête | deux `num_ctx` différents : aligner `OLLAMA_CONTEXT_LENGTH` et `OLLAMA_NUM_CTX` |
| Prompt système ignoré par Ollama | contexte dépassé : le début du prompt est tronqué ; vérifier `OLLAMA_NUM_CTX` |
| `connection refused` sur 8010 / 11434 | tunnel SSH fermé : le relancer |
| `ConnectionRefused` Neo4j | `docker compose up -d neo4j`, attendre « healthy » ; vérifier `NEO4J_PASSWORD` |
| Le tableau de bord s'affiche vide | Neo4j sans données : lancer `cti-extract` ; ports 8080/8090 pris par une pile OpenCTI : utiliser 8095 |
| Résultats qui diffèrent d'une exécution à l'autre | normal (vLLM sous requêtes concurrentes) : comparer sur ≥ 2 exécutions avec `cti-eval --compare` |

---

## 10. Règles métier

1. **Isolation par article.** Chaque rapport CTI affiche exclusivement son propre sous-graphe. Le **graphe global** et la vue
   *Acteurs* sont des vues explicites et séparées qui agrègent plusieurs articles : chaque nœud et chaque arête y porte la liste
   des articles qui l'étayent.
2. **Ancrage.** Une relation cite des numéros de phrases ; le texte de la preuve est relu par le code, jamais recopié par le modèle.
3. **Pas d'invention.** Un identifiant ATT&CK absent de la v20.0 est refusé ; un lieu non résolu en pays ISO ou en région STIX
   est refusé ; une rubrique de profil sans donnée reste vide (« origine non établie »), jamais déduite.
4. **Acteurs.** Tous les `threat-actor` et `intrusion-set` figurent dans l'onglet Acteurs, rattachés ou non à un groupe ATT&CK ;
   une campagne n'est jamais un acteur.
5. **Anti-bruit.** Chercheurs, éditeurs de sécurité et entreprises victimes ne sont jamais des acteurs de la menace ; les
   binaires natifs (`powershell.exe`, `certutil.exe`) sont des outils à double usage, jamais de l'infrastructure C2.
6. **Preprocessing universel.** Aucune liste d'éditeurs, d'acteurs ou d'outils dans le moteur Rust : le bruit est détecté par
   structure puis par apprentissage du gabarit de chaque source. Les IOC restent à leur place dans le récit.
7. **IOC par règles.** Les valeurs ne sont jamais générées par le modèle ; il n'en choisit que le rôle et l'entité de rattachement.
8. **Serveurs distants.** Aucune commande locale `ollama` / `vllm` / `systemctl` depuis ce dépôt ; jamais plus de requêtes
   simultanées que de slots.
9. **Pas de fuite du gold.** Aucun nom ni identifiant des articles annotés dans les prompts ou le code.
