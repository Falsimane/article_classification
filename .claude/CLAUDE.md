# Projet CTI Knowledge Graph — Référence Projet (CLAUDE.md)

---

## 1. But du Projet

Ce projet a pour objectif d'ingérer des articles bruts de Cyber Threat Intelligence (CTI), d'en assainir le contenu, et de construire automatiquement un **Knowledge Graph sémantique** fiable, interconnecté et validé par ontologie dans **Neo4j**.

Le pipeline permet de :
1. **Prétraiter et classifier** les articles CTI (tactique, opérationnel, stratégique, hors-sujet) en éliminant le bruit web (bannières, boutons sociaux, disclaimers).
2. **Extraire** les entités CTI (Threat Actors, Malwares, outils, Infrastructures, TTPs MITRE ATT&CK, Vulnérabilités, IOCs) avec leurs relations et citations textuelles exactes (Grounding).
3. **Explorer visuellement** les renseignements via un tableau de bord Web (OpenCTI-like) :
   - **Rapports CTI** : graphe unitaire par incident.
   - **Threat Actors** : profil hiérarchique (organigramme React Flow) reliant le sponsor étatique, l'acteur, ses infrastructures C2, ses TTPs et son arsenal.

---

## 2. Infrastructure & LLM distants

> [!IMPORTANT]
> **Les serveurs d'inférence sont DISTANTS, joints par tunnel SSH sur `localhost`.**
> - **Ne JAMAIS exécuter de commandes shell locales** comme `ollama list`, `ollama run`, `ollama pull` ou `systemctl restart ollama`. Claude n'a pas d'accès SSH au serveur : c'est l'utilisateur qui le relance.
> - **Extraction** : serveur vLLM (API OpenAI, `http://localhost:8010/v1`, nom servi `cti-qwen`), joint uniquement par `backend/extracting/llm.py`. Il doit être lancé avec un analyseur d'appels d'outils (`--enable-auto-tool-choice --tool-call-parser qwen3_coder`) et un contexte qui contient l'article entier (`--max-model-len 32768`).
> - **Classification** : serveur Ollama (`http://localhost:11434/api/generate`), joint par `backend/preprocessing/classifying/cti_classifier.py`. Un seul `num_ctx` (`OLLAMA_NUM_CTX`, 12288) : deux valeurs différentes forcent Ollama à recharger le modèle.
> - La variable d'environnement `NO_PROXY="localhost,127.0.0.1"` est appliquée pour éviter tout détournement de trafic.
> - **Jamais plus de requêtes simultanées que de slots** (`CTI_LLM_SLOTS`) : derrière le tunnel SSH, une requête abandonnée par le client continue d'occuper le serveur. `llm.py` attend un slot libre avant d'envoyer.

---

## 3. Architecture du Projet

```text
├── backend/
│   ├── preprocessing/            # Page HTML brute -> Markdown canonique (refang, bruit retiré), fast-reject & classification
│   │   ├── classifying/
│   │   │   ├── cti_classifier.py     # Classification & triage LLM (Ollama)
│   │   │   ├── audit_classifier.py   # Interface TUI (Textual) pour l'audit et la validation humaine
│   │   │   └── evaluate_cleaning.py  # Rapport qualité du preprocessing (fidélité IOC, résidus, source inconnue)
│   │   └── cleaning/
│   │       ├── cleaner.py            # UniversalCTICleaner appelant le moteur Rust cti_core (page HTML, gabarit par source, découpage atomique)
│   │       ├── cti_core/             # Moteur déterministe natif Rust (PyO3) : DOM -> Markdown canonique (html.rs), sections, découpage
│   │       └── text/                 # Partagé par extraction, STIX et évaluation (n'importe pas extracting/)
│   │           ├── evidence.py       # noms normalisés, ancrage des citations, confiance, dates
│   │           └── segment.py        # Phrases numérotées (la preuve d'une relation est un numéro de phrase) ; `render` = texte montré au modèle
│   │
│   ├── extracting/               # Construction sémantique du Knowledge Graph CTI
│   │   ├── cli.py                # CLI `cti-extract` : articles classifiés -> pipeline -> bundle STIX (fichier) -> Neo4j
│   │   ├── pipeline.py           # Extraction d'un article, trois étapes sur le texte entier : entités et techniques (un appel),
│   │   │                         #   techniques vérifiées contre ATT&CK (identifiant existant ET nom correspondant ; refusées corrigées
│   │   │                         #   par le modèle avec search_attack / get_attack), relations entre éléments numérotés (+ une correction)
│   │   ├── runner.py             # Lot d'articles (cti-extract et cti-eval) : --workers en parallèle, un seul fil écrit Neo4j, bundle atomique
│   │   ├── llm.py                # Client vLLM : sortie contrainte (`generate`), tours avec outils (`chat`), slots, tokens comptés par le serveur
│   │   ├── stix/                 # Objets STIX 2.1 (stix2), index SQLite FTS5 d'ATT&CK v20.0 (attack.py), IOC datés, règles en indicator
│   │   ├── graph/
│   │   │   ├── draft.py          # DraftGraph (vérification STIX : stix2 strict, table de relations, ATT&CK, phrases citées) et outils ATT&CK
│   │   │   └── places.py         # lieux -> ISO 3166-1 / région STIX
│   │   └── observables/
│   │       ├── iocs.py           # IOC : valeurs par règles, rôle et rattachement par le modèle ; jugés non malveillants écartés
│   │       ├── rules.py          # Règles YARA (libyara) et Sigma (YAML) par analyse syntaxique ; seule l'entité détectée est choisie par le modèle
│   │       └── update_reference.py # mise à jour des listes TLD / domaines populaires (reference/)
│   │
│   ├── evaluation/               # Mesure de l'extraction contre les articles annotés à la main (Annotations/)
│   │   ├── eval/                 # Hors git : un dossier par exécution de cti-eval (bundles, runs.json, report.md / report.json)
│   │   ├── score.py              # Méthode d'Annotations/methode_annotation.md : rappel, précision, crédit partiel, hallucinations, ancrage
│   │   └── cti_eval.py           # CLI `cti-eval` : extrait les articles du manifeste, score, report.md / report.json
│   │
│   ├── database/
│   │   ├── neo4j_store.py        # Connexion Neo4j (singleton) réutilisée par stix_store
│   │   └── stix_store.py         # Graphe STIX : nœuds (:Stix:<Type>), arêtes typées, provenance par article
│   │
│   ├── dashboard/
│   │   ├── server.py             # Serveur Web HTTP & API REST STIX (sert frontend/dist) : /api/stats|articles|graph|iocs|rules|article|bundle|actors ; DELETE /api/articles/<id>
│   │   └── stix_dashboard.py     # Graphe STIX (Neo4j) -> JSON de données pures (pas de couleurs ni de HTML)
│   ├── config.py                 # Seul endroit qui définit les chemins de données (DATA_DIR, surchargé par CTI_DATA_DIR) et les serveurs LLM
│   └── data/                     # Hors git : sources/ (cti_knowledge.db, urls_collection.db), bundles/, raw/html_pages/ (page HTML de chaque article, seule entrée du nettoyage), cleaned/ (copie lisible du texte nettoyé ; la source est SQLite)
│
├── frontend/                     # React 18 + TypeScript + Tailwind CSS 3 + React Flow 12 (Vite) ; voir frontend/README.md
├── Annotations/                  # Gold STIX annoté à la main, manifest.json, méthode d'annotation
└── pyproject.toml                # Configuration du package, dépendances uv et scripts CLI
```

---

## 4. Rôles Stricts des Bases de Données

| Base de Données | Rôle | Politique d'accès |
| :--- | :--- | :--- |
| **Neo4j** (`bolt://localhost:7687`) | **L'UNIQUE base de persistance du Knowledge Graph CTI** (graphe STIX, provenance par article). | Lecture / Écriture via `backend/database/stix_store.py`. |
| **SQLite** (`backend/data/sources/cti_knowledge.db`) | Contient les articles bruts scrappés (`knowledge`) et les résultats de classification (`article_classifications`). | **STRICTEMENT LECTURE SEULE** pour l'extraction et le dashboard. Aucune entité de graphe n'y est enregistrée. |

---

## 5. Commandes à Connaître

Toutes les commandes Python s'exécutent avec `uv` :

### A. Preprocessing & Classification LLM
```bash
uv run cti-classifier            # nettoyage (depuis la page HTML) et classification des articles
uv run cti-classifier --reclean  # recalcule seulement le texte nettoyé des articles déjà classés (base + data/cleaned/), sans LLM
uv run cti-audit           # interface TUI d'audit (validation humaine)
```

### B. Extraction du Knowledge Graph vers Neo4j
```bash
# Extraire les 10 prochains articles éligibles vers Neo4j (graphe STIX)
uv run cti-extract --limit 10

# Un article, sans écrire dans Neo4j, avec les refus de la vérification et les appels d'outils
uv run cti-extract --article-id 1553 --dry-run --show-log

# Deux bundles STIX 2.1 par article, toujours écrits dans backend/data/bundles/ (même en --dry-run ; --out change de dossier) :
#   article_<id>.json       couche sémantique (rapport, entités, techniques, relations) : ce que décrivent les gold, ce que cti-eval note
#   article_<id>.iocs.json  couche observable (observables, indicateurs, observations, infrastructures dérivées des IOC, règles)
# Neo4j et le téléchargement du dashboard reçoivent les deux. Une ré-extraction écrase les fichiers : annoter une copie.

uv run cti-extract --limit 1 --llm-log  # + <out>/article_<id>.llm.jsonl : chaque échange avec le modèle (cti-eval l'écrit toujours)
uv run cti-extract --stats              # statistiques du graphe STIX
uv run cti-extract --limit 5 --force    # re-traiter des articles déjà extraits (retire d'abord leur ancienne contribution)
# Un article dont une étape LLM a échoué (llm_failures > 0 dans Neo4j) est repris au lancement suivant ; --workers N : N articles à la fois
```

### C. Évaluation contre le gold
```bash
# Index ATT&CK v20.0 (versionné ; à reconstruire seulement depuis le bundle officiel enterprise-attack-20.0.json)
uv run python -m backend.extracting.stix.attack

# Articles annotés (Annotations/manifest.json : article_id -> gold) ; rapport dans <bundles>/report.md
uv run cti-eval --run --workers 4 --bundles backend/evaluation/eval/<nom>
uv run cti-eval --bundles backend/evaluation/eval/<nom>   # re-score sans appel au modèle
```
Le backend Python n'a pas de tests unitaires : toute modification de l'extraction se mesure avec `cti-eval` sur les 9 articles
annotés et se compare au dernier rapport (référence : `backend/evaluation/eval/base_html_1` et `base_html_2`, texte nettoyé
depuis le HTML, modèle Swift 1.5 INT4, couche sémantique seule : entités R 62,2 / 61,6 %, P 68,2 / 67,6 % ; relations
R 29,3 / 30,7 %, P 40,9 / 39,8 %). Deux exécutions du même code diffèrent de plusieurs points (vLLM sous requêtes concurrentes) :
mesurer chaque variante sur au moins deux exécutions. Passe par bloc expérimentale (`CTI_SECTION_PASS=on`) :
`sect_html_1` et `sect_html_2`.

### D. Serveur Web & Dashboard CTI
```bash
# npm install et build du frontend si besoin, puis le serveur (:8095) ; --dev : backend + Vite (:5173)
scripts/dashboard.sh
scripts/dashboard.sh --dev

# Serveur seul sur le port 8095 (8080 et 8090 sont pris par la pile OpenCTI)
uv run cti-dashboard --port 8095
```

### E. Frontend (React + Tailwind + React Flow)
```bash
cd frontend
npm install
npm run build        # typecheck + build Vite vers frontend/dist, servi par `uv run cti-dashboard`
npm run dev          # serveur de développement :5173, l'API est proxifiée vers :8095
npm test             # layouts du graphe, aucun innerHTML sur du texte d'article
```

### F. Moteur Rust (`cti_core`)
```bash
cd backend/preprocessing/cleaning/cti_core
cargo test
maturin develop --release
cd ../../../..

# Rapport qualité du preprocessing (à lancer avant d'ingérer une nouvelle source)
uv run python backend/preprocessing/classifying/evaluate_cleaning.py [--site <source>]
```

---

## 6. Règles Métier & Invariants CTI

1. **Isolation par Article :** Le dashboard ne présente aucun graphe global agrégé. Chaque rapport CTI affiche exclusivement son propre sous-graphe d'incident.
2. **Profil d'acteur (onglet Acteurs) :** seuls les `threat-actor` et les `intrusion-set` rattachés à un groupe ATT&CK (G####) y figurent (`stix_dashboard.has_profile`) ; une campagne ou un intrusion-set inconnu d'ATT&CK n'est jamais un acteur. Ce n'est PAS un graphe de connaissances mais un organigramme en rectangles (identité/pays en haut, acteur, divisions, puis Arsenal / Techniques / Infrastructure / Cibles) avec des onglets Organigramme, Arsenal, Techniques (par tactique ATT&CK), Infrastructure, Cibles, Références. Calculé côté serveur (`stix_dashboard._profile`) à partir des arêtes directes ; une rubrique sans donnée reste vide (« origine non établie »), jamais déduite. Seule vue qui agrège plusieurs articles. Dans un graphe de rapport : nœuds ronds avec icône par type, rectangles réservés aux acteurs de la menace.
3. **Coût du modèle :** il est dominé par les tokens GÉNÉRÉS ; la lecture du prompt est rapide et presque gratuite quand il commence comme le précédent (cache de préfixe). Les appels « entités » et « relations » commencent donc par le même texte d'article, et le modèle n'écrit que des lignes courtes. `llm.generate` impose un JSON sur une ligne.
4. **Preprocessing universel :** l'entrée est la page HTML (`backend/data/raw/html_pages/<site>/<sha1(url)[:16]>.html`), jamais le Markdown d'un export. Aucune liste d'éditeurs, d'acteurs ou d'outils dans Rust. Le bruit est détecté par structure dans le DOM (éléments cachés, densité de liens internes, racine du contenu) puis par apprentissage du gabarit de chaque source sur le corpus (`site_boilerplate`, relu à chaque lancement de `cti-classifier`). Les IOC restent à leur place dans le récit.
5. **Anti-Bruit :** Les chercheurs en sécurité, éditeurs CTI et entreprises victimes ne doivent jamais être labellisés en acteur de la menace. Les utilitaires natifs (`powershell.exe`, `certutil.exe`) sont catégorisés en outils à double usage, jamais en infrastructure C2.
6. **Pas de fuite du gold :** aucun nom propre ni identifiant tiré des articles annotés dans les prompts ou le code (exemples avec des gabarits : `<malware>`, `T####.###`).
7. **Suppression d'un article (bouton du rapport) :** retire sa contribution de Neo4j (ce qu'un autre article étaye est conservé) et ses bundles, et le marque `(:DeletedArticle)` : `cti-extract` le saute, sauf `--article-id` ou `--force`. SQLite n'est pas touché.
