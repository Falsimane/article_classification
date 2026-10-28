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
> - **Classification** : serveur Ollama (`http://localhost:11434/api/generate`), joint par `backend/preprocessing/cti_classifier.py`. Un seul `num_ctx` (`OLLAMA_NUM_CTX`, 12288) : deux valeurs différentes forcent Ollama à recharger le modèle.
> - La variable d'environnement `NO_PROXY="localhost,127.0.0.1"` est appliquée pour éviter tout détournement de trafic.
> - **Jamais plus de requêtes simultanées que de slots** (`CTI_LLM_SLOTS`) : derrière le tunnel SSH, une requête abandonnée par le client continue d'occuper le serveur. `llm.py` attend un slot libre avant d'envoyer.

---

## 3. Architecture du Projet

```text
├── backend/
│   ├── preprocessing/            # Ingestion, refanging universel, fast-reject & classification
│   │   ├── cleaner.py            # UniversalCTICleaner appelant le moteur Rust cti_core (gabarit par source, découpage atomique)
│   │   ├── evaluate_cleaning.py  # Rapport qualité du preprocessing (fidélité IOC, résidus, source inconnue)
│   │   ├── cti_classifier.py     # Classification & triage LLM (Ollama)
│   │   └── audit_classifier.py   # Interface TUI (Textual) pour l'audit et la validation humaine
│   │
│   ├── extracting/               # Construction sémantique du Knowledge Graph CTI
│   │   ├── extract.py            # CLI `cti-extract` : articles classifiés -> pipeline -> bundle STIX (fichier) -> Neo4j
│   │   ├── pipeline.py           # Extraction d'un article, trois étapes sur le texte entier : entités et techniques (un appel),
│   │   │                         #   techniques vérifiées contre ATT&CK (identifiant existant ET nom correspondant ; refusées corrigées
│   │   │                         #   par le modèle avec search_attack / get_attack), relations entre éléments numérotés (+ une correction)
│   │   ├── draft.py              # DraftGraph (vérification STIX : stix2 strict, table de relations, ATT&CK, phrases citées) et outils ATT&CK
│   │   ├── segment.py            # Phrases numérotées (la preuve d'une relation est un numéro de phrase) ; `render` = texte montré au modèle
│   │   ├── llm.py                # Client vLLM : sortie contrainte (`generate`), tours avec outils (`chat`), slots, tokens comptés par le serveur
│   │   ├── iocs.py               # IOC : valeurs par règles, rôle et rattachement par le modèle ; jugés non malveillants gardés (indicateur benign)
│   │   ├── rules.py              # Règles YARA (libyara) et Sigma (YAML) par analyse syntaxique ; seule l'entité détectée est choisie par le modèle
│   │   ├── evidence.py, places.py  # noms normalisés, ancrage, dates ; lieux -> ISO 3166-1 / région STIX
│   │   └── update_ioc_reference.py # mise à jour des listes TLD / domaines populaires (reference/)
│   │
│   ├── evaluation/               # Mesure de l'extraction contre les articles annotés à la main (Annotations/)
│   │   ├── score.py              # Méthode d'Annotations/methode_annotation.md : rappel, précision, crédit partiel, hallucinations, ancrage
│   │   └── cti_eval.py           # CLI `cti-eval` : extrait les articles du manifeste, score, report.md / report.json
│   │
│   ├── database/
│   │   ├── neo4j_store.py        # Connexion Neo4j (singleton) réutilisée par stix_store
│   │   └── stix_store.py         # Graphe STIX : nœuds (:Stix:<Type>), arêtes typées, provenance par article
│   │
│   ├── stix/                     # Objets STIX 2.1 (stix2), index SQLite FTS5 d'ATT&CK v20.0 (attack.py), IOC datés, règles en indicator
│   ├── cti_core/                 # Moteur déterministe natif Rust (PyO3) : nettoyage, sections, découpage
│   ├── server.py                 # Serveur Web HTTP & API REST STIX (sert frontend/dist) : /api/stats|articles|graph|iocs|rules|article|bundle|actors
│   └── stix_dashboard.py         # Graphe STIX (Neo4j) -> JSON de données pures (pas de couleurs ni de HTML)
│
├── frontend/                     # React 18 + TypeScript + Tailwind CSS 3 + React Flow 12 (Vite) ; voir frontend/README.md
├── Annotations/                  # Gold STIX annoté à la main, manifest.json, méthode d'annotation
├── db_outputs/                   # SQLite source (cti_knowledge.db), bundles STIX, rapports d'évaluation
└── pyproject.toml                # Configuration du package, dépendances uv et scripts CLI
```

---

## 4. Rôles Stricts des Bases de Données

| Base de Données | Rôle | Politique d'accès |
| :--- | :--- | :--- |
| **Neo4j** (`bolt://localhost:7687`) | **L'UNIQUE base de persistance du Knowledge Graph CTI** (graphe STIX, provenance par article). | Lecture / Écriture via `backend/database/stix_store.py`. |
| **SQLite** (`db_outputs/cti_knowledge.db`) | Contient les articles bruts scrappés (`knowledge`) et les résultats de classification (`article_classifications`). | **STRICTEMENT LECTURE SEULE** pour l'extraction et le dashboard. Aucune entité de graphe n'y est enregistrée. |

---

## 5. Commandes à Connaître

Toutes les commandes Python s'exécutent avec `uv` :

### A. Preprocessing & Classification LLM
```bash
uv run cti-classifier      # nettoyage et classification des articles
uv run cti-audit           # interface TUI d'audit (validation humaine)
```

### B. Extraction du Knowledge Graph vers Neo4j
```bash
# Extraire les 10 prochains articles éligibles vers Neo4j (graphe STIX)
uv run cti-extract --limit 10

# Un article, sans écrire dans Neo4j, avec les refus de la vérification et les appels d'outils
uv run cti-extract --article-id 1553 --dry-run --show-log

# Le bundle STIX 2.1 final de chaque article est toujours écrit dans db_outputs/stix_bundles/article_<id>.json
# (même en --dry-run ; --out change de dossier). Une ré-extraction écrase le fichier : annoter une copie.
# Le bundle contient aussi les IOC jugés non malveillants (indicator_types benign) ; Neo4j ne les reçoit pas.

uv run cti-extract --stats              # statistiques du graphe STIX
uv run cti-extract --limit 5 --force    # re-traiter des articles déjà extraits (retire d'abord leur ancienne contribution)
```

### C. Évaluation contre le gold
```bash
# Index ATT&CK v20.0 (versionné ; à reconstruire seulement depuis le bundle officiel enterprise-attack-20.0.json)
uv run python -m backend.stix.attack

# Articles annotés (Annotations/manifest.json : article_id -> gold) ; rapport dans <bundles>/report.md
uv run cti-eval --run --workers 4 --bundles db_outputs/eval/<nom>
uv run cti-eval --bundles db_outputs/eval/<nom>   # re-score sans appel au modèle
```
Le backend Python n'a pas de tests unitaires : toute modification de l'extraction se mesure avec `cti-eval` sur les 9 articles
annotés et se compare au dernier rapport (référence : `db_outputs/eval/staged_q38_27b_9art`, entités R 47,9 % / P 51,5 %,
relations R 21,7 % / P 35,9 %).

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
cd backend/cti_core
cargo test
maturin develop --release
cd ../..

# Rapport qualité du preprocessing (à lancer avant d'ingérer une nouvelle source)
uv run python backend/preprocessing/evaluate_cleaning.py [--site <source>]
```

---

## 6. Règles Métier & Invariants CTI

1. **Isolation par Article :** Le dashboard ne présente aucun graphe global agrégé. Chaque rapport CTI affiche exclusivement son propre sous-graphe d'incident.
2. **Profil d'acteur (onglet Acteurs) :** ce n'est PAS un graphe de connaissances mais un organigramme en rectangles (identité/pays en haut, acteur, divisions, puis Arsenal / Techniques / Infrastructure / Cibles) avec des onglets Organigramme, Arsenal, Techniques (par tactique ATT&CK), Infrastructure, Cibles, Références. Calculé côté serveur (`stix_dashboard._profile`) à partir des arêtes directes ; une rubrique sans donnée reste vide (« origine non établie »), jamais déduite. Seule vue qui agrège plusieurs articles. Dans un graphe de rapport : nœuds ronds avec icône par type, rectangles réservés aux acteurs de la menace.
3. **Coût du modèle :** il est dominé par les tokens GÉNÉRÉS ; la lecture du prompt est rapide et presque gratuite quand il commence comme le précédent (cache de préfixe). Les appels « entités » et « relations » commencent donc par le même texte d'article, et le modèle n'écrit que des lignes courtes. `llm.generate` impose un JSON sur une ligne.
4. **Preprocessing universel :** aucune liste d'éditeurs, d'acteurs ou d'outils dans Rust. Le bruit est détecté par structure (densité de liens, tête/queue de document) puis par apprentissage du gabarit de chaque source sur le corpus (`site_boilerplate`, relu à chaque lancement de `cti-classifier`). Les IOC restent à leur place dans le récit.
5. **Anti-Bruit :** Les chercheurs en sécurité, éditeurs CTI et entreprises victimes ne doivent jamais être labellisés en acteur de la menace. Les utilitaires natifs (`powershell.exe`, `certutil.exe`) sont catégorisés en outils à double usage, jamais en infrastructure C2.
6. **Pas de fuite du gold :** aucun nom propre ni identifiant tiré des articles annotés dans les prompts ou le code (exemples avec des gabarits : `<malware>`, `T####.###`).
