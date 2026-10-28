# Backend

Le backend Python (avec un moteur Rust) prend un article scrappé dans SQLite et produit un graphe STIX 2.1 dans Neo4j.
Il sert ensuite ce graphe au frontend par une API REST.

Ce document décrit le flux de données, le rôle de chaque module et les choix d'architecture. Pour l'installation et les
commandes, voir le [README racine](../README.md).

---

## Sommaire

1. [Flux de données](#flux-de-données)
2. [Principes de conception](#principes-de-conception)
3. [`config.py` : configuration partagée](#configpy--configuration-partagée)
4. [`cti_core/` : moteur de nettoyage Rust](#cti_core--moteur-de-nettoyage-rust)
5. [`preprocessing/` : nettoyage et classification](#preprocessing--nettoyage-et-classification)
6. [`extracting/` : extraction STIX](#extracting--extraction-stix)
7. [`stix/` : objets STIX 2.1 et bases de référence](#stix--objets-stix-21-et-bases-de-référence)
8. [`database/` : persistance Neo4j](#database--persistance-neo4j)
9. [`evaluation/` : score contre le gold](#evaluation--score-contre-le-gold)
10. [`dashboard/` : API Web](#dashboard--api-web)

---

## Flux de données

```text
SQLite knowledge (article brut)
   │
   │  preprocessing/cti_classifier.py              ── uv run cti-classifier
   │    0. rejet amont déterministe (check_viability : trop court, pas un article…)
   │    1. cti_core : nettoyage, refang, sections                     (Rust, millisecondes)
   │    2. contexte compact (titre, prose, marqueurs code/table) ──▶ LLM : catégorie + justification
   ▼
SQLite article_classifications (primary_category, clean_markdown, is_processable…)
   │
   │  extracting/cli.py -> pipeline.py              ── uv run cti-extract
   │    1. text/segment.py : phrases numérotées (unités), article entier montré au modèle
   │    2. appel « entités » : entités et techniques ATT&CK (identifiant|nom|phrases)
   │    3. techniques vérifiées contre ATT&CK v20.0 ; les refusées corrigées par le modèle avec search_attack / get_attack
   │    4. appel « relations » entre éléments numérotés (+ une correction) ; DraftGraph : stix2 strict, phrases citées
   │    5. observables/iocs.py  : valeurs par règles, rôle et rattachement choisis par le LLM
   │    6. observables/rules.py : règles YARA (libyara) / Sigma (YAML) par analyse syntaxique, entité détectée choisie par le LLM
   │    7. stix/objects.py : stix2.Bundle (identifiants déterministes)
   ├──▶ backend/data/bundles/article_<id>.json   (complet, IOC bénins compris)
   ▼
Neo4j  (:Stix:<Type>) -[:USES|TARGETS|…]-> (:Stix:<Type>)   database/stix_store.py (sans les IOC bénins)
   │
   │  dashboard/stix_dashboard.py  (données pures, aucun HTML)
   ▼
dashboard/server.py  ── /api/*  ──▶  frontend React (frontend/dist)
```

Les deux bases ont des rôles stricts :

| Base | Rôle | Écrite par | Lue par |
| :--- | :--- | :--- | :--- |
| SQLite `backend/data/sources/cti_knowledge.db` | articles bruts, classifications, gabarits de sources | `cti-classifier`, `cti-audit` | extraction et tableau de bord, **en lecture seule** |
| Neo4j `bolt://localhost:7687` | **unique** stockage du graphe de connaissances | `stix_store.py` | `stix_dashboard.py` |

---

## Principes de conception

**Le coût d'un LLM local est celui des tokens générés.** Sur le serveur mesuré, Qwen génère quelques dizaines de tokens
par seconde mais lit plusieurs milliers de tokens de prompt par seconde, et presque gratuitement quand un prompt commence
comme le précédent (cache de préfixe). Les deux appels de l'extraction commencent donc par le même texte d'article, et le
modèle n'écrit que des lignes courtes (« type|nom », « identifiant|nom|phrases », « 3|uses|7|12 »).

**Le code vérifie, le modèle décide du sens, `stix2` valide.**

- Ce qui est mécanique est fait par le code : recherche de techniques ATT&CK proches d'un comportement (index plein
  texte, offert au modèle comme outil), valeurs d'IOC (expressions régulières), règles YARA/Sigma (analyse syntaxique).
- Le *sens* est décidé par le modèle : le type d'un nom, la technique d'un comportement, l'entité qui agit, la relation
  entre deux entités. Aucune règle déterministe ne type un nom ni ne juge un fait.
- La *validité* est vérifiée par la bibliothèque officielle `stix2` en mode strict, par ATT&CK v20.0 (un identifiant
  inconnu est refusé, un identifiant révoqué est remplacé) et par le texte (les phrases citées existent et nomment
  l'entité reliée). Un refus revient au modèle avec sa raison.

**La preuve est un numéro de phrase.** Le modèle ne recopie jamais une citation : le texte de la preuve est relu par le
code à partir du numéro, il est donc exact par construction.

**Décodage déterministe.** Température 0, sortie contrainte par un schéma JSON, réflexion de Qwen désactivée par défaut :
deux exécutions donnent la même extraction.

---

## `config.py` : configuration partagée

Lit l'environnement une fois et expose les constantes utilisées par les clients LLM et les lecteurs d'articles. C'est le
seul endroit qui définit les chemins de données : `DATA_DIR` (`backend/data`, ou `CTI_DATA_DIR`) et, dessous, la base SQLite
(`SOURCE_ARTICLES_DB` = `sources/cti_knowledge.db`), les bundles (`BUNDLES_DIR`) et les évaluations (`EVAL_DIR`) ;
`raw/` (pages scrapées) et `archive/` n'y sont pas lus. Pour l'extraction, URL et modèle du serveur vLLM/SGLang (`OPENAI_BASE_URL`,
`LLM_MODEL`) et requêtes en vol (`LLM_SLOTS`) ; pour la classification, URL, modèle et contexte d'Ollama
(`OLLAMA_NUM_CTX`). Il force aussi `NO_PROXY=localhost,127.0.0.1` pour que les tunnels ne passent jamais par un proxy.

Le client de l'extraction attend un slot libre *avant* d'envoyer : derrière un tunnel SSH, une requête abandonnée continue
d'occuper le serveur. Le classifieur garde un seul `num_ctx` : deux valeurs différentes forcent Ollama à recharger le
modèle en attendant la fin des requêtes en cours.

---

## `cti_core/` : moteur de nettoyage Rust

Extension native (PyO3, construite par `maturin`) qui fait tout le travail déterministe sur le texte, en quelques
millisecondes par article. Classe exposée : `CtiEngine`.

| Méthode | Rôle |
| :--- | :--- |
| `process_article` | Nettoie un article : retire la navigation (densité de liens, tête et queue de document), les shortcodes, les lignes du gabarit appris pour la source ; découpe en sections ; produit `PreprocessingResult` (`clean_markdown`, sections, `is_processable`). |
| `check_viability` | Rejet amont : le texte brut n'est pas un article exploitable. |
| `refang` | `hxxp`, `[.]`, `(dot)`… redeviennent des IOC lisibles, dans le récit comme dans le code. |
| `learn_boilerplate` | Lignes présentes dans une forte proportion des documents d'une même source : son gabarit (menus, bannières, pieds de page). |
| `chunk_markdown`, `split_blocks` | Découpage en morceaux ou en blocs atomiques (un bloc de code ou une table ne sont jamais coupés). |

Il ne contient **aucune liste** d'éditeurs, d'acteurs ou d'outils : le bruit est reconnu par sa structure, puis par le
gabarit appris sur le corpus de chaque source. Les tests Rust (`cargo test`) couvrent les cas difficiles (liens collés,
IOC défangés, code indenté, listes de CVE avec liens internes).

---

## `preprocessing/` : nettoyage et classification

| Fichier | Rôle |
| :--- | :--- |
| `cleaner.py` | `UniversalCTICleaner`, façade Python de `cti_core`. Clé de source (`site_key`), apprentissage et stockage des gabarits dans la table `site_boilerplate`, contexte compact pour le classifieur (`build_classifier_context` : titre, prose utile, marqueurs de blocs de code et de tables). |
| `cti_classifier.py` | CLI `cti-classifier`. Demande au lancement s'il faut réinitialiser les tables, réapprend les gabarits, puis traite par lots les articles non classés (ou en erreur) avec `CTI_CLASSIFIER_WORKERS` threads. Le LLM répond `{evidence, category, confidence}` sous schéma JSON ; catégories : `tactical`, `operational`, `strategic`, `out_of_scope`. Résultat dans `article_classifications`, avec le `clean_markdown` que lira l'extraction. Un nettoyage réussi est conservé même si l'appel au LLM échoue. |
| `audit_classifier.py` | CLI `cti-audit` : interface Textual pour relire les classifications douteuses et saisir une catégorie humaine (`human_category`). |
| `evaluate_cleaning.py` | Rapport qualité du nettoyage, sans LLM ni écriture : taux de conservation, fidélité des IOC (hachages, IP, CVE du brut présents dans le nettoyé), résidus de bruit, propriétés du découpage, fuite de gabarit sur une source inconnue (*leave-one-source-out*). À lancer avant d'ingérer une nouvelle source. |

L'extraction ne prend que les articles `is_processable = 1` dont la catégorie est `tactical`, `operational` ou
`strategic`.

---

## `extracting/` : extraction STIX

### Point d'entrée : `extract.py` (`cti-extract`)

`cti-extract` lit les articles éligibles, appelle `pipeline.extract_article`, puis écrit le bundle et l'enregistre dans
Neo4j. Options : `--article-id` (répétable), `--limit`, `--force`, `--dry-run`, `--out`, `--show-log`, `--stats`.

`process_article()` est la fonction que réutilise l'évaluation. Elle écrit toujours `<out>/article_<id>.json` (même en
`--dry-run`) et, si un `StixStore` est donné, enregistre l'article dans Neo4j sans les IOC jugés bénins.

### `pipeline.py` : trois étapes sur l'article entier

| Étape | Déroulé |
| :--- | :--- |
| **1. Entités** | Un appel contraint : toutes les entités (« type\|nom\|alias ») et les techniques ATT&CK écrites par le modèle (« identifiant\|nom ATT&CK\|numéros de phrases »). |
| **2. Techniques** | Le code vérifie que chaque identifiant existe dans ATT&CK v20.0 et y porte le nom donné (un identifiant voisin écrit de mémoire est refusé). Les refusées, avec leur raison et leurs phrases, passent dans une courte conversation avec outils (`search_attack`, `get_attack`, `submit`, 6 tours au plus) ; une technique encore refusée est écartée. |
| **3. Relations** | Un appel contraint sur le même texte (relu depuis le cache du serveur) suivi de la liste numérotée des entités et techniques retenues : « numéro source\|relation\|numéro cible\|numéros de phrases ». Une technique est désignée par son identifiant, jamais par son nom (« PowerShell » est aussi un outil). Les lignes refusées reviennent au modèle une fois. |

L'article entier doit tenir dans le contexte du serveur (`--max-model-len`) ; sinon le serveur refuse l'appel et la raison
est inscrite dans les échecs de l'article (`failures`), sans troncature silencieuse. Un serveur lancé sans analyseur d'appels
d'outils refuse l'étape 2 de la même façon : les techniques déjà valides sont gardées.

### Modules communs

| Fichier | Rôle |
| :--- | :--- |
| `llm.py` | Client du serveur vLLM/SGLang (`/v1/chat/completions`). `generate` : un appel sous schéma JSON (`response_format`), JSON demandé sur une ligne, réponse tronquée récupérée élément par élément. `chat` : un tour de conversation avec outils. `map_parallel` : appels parallèles bornés par le sémaphore de slots. `try_generate` : variante qui renvoie une réponse par défaut honnête en cas d'échec (IOC : rôle `unknown`). Chaque résultat porte les tokens lus et générés comptés par le serveur. |
| `text/segment.py` | Découpe le markdown nettoyé en **unités numérotées** (phrases ; blocs de code et tables gardés entiers, montrés en extrait) ; `render` produit le texte numéroté montré au modèle. |
| `graph/draft.py` | **`DraftGraph`**, le brouillon vérifié de l'article, et les outils de recherche dans ATT&CK (`search_attack`, `get_attack`). `declare` crée une entité par sa classe `stix2` ; `relate` crée une relation et contrôle : couple de types permis par la table de relations STIX, identifiant ATT&CK existant en v20.0 (révoqué → remplaçant), phrases citées existantes qui nomment l'entité reliée (ou les trois phrases précédentes, ou le titre de section). Les techniques, groupes et logiciels connus d'ATT&CK sont les objets officiels de MITRE, pas des copies. |
| `text/evidence.py` | Comparaison de noms normalisés, ancrage des preuves, confiance exprimée par l'auteur, analyse des dates. |
| `graph/places.py` | Résout un nom de lieu (« Russia », « Russie », « Eastern Europe ») en code ISO 3166-1 ou en région du vocabulaire STIX `region-ov`. Un nom non résolu est refusé, jamais inventé. |
| `observables/iocs.py` | IOC : valeurs candidates par règles (adresses, domaines, URL, courriels, hachages), filtres (adresses privées, domaines populaires, domaine de l'éditeur, extensions de fichier prises pour des TLD), regroupement par phrase ou section d'annexe, puis réponse fermée du modèle : rôle (`c2`, `payload-delivery`…) et entité de rattachement. Les IOC jugés non malveillants sont gardés dans le bundle avec `indicator_types: ["benign"]`, pas dans Neo4j. |
| `observables/rules.py` | Règles de détection lues dans le markdown complet (pas dans les unités, qui fusionnent les espaces). YARA compilée par `libyara`, Sigma lue en YAML avec `title`, `logsource` et `detection.condition`. Une règle invalide n'est jamais réparée : elle est écartée avec sa raison. Le modèle choisit l'entité détectée. |
| `observables/update_reference.py` | Met à jour `observables/reference/tlds.txt` (IANA) et `reference/popular_domains.txt` (Tranco), données versionnées du filtrage des IOC. |

### Format d'une ligne soumise

`pipeline.py` échange avec `DraftGraph` des lignes courtes, faciles à générer :

```text
entités   : type|nom   type|nom|alias1;alias2   software|produit|éditeur   location|pays|code ISO
relations : source|relation|cible|numéros de phrases
            ex. « <malware>|uses|T1059.001|42,43 », « <campagne>|attributed-to|<intrusion-set>|5 »
```

---

## `stix/` : objets STIX 2.1 et bases de référence

| Fichier | Rôle |
| :--- | :--- |
| `objects.py` | Objets d'un article créés par les classes `stix2` en mode strict (`Malware`, `Relationship`, `Report`, `Bundle`…). Seul ajout : un **identifiant déterministe** pour les SDO et les relations (`deterministic_id`), pour qu'un même malware cité par deux articles soit un seul nœud dans Neo4j. Les observables gardent l'identifiant calculé par `stix2` selon la norme. |
| `attack.py` | MITRE ATT&CK v20.0. Le bundle officiel (52 Mo) est lu par `stix2`, et chaque objet utile est rangé dans `reference/attack_v20.sqlite` avec sa sérialisation officielle. La recherche d'une technique à partir d'un comportement utilise SQLite FTS5 : fusion des rangs (RRF) de deux recherches BM25, l'une sur noms et descriptions, l'autre sur les 17 636 exemples de procédures. `get_attack_kb()` donne l'index partagé. |
| `iocs.py` | IOC en STIX : observable (`DomainName`, `IPv4Address`, `URL`, `File`…) ← `based-on` ← `Indicator` (motif assemblé par `stix2.patterns`) → `indicates` → entité ; un `Sighting` daté par article ; `Infrastructure` → `consists-of` → observables. Le statut (actif, vieillissant, périmé) n'est jamais stocké : il est calculé à la lecture avec la table `LIFETIMES` (par exemple, une adresse IP est « active » 30 jours après sa dernière observation et « périmée » après 180 ; valeurs heuristiques, non calibrées). |
| `rules.py` | Une règle YARA ou Sigma devient un `Indicator` dont `pattern` est le texte exact de la règle et `pattern_type` son langage. Identifiant dérivé du langage et du texte. |

Reconstruire l'index ATT&CK (bundle officiel attendu dans backend/stix/reference/ ou Annotations/) :

```bash
uv run python -m backend.stix.attack [chemin/enterprise-attack-20.0.json]
```

---

## `database/` : persistance Neo4j

| Fichier | Rôle |
| :--- | :--- |
| `neo4j_store.py` | Connexion Neo4j partagée (singleton, `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`). |
| `stix_store.py` | `StixStore` : écriture et lectures du graphe STIX. |

Modèle de `StixStore` :

- chaque objet STIX est un nœud `(:Stix:<Type>)` (labels `IntrusionSet`, `Malware`, `AttackPattern`…) identifié par son
  `id` STIX déterministe. Ré-extraire le même fait met à jour le même nœud ;
- chaque relation STIX est une arête typée (`:USES`, `:TARGETS`, `:ATTRIBUTED_TO`…) qui porte `confidence`,
  `description` et une preuve par article ;
- l'article est un nœud `(:Stix:Report)` relié à ses objets par `OBJECT_REF` et à son éditeur par `CREATED_BY` ;
- **provenance** : `article_ids` liste les articles qui étayent un nœud ou une arête. `save_article` est idempotent :
  un article déjà présent perd d'abord son ancienne contribution, dans la même transaction. `purge_article` ne supprime
  que ce qu'aucun autre article n'étaye.

Lectures pour le tableau de bord : `reports`, `dashboard_graph(article_id)`, `totals`, `actors`, `actor_subgraph`,
`article_iocs`, `article_rules`, `actor_iocs`.

---

## `evaluation/` : score contre le gold

Le dossier `Annotations/` contient des articles annotés à la main en STIX (`*_gold.json`), un `manifest.json`
(`article_id` → gold) et la méthode d'annotation (`methode_annotation.md`).

| Fichier | Rôle |
| :--- | :--- |
| `cti_eval.py` | CLI `cti-eval`. `--run` extrait les articles du manifeste (`--workers N` articles à la fois), sinon re-score les bundles de `--bundles` (défaut : `backend/data/eval/latest`). Écrit `runs.json` (durées, appels par étape, échecs), `report.json` et `report.md` dans le dossier des bundles. |
| `score.py` | Méthode de score décrite ci-dessous. |

- **Rappel** (métrique principale) = objets `required` trouvés / total `required`.
- **Précision** = objets `required` ou `acceptable` trouvés / total prédit.
- **Périmètre** : la couche sémantique. Les IOC, les conteneurs (`report`, `sighting`…) et l'identité de l'éditeur
  sont ignorés des deux côtés.
- **Normalisation** : identifiant ATT&CK (alias compris), CVE, puis nom normalisé. Types équivalents : malware/tool,
  intrusion-set/threat-actor, campaign/incident.
- **Crédit partiel** des techniques : même identifiant = 1 ; même technique parente ou sous-techniques sœurs = 0,5. Une
  relation vaut le plus petit crédit de ses deux extrémités.
- **Appariement** un pour un, meilleur crédit d'abord : un doublon prédit est un faux positif. Les campagnes, nommées
  différemment, sont appariées par le nombre de relations partagées.
- **Hallucination** : identifiant ATT&CK absent de la v20.0.
- Une prédiction absente du gold n'est pas jugée fausse d'office : elle est listée pour revue (`review`).

Les prompts et le code ne doivent contenir aucun nom propre tiré des articles évalués (exemples avec des gabarits :
`<malware>`, `T####.###`), pour que le score mesure la méthode et pas la mémorisation du gold.

---

## `dashboard/` : API Web

`server.py` (CLI `cti-dashboard`, port 8095 par défaut) est un `http.server` de la bibliothèque standard. Il sert le build
du frontend (`frontend/dist`) ; toute route inconnue renvoie `index.html` (routage côté client). `stix_dashboard.py`
transforme le graphe Neo4j en JSON de **données pures** : ni couleur, ni forme, ni HTML. Le texte venu des articles est
renvoyé tel quel et échappé par React.

| Route | Réponse |
| :--- | :--- |
| `GET /api/stats` | totaux : articles, entités, relations, IOC |
| `GET /api/articles` | rapports extraits (titre, source, date, catégorie, effectifs) |
| `GET /api/graph?article_id=&type=&search=` | sous-graphe d'**un** article : nœuds (type, famille, alias, références, tactiques…) et arêtes (type, confiance, preuves) |
| `GET /api/iocs?article_id=` | indicateurs de l'article avec rôle, entité rattachée et statut calculé |
| `GET /api/rules?article_id=` | règles YARA/Sigma de l'article, texte exact |
| `GET /api/article?article_id=` | markdown nettoyé lu par l'extraction (SQLite) |
| `GET /api/bundle?article_id=` | bundle STIX écrit par l'extraction, en téléchargement ; en-tête `X-Bundle-Matches-Graph: 0` si le fichier ne couvre plus le graphe de Neo4j (ré-extraction en `--dry-run`) |
| `GET /api/actors` | acteurs (intrusion-set, threat-actor, campaign) avec effectifs |
| `GET /api/actors/<id>` | profil agrégé d'un acteur : identité, divisions, arsenal, techniques par tactique, infrastructure, cibles, IOC, rapports sources |

**Familles** (filtre du frontend, `TYPE_FAMILIES`) : `actor` (threat-actor, intrusion-set, campaign), `malware`, `tool`,
`vulnerability`, `infrastructure`, `technique` (attack-pattern), `detection` (indicator, course-of-action), `target`
(identity, location, incident).

**Profil d'acteur.** Calculé côté serveur à partir des arêtes directes de l'acteur et de ses divisions. Une rubrique
sans donnée reste vide (« origine non établie ») : rien n'est déduit.
