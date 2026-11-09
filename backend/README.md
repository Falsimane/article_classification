# Backend

Le backend Python (avec un moteur Rust) prend la page HTML brute d'un article (référencé dans SQLite) et produit un graphe
STIX 2.1 dans Neo4j.
Il sert ensuite ce graphe au frontend par une API REST.

Ce document décrit le flux de données, le rôle de chaque module et les choix d'architecture. Pour l'installation et les
commandes, voir le [README racine](../README.md).

---

## Sommaire

1. [Flux de données](#flux-de-données)
2. [Principes de conception](#principes-de-conception)
3. [`config.py` : configuration partagée](#configpy--configuration-partagée)
4. [`preprocessing/cleaning/cti_core/` : moteur de nettoyage Rust](#preprocessingcleaningcti_core--moteur-de-nettoyage-rust)
5. [`preprocessing/` : nettoyage et classification](#preprocessing--nettoyage-et-classification)
6. [`extracting/` : extraction STIX](#extracting--extraction-stix)
7. [`extracting/stix/` : objets STIX 2.1 et bases de référence](#extractingstix--objets-stix-21-et-bases-de-référence)
8. [`database/` : persistance Neo4j](#database--persistance-neo4j)
9. [`evaluation/` : score contre le gold](#evaluation--score-contre-le-gold)
10. [`dashboard/` : API Web](#dashboard--api-web)

---

## Flux de données

```text
SQLite knowledge (URL, titre, date) + backend/data/raw/html_pages/<site>/<sha1(url)[:16]>.html (page brute)
   │
   │  preprocessing/classifying/cti_classifier.py              ── uv run cti-classifier
   │    0. page HTML absente : rejet
   │    1. cti_core : DOM -> Markdown canonique, bruit retiré, refang, sections ; page vide ou d'erreur rejetée
   │                                                                     (Rust, ~20 ms)
   │    2. contexte compact (titre, prose, marqueurs code/table) ──▶ LLM : catégorie + justification
   ▼
SQLite article_classifications (primary_category, clean_markdown, is_processable…)
   │
   │  extracting/cli.py -> pipeline.py              ── uv run cti-extract
   │    1. preprocessing/cleaning/text/segment.py : phrases numérotées (unités), article entier montré au modèle
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
(`SOURCE_ARTICLES_DB` = `sources/cti_knowledge.db`), les bundles (`BUNDLES_DIR`) ; les évaluations (`EVAL_DIR`) sont dans `backend/evaluation/eval/` ;
les pages HTML des articles (`HTML_PAGES_DIR` = `raw/html_pages/`, seule entrée du nettoyage) et la copie lisible du texte
nettoyé (`CLEANED_DIR` = `cleaned/<site>/<sha1(url)[:16]>.md`). La source du texte nettoyé reste
`article_classifications.clean_markdown` : l'antivirus du poste (Microsoft Defender) met en quarantaine les copies qui
contiennent des charges d'exploit en clair (webshells, Follina, Log4j), alors qu'il ne touche pas la base. Le reste de
`raw/` n'est pas lu. Pour l'extraction, URL et modèle du serveur vLLM/SGLang (`OPENAI_BASE_URL`,
`LLM_MODEL`) et requêtes en vol (`LLM_SLOTS`) ; pour la classification, URL, modèle et contexte d'Ollama
(`OLLAMA_NUM_CTX`). Il force aussi `NO_PROXY=localhost,127.0.0.1` pour que les tunnels ne passent jamais par un proxy.

Le client de l'extraction attend un slot libre *avant* d'envoyer : derrière un tunnel SSH, une requête abandonnée continue
d'occuper le serveur. Le classifieur garde un seul `num_ctx` : deux valeurs différentes forcent Ollama à recharger le
modèle en attendant la fin des requêtes en cours.

---

## `preprocessing/cleaning/cti_core/` : moteur de nettoyage Rust

Extension native (PyO3, construite par `maturin`) qui fait tout le travail déterministe, en une vingtaine de millisecondes
par page. Classe exposée : `CtiEngine`. L'entrée est la page HTML (`html.rs`, analysée par `html5ever`) ; la sortie est un
Markdown canonique (titres `#`, paragraphes, listes `- `, code clôturé, tables `|`), que l'aval découpe.

| Méthode | Rôle |
| :--- | :--- |
| `process_html` | Nettoie une page : écarte scripts, formulaires, `<nav>`, médias et éléments cachés ; résout le streaming React (`<template id="B:n">` ← `<div hidden id="S:n">`) ; retire les blocs de navigation (texte fait de liens internes, titres-liens vers une autre page du site), les blocs du gabarit appris pour la source et les shortcodes ; descend vers la racine du contenu ; rend le code (sans numéros de ligne), les tables, les listes ; dé-neutralise ; découpe en sections. Produit `PreprocessingResult` (`clean_markdown`, sections, `is_processable`). |
| `html_template_keys` | Texte normalisé de chaque bloc feuille d'une page (hors titres, code, tables, lignes de code, paragraphes tout en gras) : compté sur les pages d'une source, il désigne son gabarit. |
| `html_text` | Texte visible de toute la page : la référence du rapport qualité. |
| `check_viability` | Rejet amont sur le texte visible : page vide, trop courte ou page d'erreur de scraping. |
| `refang` | `hxxp`, `[.]`, `(dot)`… redeviennent des IOC lisibles, dans le récit comme dans le code. |
| `chunk_markdown`, `split_blocks` | Découpage du Markdown canonique en morceaux ou en blocs atomiques (un bloc de code ou une table ne sont jamais coupés). |

Il ne contient **aucune liste** d'éditeurs, d'acteurs ou d'outils : le bruit est reconnu par sa structure dans le DOM, puis
par le gabarit appris sur le corpus de chaque source. La racine du contenu ne laisse de côté que ce qui n'est ni de la
prose ni technique (un article peut être réparti entre plusieurs conteneurs frères). Les tests Rust (`cargo test`)
couvrent les cas difficiles (streaming React, IOC dans l'URL d'un lien, listes de CVE avec liens internes, tables de mise
en page, gabarits non échappés comme `<victim_id>`).

---

## `preprocessing/` : nettoyage et classification

| Fichier | Rôle |
| :--- | :--- |
| `cleaning/cleaner.py` | `UniversalCTICleaner`, façade Python de `cti_core`. Page HTML d'un article (`load_html`), clé de source (`site_key`), apprentissage et stockage des gabarits dans la table `site_boilerplate` (texte présent dans 40 % des pages d'une source, ou phrase d'au moins 6 mots dans 15 %), contexte compact pour le classifieur (`build_classifier_context` : titre, prose utile, marqueurs de blocs de code et de tables). |
| `classifying/cti_classifier.py` | CLI `cti-classifier`. Demande au lancement s'il faut réinitialiser les tables, réapprend les gabarits, puis traite par lots les articles non classés (ou en erreur) avec `CTI_CLASSIFIER_WORKERS` threads. `--reclean` recalcule seulement le texte nettoyé des articles déjà classés (base et `data/cleaned/`), sans appel au LLM (catégories et validations humaines conservées). Le LLM répond `{evidence, category, confidence}` sous schéma JSON ; catégories : `tactical`, `operational`, `strategic`, `out_of_scope`. Résultat dans `article_classifications`, avec le `clean_markdown` que lira l'extraction. Un nettoyage réussi est conservé même si l'appel au LLM échoue. |
| `classifying/audit_classifier.py` | CLI `cti-audit` : interface Textual pour relire les classifications douteuses et saisir une catégorie humaine (`human_category`). |
| `classifying/evaluate_cleaning.py` | Rapport qualité du nettoyage, sans LLM ni écriture : part du texte visible conservée, fidélité des IOC (hachages, IP, CVE du texte visible de la page présents dans le nettoyé ; ceux des articles liés et des menus manquent à juste titre), résidus de bruit, propriétés du découpage, fuite de gabarit sur une source inconnue (*leave-one-source-out*). À lancer avant d'ingérer une nouvelle source. |

L'extraction ne prend que les articles `is_processable = 1` dont la catégorie est `tactical`, `operational` ou
`strategic`.

---

## `extracting/` : extraction STIX

### Point d'entrée : `cli.py` (`cti-extract`) et `runner.py`

`cti-extract` lit les articles éligibles et les passe à `runner.run_batch`. Options : `--article-id` (répétable),
`--limit`, `--workers`, `--force`, `--dry-run`, `--out`, `--show-log`, `--stats`. Le lot se termine par un bilan (ok,
partiels, en échec, durée, tokens générés). Code de sortie : 0 (partiels compris), 1 si un article a échoué, 2 si Neo4j est
injoignable, 130 si interrompu.

`runner.run_batch` est partagé avec l'évaluation. Il extrait `--workers` articles à la fois (le sémaphore de `llm.py` borne
toujours les requêtes en vol), écrit chaque `<out>/article_<id>.json` de façon atomique (fichier temporaire puis
`os.replace`, même en `--dry-run`), puis enregistre l'article dans Neo4j sans les IOC jugés bénins, depuis **un seul fil** :
`StixStore._write` relit les listes d'un nœud partagé avant de les réécrire. Une exception dans un article est rapportée
avec sa trace sans arrêter le lot. Un article dont une étape LLM a échoué est enregistré avec `llm_failures` > 0 et n'est
pas compté comme extrait : le lancement suivant le reprend.

### `pipeline.py` : trois étapes sur l'article entier

| Étape | Déroulé |
| :--- | :--- |
| **1. Entités** | Un appel contraint : toutes les entités (« type\|nom\|alias ») et chaque comportement de l'attaquant en anglais (« numéros de phrases\|comportement\|identifiant ATT&CK présumé »). `CTI_SECTION_PASS=on` : les comportements sont aussi relevés bloc par bloc (~1 500 tokens), l'article entier restant en tête du prompt. |
| **1 ter. Opérations** (`CTI_OPERATIONS=on`) | Un appel contraint décide des campagnes que décrit le rapport (« phrases\|nom descriptif\|groupe »), à la place de celles de l'appel 1 ; le groupe donne une relation `attributed-to`. |
| **2. Techniques** | Le code cherche les candidates de chaque comportement dans ATT&CK v20.0 (FTS5 sur les définitions et les procédures, sans celles tirées de l'article lui-même : `report_key` de son URL) ; le modèle choisit par lettres (« numéro:lettres »). `CTI_CARRIER=on` : il désigne aussi l'auteur du comportement parmi les entités numérotées (« numéro:lettres:auteur ») et le code crée la relation `uses`. Le comportement devient la description (procédure) des relations `uses` vers la technique. |
| **3. Relations** | Un appel contraint sur le même texte (relu depuis le cache du serveur) suivi de la liste numérotée des entités et techniques retenues : « numéro source\|relation\|numéro cible\|numéros de phrases ». Une technique est désignée par son identifiant, jamais par son nom (« PowerShell » est aussi un outil). Les lignes refusées reviennent au modèle une fois ; un appel relie les îlots. |
| **4. Vérification** | Chaque relation est jugée « o / n » contre le texte ; « n » la retire. |

L'article entier doit tenir dans le contexte du serveur (`--max-model-len`) ; sinon le serveur refuse l'appel et la raison
est inscrite dans les échecs de l'article (`failures`), sans troncature silencieuse.

### Modules communs

| Fichier | Rôle |
| :--- | :--- |
| `llm.py` | Client du serveur vLLM/SGLang (`/v1/chat/completions`). `generate` : un appel sous schéma JSON (`response_format`), JSON demandé sur une ligne, réponse tronquée récupérée élément par élément. `chat` : un tour de conversation avec outils. `map_parallel` : appels parallèles bornés par le sémaphore de slots. `try_generate` : variante qui renvoie une réponse par défaut honnête en cas d'échec (IOC : rôle `unknown`). Chaque résultat porte les tokens lus et générés comptés par le serveur. |
| `preprocessing/cleaning/text/segment.py` | Découpe le markdown nettoyé en **unités numérotées** (phrases ; blocs de code et tables gardés entiers, montrés en extrait) ; `render` produit le texte numéroté montré au modèle. |
| `graph/draft.py` | **`DraftGraph`**, le brouillon vérifié de l'article, et les outils de recherche dans ATT&CK (`search_attack`, `get_attack`). `declare` crée une entité par sa classe `stix2` ; `relate` crée une relation et contrôle : couple de types permis par la table de relations STIX, identifiant ATT&CK existant en v20.0 (révoqué → remplaçant), phrases citées existantes qui nomment l'entité reliée (ou les trois phrases précédentes, ou le titre de section). Les techniques, groupes et logiciels connus d'ATT&CK sont les objets officiels de MITRE, pas des copies. |
| `preprocessing/cleaning/text/evidence.py` | Comparaison de noms normalisés, ancrage des preuves, confiance exprimée par l'auteur, analyse des dates. |
| `graph/places.py` | Résout un nom de lieu (« Russia », « Russie », « Eastern Europe ») en code ISO 3166-1 ou en région du vocabulaire STIX `region-ov`. Un nom non résolu est refusé, jamais inventé. |
| `observables/iocs.py` | IOC : valeurs candidates par règles (adresses, domaines, URL, courriels, hachages), filtres (adresses privées, domaines populaires, domaine de l'éditeur, extensions de fichier prises pour des TLD), regroupement par phrase ou section d'annexe, puis réponse fermée du modèle : rôle (`c2`, `payload-delivery`…) et entité de rattachement. Un IOC jugé non malveillant n'est pas un objet du graphe : il est écarté. Les IOC et règles sont écrits dans `article_<id>.iocs.json`, à part de la couche sémantique. |
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

## `extracting/stix/` : objets STIX 2.1 et bases de référence

| Fichier | Rôle |
| :--- | :--- |
| `objects.py` | Objets d'un article créés par les classes `stix2` en mode strict (`Malware`, `Relationship`, `Report`, `Bundle`…). Seul ajout : un **identifiant déterministe** pour les SDO et les relations (`deterministic_id`), pour qu'un même malware cité par deux articles soit un seul nœud dans Neo4j. Les observables gardent l'identifiant calculé par `stix2` selon la norme. |
| `attack.py` | MITRE ATT&CK v20.0. Le bundle officiel (52 Mo) est lu par `stix2`, et chaque objet utile est rangé dans `reference/attack_v20.sqlite` avec sa sérialisation officielle. La recherche d'une technique à partir d'un comportement utilise SQLite FTS5 : fusion des rangs (RRF) de deux recherches BM25, l'une sur noms et descriptions, l'autre sur les 17 636 exemples de procédures. `get_attack_kb()` donne l'index partagé. |
| `iocs.py` | IOC en STIX : observable (`DomainName`, `IPv4Address`, `URL`, `File`…) ← `based-on` ← `Indicator` (motif assemblé par `stix2.patterns`) → `indicates` → entité ; un `Sighting` daté par article ; `Infrastructure` → `consists-of` → observables. Le statut (actif, vieillissant, périmé) n'est jamais stocké : il est calculé à la lecture avec la table `LIFETIMES` (par exemple, une adresse IP est « active » 30 jours après sa dernière observation et « périmée » après 180 ; valeurs heuristiques, non calibrées). |
| `rules.py` | Une règle YARA ou Sigma devient un `Indicator` dont `pattern` est le texte exact de la règle et `pattern_type` son langage. Identifiant dérivé du langage et du texte. |

Reconstruire l'index ATT&CK (bundle officiel attendu dans backend/extracting/stix/reference/ ou Annotations/) :

```bash
uv run python -m backend.extracting.stix.attack [chemin/enterprise-attack-20.0.json]
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
| `cti_eval.py` | CLI `cti-eval`. `--run` extrait les articles du manifeste (`--workers N` articles à la fois), sinon re-score les bundles de `--bundles` (défaut : `backend/evaluation/eval/latest`). Écrit `runs.json` (durées, appels par étape, échecs, trace), `report.json` et `report.md` dans le dossier des bundles. `--compare a1,a2 b1,b2` compare des configurations (plusieurs exécutions chacune) : écart et intervalle de confiance à 95 % par bootstrap sur les articles, compteurs de mécanisme. |
| `score.py` | Méthode de score décrite ci-dessous. |
| `losses.py` | Où se perd chaque élément required manqué ; techniques jamais proposées réparties en « aucun comportement relevé », « absente des candidates », « candidate non retenue » ; rappel de la recherche ; relations retirées par le vérificateur rapprochées du gold. |

- **Rappel** (métrique principale) = objets `required` trouvés / total `required`.
- **Précision** = objets `required` ou `acceptable` trouvés / total prédit.
- **Périmètre** : la couche sémantique. Les IOC, les conteneurs (`report`, `sighting`…) et l'identité de l'éditeur
  sont ignorés des deux côtés.
- **Normalisation** : identifiant ATT&CK (alias compris), CVE, puis nom normalisé. Types équivalents : malware/tool,
  intrusion-set/threat-actor, campaign/incident.
- **Crédit partiel** des techniques : même identifiant = 1 ; même technique parente ou sous-techniques sœurs = 0,5. Une
  relation vaut le plus petit crédit de ses deux extrémités. Le score **strict** (sans crédit partiel) est publié à côté.
- **Score relâché** des relations `uses` : la source prédite peut être toute entité du groupe d'activité de la source gold
  (campagne, groupe auquel elle est attribuée, malwares et outils reliés entre eux dans le gold). Il mesure ce dont
  l'attribution a besoin (la technique a-t-elle été vue dans l'activité ?) sans la convention du porteur.
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
