# Extraction en cascade : graphe d'abord, techniques ensuite — Plan

> **Pour les agents :** sous-skill requis : superpowers:subagent-driven-development (recommandé) ou superpowers:executing-plans
> pour exécuter ce plan tâche par tâche. Les étapes utilisent des cases à cocher (`- [ ]`).

**But :** extraire d'un rapport CTI un graphe STIX 2.1 en trois étapes simples et mesurables séparément : (1) les entités
et leurs relations, (2) des grappes centrées sur chaque acteur ou logiciel, rattachées aux passages du texte, (3) pour chaque
grappe, les techniques ATT&CK, tactique par tactique.

**Architecture :** le modèle ne prend que des décisions de sens courtes, contraintes par une grammaire STIX imposée au
décodage ; le code construit tout le reste (identifiants, objets STIX, IOC, rapport, validation).

**Technologies :** Python, vLLM (`response_format` JSON Schema, xgrammar), `stix2`, index ATT&CK v20.0 existant
(`backend/extracting/stix/attack.py`).

**Spec :** `docs/superpowers/specs/2026-11-09-typed-extraction-design.md` (diagnostic, périmètre des types, anti-objectifs).
Ce plan en remplace la partie « architecture » ; le reste de la spec s'applique.

---

## Partie 1 — L'architecture, en clair

### 1.1 L'idée en une phrase

On extrait d'abord **ce dont parle le texte** (qui, avec quoi, contre qui), puis on se demande **comment** chacun a agi, en
passant en revue les tactiques ATT&CK une par une, pour chaque acteur ou logiciel.

### 1.2 Pourquoi cet ordre

- Les entités et leurs relations sont nommées dans le texte : c'est ce qu'un modèle de 27B extrait le mieux.
- Les techniques ATT&CK sont la partie difficile : il faut traduire un récit en un catalogue de 227 techniques, et
  rattacher chacune à celui qui l'exécute. Quand le graphe existe déjà, le porteur est connu avant de chercher la technique.
- C'est la forme des données ATT&CK elles-mêmes : un porteur `uses` une technique, la procédure décrite en une phrase,
  le rapport cité (18 975 relations de ce type dans ATT&CK v20).

### 1.3 Trois règles qui valent partout

1. **Le modèle choisit, le code écrit.** Le modèle n'écrit jamais d'identifiant STIX, d'UUID, de valeur d'IOC ni
   d'identifiant ATT&CK de mémoire. Il désigne des éléments par leur numéro dans une liste qu'on lui montre.
2. **La grammaire est imposée au décodage.** Chaque réponse est un JSON dont les types STIX, les relations, les numéros
   d'entités et les identifiants ATT&CK sont des `enum` : une réponse hors ontologie est impossible à écrire, pas refusée
   après coup. Les schémas sont générés par le code depuis le registre (`stix/specs.py`) et les listes de l'article.
3. **Tout est ancré dans le texte.** Chaque entité, relation et technique cite les numéros des phrases qui l'affirment ;
   le code vérifie que ces phrases existent et nomment ce qu'elles relient. Sans phrase, pas d'élément.

### 1.4 Vue d'ensemble

```
            texte nettoyé ──► phrases numérotées
                                   │
   ┌───────────── CODE ────────────┼──────────────────────────────────────────────┐
   │ IOC et règles YARA/Sigma trouvés par règles (existant)                       │
   └───────────────────────────────┼──────────────────────────────────────────────┘
                                   ▼
 ÉTAPE 1  Sous-graphe       entités typées  ──►  relations STIX entre elles
                            (+ rôle et rattachement de chaque IOC, existant)
                                   ▼
 ÉTAPE 2  Grappes           pour chaque porteur : ses voisins + les phrases qui le décrivent
                                   ▼
 ÉTAPE 3  Techniques        pour chaque grappe :
                              3a  grille des tactiques : procédure + phrases, ou vide
                              3b  pour chaque case remplie : technique choisie dans la liste
                                  complète de la tactique, puis sous-technique
                                   ▼
   ┌───────────── CODE ───────────────────────────────────────────────────────────┐
   │ objets STIX officiels, porteur --uses--> technique, rapport, UUIDv5, stix2   │
   └──────────────────────────────────────────────────────────────────────────────┘
```

### 1.5 Étape 1 — Le sous-graphe : entités et relations

**1a. Entités.** Le modèle lit l'article et liste les entités du registre : `intrusion-set`, `threat-actor`, `campaign`,
`malware`, `tool`, `infrastructure`, `vulnerability`, `software`, `identity`, `location`, `course-of-action`,
`malware-analysis`. Grammaire :

```json
{"entities": [{"type": "<enum des types du registre>", "name": "...", "aliases": ["..."], "sentences": [12, 13]}]}
```

**1b. Relations.** Le code numérote les entités retenues et génère un schéma qui n'autorise que les relations de la table
STIX : une branche par couple (type source, relation), avec en `enum` les seules entités compatibles.

```json
{"relations": [{"source": 3, "relation": "uses", "target": 5, "sentences": [20]}]}
// branche « malware uses » : source ∈ {numéros des malwares}, target ∈ {numéros des malwares, outils, infrastructures}
```

**1c. IOC (inchangé).** Les valeurs sont trouvées par règles ; le modèle donne seulement le rôle de chaque IOC et l'entité à
laquelle il se rattache, déjà sous grammaire `enum` (`observables/iocs.py`).

Sortie : un graphe d'entités, sans technique, entièrement ancré.

### 1.6 Étape 2 — Les grappes

Une grappe est un **porteur** de techniques, avec ce qui l'entoure dans le graphe et les phrases qui décrivent ce qu'il fait.

- Porteurs possibles (ceux qui peuvent `uses` une technique en STIX) : `campaign`, `intrusion-set`, `threat-actor`,
  `malware`, `tool`. Une `malware-analysis` n'est pas un porteur : sa grappe est celle du malware analysé.
- Une grappe spéciale **« attaquants non nommés »** reçoit les actions que le texte n'attribue à aucun porteur nommé.
- Les grappes peuvent se chevaucher : « la campagne utilise un loader qui dépose X » appartient à la grappe de la campagne
  et à celle du loader.
- Le texte n'est pas découpé : l'article entier reste en tête de chaque prompt (relu depuis le cache du serveur, et utile
  pour comprendre « il », « ce malware ») ; la grappe désigne seulement des numéros de phrases.

Grammaire :

```json
{"clusters": [{"center": "<enum des porteurs + unnamed>", "members": [4, 7], "sentences": [30, 31, 32, 45]}]}
```

### 1.7 Étape 3 — Les techniques, tactique par tactique

**3a. La grille.** Pour une grappe, le modèle remplit une grille qui a une case par tactique ATT&CK v20
(reconnaissance, resource-development, initial-access, execution, persistence, privilege-escalation, stealth,
defense-impairment, credential-access, discovery, lateral-movement, collection, command-and-control, exfiltration, impact).
Chaque case contient les actions du porteur pour cette tactique, ou reste **vide** — ce qui est la réponse normale pour la
plupart des tactiques.

```json
{"initial-access": [{"procedure": "envoie un courriel avec une pièce jointe LNK", "sentences": [31]}],
 "persistence": [],
 "...": []}
```

La grille oblige le modèle à se poser la question pour chaque tactique : il ne peut plus oublier la persistance ou
l'exfiltration. Une action sans phrase citée est refusée par le code.

**3b. Le choix de la technique.** Pour chaque action de la grille, le modèle choisit la technique dans **la liste complète
de la tactique** : de 9 à 34 techniques parentes, chacune montrée avec son nom et une phrase de résumé (environ 900 tokens
au plus). Il n'y a donc pas de recherche préalable qui pourrait écarter la bonne réponse. Puis, si la technique a des
sous-techniques, il choisit parmi ses enfants ou garde la parente.

```json
{"choices": [{"action": 1, "technique": "<enum des T#### de la tactique | none>"}]}
{"choices": [{"action": 1, "subtechnique": "<enum des T####.### de cette parente | parent>"}]}
```

La recherche BM25 existante (descriptions + procédures ATT&CK) peut **mettre en avant** quelques techniques en tête de
liste, sans jamais en retirer.

**L'agent, seulement pour réparer.** Si le modèle répond `none` pour une action pourtant ancrée, un agent doté des outils
`search_attack` / `get_attack` peut reformuler la recherche, avec un nombre d'appels borné. C'est le seul endroit agentique
du pipeline.

### 1.8 Ce que fait le code à la fin

- Crée chaque technique comme l'objet ATT&CK officiel (identifiant, nom, `kill_chain_phases` tirés d'ATT&CK) ;
- écrit `porteur --uses--> technique`, avec la procédure en `description` et les phrases citées ;
- fusionne une même technique trouvée sous deux tactiques (26 techniques appartiennent à plusieurs tactiques) ;
- construit le rapport, les identifiants déterministes (UUIDv5), et valide le tout avec `stix2`.

La tactique n'est pas un nœud du graphe : c'est une propriété de la technique. Le profil d'acteur du dashboard range déjà
les techniques par tactique.

### 1.9 Ce que le modèle décide, ce que le code fait

| Le modèle décide | Le code fait |
|---|---|
| quelles entités, de quel type STIX | trouve les IOC, CVE et règles par règles |
| quelles relations STIX entre elles | numérote, génère les schémas, impose la grammaire |
| le rôle et le rattachement de chaque IOC | vérifie que chaque phrase citée existe et nomme ses entités |
| les grappes : porteurs et phrases | crée les objets STIX, les identifiants, le rapport |
| pour chaque tactique : les actions, ou rien | montre la liste complète des techniques de la tactique |
| quelle technique, quelle sous-technique | fusionne les doublons, valide avec `stix2` |

### 1.10 Comment on le mesure

Un score par étape, au lieu d'un chiffre global dominé par ATT&CK (aujourd'hui 97 des ~160 entités attendues sont des
techniques) :

1. **Graphe d'entités** (étape 1) : entités et relations sans `attack-pattern`.
2. **IOC** : rôle et rattachement.
3. **Techniques du rapport** (étape 3) : l'ensemble des techniques trouvées, quel que soit le porteur — forme comparable aux
   bundles de la CISA.
4. **Porteur** : pour chaque technique trouvée, le bon porteur.
5. **Ablation** : l'étape 3 exécutée sur les grappes construites depuis le gold, pour mesurer les techniques indépendamment
   des erreurs des étapes 1 et 2.

### 1.11 Risques connus

| Risque | Parade |
|---|---|
| Une grille de 15 cases pousse à les remplir (perte de précision) | chaque action exige des phrases ; « vide » est présenté comme la réponse normale ; précision mesurée par tactique |
| Une entité oubliée à l'étape 1 prive ses techniques de porteur | grappe « attaquants non nommés » ; score de l'étape 1 suivi à part |
| Contexte de 32k tokens | une liste de tactique ≤ 900 tokens ; une grappe par appel ; pas d'historique accumulé |
| Coût : 3 à 6 grappes × (1 grille + ~5 choix) | appels courts, même préfixe (cache), sorties contraintes |
| Sensibilité aux prompts (une phrase change une campagne) | chaque variante mesurée sur deux exécutions, comparée avec `cti-eval --compare` |

---

## Partie 2 — Feuille de route

## Contraintes globales

- `backend/extracting/llm.py` est le seul client du serveur vLLM ; jamais plus de requêtes simultanées que `CTI_LLM_SLOTS`.
- Aucun nom propre ni identifiant tiré des articles annotés dans les prompts ou le code (exemples en gabarits : `<malware>`, `T####.###`).
- ATT&CK v20.0 uniquement, depuis l'index existant (`stix/attack.py`) ; les procédures tirées de l'article lui-même restent exclues.
- Le nouveau chemin est activé par `CTI_CASCADE=on` ; sans lui, le pipeline actuel est inchangé.
- SQLite en lecture seule ; Neo4j et le dashboard ne changent pas (types déjà gérés par `stix_store`).
- Pas de tests unitaires backend : chaque tâche se valide par `cti-eval` sur les 9 articles annotés, deux exécutions, comparées à `noleak_1` / `noleak_2`.

## Points de vigilance

1. **`enum` vide** : un article sans entité d'un type donné ne doit pas produire de branche de schéma à `enum` vide (xgrammar la rejette) — la branche est omise. Vérifié en tâche 2 sur un article sans acteur (1079).
2. **Article sans porteur** (analyse d'une CVE seule, 1079) : les actions vont dans « attaquants non nommés » ; aucune technique n'est perdue faute de grappe. Vérifié en tâche 3.
3. **Même technique sous deux tactiques ou dans deux grappes** : une seule relation par couple (porteur, technique), phrases fusionnées. Vérifié en tâche 4.
4. **Case remplie sans phrase valide** : refusée et comptée dans le rapport, jamais acceptée. Vérifié en tâche 4.
5. **Article long** (1549, ~50 000 caractères) : chaque appel tient dans 32k tokens, `finish_reason` jamais `length`. Vérifié en tâche 5.

---

### Tâche 1 : Score par niveau (aucun appel au modèle)

**Fichiers :** modifier `backend/evaluation/score.py`, `backend/evaluation/cti_eval.py`.

**Interfaces :** produit `report.json["summary"]["levels"]` = `{"entity_graph": Counts, "techniques_report": Counts, "carrier": Counts}`.

- [ ] **Étape 1 :** dans `score.py`, ajouter `level_counts(by_type, by_pattern) -> dict[str, Counts]` : `entity_graph` = entités et relations dont aucun type n'est `attack-pattern` ; `techniques_report` = ensemble des `attack-pattern` de l'article, porteur ignoré ; `carrier` = relations `uses → attack-pattern` dont la technique est trouvée, porteur juste ou non.
- [ ] **Étape 2 :** publier ces trois niveaux en tête de `report.md` (rappel, précision).
- [ ] **Étape 3 :** re-scorer sans modèle : `uv run cti-eval --bundles backend/evaluation/eval/noleak_1` puis `noleak_2`. Attendu : les trois niveaux apparaissent ; noter les valeurs, elles sont la référence des tâches suivantes.
- [ ] **Étape 4 :** commit `cti-eval : score par niveau (graphe, techniques du rapport, porteur)`.

### Tâche 2 : Étape 1 sous grammaire (entités puis relations)

**Fichiers :** créer `backend/extracting/cascade/graph.py` et `backend/extracting/cascade/schemas.py` ; modifier `backend/extracting/pipeline.py` (branchement `CTI_CASCADE`).

**Interfaces :**
- `schemas.entity_schema() -> dict` (types en `enum` depuis `specs.TYPE_SPECS`) ;
- `schemas.relation_schema(entities: list[tuple[int, str]]) -> dict` (`anyOf` d'après `specs.RELATIONS`, branches à `enum` vide omises) ;
- `graph.build_graph(draft: DraftGraph, text: str, system: str, result: ExtractionResult) -> list[str]` : renvoie les identifiants STIX des entités retenues, relations appliquées via `draft.relate`.

- [ ] **Étape 1 :** écrire les deux générateurs de schéma ; ajouter `jsonschema` aux dépendances de développement (`uv add --dev jsonschema`) et vérifier sur un exemple qu'une relation conforme passe et qu'une relation hors table est rejetée par le schéma.
- [ ] **Étape 2 :** écrire `build_graph` : appel « entités » puis appel « relations » sur la liste numérotée ; aucune analyse de mini-langage (`split("|")`).
- [ ] **Étape 3 :** `uv run cti-extract --article-id 1079 --dry-run --show-log` puis `--article-id 1558` avec `CTI_CASCADE=on`. Attendu : aucun refus « n'existe pas en STIX 2.1 » ni « format attendu ».
- [ ] **Étape 4 :** `cti-eval --run` deux fois (`cascade1_a`, `cascade1_b`), comparer le niveau `entity_graph` à la tâche 1.
- [ ] **Étape 5 :** commit.

### Tâche 3 : Étape 2, les grappes

**Fichiers :** créer `backend/extracting/cascade/clusters.py`.

**Interfaces :** `clusters.build_clusters(draft, text, system, sids, result) -> list[Cluster]`, avec `Cluster(center: str | None, members: list[str], sentences: list[int])` ; `center=None` pour « attaquants non nommés ».

- [ ] **Étape 1 :** schéma : `center` en `enum` des porteurs de l'article + `unnamed` ; `members` et `sentences` en entiers ; une `malware-analysis` est remplacée par son malware (relation `analysis-of`).
- [ ] **Étape 2 :** écrire `build_clusters` ; le code vérifie que chaque phrase existe ; une grappe sans phrase valide est écartée.
- [ ] **Étape 3 :** `--dry-run --show-log` sur 1079 et 1697. Attendu : 1079 a une grappe `unnamed` ; 1697 a au moins une grappe campagne et une grappe malware.
- [ ] **Étape 4 :** commit.

### Tâche 4 : Étape 3, grille des tactiques et choix de la technique

**Fichiers :** créer `backend/extracting/cascade/techniques.py` ; modifier `backend/extracting/stix/attack.py` (liste par tactique).

**Interfaces :**
- `attack.techniques_of_tactic(tactic: str) -> list[TechniqueHit]` (parentes actives) et `attack.subtechniques_of(parent_id: str) -> list[TechniqueHit]` ;
- `techniques.attach_techniques(draft, text, system, clusters: list[Cluster], result) -> None` : écrit `porteur --uses--> technique` dans `draft`.

- [ ] **Étape 1 :** les deux fonctions d'`attack.py`, lues depuis l'index SQLite existant ; vérifier les décomptes : 15 tactiques, 227 parentes, discovery = 34.
- [ ] **Étape 2 :** appel « grille » par grappe (une clé par tactique, tableaux vides admis, `sentences` requis).
- [ ] **Étape 3 :** appel « choix » par tactique remplie (`enum` des T#### de la tactique + `none`), puis « sous-technique » (`enum` des enfants + `parent`) ; la recherche BM25 réordonne la liste sans la tronquer.
- [ ] **Étape 4 :** le code fusionne (porteur, technique) vus deux fois et refuse et compte les actions sans phrase valide. Les techniques de la grappe `unnamed` n'ont pas de porteur : elles entrent dans le rapport (`object_refs`) sans relation `uses`. Le code ne leur choisit jamais de porteur à la place du modèle.
- [ ] **Étape 5 :** `--dry-run --show-log` sur 1558. Attendu : aucune technique hors ATT&CK v20, aucun doublon (porteur, technique).
- [ ] **Étape 6 :** commit.

### Tâche 5 : Branchement, réparation par agent, mesure complète

**Fichiers :** modifier `backend/extracting/pipeline.py`, `backend/extracting/cascade/techniques.py`, `backend/evaluation/cti_eval.py`.

**Interfaces :** `cti_eval.oracle_clusters(gold: dict, units: list[Unit]) -> list[Cluster]` : une grappe par source d'une relation gold `uses → attack-pattern`, avec pour phrases celles qui nomment le centre ; consommée par `techniques.attach_techniques`.

- [ ] **Étape 1 :** `CTI_CASCADE=on` enchaîne tâches 2 → 3 → 4, puis IOC et règles comme aujourd'hui ; `relation_weaver`, `porteurs` et `corrections` ne sont plus appelés sur ce chemin.
- [ ] **Étape 2 :** réparation : pour une action ancrée restée `none`, au plus 3 tours de `llm.chat` avec `search_attack` / `get_attack` ; la technique n'est acceptée que si elle vient d'un résultat d'outil.
- [ ] **Étape 3 :** vérifier sur 1549 qu'aucun appel ne finit en `length` (journal `--llm-log`).
- [ ] **Étape 4 :** `cti-eval --run --workers 4` deux fois (`cascade_a`, `cascade_b`) ; `cti-eval --compare noleak_1,noleak_2 cascade_a,cascade_b`. Rapporter les trois niveaux de la tâche 1.
- [ ] **Étape 5 :** ablation : ajouter à `cti-eval` l'option `--oracle-clusters`, qui exécute seulement l'étape 3 sur `oracle_clusters(...)` ; deux exécutions ; rapporter les niveaux `techniques_report` et `carrier`.
- [ ] **Étape 6 :** commit.
