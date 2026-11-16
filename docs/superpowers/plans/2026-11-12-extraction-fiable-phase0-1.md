# Extraction fiable — phases 0 et 1 (références, mesure, vérificateur) — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** remettre les références d'évaluation en accord avec la convention du porteur, mesurer erreurs / omissions /
stabilité, puis construire un vérificateur par questions fermées (agent, portée, mécanisme, statut) validé hors ligne
avant d'être branché dans la cascade.

**Architecture:** trois blocs. (1) Mesure : métrique de stabilité dans `cti-eval --compare`, audit des faux positifs
étendu aux entités et relations. (2) Références : règle écrite dans la méthode d'annotation, gold révisé depuis le texte
via une feuille de révision, prompts de la cascade alignés. (3) Vérificateur `backend/extracting/cascade/verify.py`
(modes `off` / `shadow` / `on` par `CTI_VERIFY`), décision pure testée, barrière hors ligne
`backend/evaluation/verifier_gate.py`.

**Tech Stack:** Python 3 (uv), stix2, vLLM `cti-qwen` (sortie JSON contrainte), pytest (nouveau, groupe dev), page HTML
sans dépendance pour l'audit.

**Spec:** `docs/superpowers/specs/2026-11-12-extraction-fiable-design.md` (§3 convention, §6.2 vérificateur, §6.4 barrière,
§7 mesure, §9 phases 0–1). Les phases 2 à 5 (proposition large P1–P4, statut dans le dashboard, robustesse, conflits entre
articles) feront l'objet d'un plan suivant, une fois la barrière passée ; y vont aussi les signalements de cohérence
(§6.3) et l'audit des omissions (§7, point 2 : les pertes par étape de `losses.py` restent la mesure des omissions ici).

## Global Constraints

- Jamais plus de requêtes simultanées que `CTI_LLM_SLOTS` ; passer par `llm.map_parallel` / `_call`, jamais d'appel direct.
- Aucun nom ni identifiant tiré des articles annotés dans les prompts, le code ou les tests (noms inventés dans les tests).
- Le modèle décide du sens ; le code borne (énumérations), vérifie la forme (`DraftGraph.relate`) et signale.
- Pas de raisonnement libre ni de confiance verbalisée demandés au modèle.
- Porteur = celui qui fait l'action : code d'un malware/outil → ce malware/outil ; opérateurs → l'`intrusion-set` nommé ;
  opérateurs sans groupe nommé → la campagne. La campagne relie les entités centrales (`attributed-to`, `uses`
  malware/outil/infrastructure, `targets`).
- Statut : établie → `confidence` 85 ; conclusion assumée par l'auteur → 60 ; spéculative ou démentie → retirée.
- Gold révisé **depuis le texte de l'article**, jamais depuis une sortie de l'extracteur.
- Toute variante d'extraction : au moins deux exécutions, comparées par `cti-eval --compare`.
- Commit seulement à la demande de l'utilisateur (les étapes « Commit » ci-dessous attendent son accord) ; messages terminés par
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. Réponse du vérificateur tronquée ou réparée (verdict absent pour certaines affirmations) → ces affirmations restent
   telles quelles, rien n'est retiré par défaut. Test : Task 6, `test_missing_verdict_keeps_claim`.
2. Indice hors bornes ou valeur hors énumération dans un verdict → traité comme « pas de verdict ». Test : Task 6,
   `test_out_of_range_agent_is_no_verdict`.
3. Réattribution vers un agent que les phrases ne nomment pas → on essaie avec deux phrases de la grappe qui le nomment,
   sinon l'affirmation d'origine est retirée avec la raison « porteur contesté » (la précision prime). Test : Task 7,
   `test_reassign_unnamed_agent_drops_with_reason`.
4. Remontée à la parente alors que la parente existe déjà sur la même source → citations fusionnées, pas de doublon.
   Test : Task 7, `test_to_parent_merges_existing`.
5. Article sans relation ni porteur (cas réel : 1438) → aucun appel au modèle, aucune erreur de schéma (énumération vide).
   Test : Task 6, `test_no_claims_no_batches`.
6. Anciens verdicts `fp_audit.json` (clés `aid:T####`) toujours lus après l'extension de l'audit. Test : Task 2,
   `test_legacy_keys_still_count`.

---

### Task 1: pytest et métrique de stabilité dans `--compare`

**Files:**
- Modify: `pyproject.toml` (groupe dev : `pytest`)
- Create: `backend/evaluation/stability.py`
- Modify: `backend/evaluation/cti_eval.py` (`compare`, ~l. 220)
- Test: `tests/evaluation/test_stability.py`

**Interfaces:**
- Produces: `bundle_keys(bundle: dict, kb: AttackKB) -> tuple[set[tuple], set[tuple], set[tuple]]` (entités
  `(type, nom normalisé ou T####)`, techniques, relations `(type_s, nom_s, rel, type_t, nom_t)`) ;
  `jaccard(a: set, b: set) -> float` (1.0 si les deux sont vides) ;
  `stability(run_a: Path, run_b: Path) -> dict[str, float]` → `{"entities", "techniques", "relations"}` (Jaccard des unions
  sur les articles communs) ; `article_stability(run_a, run_b) -> dict[int, dict[str, float]]`.

- [ ] **Step 1: `uv add --dev pytest` ; créer `tests/__init__.py`, `tests/evaluation/__init__.py`.**
- [ ] **Step 2: Write the failing test**

```python
def test_jaccard_empty_is_one():
    assert jaccard(set(), set()) == 1.0

def test_bundle_keys_uses_technique_id_and_normalized_name():
    # bundle minimal : un malware « Alpha-Loader », une technique T1059.001, une relation uses
    ents, techs, rels = bundle_keys(BUNDLE, get_attack_kb())
    assert ("attack-pattern", "T1059.001") in techs
    assert ("malware", normalize_name("Alpha-Loader"), "uses", "attack-pattern", "T1059.001") in rels

def test_stability_identical_runs(tmp_path):  # deux dossiers avec le même article_1.json
    assert stability(tmp_path / "a", tmp_path / "b") == {"entities": 1.0, "techniques": 1.0, "relations": 1.0}
```

- [ ] **Step 3: Run** `uv run pytest tests/evaluation/test_stability.py -v` → FAIL (module absent).
- [ ] **Step 4: Implement** `stability.py` (lecture par `score.load_bundle(..., gold=False)`, comme le script d'analyse du
  2026-11-12 ; fichiers `article_<id>.json` seulement, pas `.iocs.json`). Dans `compare`, pour chaque configuration d'au
  moins deux dossiers, ajouter une ligne « stabilité (Jaccard entités / techniques / relations) » calculée sur la paire
  des deux premiers dossiers.
- [ ] **Step 5: Run** les tests → PASS ; puis `uv run cti-eval --compare noleak_1,noleak_2 cascade2_a,cascade2_b` → la ligne
  stabilité de `cascade2` affiche 0.86 / 0.85 / 0.77 (valeurs de l'analyse du 2026-11-12).
- [ ] **Step 6: Commit** `feat(eval): stabilité entre exécutions dans cti-eval --compare`.

### Task 2: audit étendu aux entités et aux relations

**Files:**
- Modify: `backend/evaluation/fp_audit.py`, `backend/evaluation/fp_audit.html`
- Test: `tests/evaluation/test_fp_audit.py`

**Interfaces:**
- Consumes: `report.json` d'une exécution (`articles[].review_entities`, `articles[].review_relations`).
- Produces: chaque item porte `kind: "technique" | "entity" | "relation"` ; clés `aid:T####` (inchangées),
  `aid:E:<describe>`, `aid:R:<relation>` ; `summary_line` publie la précision corrigée par type :
  `(appariés + J) / prédits` et `(appariés + J + D) / prédits`, D publié à part.

- [ ] **Step 1: Write the failing tests**

```python
def test_items_have_three_kinds(): ...          # analyse(run) sur un dossier factice : kinds == {"technique","entity","relation"}
def test_entity_key_format(): assert item["key"].startswith("1:E:")
def test_legacy_keys_still_count():             # verdicts {"1:T1005": {"verdict": "F"}} comptés dans les techniques
    assert "F 1" in summary_line(data, {"1:T1005": {"verdict": "F", "comment": ""}})
```

- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.** Entités : items depuis `review_entities` (hors `attack-pattern`, déjà couvertes), avec les
  phrases qui nomment l'entité (`segment` + `mentions`, au plus 3). Relations : items depuis `review_relations` (relation
  + citation), hors relations `uses → attack-pattern` dont la technique est déjà un item. Page : l'en-tête de la carte
  s'adapte à `kind` (technique : carte ATT&CK actuelle ; entité : type + nom ; relation : source → relation → cible) ;
  filtre par type à côté du filtre « À juger ».
- [ ] **Step 4: Run** les tests → PASS ; `uv run python -m backend.evaluation.fp_audit cascade2_a` affiche toujours
  « J 6 · D 8 · F 7 » pour les techniques.
- [ ] **Step 5: Commit** `feat(eval): audit des faux positifs étendu aux entités et relations`.

### Task 3: convention écrite et feuille de révision du gold

**Files:**
- Modify: `Annotations/methode_annotation.md` (section « Campagnes et acteurs »)
- Create: `backend/evaluation/gold_carriers.py`
- Test: `tests/evaluation/test_gold_carriers.py`

**Interfaces:**
- Produces: `uv run python -m backend.evaluation.gold_carriers worksheet <article_id|all>` → écrit
  `Annotations/revision/<article_id>.carriers.json` : une ligne par relation gold `uses → attack-pattern`
  `{"relation_id", "source": "<type>:<nom>", "technique": "T####", "quote", "context", "candidates": ["<id>", ...],
  "decision": "keep", "new_source": null, "reason": ""}` ; candidates = campagne, `intrusion-set` et malwares/outils du
  même groupe d'activité (`score.activity_groups`).
  `... gold_carriers apply <article_id>` → réécrit `source_ref` des lignes `decision == "move"` dans le gold, contrôle
  que la relation obtenue est dans `ALLOWED_RELATIONS` et qu'aucun doublon `(source, uses, cible)` n'apparaît (fusion des
  citations sinon) ; affiche le nombre de relations déplacées.

- [ ] **Step 1: Write in `methode_annotation.md`** la règle du §3 de la conception (porteur = qui fait l'action ;
  campagne = nœud central ; opérateurs sans groupe nommé → campagne ; campagne non nommée créée seulement si décrite).
- [ ] **Step 2: Write the failing tests**

```python
def test_worksheet_lists_only_uses_to_technique(): ...   # gold factice : 2 uses→attack-pattern, 1 uses→malware → 2 lignes
def test_apply_moves_source_and_merges_duplicate(): ...  # déplacer vers un malware qui porte déjà la technique → 1 relation, citations fusionnées
def test_apply_refuses_disallowed_relation(): ...        # new_source = location → erreur, gold inchangé
```

- [ ] **Step 3: Run** → FAIL. **Step 4: Implement.** **Step 5: Run** → PASS.
- [ ] **Step 6: Commit** `feat(gold): règle du porteur et feuille de révision du gold`.

### Task 4: révision du gold (données) — point de contrôle utilisateur

**Files:**
- Modify: les 9 gold de `Annotations/*/…_gold.json` via `gold_carriers apply`
- Create: `Annotations/revision/<article_id>.carriers.json`

- [ ] **Step 1: Générer les feuilles** `gold_carriers worksheet all`.
- [ ] **Step 2: Décider chaque ligne en lisant l'article** (`Annotations/<article>/*.md`, phrase citée et contexte de
  section) selon la règle ; `reason` = la phrase qui désigne l'auteur de l'action. Ne jamais ouvrir un bundle de
  `backend/evaluation/eval/` pendant cette étape.
- [ ] **Step 3: Point de contrôle.** Demander à l'utilisateur de choisir 2 ou 3 articles du noyau validé à la main et de
  relire leurs feuilles ; appliquer ses corrections.
- [ ] **Step 4: Appliquer** `gold_carriers apply <id>` pour chaque article ; re-noter les références :
  `uv run cti-eval --bundles backend/evaluation/eval/<run>` pour `noleak_1`, `noleak_2`, `cascade2_a`, `cascade2_b`.
- [ ] **Step 5: Run** `uv run cti-eval --compare noleak_1,noleak_2 cascade2_a,cascade2_b` et noter dans la mémoire du projet
  les nouveaux chiffres de référence (relations strictes, « autre source »).
- [ ] **Step 6: Commit** `data(gold): porteurs révisés selon la règle (feuilles dans Annotations/revision/)`.

### Task 5: prompts de la cascade alignés sur la convention

**Files:**
- Modify: `backend/extracting/cascade/clusters.py` (`CARRIER_RULE`), `backend/extracting/cascade/techniques.py`
  (`GRID_SYSTEM`, « Carrier rule »)

- [ ] **Step 1: Réécrire** les deux règles : opérateurs → le groupe nommé ; sans groupe nommé → la campagne ; code → le
  malware ou l'outil. Aucun exemple tiré du gold.
- [ ] **Step 2: Vérifier** `uv run cti-extract --article-id <un article non annoté> --dry-run --show-log` (pas d'erreur).
- [ ] **Step 3: Mesurer** deux exécutions : `CTI_CASCADE=on uv run cti-eval --run --workers 4 --bundles
  backend/evaluation/eval/cascade3_a` (puis `_b`) ; `cti-eval --compare cascade2_a,cascade2_b cascade3_a,cascade3_b`.
  Attendu : « autre source » en baisse, aucune baisse significative ailleurs ; sinon revenir à l'utilisateur avant la
  suite.
- [ ] **Step 4: Commit** `feat(cascade): règle du porteur alignée sur la méthode d'annotation`.

### Task 6: vérificateur — affirmations, schéma, décision pure

**Files:**
- Create: `backend/extracting/cascade/verify.py`
- Test: `tests/extracting/test_verify.py`

**Interfaces:**
- Produces:
  - `@dataclass Claim(key: tuple[str, str, str], kind: Literal["action", "technique", "relation"], quotes: list[str],
    procedure: str | None)` — `action` : source de type porteur et relation `uses`/`targets` vers une entité non
    technique ; `technique` : `uses → attack-pattern` (ou technique gardée sans porteur, `key = ("", "uses", sid)`) ;
    `relation` : le reste.
  - `@dataclass Verdict(agent: int | None, scope: str | None, mechanism: str | None, status: str | None)`.
  - `SCOPES = ("incident", "past_campaign", "other_actor", "general")`, `MECHANISMS = ("technique", "parent", "none")`,
    `STATUSES = ("established", "assessed", "speculative", "refuted")`, `CONFIDENCE = {"established": 85, "assessed": 60}`.
  - `@dataclass Decision(action: Literal["keep", "reassign", "to_parent", "drop"], new_source: str | None,
    confidence: int | None, reason: str)`.
  - `collect_claims(draft: DraftGraph, behaviors: list[dict]) -> list[Claim]`.
  - `batches(claims: list[Claim], size: int = 25) -> list[list[Claim]]` (liste vide si aucune affirmation).
  - `verify_schema(n_claims: int, n_agents: int) -> dict` : `{"verdicts": [{"claim": enum 1..n, "agent": enum 0..n_agents,
    "scope": enum SCOPES, "mechanism": enum MECHANISMS, "status": enum STATUSES}]}`, `minItems` 1.
  - `verify_prompt(text: str, draft: DraftGraph, batch: list[Claim], agents: list[str]) -> str` : texte entier en tête
    (cache de préfixe, comme les autres appels), puis les affirmations numérotées avec leurs phrases, puis les questions :
    « qui effectue l'action décrite (0 = le texte ne le dit pas) », « ces phrases décrivent-elles l'incident du rapport ou
    autre chose », « la phrase décrit-elle le mécanisme de cette technique, seulement de sa parente, ou aucun »,
    « comment le texte présente-t-il le fait ». Définition ATT&CK (résumé 300 caractères) jointe aux affirmations
    `technique`.
  - `parse_verdicts(answer: dict, n_claims: int, n_agents: int) -> dict[int, Verdict]` : indices hors bornes ou valeurs
    hors énumération ignorés.
  - `decide(claim: Claim, verdict: Verdict | None, agents: list[str]) -> Decision` (pure) — ordre : pas de verdict →
    keep ; statut `speculative`/`refuted` → drop ; portée ≠ incident → drop ; `technique` et mécanisme `none` → drop,
    `parent` sur une sous-technique → to_parent ; `action`/`technique` avec agent 0 → drop (« auteur non dit »), agent ≠
    source → reassign ; sinon keep ; `confidence` selon `CONFIDENCE`.

- [ ] **Step 1: Write the failing tests** (noms inventés, aucun nom du gold)

```python
def test_missing_verdict_keeps_claim():
    assert decide(CLAIM_TECH, None, AGENTS).action == "keep"

def test_out_of_range_agent_is_no_verdict():
    v = parse_verdicts({"verdicts": [{"claim": 1, "agent": 9, "scope": "incident", "mechanism": "technique", "status": "established"}]}, 1, 2)
    assert 1 not in v

def test_speculative_dropped():
    assert decide(CLAIM_TECH, Verdict(1, "incident", "technique", "speculative"), AGENTS).action == "drop"

def test_background_dropped():
    assert decide(CLAIM_REL, Verdict(1, "past_campaign", None, "established"), AGENTS).action == "drop"

def test_parent_on_subtechnique():
    assert decide(CLAIM_SUBTECH, Verdict(1, "incident", "parent", "established"), AGENTS).action == "to_parent"

def test_other_agent_reassigns():
    d = decide(CLAIM_TECH, Verdict(2, "incident", "technique", "established"), AGENTS)
    assert (d.action, d.new_source) == ("reassign", AGENTS[1])

def test_assessed_confidence_60():
    assert decide(CLAIM_REL, Verdict(1, "incident", None, "assessed"), AGENTS).confidence == 60

def test_no_claims_no_batches():
    assert batches([]) == []
```

- [ ] **Step 2: Run** `uv run pytest tests/extracting/test_verify.py -v` → FAIL.
- [ ] **Step 3: Implement** les fonctions ci-dessus. `agents` = porteurs déclarés (types de `CARRIER_TYPES`) présents dans
  les grappes `incident`, en identifiants STIX ; l'énumération 0..n_agents reste valide quand n_agents = 0.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(cascade): vérificateur par questions fermées (décision pure)`.

### Task 7: vérificateur — application au graphe et modes `CTI_VERIFY`

**Files:**
- Modify: `backend/extracting/cascade/verify.py` (application), `backend/extracting/graph/draft.py`
  (`confidence: dict[tuple[str, str, str], int]`, lu par `relationships()` avant `confidence_from_text`),
  `backend/extracting/pipeline.py` (`extract_cascade`, `ExtractionResult`)
- Test: `tests/extracting/test_verify_apply.py`

**Interfaces:**
- Consumes: Task 6.
- Produces: `apply(draft: DraftGraph, claim: Claim, decision: Decision, result) -> None` ;
  `verify_claims(draft, text, system, clusters, result, call, apply_decisions: bool) -> list[dict]` (décisions pour la
  trace : `{"key": [s, rel, t], "kind", "verdict": {...} | None, "decision": {...}}`) ;
  `ExtractionResult.verdicts: list[dict]`, écrit dans `runs.json` par `losses.trace_of` (clé `verdicts`) ;
  `VERIFY_MODE = os.environ.get("CTI_VERIFY", "off")` : `off` = vérificateur actuel seul ; `shadow` = vérificateur actuel
  appliqué, nouveau calculé et tracé sans effet ; `on` = nouveau appliqué à la place de `verify_relations`.

- [ ] **Step 1: Write the failing tests** — `DraftGraph(segment(TEXTE), ArticleContext(1, "test-source", None, "t"))`
  avec un texte inventé où « Alpha-Loader » chiffre ses chaînes et le groupe « Group-Nine » envoie les courriels.

```python
def test_reassign_moves_relation():              # uses T1027 sur Group-Nine, agent = Alpha-Loader → relation sur Alpha-Loader
def test_reassign_unnamed_agent_drops_with_reason():  # agent que les phrases ne nomment pas → retirée, reason "porteur contesté"
def test_to_parent_merges_existing():            # T1059.001 → T1059 déjà présent sur la même source : une seule relation, citations fusionnées
def test_drop_records_refusal():                 # result.refused_relations contient (s, rel, t, reason)
def test_confidence_written_to_bundle():         # decision.confidence 60 → relationship.confidence == 60
```

- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.** Réattribution : `draft.relate` avec les numéros des citations (texte → uid par
  `{u.text: u.uid}`), puis avec au plus deux phrases de la grappe qui nomment l'agent (même logique que
  `techniques._evidence`) ; échec → retrait, raison « porteur contesté ». Remontée : `draft.technique(parent)` puis relation
  sur la parente, procédures déplacées. Retrait : comme `verify_relations` (log, `refused_relations`, compteurs). Dans
  `extract_cascade`, appeler `verify_claims` après `technique_relations` selon `VERIFY_MODE`.
- [ ] **Step 4: Run** → PASS ; `CTI_CASCADE=on CTI_VERIFY=shadow uv run cti-extract --article-id <article non annoté>
  --dry-run --show-log` sans erreur, verdicts présents dans la trace.
- [ ] **Step 5: Commit** `feat(cascade): application du vérificateur, modes off/shadow/on`.

### Task 8: barrière hors ligne

**Files:**
- Create: `backend/evaluation/verifier_gate.py`
- Test: `tests/evaluation/test_verifier_gate.py`

**Interfaces:**
- Consumes: `runs.json` (`verdicts`) d'une exécution `shadow`, son `report.json`, un ou plusieurs `fp_audit.json` de
  référence.
- Produces: `uv run python -m backend.evaluation.verifier_gate <run_shadow> --audit cascade2_a [--audit ...]` → tableau :
  vrais positifs (appariés au gold) gardés / retirés ; F audités rejetés / gardés ; J et D gardés (ou remontés) / retirés ;
  verdict final « PASSE » si F rejetés ≥ 2/3 **et** vrais positifs gardés ≥ 95 %, « ÉCHOUE » sinon, avec la liste des
  vrais positifs retirés (raison) pour corriger les questions.
  Étiquetage : relation appariée au gold → garder ; technique dont la clé `aid:T####` a un verdict F → rejeter, J/D →
  garder ; entités et relations auditées (Task 2) de même ; le reste n'est pas compté.

- [ ] **Step 1: Write the failing tests**

```python
def test_gate_passes_on_thresholds(): ...   # 3 F dont 2 rejetés, 20 VP dont 19 gardés → PASSE
def test_gate_fails_on_false_rejections(): ...  # 20 VP dont 18 gardés → ÉCHOUE
def test_to_parent_counts_as_kept_for_d(): ...
```

- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(eval): barrière hors ligne du vérificateur`.

### Task 9: mesure et décision de branchement — point de contrôle utilisateur

- [ ] **Step 1: Deux exécutions shadow** : `CTI_CASCADE=on CTI_VERIFY=shadow uv run cti-eval --run --workers 4 --bundles
  backend/evaluation/eval/verify_shadow_a` (puis `_b`).
- [ ] **Step 2: Barrière** sur les deux : `verifier_gate verify_shadow_a --audit cascade2_a`. Si ÉCHOUE : corriger les
  questions du prompt (jamais les seuils), relancer Step 1. Rapporter à l'utilisateur les vrais positifs retirés.
- [ ] **Step 3: Si PASSE, deux exécutions `on`** (`verify_on_a/_b`) ; `cti-eval --compare cascade3_a,cascade3_b
  verify_on_a,verify_on_b` ; audit (Task 2) de `verify_on_a` par l'utilisateur ; précision corrigée et stabilité.
- [ ] **Step 4: Point de contrôle** : présenter à l'utilisateur précision corrigée, omissions par étape, stabilité, tokens ;
  décider avec lui de passer `CTI_VERIFY=on` par défaut en mode cascade, puis mettre à jour la mémoire du projet et
  `CLAUDE.md` (§5.C : nouvelles références et variables).
