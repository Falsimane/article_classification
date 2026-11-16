# STIX 2.1 strict — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** ramener l'extraction, le gold et l'évaluation à la norme STIX 2.1 et aux règles tirées de l'audit des faux
positifs, puis mesurer l'effet.

**Architecture:** (1) Table `RELATIONS` réduite à la norme. `software` sort de la couche sémantique. Le lien « l'outil
réalise la technique » est gardé en interne sous la forme `tool uses attack-pattern` (porteurs, vérificateur, score
inchangés) et écrit `attack-pattern uses tool` dans le bundle ; le score relit les deux sens. (2) `DraftGraph.declare`
refuse les binaires natifs sans identifiant logiciel ATT&CK et les noms de fichiers. Il garde le nom de l'article face à
un alias ATT&CK. (3) Le gold est migré par un script vérifiable (`gold_strict.py`), puis complété par les éléments jugés J
dans l'audit. (4) Les consignes au modèle reprennent les règles. Le profil d'acteur lit la chaîne du commanditaire.

**Tech Stack:** Python 3 (uv), stix2, pytest, vLLM `cti-qwen`, Neo4j (profil d'acteur).

**Spec:** la norme `docs/stix-v2.1-os.pdf` fait foi pour les objets, les propriétés et les relations. La conception est
`docs/superpowers/specs/2026-11-12-extraction-fiable-design.md` §3, entrée « STIX 2.1 strict ». Les règles
détaillées sont dans `Annotations/methode_annotation.md` : « Types d'entités », « Ce que porte un logiciel », « Techniques :
frontières ATT&CK ». Les décisions de l'utilisateur du 2026-11-13 sont notées dans
`.superpowers/sdd/2026-11-12-extraction-fiable-phase0-1/progress.md`.

## Global Constraints

- **Modèle normatif : `docs/stix-v2.1-os.pdf`** (STIX 2.1 OS, 10 juin 2021). Pour chaque objet, la section « 4.x.2
  Relationships » fait foi. L'annexe B (p. 280–282) le dit elle-même, et elle omet `remediates` alors que la section 4.3.2
  (p. 58) le définit. `av-analysis-of` n'apparaît que dans la liste inverse de malware (4.11.2), pas dans la table propre
  de malware-analysis (4.12.2, p. 100) : il est exclu. La norme autorise aussi `related-to` et des noms définis par
  l'utilisateur entre tous objets (« Relationships are not restricted to those listed below ») ; le projet les exclut par
  décision (STIX strict). Propriétés et vocabulaires aussi d'après le PDF :
  - `threat-actor-type-ov` : `nation-state` ;
  - `industry-sector-ov` : `government-national` ;
  - `operating_system_refs` du malware vers des `software` (plus tard).
- Table de référence, relevée dans les sections 4.x.2 du PDF le 2026-11-16 : c'est l'ensemble exact que doit valoir
  `ALLOWED_RELATIONS`.
  - attack-pattern : delivers → malware ; targets → identity, location, vulnerability ; uses → malware, tool
  - campaign : attributed-to → intrusion-set, threat-actor ; compromises → infrastructure ; originates-from → location ;
    targets → identity, location, vulnerability ; uses → attack-pattern, infrastructure, malware, tool
  - course-of-action : mitigates → attack-pattern, malware, tool, vulnerability ; remediates → malware, vulnerability
  - identity : located-at → location
  - infrastructure : communicates-with, consists-of, uses → infrastructure ; controls → infrastructure, malware ;
    delivers → malware ; has → vulnerability ; hosts → tool, malware ; located-at → location
  - intrusion-set : attributed-to → threat-actor ; compromises, hosts, owns → infrastructure ; originates-from → location ;
    targets → identity, location, vulnerability ; uses → attack-pattern, infrastructure, malware, tool
  - malware : authored-by → threat-actor, intrusion-set ; beacons-to, exfiltrates-to → infrastructure ; controls → malware ;
    downloads, drops → malware, tool ; exploits → vulnerability ; originates-from → location ;
    targets → identity, infrastructure, location, vulnerability ; uses → attack-pattern, infrastructure, malware, tool ;
    variant-of → malware
  - malware-analysis : analysis-of, characterizes, static-analysis-of, dynamic-analysis-of → malware
  - threat-actor : attributed-to, impersonates → identity ; compromises, hosts, owns → infrastructure ; located-at →
    location ; targets → identity, location, vulnerability ; uses → attack-pattern, infrastructure, malware, tool
  - tool : delivers, drops → malware ; has → vulnerability ; targets → identity, infrastructure, location, vulnerability ;
    uses → infrastructure
- Seule orientation interne hors norme : `("tool", "uses", "attack-pattern")`. Elle n'existe que dans le brouillon et dans
  le score ; tout bundle écrit porte `attack-pattern uses tool`.
- Binaire natif = nom (sans `.exe`) présent dans `backend/extracting/stix/reference/native_binaries.txt`. Il n'est un
  `tool` que si ATT&CK v20 en a un logiciel actif (S####) ; sinon la déclaration est refusée.
- Pas de nom ni d'identifiant tiré des articles annotés dans le code, les prompts ou les tests. Noms de test autorisés,
  vérifiés absents de `Annotations/` : Alpha-Loader, Group-Nine, Beta-Tool, PsExec, bitsadmin, odbcconf, APT28, Fancy Bear.
  Aucun identifiant de technique dans les prompts : les frontières ATT&CK sont écrites avec les noms des techniques.
- Le modèle décide du sens ; le code borne et vérifie la forme. Jamais plus de requêtes simultanées que `CTI_LLM_SLOTS`.
- Toute variante d'extraction : deux exécutions, comparées par `cti-eval --compare`. Une retouche du prompt est un
  changement de méthode.
- Commit seulement à la demande de l'utilisateur ; messages terminés par
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. Anciens bundles (`tool uses attack-pattern`, objets `software`) re-scorés : la relation outil → technique s'apparie
   dans les deux sens, `software` n'est compté ni vrai ni faux. Tests : Task 3, `test_tool_technique_matches_both_directions`,
   `test_software_ignored`.
2. Binaire natif retiré du gold alors que la même technique part déjà de l'utilisateur de l'outil : fusion, pas de doublon.
   Test : Task 4, `test_drop_native_tool_merges_existing`.
3. Outil ATT&CK écrit avec `.exe` (« bitsadmin.exe ») : l'objet ATT&CK, ni refus « binaire natif » ni refus « nom de
   fichier ». Test : Task 2, `test_tool_exe_suffix_resolves_to_attack`.
4. Nom de l'article qui ne diffère du nom ATT&CK que par la casse ou la ponctuation (« apt28 ») : l'objet officiel, pas un
   objet renommé. Test : Task 2, `test_case_variant_gives_official_object`.
5. Déplacement d'une technique vers un outil dans la révision du gold : écrit dans le sens de la norme, sans doublon avec
   une relation existante dans l'autre sens. Test : Task 3, `test_move_to_tool_writes_stix_direction`.

---

### Task 0: prérequis — Task 5 du plan précédent (règle du porteur dans les prompts)

Exécuter `docs/superpowers/plans/2026-11-12-extraction-fiable-phase0-1.md`, Task 5, telle qu'écrite : `CARRIER_RULE`,
`GRID_SYSTEM`, puis les mesures `cascade3_a` et `cascade3_b`. L'effet du porteur est ainsi mesuré seul, avant les
changements de ce plan. `cascade3_a` / `cascade3_b` servent de référence aux Tasks 6 et 8.

### Task 1: table normée et orientation interne outil → technique

**Files:**
- Modify: `backend/extracting/stix/specs.py` (docstring, `TYPE_SPECS` sans `software`, `_TARGETS`, `RELATIONS`,
  `RELATION_DEFINITIONS` sans `has` vers software, `related-to`, `av-analysis-of`)
- Modify: `backend/extracting/stix/objects.py`
- Modify: `backend/extracting/graph/draft.py` (`orient`, `relate`, `relationships`, branches `software`)
- Modify: `backend/extracting/cascade/graph.py` (`_DETAIL_TYPES`, mention « éditeur d'un software »)
- Test: `tests/extracting/test_stix_strict.py`

**Interfaces:**
- Produces, dans `objects.py` :
  - `TOOL_TECHNIQUE: tuple[str, str, str] = ("tool", "uses", "attack-pattern")` ;
  - `DRAFT_RELATIONS: frozenset = ALLOWED_RELATIONS | {TOOL_TECHNIQUE}` ;
  - `def to_stix(s_type: str, rel: str, t_type: str) -> bool` : vrai seulement pour `TOOL_TECHNIQUE` (il faut
    inverser à l'écriture) ;
  - `def to_internal(s_type: str, rel: str, t_type: str) -> bool` : vrai seulement pour
    `("attack-pattern", "uses", "tool")` (il faut inverser à la lecture).

- [ ] **Step 1: Write the failing tests** (`tests/extracting/test_stix_strict.py`, texte inventé, même fabrique de
  brouillon que `tests/extracting/test_verify_apply.py`) :

```python
OFFICIAL = {...}  # la table de « Global Constraints » (sections 4.x.2 de docs/stix-v2.1-os.pdf), en triplets, page en commentaire
def test_relations_are_stix21():
    assert ALLOWED_RELATIONS == OFFICIAL

def test_software_not_declarable(draft):
    sid, err = draft.declare("software|Alpha-Product|Beta-Vendor")
    assert sid is None and err

def test_tool_technique_written_in_stix_direction(draft):
    tool, _ = draft.declare("tool|Beta-Tool")
    assert draft.relate(f"Beta-Tool|uses|T1027|{uid(draft, 'Beta-Tool')}") is None
    rel = next(r for r in draft.relationships() if tool in (r["source_ref"], r["target_ref"]))
    assert rel["relationship_type"] == "uses" and rel["target_ref"] == tool
    assert rel["source_ref"].startswith("attack-pattern--")

def test_malware_communicates_with_infrastructure_refused(draft):
    draft.declare("infrastructure|Alpha relay")
    assert draft.relate(f"Alpha-Loader|communicates-with|Alpha relay|{uid(draft, 'relay')}") is not None
```

- [ ] **Step 2: Run** `uv run pytest tests/extracting/test_stix_strict.py -v` → FAIL. La table contient encore les
  14 triplets hors norme.
- [ ] **Step 3: Implement.**
  - `RELATIONS` égale la table de référence. Les commentaires « ATT&CK » et « OpenCTI » du docstring sont remplacés par
    une phrase sur l'orientation interne.
  - `draft.relate` vérifie contre `DRAFT_RELATIONS`. `orient()` cesse de proposer `has` pour software.
  - `DraftGraph.relationships()` inverse source et cible quand `to_stix(...)`. La description (procédure) suit la
    relation.
  - La branche « software » de `relate` (déclaration implicite d'un software) est supprimée. Une ligne qui déclare un
    software est refusée par le contrôle `ENTITY_CLASSES` existant.
- [ ] **Step 4: Run** `uv run pytest tests -q` → tout passe (54 + 4).
- [ ] **Step 5: Commit** `feat(stix): table des relations ramenée à STIX 2.1, software hors couche sémantique`.

### Task 2: contrôles de déclaration — binaires natifs, noms de fichiers, nom de l'article

**Files:**
- Modify: `backend/extracting/observables/update_reference.py` (nouvelle source `native_binaries`)
- Create: `backend/extracting/stix/reference/native_binaries.txt` (généré, versionné)
- Modify: `backend/extracting/graph/draft.py` (`_BUILTIN_SHELLS` remplacé, `declare`, `resolve`)
- Test: `tests/extracting/test_declare_rules.py`

**Interfaces:**
- Produces : `draft.NATIVE_BINARIES: frozenset[str]` (minuscules, sans `.exe`), lu depuis le fichier de référence.
- Produces : `def _attack_or_named(self, stix_type: str, name: str, hit: dict, extra: set[str]) -> tuple[str | None, str | None]`
  dans `DraftGraph`. Si `normalize_name(name) == normalize_name(hit["name"])`, il renvoie l'objet officiel
  (`_attack_object`). Sinon, il crée un objet `entity(stix_type, name, ctx, aliases=[...extra, hit["name"]],
  external_references=[référence mitre-attack de hit])`, avec un identifiant déterministe issu du nom de l'article.
  `declare` et `resolve` passent tous deux par cette fonction.

- [ ] **Step 1: Générer la référence.**
  - `update_reference.py native_binaries` télécharge les noms de `https://lolbas-project.github.io/api/lolbas.json`
    (champ `Name`) et de `https://gtfobins.github.io/api.json` (clés).
  - Il écrit une ligne par nom, en minuscules et sans `.exe`, triée.
  - Si l'une des deux URL ne répond pas ou change de format : arrêter et revenir à l'utilisateur, ne pas écrire de liste
    à la main.
  - Vérifier : `grep -cx "rundll32\|mshta\|curl\|odbcconf\|bitsadmin" backend/extracting/stix/reference/native_binaries.txt` → 5.
- [ ] **Step 2: Write the failing tests** (`tests/extracting/test_declare_rules.py`) :

```python
def test_native_binary_without_attack_id_refused(draft):
    sid, err = draft.declare("tool|odbcconf.exe")
    assert sid is None and "binaire natif" in err

def test_native_binary_with_attack_id_is_tool(draft):
    sid, _ = draft.declare("tool|bitsadmin")
    assert attack_id(draft.objects[sid]) == "S0190"

def test_tool_exe_suffix_resolves_to_attack(draft):
    sid, _ = draft.declare("tool|bitsadmin.exe")
    assert attack_id(draft.objects[sid]) == "S0190"

def test_file_name_refused_as_malware(draft):
    sid, err = draft.declare("malware|alpha_loader.dll")
    assert sid is None and "nom de fichier" in err

def test_article_name_kept_over_attack_alias(draft):
    sid, _ = draft.declare("intrusion-set|Fancy Bear")
    obj = draft.objects[sid]
    assert obj["name"] == "Fancy Bear" and "APT28" in obj["aliases"] and attack_id(obj) == "G0007"

def test_case_variant_gives_official_object(draft):
    sid, _ = draft.declare("intrusion-set|apt28")
    assert sid == draft.attack.stix_object("G0007")["id"]
```

- [ ] **Step 3: Run** `uv run pytest tests/extracting/test_declare_rules.py -v` → FAIL.
- [ ] **Step 4: Implement** dans `declare`, dans cet ordre :
  1. retirer un `.exe` final du nom d'un `tool` ;
  2. recherche ATT&CK (existante, via `_attack_or_named`) ;
  3. sans résultat ATT&CK et nom dans `NATIVE_BINARIES` → refus : « binaire natif du système : seule la technique ATT&CK
     qui l'emploie est extraite » ;
  4. pour `malware` et `infrastructure`, nom conforme à
     `(?i)^[^\s/\\]+\.(dll|exe|sys|log|dat|bin|tmp|ps1|psm1|vbs|vbe|js|jse|hta|lnk|bat|cmd|scr|msi|cab|iso|zip|rar|7z|docx?|docm|xlsx?|xlsm|pdf)$`
     → refus : « nom de fichier : c'est un IOC ; déclarer le composant par le libellé que lui donne l'article ».

  `_BUILTIN_SHELLS` disparaît : cmd devient l'objet ATT&CK S0106, et le reste est couvert par la liste.
- [ ] **Step 5: Run** `uv run pytest tests -q` → tout passe.
- [ ] **Step 6: Commit** `feat(draft): binaires natifs, noms de fichiers et nom de l'article contrôlés à la déclaration`.

### Task 3: évaluation — deux sens de l'outil, software hors périmètre, révision vers un outil

**Files:**
- Modify: `backend/evaluation/score.py` (`in_scope`, `load_bundle`)
- Modify: `backend/evaluation/gold_carriers.py` (`apply_rows`)
- Test: `tests/evaluation/test_strict_scoring.py`, `tests/evaluation/test_gold_carriers.py` (un test ajouté)

**Interfaces:**
- Consumes : `to_internal`, `to_stix`, `DRAFT_RELATIONS` (Task 1).
- `load_bundle` renvoie toujours l'orientation interne : une relation `attack-pattern uses tool` devient
  `Relation(sid, tool, "uses", attack-pattern, …)`. `fp_audit`, `graph_view`, `verifier_gate`, `stability` et
  `worksheet` en héritent sans changement.

- [ ] **Step 1: Write the failing tests**
  - `test_tool_technique_matches_both_directions` : gold `attack-pattern uses tool:Beta-Tool`, prédiction
    `tool:Beta-Tool uses attack-pattern` (ancien bundle) → `score_article(...).relations.found_required == 1`.
  - `test_software_ignored` : prédiction avec un `software` absent du gold → `entities.predicted` ne le compte pas.
  - `test_move_to_tool_writes_stix_direction` : une ligne `move` vers un tool donne un objet de relation dont
    `source_ref` est la technique et `target_ref` l'outil. Elle est fusionnée (pas dupliquée) si
    `attack-pattern uses tool` existe déjà.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.**
  - `in_scope` exclut `software`.
  - `load_bundle` inverse quand `to_internal(...)`.
  - `apply_rows` valide le triplet interne contre `DRAFT_RELATIONS`, écrit dans le sens de la norme (`to_stix`), et
    cherche le jumeau dans les deux sens.
- [ ] **Step 4: Run** `uv run pytest tests -q` → tout passe.
- [ ] **Step 5: Commit** `feat(eval): orientation outil → technique lue dans les deux sens, software hors périmètre`.

### Task 4: migration du gold vers STIX strict

**Files:**
- Create: `backend/evaluation/gold_strict.py`
- Test: `tests/evaluation/test_gold_strict.py`
- Modify (données) : les 9 golds du manifeste

**Interfaces:**
- Consumes : `ALLOWED_RELATIONS` (Task 1), `NATIVE_BINARIES` (Task 2).
- Produces :
  - `def violations(bundle: dict, kb: AttackKB) -> list[str]` : relation hors `ALLOWED_RELATIONS` (sens écrit), objet
    `software`, `tool` binaire natif sans S####, `malware` dont le nom est un nom de fichier.
  - `def strip_software(bundle: dict) -> tuple[dict, int]` : retire les `software` et les relations qui les touchent. Il
    ajoute « Produit visé : <name>[ (<vendor>)] » à la `description` de la vulnérabilité (relation `has`) ou de la
    source d'un `targets`.
  - `def drop_native_tools(bundle: dict, kb: AttackKB) -> tuple[dict, int]` :
    - retire les tools binaires natifs sans S#### ;
    - chaque paire `X uses tool` + `tool uses T` devient `X uses T`. Le label est required si l'une des deux l'est. La
      citation vient de `tool uses T`, et `x_gold_context` reçoit « via <outil> ».
    - Si `X uses T` existe déjà, il y a fusion comme dans `apply_rows` (`description`, `x_gold_merged_from`).
  - `def invert_tool_techniques(bundle: dict) -> tuple[dict, int]` : `tool uses attack-pattern` → `attack-pattern uses
    tool`, avec `x_gold_inverted: true`.
  - CLI `uv run python -m backend.evaluation.gold_strict check|migrate <id|all>`. `migrate` applique les trois
    transformations dans l'ordre drop_native_tools → invert_tool_techniques → strip_software, puis réécrit le gold sans
    changer sa fin de fichier.
  - Toutes ces fonctions travaillent sur une copie et ne modifient jamais le bundle d'entrée.

- [ ] **Step 1: Write the failing tests** (bundles inventés) :
  `test_strip_software_keeps_product_in_description`, `test_drop_native_tool_rewires_technique`,
  `test_drop_native_tool_merges_existing`, `test_invert_tool_technique`, `test_input_bundle_untouched`, puis
  `test_all_golds_strict` (vrais golds du manifeste : `violations(...) == []` pour chacun).
- [ ] **Step 2: Run** → les tests unitaires échouent (module absent).
- [ ] **Step 3: Implement** `gold_strict.py`. Run → tests unitaires PASS ; `test_all_golds_strict` FAIL (données non
  migrées).
- [ ] **Step 4: Migrer** : `uv run python -m backend.evaluation.gold_strict migrate all`, puis `check all` → aucune
  violation. Lire le `git diff` de 1553 et 1602 et vérifier deux points :
  - les tools natifs retirés (rundll32, regsvr32, mshta, wscript, curl, PowerShell) n'ont fait perdre aucune technique ;
  - cmd, certutil et Expand restent des tools, en sens inversé.
- [ ] **Step 5: Run** `uv run pytest tests -q` → tout passe.
- [ ] **Step 6: Re-score sans modèle** `cascade2_a`, `cascade2_b`, `cascade3_a`, `cascade3_b` (`uv run cti-eval
  --bundles …`). Noter les chiffres dans le journal de suivi.
- [ ] **Step 7: Commit** `data(gold): migration STIX 2.1 strict (software, binaires natifs, sens outil → technique)`.

### Task 5: gold — ajouts validés par l'audit, commanditaire, noms en anglais — point de contrôle utilisateur

**Files:**
- Modify: `backend/evaluation/gold_strict.py` (`additions_from_audit`, `apply_additions`, action CLI `add`)
- Create (données) : `Annotations/revision/additions.json`
- Test: `tests/evaluation/test_gold_strict.py` (deux tests ajoutés)

**Interfaces:**
- `def additions_from_audit(run: str, audits: dict[str, str], kb: AttackKB) -> dict[int, list[dict]]` :
  - entrées : les clés J de `fp_audit.json` absentes du gold après migration ;
  - pour chacune, les objets copiés depuis le bundle prédit (entité, et relation avec sa citation), avec le label
    `gold:acceptable` et `x_gold_source: "audit <run> J"` ;
  - les candidats pour lesquels `violations` signale quelque chose sont écartés.
- `def apply_additions(bundle: dict, items: list[dict]) -> tuple[dict, int]` : ajoute les objets, sans doublon
  d'identifiant ; un objet `rename` (`{"rename": id, "name": nouveau}`) change seulement le nom.
- Tests : `test_additions_skip_violations` (un J sur un software n'est pas proposé), `test_apply_additions_rename`.

- [ ] **Step 1: TDD** des deux fonctions (tests → FAIL → implémentation → PASS).
- [ ] **Step 2: Générer** `additions.json` depuis `cascade2_a` (audit corrigé du 2026-11-13).
- [ ] **Step 3: Compléter `additions.json` à la main.** Chaque citation est copiée mot pour mot de l'article.
  - 1281 :
    - malware ZshBucket `uses` T1105 et T1041 (acceptable, verdict D sur T1041) ;
    - intrusion-set STARDUST CHOLLIMA `originates-from` location Corée du Nord (`KP`), acceptable.
  - 1553, chaîne du commanditaire, confiance 60 sur les deux relations, acceptable :
    - threat-actor « Belarusian state actor » (`threat_actor_types: ["nation-state"]`) ;
    - identity « Government of Belarus » (`organization`, `government-national`) ;
    - UAC-0057 `attributed-to` le threat-actor ;
    - le threat-actor `attributed-to` l'identity.
  - Renommages selon la convention :

| Article | Nom actuel | Nouveau nom |
|---|---|---|
| 1281 | Compromission du paquet npm Axios (31 mars 2026) | Axios npm package compromise campaign (STARDUST CHOLLIMA, March 2026) |
| 1602 | Nouvelle campagne ISMAgent (ClearSky, août 2017) | ISMAgent delivery campaign (GreenBug, August 2017) |
| 1553 | Campagne ciblant la Pologne (avril-mai 2025) | Poland targeting campaign (UAC-0057, April-May 2025) |
| 1553 | Campagne ciblant l'Ukraine (mai-juillet 2025) | Ukraine targeting campaign (UAC-0057, May-July 2025) |
| 1558 | Campagne fake CAPTCHA (HijackLoader / Lumma Stealer) | Fake CAPTCHA campaign (HijackLoader, Lumma Stealer) |
| 1549 | Campagne de spearphishing Gamaredon exploitant CVE-2025-8088 (septembre 2025 - mai 2026) | CVE-2025-8088 spearphishing campaign (Gamaredon, September 2025 - May 2026) |
| 1697 | Campagne CL-STA-1062 contre les gouvernements et l'énergie en Asie du Sud-Est (2025) | Southeast Asian government and energy campaign (CL-STA-1062, 2025) |
| 1338 | Pilote noyau malveillant (désactivation de csagent.sys) (malware) | malicious kernel driver |

  - La campagne de 1338 ajoutée depuis l'audit reçoit le nom « Telecom and BPO targeting campaign (SCATTERED SPIDER,
    2022) ».
- [ ] **Step 4: Point de contrôle.** Montrer à l'utilisateur un tableau par article (ajouts, renommages). Appliquer
  seulement après son accord : `uv run python -m backend.evaluation.gold_strict add all`, puis `check all` → aucune
  violation, puis `uv run pytest tests -q`.
- [ ] **Step 5: Re-score** les quatre exécutions de la Task 4 et noter les chiffres.
- [ ] **Step 6: Commit** `data(gold): ajouts validés par l'audit, commanditaire, noms en anglais`.

### Task 6: consignes au modèle

**Files:**
- Modify: `backend/extracting/stix/specs.py` (`TYPE_SPECS` : location, identity, malware, tool, infrastructure,
  threat-actor, course-of-action ; `RELATION_DEFINITIONS["targets"]`)
- Modify: `backend/extracting/cascade/techniques.py` (`GRID_SYSTEM` : frontières)
- Modify: `backend/extracting/pipeline.py` (consignes qui citent `software` ou `related-to`, l. ~233, ~241, ~394)

- [ ] **Step 1: Réécrire les définitions** de `TYPE_SPECS`, une phrase par règle de « Types d'entités »
  (`methode_annotation.md`) :
  - un pays est toujours un `location` ;
  - une organisation usurpée dans un leurre n'est pas une victime ;
  - un malware n'est jamais nommé par un nom de fichier ;
  - un utilitaire du système n'est un outil que si ATT&CK le connaît comme logiciel ;
  - une infrastructure est nommée avec les mots du texte, sans adresse ni qualificatif ajouté, et un hébergeur n'en est
    pas une ;
  - le `threat-actor` est l'État commanditaire auquel un groupe est rattaché ;
  - la course-of-action est seulement le correctif d'une vulnérabilité nommée.

  Dans la définition de `targets`, retirer « produit ».
- [ ] **Step 2: Ajouter les frontières** au `GRID_SYSTEM`, avec les noms ATT&CK et sans identifiant : les dix règles de
  « Techniques : frontières ATT&CK », et « un logiciel tiers n'est relié qu'à ce qu'il fait lui-même ». Aucun exemple tiré
  d'un article annoté.
- [ ] **Step 3: Vérifier** `CTI_CASCADE=on uv run cti-extract --article-id <article non annoté> --dry-run --show-log` :
  pas d'erreur, aucun objet `software`, aucun `tool uses attack-pattern` dans le bundle écrit.
- [ ] **Step 4: Mesurer** deux exécutions : `CTI_CASCADE=on uv run cti-eval --run --workers 4 --bundles
  backend/evaluation/eval/strict_a` (puis `strict_b`) ; `uv run cti-eval --compare cascade3_a,cascade3_b
  strict_a,strict_b`. Attendu :
  - moins de faux positifs du type corrigé (noms de fichiers, binaires natifs, pays en identity, leurres en cible) ;
  - aucune campagne perdue ;
  - pas de baisse significative du rappel.

  Sinon, revenir à l'utilisateur avec les articles en cause.
- [ ] **Step 5: Commit** `feat(cascade): consignes STIX strict (types, leurres, frontières ATT&CK)`.

### Task 7: profil d'acteur — chaîne du commanditaire

**Files:**
- Modify: `backend/database/stix_store.py` (`actor_subgraph`)
- Modify: `backend/dashboard/stix_dashboard.py` (`_profile`)
- Test: `tests/dashboard/test_profile.py` (dossier nouveau, avec `__init__.py`)

**Interfaces:**
- `actor_subgraph` ajoute aux nœuds et arêtes les identités atteintes par
  `(a)-[:ATTRIBUTED_TO]->(t:ThreatActor)-[:ATTRIBUTED_TO]->(i:Identity)`, avec la même forme d'arête qu'aujourd'hui.
- `_profile` : une arête `attributed-to` d'un parent (threat-actor) vers une identity donne une entrée de `sponsors` avec
  la clé supplémentaire `"via": <id du parent>`.

- [ ] **Step 1: Write the failing test** `test_sponsor_through_parent` : nœuds intrusion-set Group-Nine, threat-actor
  Alpha-State, identity Alpha-Government ; arêtes Group-Nine → Alpha-State et Alpha-State → Alpha-Government
  (`attributed-to`). On vérifie que `out["parents"]` contient Alpha-State, que `out["sponsors"][0]["node"]["id"]` est
  Alpha-Government et que `out["sponsors"][0]["via"]` est l'id d'Alpha-State.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** `uv run pytest tests -q` → PASS ; `cd frontend &&
  npm test` → PASS.
- [ ] **Step 5: Commit** `feat(dashboard): commanditaire lu à travers le threat-actor parent`.

### Task 8: références et décision — point de contrôle utilisateur

- [ ] **Step 1: Re-score** sur le gold final : `v5_base_1/2`, `cascade2_a/b`, `cascade3_a/b`, `strict_a/b`. Dresser un
  tableau : entités et relations, score principal, score strict et score relâché, plus la stabilité.
- [ ] **Step 2: Mettre à jour** la référence de `.claude/CLAUDE.md` (§5.C : exécutions de référence et chiffres) et la
  mémoire du projet.
- [ ] **Step 3: Présenter** le tableau à l'utilisateur. Le choix de la suite lui revient : Task 9 du plan précédent
  (vérificateur en `shadow`, barrière), puis ré-extraction du corpus vers Neo4j.
