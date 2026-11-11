# Generate wide, judge narrow: STIX extraction from CTI reports — design

Status: draft for approval (revision 3, after external review). Date: 2026-11-09. Branch to create at build time:
`feature/typed-extraction`.

## 1. Intent and why

The project must become the basis of a research paper (AAAI workshop). Scope for now: **CTI reports only**. The goal is a much
better extraction pipeline: from a report, a STIX 2.1 graph covering every type a report asserts, with high recall and precision
on entities, relations and properties, each claim traceable to the sentences that support it.

What the `noleak_1` report (9 annotated articles) shows about the current system:

- Score is dominated by ATT&CK technique mapping (97 of ~160 required entities, ~160 of ~240 required relations).
- 77 required relations are lost because an endpoint (mostly a technique) was never extracted; 27 more have the right technique
  and the wrong source. In the gold, sources of `uses -> attack-pattern` are malware 109, campaign 88, tool 8, intrusion-set 5
  (9 gold files + holdout): the wrong-source losses are the campaign-vs-malware choice. No gold uses `incident`.
- Every stage reads the whole article and writes long pipe-delimited lists; long articles lose content and take 200-280 s.
- 16 required techniques never reach the candidate list (composite behaviors: one line, several mechanisms).
- Identity precision 7 %, software 29 %; articles 1438 and 1338 near zero on relations (cause not yet investigated).
- Only 10 entity types and ~12 relation patterns; no course-of-action, no malware-analysis, no property qualification.
- The "agents" in `agents.py` are specialized prompts over the whole article, not agents.

Core diagnosis: every current prompt is asked to be **complete and precise at once** in one long generation. A 27B model is weak at
long exhaustive generation and good at short, local, bounded decisions.

Core idea: **separate recall from precision.**
- Candidate stage, tuned for recall: over-generate from several independent sources and take the union.
- Judge stage, tuned for precision: one short, local, evidence-bound decision per candidate, with a continuous confidence.

Recall grows by adding candidate sources; precision is read off a curve over the judge confidence; both are measurable per stage.

## 2. Scope

### Types (confirmed by the user)

attack-pattern, campaign, course-of-action, identity, infrastructure, intrusion-set, location, malware, malware-analysis,
threat-actor, tool, vulnerability; the report container; `software` as an observable (product targeted). IOCs and rules stay in
the existing deterministic layer (`backend/extracting/observables/`), unchanged: the LLM never writes an IOC value, it only
qualifies an IOC's role and attaches it, as today.

Out: grouping, note, opinion, observed-data (comes from the IOC engine), incident (not used by the gold; revisit with the
evaluation project).

### Properties: three provenances

Every property records where it comes from:
- **text-derived** (e.g. `malware_types`, `capabilities`, `roles`, `sophistication`, `resource_level`, `primary_motivation`,
  `goals`, `infrastructure_types`, `identity_class`, `sectors`, `first_seen` / `last_seen`): closed choice from the STIX open
  vocabulary or copied from the text, with supporting sentences; without them the property stays empty. Code never invents one.
- **knowledge-base-derived** (e.g. ATT&CK `kill_chain_phases`, ATT&CK aliases of a group or software, technique names): copied
  from ATT&CK v20.0 with that provenance, no evidence sentence required.
- **structural** (required by STIX, e.g. `is_family` on malware, `identity_class` defaults): set by the model when the text
  decides it, otherwise a documented default, marked as default.

## 3. Goals, non-goals, anti-goals

Goals
- Recall and precision handled by separate stages, each measurable on its own.
- Full type coverage driven by a registry: a new type or property is a spec, not a new hand-written prompt.
- Every emitted object, relation and text-derived property carries verified supporting sentences and a confidence.
- Gold-free diagnostics for every stage, plus a small, explicitly labelled set of gold-based coverage diagnostics (5.10).
- Ablation switches for the paper: each candidate source, confidence method (logprobs / votes), repair agent, thinking mode.

Non-goals (this phase)
- Other sources (X, forums, dark web). The design avoids depending on report structure where it can, but nothing is built or
  measured for them.
- Reading against the existing Neo4j graph (prior entities as context). Future work; also a leakage risk, the graph contains the
  annotated articles.
- Redesigning the evaluation, fixing the gold, dev/test split, extending the scorer, external datasets: next project. Candidate
  external checks for techniques: MITRE TRAM data, AnnoCTR (not yet verified for fit or licence).
- Dashboard / Neo4j schema changes beyond storing new types through the existing generic STIX store.
- Fine-tuning or any trained component.
- Changes to preprocessing, classifier, IOC / YARA / Sigma engines.

Anti-goals (failure even if it runs)
- Tuning prompts, rules or thresholds against the current gold. In this phase no operating threshold is chosen: results are
  reported as curves over confidence. A threshold is chosen later, on a dev split only.
- Any name or identifier from annotated articles in prompts or code (examples use templates: `<malware>`, `T####.###`).
- Calling prompted stages "agents". Only the repair loop (5.8) is an agent, described as one agent with tools.
- Any run-time dependency on a model other than the local one (including Claude).
- A deterministic rule that types or judges a name. Code proposes candidates, bounds choices and validates structure; the LLM
  decides meaning.
- Silent loss: every dropped candidate is counted with its stage and reason.

## 4. Constraints

- Model: local Qwen3.8-27B on vLLM, no fine-tuning (user decision). Client stays `backend/extracting/llm.py` (slots, constrained
  output, `chat` for tool turns). Thinking off by default (already the default in `llm.py`); on only as an ablation.
- Context 32 768 tokens. Calls carry the article prefix (cached). If article + instructions + batch do not fit, the call carries
  the current section window plus a compact roster summary (entity names, types, first sentence numbers) instead of the whole
  article.
- Cost is dominated by generated tokens; prefill on a shared prefix is cheap. Outputs are short codes.
- Never run `ollama` / `ssh` / server commands locally; servers are remote behind a tunnel. Never more concurrent requests than
  slots.
- No Python unit tests exist; checks are runs (`cti-extract --dry-run --show-log`) and diagnostics.
- vLLM is not deterministic under concurrency: every measured result is reported on at least two runs.
- The gold was annotated with Claude's help, so it may contain inferences a 27B model cannot reach. In this phase it is used to
  measure coverage at milestones (section 7), never to tune.
- Old `pipeline.py` / `agents.py` stay untouched on the branch as the baseline (my call, section 9).

## 5. Architecture

```
report text
 -> 0 SEGMENT     numbered sentences + headings -> sections                        (existing text/segment.py)
 -> 1 CANDIDATES  union of independent sources, permissive                         recall
 -> 2 RESOLVE     mentions -> entities: KB aliases + exact normalization; references by model choice
 -> 3 JUDGE       type-neutral local decision per entity, confidence                precision
 -> 4 TECHNIQUES  action sentences -> single mechanisms -> ATT&CK top-k -> choice
 -> 5 RELATIONS   code builds allowed pairs (entities AND techniques); judge: type or none + sentences
 -> 6 QUALIFY     one judgment per text-derived property
 -> 7 GRAPH CHECK structural checks (defined in 5.7)
 -> 8 REPAIR      (optional) one agent with tools, only for low-confidence or rejected items
 -> STIX bundles  semantic + observable layers (as today), confidence + evidence + provenance on every object
```

### 5.0 Registry

One spec per type: definition, what it is and is not, properties with provenance class and vocabulary, allowed relations as
source/relation/target patterns, judge wording. Replaces `ENTITY_CLASSES`, the hard-coded `RELATIONS` table and the per-concern
prompt classes. `DraftGraph` (stix2 strict) remains the structural gatekeeper.

### 5.1 Candidates (recall)

Sources, each switchable, results unioned with origin recorded:
- per-section model pass: one call per section returning all type groups (default; one call per type group per section is an
  ablation, because it multiplies calls);
- one document-level roster pass;
- one extra sample at a higher temperature (ablation, off by default);
- lookups without a model: ATT&CK group / software names and aliases from v20.0, CVE patterns, names already proposed elsewhere
  in the report.

Candidate = (surface name, proposed type or none, sentence numbers, source).

### 5.2 Resolve

Code merges only on knowledge-base aliases (ATT&CK) and exact normalized names. Anything fuzzier, including references ("the
group", "the loader"), is a closed model choice among existing entities of the report, recorded as a resolution link with its
sentence numbers.

### 5.3 Judge (precision)

Type-neutral and closed: "Does the report assert `<name>` (sentences [n…]) as part of the activity it describes? Which of:
`<types allowed for this candidate>` / none". The proposed type is not presented as the answer, so a type error does not turn
into a loss. Many questions per call, answers of a few tokens. The judge sees the report and the claim, not the generator's
output.

Confidence: renormalized logprobs of the answer tokens in one pass (default). Fallback if the server does not return logprobs:
3 samples, agreement. Votes stay as an ablation either way.

### 5.4 Techniques (most of the score; specified in full)

1. **Action sentences, tuned for recall.** Per section, the model marks every sentence that describes an attacker or malware
   action, including commands and artifacts. Short answer: sentence numbers. Missing an action sentence is the expensive error,
   so the prompt asks to over-include; the judge in step 4 absorbs false positives.
2. **Splitting composite behaviors.** For each action sentence (or small group of adjacent ones), the model writes one line per
   single mechanism: "<action> <mechanism> to <goal>", no names, no IOCs. Instruction: one mechanism per line, a sentence with
   three mechanisms gives three lines. This is where the 16 never-candidate techniques come from.
3. **Retrieval.** Each mechanism line queries the ATT&CK v20.0 FTS5 index (definitions + procedure examples, article's own
   procedures excluded, as today) plus the model's presumed ID and its parent. Keep top k (default 15; ablation 6 / 15 / 20).
4. **Choice.** The model picks, by letter, the candidates whose definition describes the mechanism in those sentences, or none,
   with a logprob confidence. Sub-technique vs parent is part of the choice.
5. **Diagnostic (the most informative one):** top-k coverage: for each gold technique, is it in the top k of a mechanism whose
   sentences overlap its gold evidence? Reported with the loss breakdown: no action sentence / no mechanism / not in top k /
   not chosen.

The chosen technique becomes an entity; its carrier is decided in 5.5.

### 5.5 Relations

Runs after 5.3 and 5.4, so techniques are endpoints. Code builds candidate pairs: allowed by the registry and co-occurring in a
section, or connected through a resolution link. Judge per pair: relation type or none, plus supporting sentences. Evidence may be
a set of sentences plus the resolution link (subject in [3], "the loader" in [14] resolved to it). Relations are classified, never
written freely, with logprob confidence.

Carrier (campaign vs malware vs tool vs group): from the subject of the supporting sentences; a documented projection policy may
add convention edges afterwards (switchable, reported separately).

### 5.6 Qualify

Per entity, per text-derived property in the registry: vocabulary choice or text copy with sentences, or empty. Knowledge-base and
structural properties are filled by code with their provenance (2, "Properties").

### 5.7 Graph check

Structural pass in code, defined narrowly: objects left without any relation (orphans) and pairs judged with two incompatible
relation types for the same supporting sentences (e.g. `uses` and `targets` between the same two entities). Flagged items go to
5.8 if enabled, else dropped and counted. Evidence support is not rechecked here (already enforced at every stage).

### 5.8 Repair agent (optional, ablation)

The only agent. Input: items under a confidence floor or rejected by `DraftGraph` / 5.7. Tools: read section, search ATT&CK, list
report entities, resubmit item (validated, returns errors). Step and token budget per article. Off by default; built last.

### 5.9 Gold-free diagnostics

Per article and stage: candidates per source, overlap between sources, resolution links, judge confidence distribution, pairs
built vs kept, action sentences and mechanisms per section, items dropped with reason, agreement between two runs per type and
relation pattern, calls, generated tokens and wall time per stage. Printed by `cti-extract`, written next to the bundle.

### 5.10 Gold-based coverage diagnostics (labelled as such, measurement only)

- candidate coverage of gold entities, **always reported with candidate volume** (coverage at a given number of candidates);
- technique top-k coverage and loss breakdown (5.4.5);
- gold relations whose pair was never built (is section co-occurrence too tight?);
- precision/recall curves over judge confidence, per type.

## 6. What is kept

`llm.py`, `DraftGraph`, ATT&CK index and search, `text/` (segmentation, evidence anchoring), IOC and rules engines,
`stix_store.py`, `runner.py`, bundle layout (semantic + observable files), CLI entry points.

## 7. Build order with measurement gates

Each step reports its number (two runs) before the next starts. A gate that fails is brought back to the user, not worked around.

1. **Diagnose 1338 and 1438** with the baseline: what fails (gold, carrier, extraction). Outcome may change the design.
2. **Registry + candidates + resolve.** Gate: candidate coverage of gold entities vs candidate volume, against the baseline's final
   recall.
3. **Techniques (5.4).** Gate: top-k coverage and loss breakdown, against the baseline's 16 never-candidate techniques.
4. **Judges (5.3).** Gate: precision/recall curve for entities; logprobs available or fallback in use.
5. **Relations (5.5).** Gate: pairs-never-built count, relation curve.
6. **Qualification (5.6).** Gate: all types and properties produced and `stix2` valid on 9 annotated + 3 unannotated reports.
7. **Graph check, then repair agent (5.7, 5.8).** Gate: repair changes the curve beyond run noise, or stays off.

End-of-phase criteria (my call): zero emitted claim without supporting sentences; all diagnostics produced; on shared types, the
curve passes through or above the `noleak_1` point beyond run noise (sanity check, not a target); cost reported per stage against
the baseline.

## 8. Cost estimate (to check at gate 2)

Long report (~200 sentences, ~10 sections), default settings:

| Stage | Calls |
|---|---|
| candidates (1 per section + roster) | ~11 |
| reference resolution | ~1-2 |
| judges (batches of ~20 entities) | ~3-5 |
| techniques: action sentences (per section), mechanisms (batched), choice (batched) | ~10 + ~5 + ~5 |
| relations (batches of ~40 pairs) | ~5-10 |
| qualification (batched per type) | ~5-10 |
| **total** | **~45-60** |

All calls share the cached prefix and generate short codes. Rough wall time: 3-8 min per long report sequentially, less with
parallel slots, against 200-280 s today. Ablations (votes, per-type-group candidate passes, higher-temperature sample) multiply
parts of this.

## 9. Left to the builder

Module layout under `backend/extracting/`, prompt wording and answer codes, batch sizes and token budgets, pair pruning details,
section window size for the 32k fallback, minimal STIX form of malware-analysis and course-of-action, structural defaults, how
diagnostics are formatted.

## 10. Calls made by me (not agreed with the user)

1. Old `pipeline.py` / `agents.py` kept on the branch as the baseline; new code in a new package.
2. Repair agent built last and off by default.
3. Confidence by logprobs, votes as fallback and ablation.
4. Carrier from the subject of the supporting sentences, plus an optional, separately reported projection policy.
5. One candidate call per section for all types (per-type-group calls as an ablation).
6. Top-k = 15 for technique retrieval.
7. No operating threshold in this phase; curves only.
8. Build order and gates in section 7; end-of-phase criteria.
9. Out of scope: grouping, note, opinion, observed-data, incident; reading against the graph; malware-analysis lowest priority.
10. Document in English.
