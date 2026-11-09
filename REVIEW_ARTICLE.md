# REVIEW_ARTICLE — Research papers applied to the STIX bundle extraction pipeline

Synthesis of the four papers in `papiers_recherche/`, mapped onto the extraction pipeline
(`backend/extracting/`) and the measured losses in `POUR_ANALYSE.md` §4. Source texts were
extracted with `pdftotext -layout` for reading; section references below are to the papers.

## 1. The papers at a glance

| Paper | Core idea | Pipeline shape |
|---|---|---|
| **CTINexus** (Cheng et al., Virginia Tech / UC Berkeley) | ICL with kNN-retrieved demonstrations (ordered ascending by similarity, recency bias); single-pass triplet extraction with the ontology in JSON in the prompt; **hierarchical entity alignment** (coarse type grouping via ICL, then embedding merge within type, threshold 0.6, with IOC protection so `CVE-2023-23397` ≠ `CVE-2023-23392` and `.akira files` ≠ `Akira`); **long-distance relation prediction** via DFS subgraphs, degree-central node per subgraph + global topic node | 3 phases: extract → align → link distant subgraphs |
| **TACTIC-KG** (Bouchiha & Blanc, Télécom SudParis, arXiv:2607.05001) | "Faithfulness before connectivity": decompose into specialized agents (Extractor → Typer → Verifier → Curator) on small 3B–8B models with LoRA; **token log-prob confidence** propagated to the verifier; **closed-world verifier** (SUPPORTED / NOT_SUPPORTED per triplet, must extract a minimal supporting span, external knowledge forbidden); **curator** = dedup, canonicalization, alias merging, minimal constrained repair only when textually supported; semantic chunking with overlap; JSON-serialized HITL-friendly protocol | multi-agent, each stage a narrow transformation |
| **MTPE** (Li et al., IEEE Trans. Consumer Electronics 2026, DOI 10.1109/TCE.2026.3744478) | Reliability via **multi-temperature parallel inference** (MTPI: same prompt decoded at T=0.2 for explicit IOCs, T=0.5 for regular relations, T=1.0 for implicit TTPs / long-range logic; union of candidates), then **prompt-constrained fusion** (PCF: merge equivalent triples, remove redundancy, screen conflicts on the same entity pair, simplify entities, resolve coreference, normalize relations, decompose composite triples into atomic ones), then **semantic entity alignment** (SEA: alias KB + contextual embeddings `[ENT] name [CTX] context` + agglomerative clustering on cosine distance + canonical entity election + triple rewiring; IOCs merge by exact match only, CIDR ranges stay separate) | expand → normalize → unify |
| **KGAgent4CTI** (Yang et al., Cybersecurity (2026) 9:76, DOI 10.1186/s42400-025-00458-2) | 5 agents with shared JSON memory (A_preprocess, A_entity, A_relation, A_technique, A_merge); **semantic segmentation** of long texts by sentence-embedding cosine distance with breakpoint threshold µ + k·σ; relation extraction as 3-step CoT with an explicit evidence segment per triple; **iterative hybrid RAG for ATT&CK identification** (HNSW vector top-5 + BM25 top-5, query rewriting that maps IOCs to semantic categories like "C2 server", retrieval/reasoning index decoupling, rerank, self-reflection on sufficiency → re-retrieve); **version-aware indexing** that monitors the MITRE repo and re-indexes on ATT&CK updates (~6-month cycle) | agent pipeline + dynamic knowledge engine |

Reported results worth remembering: MTPE reaches 93.16% RE F1 / 92.79% NER F1 on CTINEXUS
(vs 87.65 / 90.13 for CTINexus framework); its ablation shows removing PCF costs the most
(93.16 → 86.67), then SEA (→ 87.98), then MTPI (→ 90.56). TACTIC-KG with a 8B model +
LoRA beats monolithic DeepSeek-V3.1-671B ICL (F1 80 vs 72, recall up to 90 vs ≤ 66) and
argues small models cannot exploit ICL demos (GPT-OSS-20B ICL: 47 F1). KGAgent4CTI reports
92.3% attack-technique identification precision.

## 2. What we already do that the papers recommend (do not rebuild)

- **Task decomposition into closed steps** (TACTIC-KG's core, minus LoRA): `pipeline.py`
  already splits extraction into entities/behaviors → technique choice → relations →
  corrections/islands → verification, each with a strict JSON schema. This is the "reduce
  task entropy" the paper credits for small-model performance.
- **Closed-choice technique identification** (KGAgent4CTI's RAG, in deterministic form): the
  code retrieves ATT&CK candidates (`stix/attack.py`, SQLite FTS5, RRF fusion of two BM25
  queries) and the model only picks letters (`choice_prompt`), so hallucinated ATT&CK IDs
  are structurally impossible — 0 hallucinations in eval (§4.7.6). The tool-calling
  `search_attack` / `get_attack` correction loop (`graph/draft.py`) is the equivalent of
  KGAgent4CTI's iterative RAG.
- **Evidence-grounded verification** (TACTIC-KG's Verifier): `verify_relations` judges each
  relation o/n against the text and keeps only the single best evidence phrase;
  `draft.relate` re-reads the cited sentences in code. The closed-world assumption is
  already in the prompt.
- **Deterministic STIX IDs**: `stix/objects.py:77` `deterministic_id()` — the same entity in
  two articles already lands on one Neo4j node. That covers the "canonical entity
  selection" half of SEA/curator at the cross-article level.

## 3. Ideas that map onto concrete gaps in our pipeline

### A. Multi-temperature candidate expansion (MTPE's MTPI) — targets our #1 loss

Biggest measured loss: **137/177 missed relations have an absent endpoint, and 35/97
techniques are never proposed** (§4.6). MTPE's core finding: no single decoding temperature
optimizes both explicit indicators and implicit TTPs — low T wins precision on IOCs, high T
recovers implicit relations (their Table VII). `llm.py` hardcodes `temperature: 0, top_k: 1,
seed: 0`, which systematically suppresses exploratory behavior descriptions.

Action: add a `temperature` parameter to `llm.generate`; run **only the step-1
"entities/behaviors" call** at T≈0.2 / 0.5 / 1.0 in parallel (`llm.map_parallel` exists),
union the behavior lines, deduplicate with the existing `_behavior_key` machinery from
`section_behaviors` (`pipeline.py:498`). Keep T=0 for relations, corrections, verification —
determinism where it matters, exploration where recall is lost. MTPE's ablation shows fusion
matters more than expansion, so pair with (B). Cost ≈ 3× tokens on one call; measure with
`cti-eval` against `sect_html_*`.

### B. Fusion / conflict-resolution pass over the union of candidates (MTPE's PCF)

We have correction and island passes, but they operate per-call. PCF consolidates the merged
multi-temperature candidate set: merge equivalents, screen conflicting relations on the same
pair, decompose composite relations into atomic ones. Action: after all relation-producing
steps (relations + corrections + islands + carrier), run one "fusion" call receiving all
candidate relations plus the text, outputting the consolidated set with conflicts resolved
toward the textually supported one. Directly addresses the **33 "right target, wrong
source"** relations and the `intrusion-set uses attack-pattern` 0%-precision problem
(§4.7.3) — the relation that matters most for attribution.

### C. Entity alignment within type, with IOC protection (CTINexus §4.3 + MTPE's SEA)

We merge only by normalized name and ATT&CK ID. Both papers add embedding-based clustering of
mentions **within the same type**, using the mention's local context, then elect a canonical
name and rewire relations — with IOCs merging by exact match only. Our IOCs are regex-extracted
and never entities, so they are already protected; the win is alias-level merging of *named*
entities ("GammaDrop" vs "the GammaDrop loader" vs "a new loader"), within one article and
across articles. Action: post-extraction alignment in `graph/draft.py` — group declared
entities by STIX type, embed `name + evidence sentences`, agglomerative cluster (cosine,
τ≈0.6 as in both papers), canonical = ATT&CK official name if known else most frequent
mention, rewire `draft.evidence`. Also improves the actor-profile view that feeds attribution
(§4.8 gap: no cross-article resolution beyond ATT&CK IDs and exact names).

### D. Smarter long-distance linking (CTINexus §4.4, tempered by TACTIC-KG)

`islands()` asks the model to link disconnected components blindly. CTINexus picks per
subgraph the highest-degree central node and one global topic node, and queries only those —
cheaper, less noisy. TACTIC-KG warns against forcing connectivity ("faithfulness before
connectivity"; over-completion is structural hallucination). Our `island_prompt` already
forbids inventing links — the right guard. Action: keep the islands step but target it —
compute degree centrality in `islands()` (components are already computed), show each
island's central element + the topic element, keep the closed-world instruction.

### E. Iterative, rewritten retrieval for techniques (KGAgent4CTI's A_technique)

Candidate recall is 72% @ 6, 83% @ 15, 87% @ 20 (`CTI_CANDIDATES`, `pipeline.py:36`) — about
13% of gold techniques are unreachable regardless of the model's choice. Transposed fixes:

- **Query rewriting before retrieval**: strip IOC-looking tokens from the behavior query and
  map them to semantic categories ("C2 server", "phishing kit") — raw indicators in a
  behavior poison the FTS query.
- **Iterative re-retrieval on failure**: when a behavior gets no chosen candidate, run a second
  retrieval with a paraphrased query (the model rewrites the behavior in ATT&CK vocabulary via
  `search_attack`, as in the existing tool correction) instead of dropping it. Most direct
  attack on the 35 never-proposed techniques.
- **Hybrid retrieval**: we have BM25×2-RRF; adding a dense-vector channel over the same
  `tech_fts` / `proc_fts` content (HNSW top-5 + BM25 top-5) mirrors their setup. Optional —
  the iterative rewrite is higher value.
- **Version-aware index**: ATT&CK v20.0 is pinned in a versioned SQLite (good); add a
  script/CI check comparing its meta against the current ATT&CK STIX bundle and rebuild via
  `python -m backend.extracting.stix.attack` (KGAgent4CTI's auto re-indexing, light version).

### F. Semantic chunking (KGAgent4CTI's A_preprocess / TACTIC-KG's chunking)

Segment on sentence-embedding cosine distances with breakpoint at distance > µ + k·σ instead
of fixed blocks. Our `CTI_SECTION_PASS` uses fixed 6000-char blocks (`blocks_of`,
`pipeline.py:486`): recall 61 → 76-78% on techniques for long articles, at 1.9× tokens. A
distance-based boundary puts breaks at real topic shifts. True embedding segmentation needs a
small local encoder (runs fine on CPU); medium effort — test against `sect_html_*` evals.

### G. Confidence via logprobs (TACTIC-KG §4.2)

Ask vLLM for token logprobs (`"logprobs": true` in the payload), aggregate mean logprob per
relation line, and send low-confidence lines to `verify_relations` first / flag them in the
journal. Cheap, no new model; prioritizes the verification budget where the model is unsure.

### H. kNN demonstrations from a non-gold example bank (CTINexus §4.2 / MTPE's RAG)

Both papers retrieve top-k similar annotated reports as ICL demos, ordered ascending by
similarity. Constraint: our rules forbid leaking the gold (`Annotations/`) into prompts, and
CTINexus itself trains retrieval on the train split only. Transposition: build the example
bank from **our own previously extracted bundles** (`backend/data/bundles/article_*.json`,
text + STIX pairs), not from `Annotations/`, plus a few hand-written examples; small vector
index, k=3-5 per article, ascending order. Should stabilize entity typing on atypical
articles (1438, 1338, §4.7.5). Watch prompt budget: the article already fills most of the
32k context, so demos must be short (behavior lines, not full articles).

## 4. What the papers say that we should *not* adopt

- **LoRA fine-tuning per agent** (TACTIC-KG): forbidden by project constraints ("aucun
  entraînement ni fine-tuning"). Keep the decomposition and constrained verification; skip the
  LoRA.
- **Forced graph connectivity** (CTINexus phase 3): TACTIC-KG shows over-completion is
  structural hallucination. The islands step stays, but closed-world and centrality-targeted
  (idea D).
- **Multi-temperature everywhere**: our determinism (temp 0, seed 0) is deliberate — eval
  already shows 4-6 pts of server-side non-determinism. Restrict multi-T to candidate
  expansion (idea A), never to verification.

## 5. Suggested priority order (by measured loss addressed)

1. **A + E-iterative** — multi-temperature behavior expansion + re-retrieval with rewritten
   query on unchosen behaviors → attacks the 137 missing-endpoint relations and 35 unproposed
   techniques (dominant losses).
2. **B** — fusion/conflict pass → attacks the 33 wrong-carrier relations and the
   attribution-critical `intrusion-set uses attack-pattern`.
3. **C** — within-article entity alignment with IOC protection → typing consistency, better
   actor aggregation, cross-article alias resolution (§4.8).
4. **D** — centrality-targeted island linking → cheaper, cleaner connectivity.
5. **G** — logprob confidence into verification → cheap precision guard.
6. **H** — demo retrieval from self-generated bundles → helps atypical articles; respect the
   no-gold-leak rule.
7. **F** — embedding-based semantic chunking → possible replacement for fixed blocks in
   `CTI_SECTION_PASS`.

Measure everything with the existing harness: `uv run cti-eval --run --bundles
backend/evaluation/eval/<nom>`, compared against `base_html_1/2` and `sect_html_1/2`
(§4.2), watching relations R/P, `campaign uses attack-pattern`, `malware uses
attack-pattern`, and the "jamais proposée" row of §4.6.

Caveat: the eval set is 9 articles with 4-6 pts run-to-run noise, so run each ablation twice
(as with the `*_1` / `*_2` pairs) before trusting a delta.
