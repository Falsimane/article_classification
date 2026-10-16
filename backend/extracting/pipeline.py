"""Extraction d'un article : segmenter, extraire les entités, extraire les relations, valider avec l'ontologie STIX.

    clean_markdown --segment--> phrases numérotées --passes--> [LLM entités] ×N en parallèle
        --fusion + ATT&CK--> entités --> [LLM relations] ×N en parallèle (phrases utiles seulement)
        --ontologie STIX--> graphe validé (types, relations, preuves)

Aucune passe ne dépend d'une autre : l'ancienne « mémoire inter-segments » imposait l'exécution séquentielle.
La cohérence entre passes vient de la fusion déterministe des entités (identifiants STIX, alias ATT&CK).
"""

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from backend.ontology.stix import PROFILES, SanitizedGraph, normalize_name, sanitize_extraction
from backend.ontology.stix.validate import Issue

from . import llm
from .segment import Pass, Unit, make_passes, segment
from .stages import (
    ADVERSARY, ENTITY_SCHEMA, MAX_ENTITY_TOKENS, MAX_RELATION_TOKENS, EntityRow, entity_system, entity_user,
    kb_hints, llm_entity_types, parse_entities, parse_relations, relation_schema, relation_system, relation_user,
    entity_hits,
)  # fmt: skip

MAX_PASS_CHARS = 7000  # caractères d'article montrés par appel
MAX_ADVERSARIES_IN_SCOPE = 4


@dataclass
class CallStat:
    stage: str
    pass_index: int
    prompt_tokens: int
    output_tokens: int
    seconds: float
    tokens_per_second: float
    truncated: bool  # la réponse a atteint la limite de tokens : des éléments ont pu être perdus


@dataclass
class ArticleExtraction:
    article_id: int
    profile: str
    graph: SanitizedGraph
    n_units: int
    n_passes: int
    calls: list[CallStat] = field(default_factory=list)
    entity_issues: list[Issue] = field(default_factory=list)
    dropped_entity_lines: int = 0
    dropped_relation_lines: int = 0
    seconds: float = 0.0

    @property
    def output_tokens(self) -> int:
        return sum(c.output_tokens for c in self.calls)

    @property
    def prompt_tokens(self) -> int:
        return sum(c.prompt_tokens for c in self.calls)


def _stat(stage: str, index: int, result: llm.LLMResult, limit: int) -> CallStat:
    return CallStat(stage, index, result.prompt_tokens, result.output_tokens, result.seconds, result.tokens_per_second, result.output_tokens >= limit)


def _merge_entities(per_pass: list[list[dict]]) -> list[dict]:
    """Une entité par (type, nom normalisé) ; les alias se cumulent d'une passe à l'autre."""
    merged: dict[tuple[str, str], dict] = {}
    for entities in per_pass:
        for ent in entities:
            key = (ent["type"], normalize_name(ent["name"]))
            if key in merged:
                known = merged[key].setdefault("aliases", [])
                known += [a for a in ent.get("aliases", []) if a not in known and normalize_name(a) != key[1]]
            else:
                merged[key] = {**ent, "aliases": list(ent.get("aliases", []))}
    return list(merged.values())


def extract_article(
    article_id: int,
    title: str,
    category: str,
    clean_markdown: str,
    site_name: str | None = None,
    *,
    workers: int = 2,
    max_pass_chars: int = MAX_PASS_CHARS,
) -> ArticleExtraction:
    """Extrait le graphe d'un article. `category` choisit le profil d'extraction (operational, tactical, strategic)."""
    if category not in PROFILES:
        raise ValueError(f"aucun profil d'extraction pour la catégorie {category!r}")
    t0 = time.perf_counter()
    profile = PROFILES[category]
    units = segment(clean_markdown)
    passes = make_passes(units, max_pass_chars)
    publishers = [site_name] if site_name else []
    out = ArticleExtraction(article_id, category, SanitizedGraph(), len(units), len(passes))
    by_uid = {u.uid: u for u in units}

    # --- Étape 1 : entités, une passe = un appel, toutes en parallèle -----------------------------------------------
    allowed_types = llm_entity_types(category)
    system = entity_system(category)

    def run_entities(p: Pass):
        res = llm.generate(system, entity_user(title, category, p, kb_hints(p.units)), ENTITY_SCHEMA, max_output_tokens=MAX_ENTITY_TOKENS)
        items = (res.parsed or {}).get("entities", []) if isinstance(res.parsed, dict) else []
        entities, dropped = parse_entities(items, allowed_types)
        return p.index, res, entities, dropped

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        results = list(pool.map(run_entities, passes))
    per_pass = []
    for index, res, entities, dropped in results:
        out.calls.append(_stat("entities", index, res, MAX_ENTITY_TOKENS))
        out.dropped_entity_lines += dropped
        per_pass.append(entities)

    # Assainissement des entités AVANT l'étape relations : rejette l'éditeur, les termes génériques, corrige les types
    # et les identifiants ATT&CK, fusionne les alias. Seules les entités valides sont proposées au modèle.
    stage1 = sanitize_extraction(
        {"entities": _merge_entities(per_pass), "relationships": []}, profile, None, publisher_names=publishers, keep_orphans=True
    )
    out.entity_issues = stage1.issues
    entities = stage1.entities
    rows: list[EntityRow] = []
    for i, ent in enumerate(entities, 1):
        rows.append(EntityRow(f"E{i}", ent["type"], ent["name"], tuple([ent["name"], *ent.get("aliases", [])])))
    id_of = {r.eid: ent["id"] for r, ent in zip(rows, entities)}
    out.seconds = time.perf_counter() - t0
    if len(rows) < 2:
        out.graph = SanitizedGraph(entities=[], relationships=[], issues=stage1.issues)
        return out

    # --- Étape 2 : relations, sur les seules phrases qui nomment une entité -----------------------------------------
    relation_names = tuple(sorted({r for _, r, _ in profile.pairs()}))
    schema = relation_schema(relation_names)
    rel_system = relation_system(category)
    adversary_rows = [r for r in rows if r.stix_type in ADVERSARY]

    def run_relations(p: Pass):
        hits = entity_hits(p.units, rows)  # une phrase sans entité nommée ne peut étayer aucune relation
        useful = [u for u in p.units if u.uid in hits]
        if not useful:
            return p.index, None, [], 0
        present = set().union(*hits.values())
        scope = [r for r in rows if r.eid in present]
        extra = [r for r in adversary_rows if r.eid not in present][:MAX_ADVERSARIES_IN_SCOPE]  # sujet implicite d'une phrase
        table = scope + extra
        if len(table) < 2:
            return p.index, None, [], 0
        res = llm.generate(rel_system, relation_user(title, category, table, useful), schema, max_output_tokens=MAX_RELATION_TOKENS)
        items = (res.parsed or {}).get("relations", []) if isinstance(res.parsed, dict) else []
        parsed, dropped = parse_relations(items, {r.eid for r in table}, {u.uid for u in useful})
        return p.index, res, parsed, dropped

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        rel_results = list(pool.map(run_relations, passes))
    raw_relations = []
    for index, res, parsed, dropped in rel_results:
        if res is not None:
            out.calls.append(_stat("relations", index, res, MAX_RELATION_TOKENS))
        out.dropped_relation_lines += dropped
        for uid, source, rel, target in parsed:
            unit: Unit = by_uid[uid]
            raw_relations.append({"source": source, "type": rel, "target": target, "evidence": unit.text, "section": unit.heading_path})

    # --- Validation finale par l'ontologie STIX -------------------------------------------------------------------------
    raw_entities = [{**ent, "ref": row.eid} for row, ent in zip(rows, entities)]
    out.graph = sanitize_extraction(
        {"entities": raw_entities, "relationships": raw_relations}, profile, clean_markdown, publisher_names=publishers
    )
    out.graph.issues = stage1.issues + out.graph.issues
    out.seconds = time.perf_counter() - t0
    return out
