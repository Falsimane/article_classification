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
    ENTITY_SCHEMA, MAX_ENTITY_TOKENS, MAX_RELATION_TOKENS, EntityRow, build_candidates, entity_system, entity_user,
    ENTITY_VERIFY_BATCH, MAX_ENTITY_VERIFY_TOKENS, MAX_VERIFY_TOKENS, VERIFY_BATCH, entity_verify_system, entity_verify_user, first_mentions, _claim, group_candidate_units, kb_hints, llm_entity_types, parse_answers,
    parse_entities, parse_verdicts, relation_schema, relation_system, relation_user, verify_schema, verify_system,
    verify_user,
)  # fmt: skip

MAX_PASS_CHARS = 7000  # caractères d'article montrés par appel


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
    n_candidates: int = 0
    n_proposed: int = 0  # relations proposées avant vérification
    n_verified: int = 0  # relations confirmées par la passe de vérification
    seconds: float = 0.0

    @property
    def output_tokens(self) -> int:
        return sum(c.output_tokens for c in self.calls)

    @property
    def prompt_tokens(self) -> int:
        return sum(c.prompt_tokens for c in self.calls)


def _stat(stage: str, index: int, result: llm.LLMResult, limit: int) -> CallStat:
    return CallStat(stage, index, result.prompt_tokens, result.output_tokens, result.seconds, result.tokens_per_second, result.output_tokens >= limit)


def clean_title(title: str, site_name: str | None) -> str:
    """Titre sans le suffixe de l'éditeur (« Rapport - The DFIR Report » -> « Rapport »)."""
    for sep in (" - ", " | ", " – ", " — "):
        head, _, tail = title.rpartition(sep)
        if head and site_name and normalize_name(tail) == normalize_name(site_name):
            return head.strip()
    return title


def _terms(ent: dict) -> tuple[str, ...]:
    """Termes qui repèrent une entité dans une phrase : nom, alias, et radical du secteur pour une identité de classe
    `class` (« financial-services » est nommé « financial » dans le texte)."""
    terms = [ent["name"], *ent.get("aliases", [])]
    terms += [f"~{sector.split('-')[0][:6]}" for sector in ent.get("sectors", [])]
    return tuple(terms)


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
    workers: int = 1,
    max_pass_chars: int = MAX_PASS_CHARS,
    verify: bool = True,
) -> ArticleExtraction:
    """Extrait le graphe d'un article. `category` choisit le profil d'extraction (operational, tactical, strategic)."""
    if category not in PROFILES:
        raise ValueError(f"aucun profil d'extraction pour la catégorie {category!r}")
    t0 = time.perf_counter()
    profile = PROFILES[category]
    title = clean_title(title, site_name)
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
    entities = list(stage1.entities)
    rows: list[EntityRow] = [
        EntityRow(f"E{i}", ent["type"], ent["name"], _terms(ent)) for i, ent in enumerate(entities, 1)
    ]

    # Vérification des entités : une question fermée par entité, avec sa première phrase et sa section
    first = first_mentions(units, rows)
    to_check = [(i, r, first[r.eid]) for i, r in enumerate(rows, 1) if r.eid in first]
    for r in rows:
        if r.eid not in first:
            stage1.issues.append(Issue("reject", "ENTITY_NOT_IN_TEXT", f"{r.stix_type}:{r.name}", "aucune phrase du texte ne nomme cette entité"))
    keep_ids = set(first)
    if to_check and verify:
        batches = [to_check[i : i + ENTITY_VERIFY_BATCH] for i in range(0, len(to_check), ENTITY_VERIFY_BATCH)]
        ev_system = entity_verify_system(category)

        def run_entity_verify(batch):
            numbers = [n for n, _, _ in batch]
            res = llm.generate(ev_system, entity_verify_user(batch), verify_schema(numbers), max_output_tokens=MAX_ENTITY_VERIFY_TOKENS)
            items = (res.parsed or {}).get("verdicts", []) if isinstance(res.parsed, dict) else []
            return res, parse_verdicts(items, numbers)

        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            ev_results = list(pool.map(run_entity_verify, batches))
        confirmed_numbers: set[int] = set()
        for i, (res, ok) in enumerate(ev_results):
            out.calls.append(_stat("entity-check", i, res, MAX_ENTITY_VERIFY_TOKENS))
            confirmed_numbers |= ok
        for n, r, _u in to_check:
            if n not in confirmed_numbers:
                keep_ids.discard(r.eid)
                stage1.issues.append(Issue("reject", "ENTITY_VERIFICATION_REJECTED", f"{r.stix_type}:{r.name}", "contexte : ne désigne pas une entité de ce type dans l'attaque décrite"))
    kept = [(row, ent) for row, ent in zip(rows, entities) if row.eid in keep_ids]
    rows = [row for row, _ in kept]
    entities = [ent for _, ent in kept]

    # L'intrusion décrite est un objet à part entière (profil opérationnel) : sujet implicite quand l'acteur n'est pas nommé
    incident_row = None
    if "incident" in profile.entity_types:
        incident_row = EntityRow(f"E{max((int(r.eid[1:]) for r in rows), default=0) + 1}", "incident", title, ())
        entities.append({"type": "incident", "name": title})
        rows.append(incident_row)
    out.seconds = time.perf_counter() - t0
    candidates = build_candidates(units, rows, category, implicit=incident_row)
    out.n_candidates = sum(len(c) for _, c in candidates)
    if not candidates:
        out.graph = SanitizedGraph(entities=[], relationships=[], issues=stage1.issues)
        return out

    # --- Étape 2 : le modèle classe des candidats fermés -------------------------------------------------------------
    rel_system = relation_system(category)
    groups = group_candidate_units(candidates)

    def run_relations(item):
        index, group = item
        res = llm.generate(rel_system, relation_user(title, category, rows, group), relation_schema(group), max_output_tokens=MAX_RELATION_TOKENS)
        items = (res.parsed or {}).get("relations", []) if isinstance(res.parsed, dict) else []
        answers, dropped = parse_answers(items, group)
        return index, res, answers, dropped

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        rel_results = list(pool.map(run_relations, list(enumerate(groups))))
    raw_relations = []
    for index, res, answers, dropped in rel_results:
        out.calls.append(_stat("relations", index, res, MAX_RELATION_TOKENS))
        out.dropped_relation_lines += dropped
        for unit, cand, rel in answers:
            # fenêtre de deux phrases : les deux sont citées, séparées par [...] (chaque fragment est vérifié dans le texte)
            evidence = unit.text if cand.prev_uid is None else f"{by_uid[cand.prev_uid].text} [...] {unit.text}"
            raw_relations.append({"source": cand.source, "type": rel, "target": cand.target, "evidence": evidence, "section": unit.heading_path})

    # --- Étape 3 : vérification, une question fermée par relation -------------------------------------------------------
    out.n_proposed = len(raw_relations)
    if raw_relations and verify:
        by_eid = {r.eid: r for r in rows}
        numbered = [
            (i, rel["evidence"], _claim(by_eid[rel["source"]].name, by_eid[rel["source"]].stix_type, rel["type"], by_eid[rel["target"]].name, by_eid[rel["target"]].stix_type))
            for i, rel in enumerate(raw_relations, 1)
        ]
        batches = [numbered[i : i + VERIFY_BATCH] for i in range(0, len(numbered), VERIFY_BATCH)]

        def run_verify(batch):
            numbers = [n for n, _, _ in batch]
            res = llm.generate(verify_system(), verify_user(batch), verify_schema(numbers), max_output_tokens=MAX_VERIFY_TOKENS)
            items = (res.parsed or {}).get("verdicts", []) if isinstance(res.parsed, dict) else []
            return res, parse_verdicts(items, numbers)

        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            verdicts = list(pool.map(run_verify, batches))
        confirmed: set[int] = set()
        for i, (res, ok) in enumerate(verdicts):
            out.calls.append(_stat("verification", i, res, MAX_VERIFY_TOKENS))
            confirmed |= ok
        out.n_verified = len(confirmed)
        kept = []
        for i, rel in enumerate(raw_relations, 1):
            if i in confirmed:
                kept.append(rel)
            else:
                stage1.issues.append(Issue("reject", "VERIFICATION_REJECTED", f"{rel['source']} --{rel['type']}--> {rel['target']}", f"non confirmée : « {rel['evidence'][:90]} »"))
        raw_relations = kept

    # --- Validation finale par l'ontologie STIX -------------------------------------------------------------------------
    raw_entities = [{**ent, "ref": row.eid} for row, ent in zip(rows, entities)]
    out.graph = sanitize_extraction(
        {"entities": raw_entities, "relationships": raw_relations}, profile, clean_markdown, publisher_names=publishers
    )
    out.graph.issues = stage1.issues + out.graph.issues
    out.seconds = time.perf_counter() - t0
    return out
