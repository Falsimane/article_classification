"""Stabilité entre deux exécutions du même code : Jaccard des entités, des techniques et des relations des bundles
sémantiques (`article_<id>.json`, pas la couche observable). Une entité est identifiée par (type, nom normalisé) ou par
son identifiant ATT&CK ; une relation par ses deux extrémités ainsi identifiées."""

import json
from pathlib import Path

from backend.evaluation.score import load_bundle
from backend.extracting.stix.attack import AttackKB, get_attack_kb
from backend.preprocessing.cleaning.text.evidence import normalize_name


def bundle_keys(bundle: dict, kb: AttackKB) -> tuple[set[tuple], set[tuple], set[tuple]]:
    """(entités, techniques, relations) d'un bundle prédit, en clés comparables d'une exécution à l'autre."""
    ents, rels = load_bundle(bundle, kb, gold=False)
    key = {sid: (e.stix_type, e.technique or normalize_name(e.name)) for sid, e in ents.items()}
    entities = set(key.values())
    techniques = {k for k in entities if k[0] == "attack-pattern"}
    relations = {(*key[r.source][:2], r.rel, *key[r.target][:2]) for r in rels}
    return entities, techniques, relations


def jaccard(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if a | b else 1.0


def _articles(run: Path) -> dict[int, Path]:
    return {int(p.stem.split("_")[1]): p for p in run.glob("article_*.json") if p.stem.split("_")[1].isdigit()}


def _keys(path: Path, kb: AttackKB) -> tuple[set, set, set]:
    return bundle_keys(json.loads(path.read_text(encoding="utf-8")), kb)


def article_stability(run_a: Path, run_b: Path) -> dict[int, dict[str, float]]:
    kb = get_attack_kb()
    a, b = _articles(run_a), _articles(run_b)
    out = {}
    for aid in sorted(a.keys() & b.keys()):
        ka, kb_ = _keys(a[aid], kb), _keys(b[aid], kb)
        out[aid] = {name: jaccard(x, y) for name, x, y in zip(("entities", "techniques", "relations"), ka, kb_)}
    return out


def stability(run_a: Path, run_b: Path) -> dict[str, float]:
    """Jaccard des unions sur les articles communs (chaque clé préfixée par l'article)."""
    kb = get_attack_kb()
    a, b = _articles(run_a), _articles(run_b)
    sets = {name: (set(), set()) for name in ("entities", "techniques", "relations")}
    for aid in a.keys() & b.keys():
        for side, path in ((0, a[aid]), (1, b[aid])):
            for name, keys in zip(sets, _keys(path, kb)):
                sets[name][side].update((aid, *k) for k in keys)
    return {name: jaccard(x, y) for name, (x, y) in sets.items()}
