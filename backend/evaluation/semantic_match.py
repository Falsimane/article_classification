"""Appariement sémantique de l'évaluation : une entité prédite et une entité du gold qui désignent le même objet sous deux
libellés différents (« C++ loader » / « first stage C++ DLL implant ») ne partagent aucun nom, donc aucun crédit.

Un juge (le modèle, sortie contrainte) décide, classe par classe, quelles entités restées sans appariement désignent la même
chose, d'après leur nom, leur description et les phrases de leurs relations. Il ne voit que les entités que le score n'a pas
appariées par leur nom : il ne peut ni défaire un appariement ni rapprocher deux types différents. Le résultat est écrit dans
`<bundles>/semantic_matches.json` (une ligne par paire, lisible et corrigeable) ; le score le relit sans rappeler le modèle."""

import json
from collections.abc import Callable
from pathlib import Path

from backend.evaluation.score import _align_operations, _candidates, load_bundle
from backend.extracting.stix.attack import AttackKB

FILE = "semantic_matches.json"
# Classes nommées par un libellé libre ; techniques, vulnérabilités, lieux et groupes ont un identifiant ou un nom propre
JUDGED = ("malware", "identity", "infrastructure", "course-of-action")
MAX_QUOTES = 4
Judge = Callable[[dict], dict[int, int]]  # groupe -> {numéro gold: numéro prédit, 0 = aucun}

SYSTEM = """You compare two annotations of the same threat report. Each lists entities of one STIX type, with the passages that
describe them. Two entities are the SAME when they denote the same object of the report (the same malware component, the same
victim, the same infrastructure, the same measure), even under different labels. They are NOT the same when they are two
distinct objects of the same kind (two different stages of a chain, two different victims), or when one is only a part or a
generalisation of the other. For each reference entity, give the number of the candidate that is the same object, or 0 when
none is. A candidate is used at most once."""


def _context(obj: dict, objs: dict[str, dict], rels: list[dict]) -> str:
    parts = [f"aliases: {', '.join(obj['aliases'])}"] if obj.get("aliases") else []
    if obj.get("description"):
        parts.append(f"description: {obj['description'][:300]}")
    quotes: list[str] = []
    for r in rels:
        if obj["id"] not in (r["source_ref"], r["target_ref"]):
            continue
        other = objs.get(r["target_ref"] if r["source_ref"] == obj["id"] else r["source_ref"], {})
        direction = "->" if r["source_ref"] == obj["id"] else "<-"
        quote = r.get("x_gold_evidence_quote") or r.get("description") or ""
        quotes.append(f"{direction} {r['relationship_type']} {other.get('name', '?')}" + (f": « {quote[:220]} »" if quote else ""))
    return " | ".join(parts + quotes[:MAX_QUOTES])


def pending(gold_bundle: dict, pred_bundle: dict, kb: AttackKB) -> list[dict]:
    """Par classe jugée : les entités du gold et les entités prédites que le score n'apparie pas par leur nom."""
    gold, gold_rels = load_bundle(gold_bundle, kb, gold=True)
    pred, pred_rels = load_bundle(pred_bundle, kb, gold=False)
    cands = _candidates(gold, pred)
    _align_operations(gold, pred, gold_rels, pred_rels, cands)
    taken = {g for gs in cands.values() for g in gs}
    groups = []
    for klass in JUDGED:
        side = []
        for bundle, ents, keep in ((gold_bundle, gold, lambda e: e.sid not in taken), (pred_bundle, pred, lambda e: e.sid not in cands)):
            objs = {o["id"]: o for o in bundle.get("objects", [])}
            rels = [o for o in objs.values() if o.get("type") == "relationship"]
            side.append([{"sid": e.sid, "name": e.name, "context": _context(objs[e.sid], objs, rels)} for e in ents.values() if e.klass == klass and keep(e)])
        if side[0] and side[1]:
            groups.append({"klass": klass, "gold": side[0], "pred": side[1]})
    return groups


def match_article(gold_bundle: dict, pred_bundle: dict, kb: AttackKB, judge: Judge) -> list[dict]:
    """Paires jugées identiques, une entité prédite au plus par entité du gold et inversement."""
    pairs = []
    for group in pending(gold_bundle, pred_bundle, kb):
        used: set[int] = set()
        for g_num, p_num in sorted(judge(group).items()):
            if not (isinstance(g_num, int) and isinstance(p_num, int)) or not 1 <= g_num <= len(group["gold"]) or not 1 <= p_num <= len(group["pred"]) or p_num in used:
                continue
            used.add(p_num)
            g, p = group["gold"][g_num - 1], group["pred"][p_num - 1]
            pairs.append({"gold": g["sid"], "pred": p["sid"], "gold_name": g["name"], "pred_name": p["name"]})
    return pairs


def prompt_of(group: dict) -> str:
    rows = lambda items: "\n".join(f"{i}. {e['name']}" + (f" — {e['context']}" if e["context"] else "") for i, e in enumerate(items, 1))  # noqa: E731
    return f"STIX type: {group['klass']}\n\nReference entities:\n{rows(group['gold'])}\n\nCandidates:\n{rows(group['pred'])}"


def schema_of(group: dict) -> dict:
    n, m = len(group["gold"]), len(group["pred"])
    item = {
        "type": "object", "additionalProperties": False, "required": ["reference", "candidate"],
        "properties": {"reference": {"type": "integer", "enum": list(range(1, n + 1))}, "candidate": {"type": "integer", "enum": list(range(m + 1))}},
    }  # fmt: skip
    return {"type": "object", "additionalProperties": False, "required": ["matches"], "properties": {"matches": {"type": "array", "items": item, "minItems": n, "maxItems": n}}}


def llm_judge(group: dict) -> dict[int, int]:
    from backend.extracting import llm  # import tardif : re-scorer sans juge ne charge pas le client

    answer = llm.generate(SYSTEM, prompt_of(group), schema_of(group), max_output_tokens=60 + 20 * len(group["gold"]), stage="appariement").parsed
    out: dict[int, int] = {}
    for m in (answer or {}).get("matches", []):
        out.setdefault(m.get("reference"), m.get("candidate"))
    return out


def load(out_dir: Path) -> dict[int, list[dict]]:
    path = out_dir / FILE
    return {int(k): v for k, v in json.loads(path.read_text(encoding="utf-8")).items()} if path.exists() else {}


def save(out_dir: Path, matches: dict[int, list[dict]]) -> None:
    (out_dir / FILE).write_text(json.dumps({str(k): v for k, v in sorted(matches.items())}, ensure_ascii=False, indent=1), encoding="utf-8")
