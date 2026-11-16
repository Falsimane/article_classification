"""Révision des porteurs du gold selon la règle « porteur = celui qui fait l'action » (Annotations/methode_annotation.md).

Une feuille par article liste chaque relation gold `uses → attack-pattern` avec sa citation, son contexte et les porteurs
possibles (entités du même groupe d'activité). La décision se prend EN LISANT L'ARTICLE, jamais une sortie de l'extracteur :
`decision` = « keep » ou « move » (+ `new_source`, `reason` = la phrase qui désigne l'auteur de l'action).

  uv run python -m backend.evaluation.gold_carriers worksheet all        # Annotations/revision/<id>.carriers.json
  uv run python -m backend.evaluation.gold_carriers apply 1558           # réécrit le gold de l'article
"""

import argparse
import copy
import json
import sys
from pathlib import Path

root_dir = Path(__file__).resolve().parents[2]
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from backend.evaluation.cti_eval import load_manifest  # noqa: E402
from backend.evaluation.score import LABEL_REQUIRED, activity_groups, load_bundle  # noqa: E402
from backend.extracting.stix.attack import get_attack_kb  # noqa: E402
from backend.extracting.stix.objects import DRAFT_RELATIONS, to_stix  # noqa: E402

REVISION_DIR = root_dir / "Annotations" / "revision"
_CARRIERS = ("campaign", "intrusion-set", "threat-actor", "malware", "tool")


def worksheet(bundle: dict) -> list[dict]:
    """Une ligne par relation `uses → attack-pattern` du gold, décision « keep » par défaut."""
    ents, rels = load_bundle(bundle, get_attack_kb(), gold=True)
    groups = activity_groups(ents, rels)
    objs = {o["id"]: o for o in bundle["objects"]}
    rows = []
    for r in rels:
        if r.rel != "uses" or ents[r.target].stix_type != "attack-pattern":
            continue
        group = groups.get(r.source, {r.source}) | {r.source}
        candidates = sorted(sid for sid in group if ents[sid].stix_type in _CARRIERS)
        rows.append({
            "relation_id": r.sid, "source": f"{ents[r.source].stix_type}:{ents[r.source].name}",
            "technique": ents[r.target].technique, "technique_name": ents[r.target].name,
            "quote": objs[r.sid].get("x_gold_evidence_quote", ""), "context": objs[r.sid].get("x_gold_context", ""),
            "candidates": candidates, "candidate_names": {sid: f"{ents[sid].stix_type}:{ents[sid].name}" for sid in candidates},
            "decision": "keep", "new_source": None, "reason": "",
        })  # fmt: skip
    return rows


def apply_rows(bundle: dict, rows: list[dict]) -> tuple[dict, int]:
    """Bundle révisé (copie) et nombre de relations déplacées. Une relation déplacée sur un couple (source, uses, cible) déjà
    présent est fusionnée dans l'existante (citation ajoutée à `description`, label required s'il l'un l'est).
    ValueError si un déplacement donne une relation hors STIX 2.1 ; le bundle d'entrée n'est jamais modifié."""
    out = copy.deepcopy(bundle)
    objs = {o["id"]: o for o in out["objects"]}
    moves = [r for r in rows if r.get("decision") == "move"]
    for row in moves:
        new, rel = row.get("new_source"), objs.get(row["relation_id"])
        if rel is None or new not in objs:
            raise ValueError(f"{row['relation_id']} : relation ou nouvelle source introuvable")
        triple = (objs[new]["type"], "uses", objs[_technique(rel, objs)]["type"])
        if triple not in DRAFT_RELATIONS:
            raise ValueError(f"{row['relation_id']} : {' '.join(triple)} n'existe pas en STIX 2.1")
    moved, removed = 0, set()
    for row in moves:
        rel, new = objs[row["relation_id"]], row["new_source"]
        tech = _technique(rel, objs)
        old = rel["target_ref"] if rel["source_ref"] == tech else rel["source_ref"]
        if old == new:
            continue
        pair = {new, tech}
        twin = next((o for o in out["objects"] if o.get("type") == "relationship" and o["id"] not in removed and o["id"] != rel["id"]
                     and o["relationship_type"] == "uses" and {o["source_ref"], o["target_ref"]} == pair), None)  # fmt: skip
        if twin:
            quotes = [q for q in (twin.get("description", "").split(" | ") if twin.get("description") else []) + [rel.get("x_gold_evidence_quote", "")] if q]
            twin["description"] = " | ".join(dict.fromkeys(quotes))
            twin["x_gold_merged_from"] = list(dict.fromkeys([*twin.get("x_gold_merged_from", []), old]))
            if LABEL_REQUIRED in rel.get("labels", []) and LABEL_REQUIRED not in twin.get("labels", []):
                twin["labels"] = [LABEL_REQUIRED]
            removed.add(rel["id"])
        else:
            rel["x_gold_revised_from"] = old
            stix = to_stix(objs[new]["type"], "uses", "attack-pattern")  # vers un outil : « technique uses outil »
            rel["source_ref"], rel["target_ref"] = (tech, new) if stix else (new, tech)
        moved += 1
    out["objects"] = [o for o in out["objects"] if o["id"] not in removed]
    return out, moved


def _technique(rel: dict, objs: dict) -> str:
    """La technique d'une relation « uses » de la feuille, quel que soit son sens d'écriture."""
    return rel["source_ref"] if objs[rel["source_ref"]]["type"] == "attack-pattern" else rel["target_ref"]


def update_row(rows: list[dict], relation_id: str, decision: str, new_source: str | None, reason: str, allowed: set[str]) -> list[dict]:
    """Feuille avec la décision d'une ligne modifiée (interface de révision). ValueError si la décision est inconnue ou si
    la nouvelle source n'est pas un porteur de l'article."""
    if decision not in ("keep", "move"):
        raise ValueError(f"décision inconnue : {decision}")
    if decision == "move" and new_source not in allowed:
        raise ValueError("nouvelle source hors des porteurs de l'article")
    out = copy.deepcopy(rows)
    row = next((r for r in out if r["relation_id"] == relation_id), None)
    if row is None:
        raise ValueError(f"relation inconnue : {relation_id}")
    row.update(decision=decision, new_source=new_source if decision == "move" else None, reason=str(reason or "")[:1000])
    return out


def _gold_path(article_id: int) -> Path:
    return next(e["gold_path"] for e in load_manifest() if e["article_id"] == article_id)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=("worksheet", "apply"))
    parser.add_argument("article", help="identifiant d'article, ou « all » pour worksheet")
    args = parser.parse_args()
    REVISION_DIR.mkdir(parents=True, exist_ok=True)
    ids = [e["article_id"] for e in load_manifest()] if args.article == "all" else [int(args.article)]
    for aid in ids:
        gold_path, sheet = _gold_path(aid), REVISION_DIR / f"{aid}.carriers.json"
        raw = gold_path.read_text(encoding="utf-8")
        bundle = json.loads(raw)
        if args.action == "worksheet":
            if sheet.exists():
                print(f"{aid} : {sheet.name} existe déjà (décisions conservées)")
                continue
            sheet.write_text(json.dumps(worksheet(bundle), ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"{aid} : {sheet}")
        else:
            out, moved = apply_rows(bundle, json.loads(sheet.read_text(encoding="utf-8")))
            ending = "\n" if raw.endswith("\n") else ""  # mise en forme d'origine : diff limité aux relations déplacées
            gold_path.write_text(json.dumps(out, ensure_ascii=False, indent=2) + ending, encoding="utf-8")
            print(f"{aid} : {moved} relation(s) déplacée(s)")


if __name__ == "__main__":
    main()
