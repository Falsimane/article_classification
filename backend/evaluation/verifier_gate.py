"""Barrière hors ligne du vérificateur par questions fermées (conception 2026-11-12, §6.4).

Lit la trace `verdicts` d'une exécution `CTI_VERIFY=shadow` (runs.json) et étiquette chaque affirmation :
  tp  relation du bundle appariée au gold (ou technique au niveau du rapport appariée)  → doit être gardée telle quelle
  f   technique ou relation auditée F (fp_audit.json d'une exécution de référence)       → doit être retirée
  jd  auditée J ou D                                                                     → doit rester (gardée, remontée ou réattribuée)
Le reste n'est pas compté. Le vérificateur passe si F rejetés ≥ 2/3 ET vrais positifs gardés ≥ 95 % (rejets à tort).

  uv run python -m backend.evaluation.verifier_gate verify_shadow_a --audit cascade2_a
"""

import argparse
import json
import sys
from pathlib import Path

root_dir = Path(__file__).resolve().parents[2]
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from backend.config import EVAL_DIR  # noqa: E402
from backend.evaluation.score import load_bundle  # noqa: E402
from backend.extracting.stix.attack import get_attack_kb  # noqa: E402

F_REJECTED = 2 / 3
TP_KEPT = 0.95


def gate(rows: list[tuple[str, str]]) -> dict:
    """rows : (étiquette tp | f | jd, action du vérificateur). Compteurs et verdict PASSE / ÉCHOUE / INDÉTERMINÉ."""
    out = {"tp": 0, "tp_kept": 0, "tp_modified": 0, "f": 0, "f_rejected": 0, "jd": 0, "jd_kept": 0}
    for label, action in rows:
        out[label] += 1
        if label == "tp":
            out["tp_kept"] += action == "keep"
            out["tp_modified"] += action in ("reassign", "to_parent")
        elif label == "f":
            out["f_rejected"] += action == "drop"
        else:
            out["jd_kept"] += action != "drop"
    if not out["f"] or not out["tp"]:
        out["verdict"] = "INDÉTERMINÉ"
    else:
        ok = out["f_rejected"] / out["f"] >= F_REJECTED and out["tp_kept"] / out["tp"] >= TP_KEPT
        out["verdict"] = "PASSE" if ok else "ÉCHOUE"
    return out


def _audits(names: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for name in names:
        path = EVAL_DIR / name / "fp_audit.json"
        if path.exists():
            out.update({k: v["verdict"] for k, v in json.loads(path.read_text(encoding="utf-8")).items() if v.get("verdict")})
    return out


def label_run(run: str, audits: dict[str, str]) -> tuple[list[tuple[str, str]], list[str]]:
    """Étiquettes (tp | f | jd, action) des affirmations tracées, et les vrais positifs modifiés ou retirés (pour corriger)."""
    folder = EVAL_DIR / run
    runs = json.loads((folder / "runs.json").read_text(encoding="utf-8"))
    report = {a["article_id"]: a for a in json.loads((folder / "report.json").read_text(encoding="utf-8"))["articles"]}
    kb, rows, lost = get_attack_kb(), [], []
    for aid_s, r in runs.items():
        aid = int(aid_s)
        path = folder / f"article_{aid}.json"
        if aid not in report or not path.exists():
            continue
        ents, _ = load_bundle(json.loads(path.read_text(encoding="utf-8")), kb, gold=False)
        unmatched_rel = {x["relation"] for x in report[aid]["review_relations"]}
        unmatched_ent = set(report[aid]["review_entities"])
        for v in (r.get("trace") or {}).get("verdicts") or []:
            s, rel, t = v["key"]
            action = v["decision"]["action"]
            if t not in ents or (s and s not in ents):
                continue  # retirée ensuite par l'ancien vérificateur ou absente du bundle : pas d'étiquette
            text = f"{ents[s].describe()} --{rel}--> {ents[t].describe()}" if s else None
            audit = audits.get(f"{aid}:{v['technique']}") if v.get("technique") else audits.get(f"{aid}:R:{text}")
            if audit:
                label = "f" if audit == "F" else "jd"
            elif (text and text not in unmatched_rel) or (not s and ents[t].describe() not in unmatched_ent):
                label = "tp"
            else:
                continue
            rows.append((label, action))
            if label == "tp" and action != "keep":
                lost.append(f"{aid} {text or ents[t].describe()} : {action} ({v['decision'].get('reason', '')})")
    return rows, lost


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("run", help="exécution CTI_VERIFY=shadow (dossier de backend/evaluation/eval/)")
    parser.add_argument("--audit", action="append", default=[], help="exécution dont fp_audit.json sert d'étiquettes (répétable)")
    args = parser.parse_args()
    rows, lost = label_run(args.run, _audits(args.audit))
    g = gate(rows)
    pct = lambda a, b: f"{100 * a / b:.0f} %" if b else "—"  # noqa: E731
    print(f"vrais positifs gardés  {g['tp_kept']}/{g['tp']} ({pct(g['tp_kept'], g['tp'])}) · modifiés {g['tp_modified']}")
    print(f"F rejetés              {g['f_rejected']}/{g['f']} ({pct(g['f_rejected'], g['f'])})")
    print(f"J et D gardés          {g['jd_kept']}/{g['jd']} ({pct(g['jd_kept'], g['jd'])})")
    print(f"verdict : {g['verdict']}")
    for line in lost:
        print("  " + line)


if __name__ == "__main__":
    main()
