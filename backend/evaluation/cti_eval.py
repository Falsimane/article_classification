"""Évaluation de l'extraction contre les articles annotés à la main (Annotations/manifest.json).

    uv run cti-eval --run --workers 4                  # extrait les articles annotés (4 à la fois), puis score
    uv run cti-eval --run --bundles backend/evaluation/eval/<nom>   # même chose, dans un dossier nommé (comparer deux versions)
    uv run cti-eval --bundles backend/evaluation/eval/<nom>         # score des bundles déjà produits, sans appel au modèle
    uv run cti-eval --compare <a1>,<a2> <b1>,<b2>                    # configuration b contre a (plusieurs exécutions chacune)

Chaque exécution écrit dans le dossier des bundles : `report.json` (scores, manques, prédictions à revoir) et `report.md`.
La méthode de score est celle de `score.py` (rappel principal, précision, crédit partiel, hallucinations, ancrage).

`--compare` lit les `report.json` (re-scorer d'abord les anciens dossiers) : pour chaque configuration, la moyenne de ses
exécutions article par article ; l'écart avec la première et son intervalle de confiance à 95 % par bootstrap sur les
ARTICLES (les relations d'un article ne sont pas indépendantes : rééchantillonner les relations sous-estimerait le bruit).
Un écart n'est retenu que si son intervalle exclut 0 et que le compteur du mécanisme visé bouge dans le sens prévu.
"""

import argparse
import json
import random
import sys
import time
from collections import Counter
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.table import Table

root_dir = Path(__file__).resolve().parents[2]
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from backend.config import EVAL_DIR, SOURCE_ARTICLES_DB  # noqa: E402
from backend.evaluation.losses import ENTITY_STAGES, RELATION_STAGES, TECHNIQUE_STAGES, diagnose, tally, trace_of  # noqa: E402
from backend.evaluation.score import ArticleScore, score_article, total  # noqa: E402

MANIFEST = root_dir / "Annotations" / "manifest.json"

console = Console()


def load_manifest(path: Path = MANIFEST) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [{**a, "gold_path": path.parent / a["gold"]} for a in data["articles"]]


def fetch_article(article_id: int) -> dict:
    """Article et classification, sans les filtres d'éligibilité de l'extraction (le gold peut porter sur tout article)."""
    from backend.extracting.cli import read_articles

    rows = read_articles("k.id = ?", [article_id])
    if not rows:
        raise LookupError(f"article {article_id} absent de {SOURCE_ARTICLES_DB}")
    return rows[0]


def run_entry(out) -> dict:
    """Ligne de `runs.json` d'un article extrait (`runner.Outcome`)."""
    result = out.result
    return {
        "seconds": round(out.seconds, 1), "output_tokens": result.output_tokens, "llm_calls": len(result.calls),
        "calls_by_stage": dict(Counter(c.stage for c in result.calls)), "failures": result.failures, "trace": trace_of(result),
    }  # fmt: skip


def run_all(arts: list[dict], out_dir: Path, workers: int, runs: dict) -> float:
    """Extrait les articles, `workers` à la fois (le serveur groupe leurs requêtes), sans Neo4j.
    Un article échoué est signalé et laissé sans bundle. Retourne la durée totale, celle que voit l'utilisateur."""
    from backend.extracting.runner import run_batch, write_atomic

    t0 = time.perf_counter()
    for out in run_batch(arts, out_dir, workers, llm_log=True):  # article_<id>.llm.jsonl : chaque échange avec le modèle
        if out.error:
            console.print(f"[red]Échec[/] article {out.art['id']} : {escape(out.error)}")
            console.print(out.trace, style="dim", markup=False, highlight=False)
            continue
        runs[out.art["id"]] = run_entry(out)
        console.print(f"[bold]Extrait[/] article {out.art['id']} — {escape(out.art['title'] or '')} ({runs[out.art['id']]['seconds']} s)")
        write_atomic(out_dir / "runs.json", json.dumps(runs, indent=1))
    return time.perf_counter() - t0


def _pct(value: float | None) -> str:
    return "—" if value is None else f"{100 * value:.1f} %"


def print_scores(scores: list[ArticleScore], summary: dict, runs: dict, wall: float | None = None) -> None:
    table = Table(title="Score contre le gold (ATT&CK v20.0)", header_style="bold magenta", border_style="dim")
    for col in ("Article", "Ent. rappel", "Ent. précision", "Rel. rappel", "Rel. précision", "Prédits (ent/rel)", "Halluc.", "Citations ancrées", "Durée"):
        table.add_column(col, justify="right")

    def row(name, ents, rels, halluc, ground, run):
        anchored = f"{ground['exact'] + ground['approximate']}/{ground['with_quote']}" if ground["with_quote"] else "—"
        table.add_row(
            name, _pct(ents["recall"]), _pct(ents["precision"]), _pct(rels["recall"]), _pct(rels["precision"]),
            f"{ents['predicted']}/{rels['predicted']}", str(halluc), anchored, f"{run.get('seconds', '—')} s" if run else "—",
        )  # fmt: skip

    for s in scores:
        d = s.as_dict()
        row(str(s.article_id), d["entities"], d["relations"], len(s.hallucinations), s.grounding, runs.get(s.article_id))
    seconds = sum(r["seconds"] for r in runs.values()) if runs else None
    row("TOTAL", summary["entities"], summary["relations"], summary["hallucinations"], summary["grounding"], {"seconds": round(seconds, 1)} if runs else None)
    console.print(table)
    if wall is not None:
        console.print(f"Durée réelle de l'extraction : {wall:.1f} s (somme des durées par article : {seconds:.1f} s)")


def losses_report(losses: dict[int, dict]) -> list[str]:
    """Section « Pertes par étape » : où se perdent les éléments required manqués (articles extraits avec la trace)."""
    counts = tally(list(losses.values()))
    lines = ["", f"## Pertes par étape ({len(losses)} articles avec trace)", "", "| Étape | Techniques | Autres entités |", "|---|---|---|"]
    lines += [f"| {s} | {counts['techniques'][s]} | {counts['entities'][s]} |" for s in ENTITY_STAGES if s not in TECHNIQUE_STAGES or counts["techniques"][s]]
    lines += ["", "| Étape | Relations |", "|---|---|", *[f"| {s} | {counts['relations'][s]} |" for s in RELATION_STAGES]]
    for aid, d in losses.items():
        lines += ["", f"### Article {aid}", ""]
        lines += [f"- {e['stage']} : {e['gold']}" + (f" — {e['detail']}" if e["detail"] else "") for e in d["entities"]]
        lines += [f"- {r['stage']} : {r['gold']}" + (f" — {r['detail']}" if r["detail"] else "") for r in d["relations"]]
    return lines


def checks_report(summary: dict) -> list[str]:
    """Scores strict et relâché, vérificateur, rappel de la recherche, compteurs de mécanisme."""
    lines = ["", "## Variantes du score (total)", "", "| Score | Rappel | Précision |", "|---|---|---|"]
    for key, label in (("entities_strict", "Entités, sans crédit partiel"), ("relations_strict", "Relations, sans crédit partiel"),
                       ("relations_relaxed", "Relations, source « uses » dans le groupe d'activité")):  # fmt: skip
        if key in summary:
            lines.append(f"| {label} | {_pct(summary[key]['recall'])} | {_pct(summary[key]['precision'])} |")
    lines += ["", "## Compteurs de mécanisme", "", *[f"- {k} : {v}" for k, v in mechanism(summary).items()]]
    losses = summary.get("losses")
    if losses:
        v, r = losses["verifier"], losses["retrieval"]
        lines += ["", "## Vérificateur et recherche des techniques", "",
                  f"- Relations retirées par le vérificateur : {sum(v.values())} (required {v['required']}, acceptable {v['acceptable']}, absentes du gold {v['absente du gold']})"]  # fmt: skip
        if r["covered"]:
            lines.append(f"- Rappel de la recherche : sur {r['covered']} techniques required dont une phrase est citée par un comportement, "
                         f"{r['exact']} proposées ({_pct(r['exact'] / r['covered'])}), {r['family']} de la bonne famille ({_pct(r['family'] / r['covered'])})")  # fmt: skip
    return lines


def mechanism(summary: dict) -> dict[str, float]:
    """Compteurs moins bruités que le rappel global, qui disent si une modification agit par le mécanisme visé."""
    pat = summary.get("relations_by_pattern", {})
    out = {
        "intrusion-set uses attack-pattern prédites": pat.get("intrusion-set uses attack-pattern", {}).get("predicted", 0),
        "campagnes prédites": summary.get("entities_by_type", {}).get("campaign", {}).get("predicted", 0),
        "campagnes trouvées (required)": summary.get("entities_by_type", {}).get("campaign", {}).get("found_required", 0),
    }
    if "losses" in summary:
        out["relations perdues « autre source »"] = summary["losses"]["relations"]["autre source"]
        out["relations perdues « extrémité manquante »"] = summary["losses"]["relations"]["extrémité manquante"]
    return out


def markdown_report(system: str, scores: list[ArticleScore], summary: dict, runs: dict, wall: float | None = None, losses: dict | None = None) -> str:
    lines = [f"# Évaluation `{system}` contre le gold (ATT&CK v20.0)", ""]
    if wall is not None:
        lines += [f"Durée réelle de l'extraction : **{wall:.1f} s** pour {len(runs)} articles (somme des durées par article : {sum(r['seconds'] for r in runs.values()):.1f} s).", ""]
    lines += ["| Article | Entités rappel | Entités précision | Relations rappel | Relations précision | Hallucinations | Durée |", "|---|---|---|---|---|---|---|"]
    for s in scores:
        d = s.as_dict()
        run = runs.get(s.article_id, {})
        lines.append(
            f"| {s.article_id} | {_pct(d['entities']['recall'])} | {_pct(d['entities']['precision'])} | {_pct(d['relations']['recall'])} | "
            f"{_pct(d['relations']['precision'])} | {len(s.hallucinations)} | {run.get('seconds', '—')} s |"
        )
    e, r = summary["entities"], summary["relations"]
    lines.append(f"| **Total** | **{_pct(e['recall'])}** | **{_pct(e['precision'])}** | **{_pct(r['recall'])}** | **{_pct(r['precision'])}** | {summary['hallucinations']} | |")
    lines += ["", "## Entités par type (total)", "", "| Type | Required | Trouvés | Rappel | Prédits | Précision |", "|---|---|---|---|---|---|"]
    for t, c in summary["entities_by_type"].items():
        lines.append(f"| {t} | {c['gold_required']} | {c['found_required']:g} | {_pct(c['recall'])} | {c['predicted']} | {_pct(c['precision'])} |")
    lines += ["", "## Relations par motif (total)", "", "| Motif | Required | Trouvées | Rappel | Prédites | Précision |", "|---|---|---|---|---|---|"]
    for t, c in summary["relations_by_pattern"].items():
        lines.append(f"| {t} | {c['gold_required']} | {c['found_required']:g} | {_pct(c['recall'])} | {c['predicted']} | {_pct(c['precision'])} |")
    lines += checks_report(summary)
    if losses:
        lines += losses_report(losses)
    for s in scores:
        lines += ["", f"## Article {s.article_id}", ""]
        if s.hallucinations:
            lines += [f"**Hallucinations :** {', '.join(s.hallucinations)}", ""]
        lines += ["**Entités manquées :**", *([f"- {x}" for x in s.missed_entities] or ["- aucune"]), ""]
        lines += ["**Relations manquées :**", *([f"- {x}" for x in s.missed_relations] or ["- aucune"]), ""]
        lines += ["**Entités prédites absentes du gold (à revoir) :**", *([f"- {x}" for x in s.review_entities] or ["- aucune"]), ""]
        lines += ["**Relations prédites absentes du gold (à revoir) :**", *([f"- {x['relation']} — « {x['quote'][:140]} »" for x in s.review_relations] or ["- aucune"])]
    return "\n".join(lines) + "\n"


# --- Comparaison de configurations --------------------------------------------------------------------------------------
_METRICS = (("entities", "Entités"), ("relations", "Relations"), ("relations_relaxed", "Relations relâchées"), ("relations_strict", "Relations strictes"))


def _per_article(dirs: list[Path]) -> dict[int, dict[str, dict[str, float]]]:
    """Comptes moyens par article sur les exécutions d'une configuration : {article: {score: {comptes}}}."""
    reports = [json.loads((d / "report.json").read_text(encoding="utf-8")) for d in dirs]
    out: dict[int, dict] = {}
    for rep in reports:
        for a in rep["articles"]:
            for key, _ in _METRICS:
                if key not in a:
                    raise SystemExit(f"{rep['system']} : pas de score « {key} », re-scorer avec cti-eval --bundles <dossier>")
                acc = out.setdefault(a["article_id"], {}).setdefault(key, {"gold_required": 0.0, "found_required": 0.0, "found": 0.0, "predicted": 0.0})
                c = a[key]
                for k, v in (("gold_required", c["gold_required"]), ("found_required", c["found_required"]),
                             ("found", c["found_required"] + c["found_acceptable"]), ("predicted", c["predicted"])):  # fmt: skip
                    acc[k] += v / len(reports)
            mech = out[a["article_id"]].setdefault("mechanism", {})
            for k, v in mechanism({"relations_by_pattern": a["relations_by_pattern"], "entities_by_type": a["entities_by_type"],
                                   **({"losses": tally([a["losses"]])} if "losses" in a else {})}).items():  # fmt: skip
                mech[k] = mech.get(k, 0) + v / len(reports)
    return out


def _micro(data: dict, ids: list[int], key: str) -> tuple[float, float]:
    tot = {k: sum(data[i][key][k] for i in ids) for k in ("gold_required", "found_required", "found", "predicted")}
    return (tot["found_required"] / tot["gold_required"] if tot["gold_required"] else 0.0, tot["found"] / tot["predicted"] if tot["predicted"] else 0.0)


def compare(groups: list[list[Path]], samples: int = 4000, seed: int = 0) -> str:
    """Rapport Markdown : chaque configuration contre la première (voir l'en-tête du module)."""
    data = [_per_article(g) for g in groups]
    ids = sorted(set.intersection(*(set(d) for d in data)))
    names = [" + ".join(p.name for p in g) for g in groups]
    rng = random.Random(seed)
    draws = [[rng.choice(ids) for _ in ids] for _ in range(samples)]
    lines = [f"# Comparaison ({len(ids)} articles communs)", "", *[f"- **{chr(65 + i)}** : {n}" for i, n in enumerate(names)], ""]
    lines += ["| Score | " + " | ".join(chr(65 + i) for i in range(len(groups))) + " | " + " | ".join(f"{chr(65 + i)} − A (IC 95 %)" for i in range(1, len(groups))) + " |",
              "|---" * (2 * len(groups)) + "|"]  # fmt: skip
    for key, label in _METRICS:
        for j, part in enumerate(("rappel", "précision")):
            values = [_micro(d, ids, key)[j] for d in data]
            cells = []
            for d in data[1:]:
                diffs = sorted(_micro(d, s, key)[j] - _micro(data[0], s, key)[j] for s in draws)
                lo, hi = diffs[int(0.025 * samples)], diffs[int(0.975 * samples) - 1]
                mark = " ✔" if lo > 0 or hi < 0 else ""
                cells.append(f"{100 * (_micro(d, ids, key)[j] - values[0]):+.1f} [{100 * lo:+.1f} ; {100 * hi:+.1f}]{mark}")
            lines.append(f"| {label} {part} | " + " | ".join(f"{100 * v:.1f} %" for v in values) + " | " + " | ".join(cells) + " |")
    lines += ["", "✔ : l'intervalle exclut 0.", "", "## Compteurs de mécanisme (moyenne par exécution)", "",
              "| Compteur | " + " | ".join(chr(65 + i) for i in range(len(groups))) + " |", "|---" * (len(groups) + 1) + "|"]  # fmt: skip
    for k in data[0][ids[0]]["mechanism"]:
        lines.append(f"| {k} | " + " | ".join(f"{sum(d[i]['mechanism'].get(k, 0) for i in ids):.1f}" for d in data) + " |")
    lines += ["", "## Relations par article (rappel / précision)", "", "| Article | " + " | ".join(chr(65 + i) for i in range(len(groups))) + " |",
              "|---" * (len(groups) + 1) + "|"]  # fmt: skip
    for i in ids:
        lines.append(f"| {i} | " + " | ".join("{:.0f} / {:.0f}".format(*(100 * x for x in _micro(d, [i], "relations"))) for d in data) + " |")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Évaluation de l'extraction contre les articles annotés")
    parser.add_argument("--run", action="store_true", help="Extrait d'abord les articles annotés (appels au modèle)")
    parser.add_argument("--bundles", type=Path, default=EVAL_DIR / "latest", help="Dossier des bundles prédits (défaut : backend/evaluation/eval/latest)")
    parser.add_argument("--article-id", type=int, action="append", help="Limiter à ces articles (option répétable)")
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--workers", type=int, default=1, help="Articles extraits en même temps")
    parser.add_argument("--compare", nargs="+", metavar="DOSSIERS", help="Configurations à comparer, chacune « dossier1,dossier2 » (la première est la référence)")
    args = parser.parse_args()
    if args.compare:
        groups = [[Path(p) if Path(p).is_absolute() or Path(p).exists() else EVAL_DIR / p for p in g.split(",")] for g in args.compare]
        report = compare(groups)
        console.print(report, markup=False, highlight=False)
        return

    out_dir = args.bundles
    entries = [a for a in load_manifest(args.manifest) if not args.article_id or a["article_id"] in args.article_id]
    runs_file = out_dir / "runs.json"
    runs: dict[int, dict] = {int(k): v for k, v in json.loads(runs_file.read_text()).items()} if runs_file.exists() else {}
    arts = {e["article_id"]: fetch_article(e["article_id"]) for e in entries}
    wall = None
    if args.run:
        for art in arts.values():
            console.print(f"[bold]Extraction[/] article {art['id']} — {art['title']}")
        wall = run_all(list(arts.values()), out_dir, args.workers, runs)
    scores, losses = [], {}
    for entry in entries:
        art = arts[entry["article_id"]]
        pred_path = out_dir / f"article_{art['id']}.json"
        if not pred_path.exists():
            console.print(f"[yellow]Pas de bundle pour l'article {art['id']} ({pred_path}) : lancer avec --run[/]")
            continue
        gold = json.loads(entry["gold_path"].read_text(encoding="utf-8"))
        pred = json.loads(pred_path.read_text(encoding="utf-8"))
        scores.append(score_article(art["id"], gold, pred, art["clean_markdown"]))
        if "trace" in runs.get(art["id"], {}):  # exécutions antérieures à la trace : pas de pertes par étape
            losses[art["id"]] = diagnose(gold, pred, runs[art["id"]]["trace"], source_text=art["clean_markdown"])
    if not scores:
        return
    summary = total(scores)
    runs = {k: v for k, v in runs.items() if k in {s.article_id for s in scores}}
    print_scores(scores, summary, runs, wall)
    if losses:
        summary["losses"] = tally(list(losses.values()))
    articles = [{**s.as_dict(), **({"losses": losses[s.article_id]} if s.article_id in losses else {})} for s in scores]
    report = {"system": out_dir.name, "summary": summary, "runs": runs, "wall_seconds": wall, "articles": articles}
    (out_dir / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    (out_dir / "report.md").write_text(markdown_report(out_dir.name, scores, summary, runs, wall, losses), encoding="utf-8")
    console.print(f"Rapport : {out_dir / 'report.md'}")


if __name__ == "__main__":
    main()
