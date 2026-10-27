"""Évaluation de l'extraction contre les articles annotés à la main (Annotations/manifest.json).

    uv run cti-eval --run                          # extrait les articles annotés avec l'agent, puis score
    uv run cti-eval --system fast --run            # même chose avec l'extraction rapide (fast_extract), dans db_outputs/eval/fast
    uv run cti-eval --bundles db_outputs/eval/agent   # score des bundles déjà produits, sans appel au modèle

Avec un serveur SGLang/vLLM (CTI_LLM_BACKEND=openai, tunnel vers CTI_OPENAI_URL) les articles s'extraient en parallèle :
    CTI_LLM_BACKEND=openai uv run cti-eval --system fast --run --workers 4 --bundles db_outputs/eval/fast_sglang

Chaque exécution écrit dans le dossier des bundles : `report.json` (scores, manques, prédictions à revoir) et `report.md`.
La méthode de score est celle de `score.py` (rappel principal, précision, crédit partiel, hallucinations, ancrage).
"""

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from rich.console import Console
from rich.table import Table

root_dir = Path(__file__).resolve().parents[2]
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from backend.config import SOURCE_ARTICLES_DB  # noqa: E402
from backend.evaluation.score import ArticleScore, score_article, total  # noqa: E402

MANIFEST = root_dir / "Annotations" / "manifest.json"
EVAL_DIR = root_dir / "db_outputs" / "eval"

console = Console()


def load_manifest(path: Path = MANIFEST) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [{**a, "gold_path": path.parent / a["gold"]} for a in data["articles"]]


def fetch_article(article_id: int) -> dict:
    """Article et classification, sans les filtres d'éligibilité de l'extraction (le gold peut porter sur tout article)."""
    from backend.extracting.stix_agent import read_articles

    rows = read_articles("k.id = ?", [article_id])
    if not rows:
        raise LookupError(f"article {article_id} absent de {SOURCE_ARTICLES_DB}")
    return rows[0]


def run_agent(art: dict, out_dir: Path, system: str = "agent") -> dict:
    """Extrait un article (agent ou extraction rapide), sans Neo4j ; le bundle est écrit dans `out_dir/article_<id>.json`."""
    from backend.extracting.stix_agent import process_article

    t0 = time.perf_counter()
    result = process_article(art, out_dir=out_dir, fast=system == "fast", closed=system == "closed")
    return {
        "seconds": round(time.perf_counter() - t0, 1), "output_tokens": result.output_tokens, "llm_calls": len(result.turns),
        "failed_passages": result.failed_passages,
    }  # fmt: skip


def run_all(arts: list[dict], out_dir: Path, system: str, workers: int, runs: dict) -> float:
    """Extrait les articles, `workers` à la fois (le serveur groupe leurs requêtes ; Ollama, lui, les traite l'une après l'autre).
    Un article échoué est signalé et laissé sans bundle. Retourne la durée totale, celle que voit l'utilisateur."""
    out_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(run_agent, art, out_dir, system): art for art in arts}
        for future in as_completed(futures):
            art = futures[future]
            try:
                runs[art["id"]] = future.result()
            except Exception as exc:  # noqa: BLE001 : un article perdu n'arrête pas les autres
                console.print(f"[red]Échec[/] article {art['id']} : {type(exc).__name__}: {exc}")
                continue
            console.print(f"[bold]Extrait[/] article {art['id']} — {art['title']} ({runs[art['id']]['seconds']} s)")
            (out_dir / "runs.json").write_text(json.dumps(runs, indent=1), encoding="utf-8")
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


def markdown_report(system: str, scores: list[ArticleScore], summary: dict, runs: dict, wall: float | None = None) -> str:
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
    for s in scores:
        lines += ["", f"## Article {s.article_id}", ""]
        if s.hallucinations:
            lines += [f"**Hallucinations :** {', '.join(s.hallucinations)}", ""]
        lines += ["**Entités manquées :**", *([f"- {x}" for x in s.missed_entities] or ["- aucune"]), ""]
        lines += ["**Relations manquées :**", *([f"- {x}" for x in s.missed_relations] or ["- aucune"]), ""]
        lines += ["**Entités prédites absentes du gold (à revoir) :**", *([f"- {x}" for x in s.review_entities] or ["- aucune"]), ""]
        lines += ["**Relations prédites absentes du gold (à revoir) :**", *([f"- {x['relation']} — « {x['quote'][:140]} »" for x in s.review_relations] or ["- aucune"])]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Évaluation de l'extraction contre les articles annotés")
    parser.add_argument("--run", action="store_true", help="Extrait d'abord les articles annotés (appels au modèle)")
    parser.add_argument("--system", choices=("agent", "fast", "closed"), default="agent", help="Extracteur lancé par --run")
    parser.add_argument("--bundles", type=Path, help="Dossier des bundles prédits (défaut : db_outputs/eval/<système>)")
    parser.add_argument("--article-id", type=int, action="append", help="Limiter à ces articles (option répétable)")
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--workers", type=int, default=1, help="Articles extraits en même temps (utile avec CTI_LLM_BACKEND=openai ; Ollama traite une requête à la fois)")
    args = parser.parse_args()

    out_dir = args.bundles or EVAL_DIR / args.system
    entries = [a for a in load_manifest(args.manifest) if not args.article_id or a["article_id"] in args.article_id]
    runs_file = out_dir / "runs.json"
    runs: dict[int, dict] = {int(k): v for k, v in json.loads(runs_file.read_text()).items()} if runs_file.exists() else {}
    arts = {e["article_id"]: fetch_article(e["article_id"]) for e in entries}
    wall = None
    if args.run:
        for art in arts.values():
            console.print(f"[bold]Extraction[/] article {art['id']} — {art['title']}")
        wall = run_all(list(arts.values()), out_dir, args.system, args.workers, runs)
    scores = []
    for entry in entries:
        art = arts[entry["article_id"]]
        pred_path = out_dir / f"article_{art['id']}.json"
        if not pred_path.exists():
            console.print(f"[yellow]Pas de bundle pour l'article {art['id']} ({pred_path}) : lancer avec --run[/]")
            continue
        gold = json.loads(entry["gold_path"].read_text(encoding="utf-8"))
        pred = json.loads(pred_path.read_text(encoding="utf-8"))
        scores.append(score_article(art["id"], gold, pred, art["clean_markdown"]))
    if not scores:
        return
    summary = total(scores)
    runs = {k: v for k, v in runs.items() if k in {s.article_id for s in scores}}
    print_scores(scores, summary, runs, wall)
    report = {"system": out_dir.name, "summary": summary, "runs": runs, "wall_seconds": wall, "articles": [s.as_dict() for s in scores]}
    (out_dir / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    (out_dir / "report.md").write_text(markdown_report(out_dir.name, scores, summary, runs, wall), encoding="utf-8")
    console.print(f"Rapport : {out_dir / 'report.md'}")


if __name__ == "__main__":
    main()
