"""Extraction du Knowledge Graph : articles classifiés -> bundle STIX 2.1 (bibliothèque `stix2`) -> Neo4j.

    uv run cti-extract --limit 10                          # les 10 prochains articles non extraits, vers Neo4j
    uv run cti-extract --limit 20 --workers 2              # deux articles à la fois
    uv run cti-extract --article-id 1553 --dry-run         # sans écrire dans Neo4j
    uv run cti-extract --article-id 1553 --dry-run --show-log   # chaque refus de la vérification et chaque appel d'outil
    uv run cti-extract --stats

Chaque article passe par `pipeline.extract_article` (lot : `runner.run_batch`) ; le `stix2.Bundle` est écrit dans
backend/data/bundles/article_<id>.json (même en --dry-run), puis enregistré dans Neo4j sans les IOC jugés bénins. Un article
dont une étape LLM a échoué est enregistré tel quel et repris au lancement suivant.

Code de sortie : 0 (articles partiels compris), 1 si un article a échoué, 2 si Neo4j est injoignable, 130 si interrompu.
"""

import argparse
import sqlite3
import sys
import time
from pathlib import Path

root_dir = Path(__file__).resolve().parents[2]
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from rich.console import Console  # noqa: E402
from rich.markup import escape  # noqa: E402
from rich.table import Table  # noqa: E402

from backend.config import BUNDLES_DIR, SOURCE_ARTICLES_DB  # noqa: E402
from backend.extracting.runner import Outcome, run_batch  # noqa: E402

CATEGORIES = ("operational", "tactical", "strategic")

console = Console()


def read_articles(where: str, params: list) -> list[dict]:
    """Articles joints à leur classification, en lecture seule (le graphe vit dans Neo4j) : `where` filtre la jointure."""
    query = f"""
        SELECT k.id, k.title, k.url, k.site_name, k.publication_date, c.primary_category, c.clean_markdown
        FROM knowledge k JOIN article_classifications c ON c.knowledge_id = k.id WHERE {where}
    """
    with sqlite3.connect(f"file:{SOURCE_ARTICLES_DB}?mode=ro", uri=True, timeout=30.0) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute(query, params)]


def _marks(values) -> str:
    return ",".join("?" * len(values))


def fetch_articles(limit: int, article_ids: list[int] | None, skip_ids: set[int]) -> list[dict]:
    """Articles classifiés, dans l'ordre des identifiants, sans ceux déjà extraits."""
    where = f"c.is_processable = 1 AND c.primary_category IN ({_marks(CATEGORIES)}) AND c.clean_markdown IS NOT NULL AND c.clean_markdown != ''"
    params: list = list(CATEGORIES)
    if article_ids:
        where += f" AND k.id IN ({_marks(article_ids)})"
        params += article_ids
    if skip_ids:
        where += f" AND k.id NOT IN ({_marks(skip_ids)})"
        params += sorted(skip_ids)
    return read_articles(f"{where} ORDER BY k.id ASC LIMIT ?", [*params, limit])


def summary_line(out: Outcome) -> str:
    if out.error and out.result is None:
        return f"[red]Échec[/] article {out.art['id']} {out.seconds:.0f}s │ {escape(out.error)}"
    result = out.result
    failed = f" │ {len(result.failures)} étape(s) en échec" if result.failures else ""
    iocs = len(result.iocs.findings) - result.iocs.n_not_malicious
    return (
        f"Article {result.article_id} {result.seconds:.0f}s │ {len(result.draft.linked())} entités {len(result.draft.evidence)} relations "
        f"{iocs} IOC (+{result.iocs.n_not_malicious} bénins) {len(result.rules.rules)} règles │ {len(result.calls)} appels, "
        f"{result.output_tokens} tokens générés │ lignes acceptées {result.accepted}, refusées {result.refused}{failed}"
    )


def run_summary(outcomes: list[Outcome], wall: float, planned: int) -> str:
    """Bilan du lot : effectifs par statut, durée, tokens générés, articles à revoir."""
    by = {s: [o.art["id"] for o in outcomes if o.status == s] for s in ("ok", "partial", "failed")}
    tokens = sum(o.result.output_tokens for o in outcomes if o.result is not None)
    line = f"{len(by['ok'])} ok, {len(by['partial'])} partiel(s), {len(by['failed'])} en échec"
    if len(outcomes) < planned:
        line += f", {planned - len(outcomes)} non traité(s)"
    line += f" │ {wall:.0f}s │ {tokens} tokens générés"
    if by["partial"]:
        line += f"\n  partiels (repris au prochain lancement) : {', '.join(map(str, by['partial']))}"
    if by["failed"]:
        line += f"\n  en échec : {', '.join(map(str, by['failed']))}"
    return line


def print_stats() -> int:
    from backend.database.stix_store import StixStore

    store = StixStore()
    ok, err = store._store.check_connection()
    if not ok:
        console.print(f"[bold red]Neo4j non joignable ({err})[/]")
        return 2
    stats = store.stats()
    table = Table(title=f"Knowledge Graph STIX : {stats['articles']} article(s)", header_style="bold magenta", border_style="dim")
    for col in ("Nœuds (type STIX)", "Effectif", "Relations", "Effectif "):
        table.add_column(col)
    nodes, edges = list(stats["nodes"].items()), list(stats["edges"].items())
    for i in range(max(len(nodes), len(edges))):
        n = nodes[i] if i < len(nodes) else ("", "")
        e = edges[i] if i < len(edges) else ("", "")
        table.add_row(n[0], str(n[1]), e[0], str(e[1]))
    console.print(table)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Extraction STIX 2.1 (stix2) des articles classifiés, vérifiée contre ATT&CK v20.0")
    parser.add_argument("--article-id", type=int, action="append", help="Article à extraire (option répétable ; ré-extrait même s'il existe)")
    parser.add_argument("--limit", type=int, default=10, help="Nombre maximal d'articles")
    parser.add_argument("--workers", type=int, default=1, help="Articles extraits en même temps (Neo4j reste écrit par un seul fil)")
    parser.add_argument("--force", action="store_true", help="Ré-extraire aussi les articles déjà dans Neo4j")
    parser.add_argument("--dry-run", action="store_true", help="N'écrit rien dans Neo4j")
    parser.add_argument("--out", type=Path, default=BUNDLES_DIR, help=f"Dossier des bundles STIX 2.1 (défaut : {BUNDLES_DIR})")
    parser.add_argument("--show-log", action="store_true", help="Affiche les refus de la vérification et les appels d'outils")
    parser.add_argument("--stats", action="store_true", help="Statistiques du graphe STIX dans Neo4j")
    args = parser.parse_args()
    if args.stats:
        return print_stats()
    store, skip = None, set()
    if not args.dry_run:
        from backend.database.stix_store import StixStore

        store = StixStore()
        ok, err = store._store.check_connection()
        if not ok:
            console.print(f"[bold red]Neo4j non joignable ({err}) : relancer avec --dry-run pour n'écrire que les bundles[/]")
            return 2
        store.init_schema()
        skip = set() if args.force or args.article_id else store.extracted_article_ids()
    articles = fetch_articles(len(args.article_id) if args.article_id else args.limit, args.article_id, skip)
    outcomes: list[Outcome] = []
    t0 = time.perf_counter()
    try:
        for out in run_batch(articles, args.out, args.workers, store):
            outcomes.append(out)
            console.print(summary_line(out))
            if out.error and out.result is not None:  # extrait, mais Neo4j a refusé l'écriture
                console.print(f"  [red]{escape(out.error)}[/]")
            if out.trace:
                console.print(out.trace, style="dim", markup=False, highlight=False)
            for f in out.result.failures if out.result else ():
                console.print(f"  [red]{f}[/]")
            if args.show_log and out.result:
                for line in out.result.draft.log:
                    console.print(f"  [dim]{line}[/]")
            if out.result:
                console.print(f"  bundle : {args.out / f'article_{out.art['id']}.json'}")
    except KeyboardInterrupt:
        console.print("[yellow]Interrompu : les articles en cours finissent leur bundle, rien de plus n'est écrit dans Neo4j[/]")
        console.print(run_summary(outcomes, time.perf_counter() - t0, len(articles)))
        return 130
    if articles:
        console.print(run_summary(outcomes, time.perf_counter() - t0, len(articles)))
    return 1 if any(o.status == "failed" for o in outcomes) else 0


if __name__ == "__main__":
    sys.exit(main())
