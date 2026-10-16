"""CLI d'extraction du Knowledge Graph STIX 2.1 : articles classifiés -> objets STIX validés -> Neo4j.

    uv run cti-extractor --limit 10                 # les 10 prochains articles non extraits
    uv run cti-extractor --article-id 686 --show-triples
    uv run cti-extractor --article-id 686 --dry-run --out /tmp/bundles   # sans écrire dans Neo4j, bundle STIX en fichier
    uv run cti-extractor --stats

Pourquoi `--workers` vaut 1 par défaut : le serveur Ollama de ce projet traite les requêtes l'une après l'autre
(mesuré : 1, 2, 3 et 4 requêtes simultanées prennent respectivement 5, 10, 15 et 21 secondes, soit un débit global
constant). Lancer plusieurs appels en parallèle n'accélère rien ; le gain vient du nombre de tokens générés.
"""

import argparse
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

root_dir = Path(__file__).resolve().parents[2]
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from backend.database.stix_store import StixStore  # noqa: E402
from backend.extracting import llm  # noqa: E402
from backend.extracting.pipeline import ArticleExtraction, extract_article  # noqa: E402
from backend.ontology.stix import build_stix_objects, to_bundle  # noqa: E402

os.environ["NO_PROXY"] = "localhost,127.0.0.1"

SOURCE_ARTICLES_DB = root_dir / "db_outputs" / "cti_knowledge.db"  # lecture seule : le graphe vit dans Neo4j
CATEGORIES = ("operational", "tactical", "strategic")

console = Console()


def fetch_articles(limit: int, article_id: int | None, skip_ids: set[int]) -> list[dict]:
    """Articles classifiés, dans l'ordre des identifiants, sans ceux déjà extraits. Lecture seule."""
    query = """
        SELECT k.id, k.title, k.url, k.site_name, k.publication_date, c.primary_category, c.clean_markdown
        FROM knowledge k JOIN article_classifications c ON c.knowledge_id = k.id
        WHERE c.is_processable = 1 AND c.primary_category IN ({cats}) AND c.clean_markdown IS NOT NULL AND c.clean_markdown != ''
    """.format(cats=",".join("?" * len(CATEGORIES)))
    params: list = list(CATEGORIES)
    if article_id is not None:
        query += " AND k.id = ?"
        params.append(article_id)
    query += " ORDER BY k.id ASC"
    with sqlite3.connect(f"file:{SOURCE_ARTICLES_DB}?mode=ro", uri=True, timeout=30.0) as conn:
        conn.row_factory = sqlite3.Row
        rows = [dict(r) for r in conn.execute(query, params)]
    rows = [r for r in rows if r["id"] not in skip_ids]
    return rows[:limit]


def process_article(art: dict, store: StixStore | None, *, verify: bool, out_dir: Path | None) -> tuple[ArticleExtraction, dict]:
    t0 = time.perf_counter()
    result = extract_article(
        art["id"], art["title"] or f"Article {art['id']}", art["primary_category"], art["clean_markdown"], art["site_name"], verify=verify
    )
    meta = {
        "source_id": art["id"], "title": art["title"], "url": art["url"], "site_name": art["site_name"],
        "published": art["publication_date"], "category": art["primary_category"],
    }  # fmt: skip
    objects = build_stix_objects(result.graph, meta)
    bundle = to_bundle(objects)  # lève une exception si un objet n'est pas du STIX 2.1 valide
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"article_{art['id']}.json").write_text(bundle, encoding="utf-8")
    if store is not None:
        store.purge_article(art["id"])  # ré-extraction : retire l'ancienne contribution avant d'écrire la nouvelle
        store.save_article(
            objects, art["id"],
            {"title": art["title"], "url": art["url"], "site_name": art["site_name"], "category": art["primary_category"],
             "model": llm.MODEL_NAME, "extraction_seconds": round(time.perf_counter() - t0, 1), "extracted_at": time.strftime("%Y-%m-%dT%H:%M:%S")},
        )  # fmt: skip
    return result, meta


def print_triples(result: ArticleExtraction, limit: int = 40) -> None:
    names = {e["id"]: e["name"] for e in result.graph.entities}
    table = Table(title=f"Relations extraites (article {result.article_id}, profil {result.profile})", header_style="bold magenta", border_style="dim")
    for col, style in (("Source", "bold cyan"), ("Relation", "bold yellow"), ("Cible", "bold green"), ("Preuve (phrase du texte)", "dim white")):
        table.add_column(col, style=style, overflow="fold")
    for r in result.graph.relationships[:limit]:
        table.add_row(names[r["source_ref"]], r["relationship_type"], names[r["target_ref"]], r["_evidence"][0]["quote"][:140])
    console.print(table)


def print_stats() -> None:
    store = StixStore()
    ok, err = store._store.check_connection()
    if not ok:
        console.print(f"[bold red]Neo4j non joignable ({err})[/]")
        return
    stats = store.stats()
    table = Table(title=f"Knowledge Graph STIX : {stats['articles']} article(s)", header_style="bold magenta", border_style="dim")
    table.add_column("Nœuds (type STIX)")
    table.add_column("Effectif", justify="right")
    table.add_column("Relations")
    table.add_column("Effectif ", justify="right")
    nodes, edges = list(stats["nodes"].items()), list(stats["edges"].items())
    for i in range(max(len(nodes), len(edges))):
        n = nodes[i] if i < len(nodes) else ("", "")
        e = edges[i] if i < len(edges) else ("", "")
        table.add_row(n[0], str(n[1]), e[0], str(e[1]))
    console.print(table)


def main() -> None:
    parser = argparse.ArgumentParser(description="Extraction du Knowledge Graph STIX 2.1 depuis les articles classifiés")
    parser.add_argument("--article-id", type=int, help="Traiter un article précis (ré-extrait même s'il existe déjà)")
    parser.add_argument("--limit", type=int, default=10, help="Nombre maximal d'articles")
    parser.add_argument("--force", action="store_true", help="Ré-extraire aussi les articles déjà dans Neo4j")
    parser.add_argument("--no-verify", action="store_true", help="Sans passes de vérification (plus rapide, moins fiable)")
    parser.add_argument("--dry-run", action="store_true", help="N'écrit rien dans Neo4j")
    parser.add_argument("--out", type=Path, help="Écrit le bundle STIX 2.1 de chaque article dans ce dossier")
    parser.add_argument("--show-triples", action="store_true", help="Affiche les relations et leur phrase de preuve")
    parser.add_argument("--show-issues", action="store_true", help="Affiche les corrections et rejets de l'ontologie")
    parser.add_argument("--stats", action="store_true", help="Statistiques du graphe STIX dans Neo4j")
    parser.add_argument("--model", default=llm.MODEL_NAME)
    args = parser.parse_args()

    if args.stats:
        print_stats()
        return
    llm.MODEL_NAME = args.model

    store: StixStore | None = None
    skip: set[int] = set()
    if not args.dry_run:
        store = StixStore()
        ok, err = store._store.check_connection()
        if not ok:
            console.print(Panel(f"[bold red]Neo4j non joignable.[/]\n{err}\nLancez le conteneur ou utilisez --dry-run.", border_style="red"))
            return
        store.init_schema()
        if not (args.force or args.article_id is not None):
            skip = store.extracted_article_ids()

    articles = fetch_articles(args.limit, args.article_id, skip)
    if not articles:
        console.print("[yellow]Aucun article classifié en attente d'extraction.[/]")
        return
    console.print(
        Panel(
            f"[bold cyan]Extraction STIX 2.1[/]  │  modèle [yellow]{args.model}[/]  │  articles [magenta]{len(articles)}[/]  │  "
            f"vérification [green]{'non' if args.no_verify else 'oui'}[/]  │  {'sans écriture' if args.dry_run else 'Neo4j'}",
            border_style="cyan",
        )
    )

    total_s, total_tok = 0.0, 0
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), MofNCompleteColumn(), TimeElapsedColumn(), console=console) as progress:
        task = progress.add_task("Extraction", total=len(articles))
        for art in articles:
            progress.update(task, description=f"[cyan]Article {art['id']}[/] [dim]{(art['title'] or '')[:40]}[/]")
            t0 = time.perf_counter()
            try:
                result, _ = process_article(art, store, verify=not args.no_verify, out_dir=args.out)
            except Exception as exc:  # noqa: BLE001 : un article en échec ne doit pas arrêter le lot
                progress.console.print(f"  [bold red]✗[/] Article {art['id']:4d} : {type(exc).__name__}: {exc}")
                progress.advance(task)
                continue
            dt = time.perf_counter() - t0
            total_s += dt
            total_tok += result.output_tokens
            g = result.graph
            trunc = [f"{c.stage}#{c.pass_index}" for c in result.calls if c.truncated]
            progress.console.print(
                f"  [bold green]✓[/] Article {art['id']:4d} [dim][{art['primary_category'][:4]}][/] {dt:5.1f}s │ "
                f"[cyan]{len(g.entities)} entités[/] [yellow]{len(g.relationships)} relations[/] │ "
                f"candidats {result.n_candidates} → {result.n_proposed} → {result.n_verified} vérifiés │ {result.output_tokens} tokens générés"
                + (f" │ [red]tronqué : {', '.join(trunc)}[/]" if trunc else "")
            )
            if args.show_triples:
                print_triples(result)
            if args.show_issues:
                for issue in g.issues:
                    progress.console.print(f"      [dim]{issue}[/]")
            if args.out and args.article_id is not None:
                progress.console.print(f"  bundle : {args.out / f'article_{art['id']}.json'}")
            progress.advance(task)
    console.print(f"\n[bold green]Terminé[/] : {len(articles)} article(s) en {total_s:.0f}s ({total_s / len(articles):.1f}s/article, {total_tok} tokens générés).")
    if not args.dry_run:
        print_stats()


if __name__ == "__main__":
    main()
