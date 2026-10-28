"""Extraction du Knowledge Graph : articles classifiés -> bundle STIX 2.1 (bibliothèque `stix2`) -> Neo4j.

    uv run cti-extract --limit 10                          # les 10 prochains articles non extraits, vers Neo4j
    uv run cti-extract --article-id 1553 --dry-run         # sans écrire dans Neo4j
    uv run cti-extract --article-id 1553 --dry-run --show-log   # chaque refus de la vérification et chaque appel d'outil
    uv run cti-extract --stats

Chaque article passe par `pipeline.extract_article` ; le `stix2.Bundle` est écrit dans backend/data/bundles/article_<id>.json
(même en --dry-run), puis enregistré dans Neo4j sans les IOC jugés bénins.
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
from rich.table import Table  # noqa: E402

from backend.config import BUNDLES_DIR, LLM_MODEL, SOURCE_ARTICLES_DB  # noqa: E402
from backend.text.evidence import parse_date  # noqa: E402
from backend.extracting.pipeline import ExtractionResult, clean_title, extract_article  # noqa: E402
from backend.stix.iocs import build_ioc_objects, without_benign  # noqa: E402
from backend.stix.objects import as_dict, bundle, report  # noqa: E402
from backend.stix.rules import build_rule_objects  # noqa: E402

CATEGORIES = ("operational", "tactical", "strategic")

console = Console()


def article_objects(result: ExtractionResult, art: dict) -> tuple[list, list]:
    """Objets `stix2` de l'article (éditeur, entités, objets ATT&CK, relations, IOC, règles), puis les objets de support : l'auteur
    et le marquage que référencent les objets ATT&CK, joints au bundle mais ni au rapport ni à Neo4j."""
    draft, ctx = result.draft, result.draft.ctx
    published = parse_date(art.get("publication_date"))
    objects = [ctx.publisher, *draft.linked(), *draft.relationships()]
    objects += build_ioc_objects(result.iocs.findings, ctx, published)
    objects += build_rule_objects(result.rules.rules, ctx, published)
    objects = list({o["id"]: o for o in objects}.values())
    known = {o["id"] for o in objects}
    refs = {r for o in objects for r in [o.get("created_by_ref"), *(o.get("object_marking_refs") or [])] if r and r not in known}
    return objects, draft.attack.support_objects(refs)


def article_bundle(result: ExtractionResult, art: dict, objects: list, support: list = ()):
    """`stix2.Bundle` de l'article : le `stix2.Report` qui liste ses objets, les objets, et les objets de support."""
    ctx = result.draft.ctx
    title = clean_title(art["title"] or "", art.get("site_name")) or art["title"]
    rep = report(ctx, title, parse_date(art.get("publication_date")), [o["id"] for o in objects if o["id"] != ctx.publisher.id], [art["primary_category"]] if art.get("primary_category") else None)
    return bundle([rep, *objects, *support])


def process_article(art: dict, *, out_dir: Path = BUNDLES_DIR, store=None) -> ExtractionResult:
    """Extrait un article, écrit `out_dir/article_<id>.json` et, si `store` est donné, l'enregistre dans Neo4j."""
    result = extract_article(art)
    objects, support = article_objects(result, art)
    out_dir.mkdir(parents=True, exist_ok=True)
    # indent et non pretty=True : le tri des clés dans l'ordre de la spécification prenait 150 s sur un bundle de 2 000 objets
    (out_dir / f"article_{art['id']}.json").write_text(article_bundle(result, art, objects, support).serialize(indent=1), encoding="utf-8")
    if store is not None:
        # Neo4j : sans les IOC jugés bénins (l'indicateur d'une valeur est partagé entre articles, un verdict écraserait l'autre)
        nodes = [as_dict(o) for o in article_bundle(result, art, without_benign(objects)).objects]
        store.save_article(
            nodes, art["id"],
            {"title": art["title"], "url": art["url"], "site_name": art["site_name"], "category": art["primary_category"],
             "model": LLM_MODEL, "extraction_seconds": round(result.seconds, 1), "extracted_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
             "llm_failures": len(result.failures)},
        )  # fmt: skip
    return result


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


def summary_line(result: ExtractionResult) -> str:
    failed = f" │ {len(result.failures)} étape(s) en échec" if result.failures else ""
    iocs = len(result.iocs.findings) - result.iocs.n_not_malicious
    return (
        f"Article {result.article_id} {result.seconds:.0f}s │ {len(result.draft.linked())} entités {len(result.draft.evidence)} relations "
        f"{iocs} IOC (+{result.iocs.n_not_malicious} bénins) {len(result.rules.rules)} règles │ {len(result.calls)} appels, "
        f"{result.output_tokens} tokens générés │ lignes acceptées {result.accepted}, refusées {result.refused}{failed}"
    )


def print_stats() -> None:
    from backend.database.stix_store import StixStore

    store = StixStore()
    ok, err = store._store.check_connection()
    if not ok:
        console.print(f"[bold red]Neo4j non joignable ({err})[/]")
        return
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Extraction STIX 2.1 (stix2) des articles classifiés, vérifiée contre ATT&CK v20.0")
    parser.add_argument("--article-id", type=int, action="append", help="Article à extraire (option répétable ; ré-extrait même s'il existe)")
    parser.add_argument("--limit", type=int, default=10, help="Nombre maximal d'articles")
    parser.add_argument("--force", action="store_true", help="Ré-extraire aussi les articles déjà dans Neo4j")
    parser.add_argument("--dry-run", action="store_true", help="N'écrit rien dans Neo4j")
    parser.add_argument("--out", type=Path, default=BUNDLES_DIR, help=f"Dossier des bundles STIX 2.1 (défaut : {BUNDLES_DIR})")
    parser.add_argument("--show-log", action="store_true", help="Affiche les refus de la vérification et les appels d'outils")
    parser.add_argument("--stats", action="store_true", help="Statistiques du graphe STIX dans Neo4j")
    args = parser.parse_args()
    if args.stats:
        print_stats()
        return
    store, skip = None, set()
    if not args.dry_run:
        from backend.database.stix_store import StixStore

        store = StixStore()
        ok, err = store._store.check_connection()
        if not ok:
            console.print(f"[bold red]Neo4j non joignable ({err}) : relancer avec --dry-run pour n'écrire que les bundles[/]")
            return
        store.init_schema()
        skip = set() if args.force or args.article_id else store.extracted_article_ids()
    articles = fetch_articles(len(args.article_id) if args.article_id else args.limit, args.article_id, skip)
    for art in articles:
        result = process_article(art, out_dir=args.out, store=store)
        console.print(summary_line(result))
        for f in result.failures:
            console.print(f"  [red]{f}[/]")
        if args.show_log:
            for line in result.draft.log:
                console.print(f"  [dim]{line}[/]")
        console.print(f"  bundle : {args.out / f'article_{art['id']}.json'}")


if __name__ == "__main__":
    main()
