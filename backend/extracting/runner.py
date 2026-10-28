"""Exécution d'un lot d'articles, commune à `cti-extract` et `cti-eval`.

Les articles sont extraits `workers` à la fois (le sémaphore de `llm` borne toujours les requêtes en vol), mais un seul
fil écrit dans Neo4j : `StixStore._write` relit les listes d'un nœud partagé avant de les réécrire, deux transactions
simultanées sur le même nœud perdraient une mise à jour. Un article en échec est rapporté sans arrêter les autres.
"""

import os
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from backend.config import LLM_MODEL
from backend.extracting.pipeline import ExtractionResult, clean_title, extract_article
from backend.stix.iocs import build_ioc_objects, without_benign
from backend.stix.objects import as_dict, bundle, report
from backend.stix.rules import build_rule_objects
from backend.text.evidence import parse_date


@dataclass
class Outcome:
    """Résultat d'un article : `error` (exception, bundle non écrit) ou `result` (dont `failures` : étapes perdues)."""

    art: dict
    result: ExtractionResult | None = None
    nodes: list | None = None  # objets pour Neo4j, sans les IOC bénins (None sans écriture Neo4j)
    meta: dict | None = None
    error: str | None = None
    trace: str | None = None
    seconds: float = 0.0

    @property
    def status(self) -> str:
        """ok, partial (une étape LLM perdue : l'article sera repris au prochain lancement) ou failed."""
        if self.error:
            return "failed"
        return "partial" if self.result.failures else "ok"


def write_atomic(path: Path, text: str) -> None:
    """Écrit `path` en entier ou pas du tout : un arrêt pendant l'écriture laisse l'ancien fichier, jamais un JSON tronqué."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


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


def extract_one(art: dict, out_dir: Path, for_store: bool) -> Outcome:
    """Extrait un article et écrit `out_dir/article_<id>.json` ; avec `for_store`, prépare aussi les nœuds pour Neo4j (sans
    les écrire). Ne lève pas : une exception devient `Outcome.error`."""
    t0 = time.perf_counter()
    try:
        result = extract_article(art)
        objects, support = article_objects(result, art)
        # indent et non pretty=True : le tri des clés dans l'ordre de la spécification prenait 150 s sur un bundle de 2 000 objets
        write_atomic(out_dir / f"article_{art['id']}.json", article_bundle(result, art, objects, support).serialize(indent=1))
        out = Outcome(art, result)
        if for_store:
            # Neo4j : sans les IOC jugés bénins (l'indicateur d'une valeur est partagé entre articles, un verdict écraserait l'autre)
            out.nodes = [as_dict(o) for o in article_bundle(result, art, without_benign(objects)).objects]
            out.meta = {
                "title": art["title"], "url": art["url"], "site_name": art["site_name"], "category": art["primary_category"],
                "model": LLM_MODEL, "extraction_seconds": round(result.seconds, 1), "extracted_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "llm_failures": len(result.failures),
            }  # fmt: skip
    except Exception as exc:  # noqa: BLE001 : un article perdu n'arrête pas le lot ; la trace est gardée pour le rapport
        out = Outcome(art, error=f"{type(exc).__name__}: {exc}", trace=traceback.format_exc())
    out.seconds = time.perf_counter() - t0
    return out


def run_batch(arts: list[dict], out_dir: Path, workers: int, store=None) -> Iterator[Outcome]:
    """Rend chaque article dans l'ordre où il se termine, après son écriture dans Neo4j si `store` est donné (fil appelant,
    un article à la fois). Interrompu, n'en lance plus : ceux en cours finissent leur bundle, rien n'est écrit dans Neo4j."""
    pool = ThreadPoolExecutor(max_workers=max(1, workers))
    try:
        futures = [pool.submit(extract_one, art, out_dir, store is not None) for art in arts]
        for future in as_completed(futures):
            out = future.result()
            if store is not None and out.error is None:
                try:
                    store.save_article(out.nodes, out.art["id"], out.meta)
                except Exception as exc:  # noqa: BLE001 : Neo4j perdu en cours de lot, le bundle reste écrit
                    out.error, out.trace = f"Neo4j : {type(exc).__name__}: {exc}", traceback.format_exc()
            yield out
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
