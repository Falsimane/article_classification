"""Données du graphe STIX pour l'interface (React).

L'API renvoie des DONNÉES structurées, jamais de présentation : couleurs, formes et infobulles sont décidées par le
frontend. Tout texte venu des articles (noms, preuves, titres) est renvoyé tel quel : React l'échappe à l'affichage et
le frontend n'utilise jamais `dangerouslySetInnerHTML` (un test le garantit).

Chaque graphe est celui d'UN article (invariant du projet : aucun graphe global agrégé), sauf la vue Acteurs, qui agrège
volontairement tout ce que les articles disent d'un même acteur.
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.config import BUNDLES_DIR, SOURCE_ARTICLES_DB
from backend.database.stix_store import StixStore
from backend.extracting.stix.iocs import ioc_status

# Familles de types STIX regroupées par les filtres du frontend
TYPE_FAMILIES: dict[str, frozenset[str]] = {
    "actor": frozenset({"threat-actor", "intrusion-set", "campaign"}),
    "malware": frozenset({"malware"}),
    "tool": frozenset({"tool"}),
    "vulnerability": frozenset({"vulnerability"}),
    "infrastructure": frozenset({"infrastructure"}),
    "technique": frozenset({"attack-pattern"}),
    "detection": frozenset({"indicator", "course-of-action"}),
    "target": frozenset({"identity", "location", "incident"}),
}
ACTOR_TYPES = ("threat-actor", "intrusion-set", "campaign")


def family_of(stix_type: str) -> str:
    return next((f for f, types in TYPE_FAMILIES.items() if stix_type in types), "target")


def _json_list(node: dict, key: str) -> list:
    raw = node.get(f"{key}_json")
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except ValueError:
        return []
    return value if isinstance(value, list) else []


def _references(node: dict) -> list[dict]:
    """Identifiants externes d'un nœud : ATT&CK (G…, S…, T…), CVE."""
    out = []
    for ref in _json_list(node, "external_references"):
        if ref.get("source_name") in ("mitre-attack", "cve") and ref.get("external_id"):
            out.append({"source": ref["source_name"], "id": ref["external_id"]})
    return out


def _tactics(node: dict | None) -> list[str]:
    if not node:
        return []
    return [p["phase_name"] for p in _json_list(node, "kill_chain_phases") if p.get("kill_chain_name") == "mitre-attack" and p.get("phase_name")]


def _node(n: dict, degree: int) -> dict[str, Any]:
    stix_type = n.get("type", "")
    return {
        "id": n["id"],
        "label": n.get("name", n["id"]),
        "type": stix_type,
        "family": family_of(stix_type),
        "aliases": n.get("aliases", []),
        "references": _references(n),
        "tactics": _tactics(n),
        "sectors": n.get("sectors", []),
        "identity_class": n.get("identity_class"),
        "is_family": bool(n.get("is_family")) if stix_type == "malware" else None,
        "labels": n.get("labels", []),
        "is_dual_use": stix_type == "tool" and "living-off-the-land" in (n.get("labels") or []),
        "article_ids": n.get("article_ids", []),
        "degree": degree,
    }


def _evidence(edge: dict, article_id: int | None) -> list[dict]:
    """Preuves d'une arête : `{article, quote}`. Pour un article donné, seulement les siennes."""
    items = []
    for raw in edge.get("evidence") or []:
        try:
            item = json.loads(raw)
        except ValueError:
            continue
        if item.get("quote") and (article_id is None or item.get("article") == article_id):
            items.append({"article": item.get("article"), "quote": item["quote"]})
    return items


def _edge(e: dict, by_id: dict[str, dict], article_id: int | None) -> dict[str, Any]:
    tactic = (_tactics(by_id[e["target"]]) or _tactics(by_id[e["source"]]) or [""])[0]
    return {
        "id": e["id"], "source": e["source"], "target": e["target"], "type": e["type"].lower().replace("_", "-"),
        "confidence": e.get("confidence"), "tactic": tactic, "evidence": _evidence(e, article_id),
        "article_ids": e.get("article_ids", []),
    }  # fmt: skip


def _filter_nodes(nodes: list[dict], params: dict[str, list[str]]) -> list[dict]:
    type_filter = params.get("type", [None])[0]
    dual_use_only = params.get("dual_use_only", ["0"])[0] in ("1", "true")
    search = params.get("search", [""])[0].strip().lower()
    hide_orphans = params.get("hide_orphans", ["1"])[0] in ("1", "true")
    filtered = type_filter not in (None, "", "all") or dual_use_only or bool(search)

    def keep(n: dict) -> bool:
        if type_filter and type_filter != "all" and n["family"] != type_filter and n["type"] != type_filter:
            return False
        if dual_use_only and not n["is_dual_use"]:
            return False
        if search and search not in n["label"].lower() and not any(search in a.lower() for a in n["aliases"]):
            return False
        return not (hide_orphans and not filtered and n["degree"] == 0)

    return [n for n in nodes if keep(n)]


def _moment(value: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None
    except ValueError:
        return None


def _ioc_row(rec: dict, now: datetime) -> dict[str, Any]:
    """Une ligne d'IOC. Première et dernière observation viennent des observations (une par article) ; le STATUT est calculé ici,
    à chaque lecture, depuis la dernière observation : il n'est jamais stocké."""
    ind, obs = rec["indicator"], rec["observable"]
    sightings = [x for x in rec["sightings"] if x.get("first")]
    firsts = [m for m in (_moment(x["first"]) for x in sightings) if m]
    lasts = [m for m in (_moment(x.get("last") or x["first"]) for x in sightings) if m]
    last_seen = max(lasts) if lasts else None
    articles = sorted({x["article"] for x in sightings if x.get("article") is not None})
    seen_quotes: set[tuple] = set()
    evidence = []
    for x in sightings:
        key = (x.get("article"), x.get("quote"))
        if x.get("quote") and key not in seen_quotes:
            seen_quotes.add(key)
            evidence.append({"article": x.get("article"), "quote": x["quote"]})
    labels = ind.get("labels") or []
    return {
        "id": ind["id"], "kind": obs["type"], "value": obs.get("value", ""), "algo": obs.get("hash_algo"),
        "name": obs.get("name"), "hashes": json.loads(obs["hashes_json"]) if obs.get("hashes_json") else {},
        "role": labels[0] if labels else "unknown", "roles": labels, "confidence": ind.get("confidence"),
        "first_seen": min(firsts).date().isoformat() if firsts else None,
        "last_seen": last_seen.date().isoformat() if last_seen else None,
        "status": ioc_status(obs["type"], last_seen, now),
        "sources": len(articles), "article_ids": articles,
        "attached_to": [{"id": t["id"], "name": t["name"], "type": t["type"]} for t in rec["targets"] if t.get("id")],
        "evidence": evidence[:4],
    }  # fmt: skip


def iocs_of_article(article_id: int, store: StixStore | None = None, now: datetime | None = None) -> dict[str, Any]:
    store = store or StixStore()
    now = now or datetime.now(timezone.utc)
    rows = [_ioc_row(r, now) for r in store.article_iocs(article_id)]
    return {"article_id": article_id, "iocs": rows, "count": len(rows)}


def _rule_row(rec: dict) -> dict[str, Any]:
    """Une règle de détection : son texte exact (`pattern`, validé à l'extraction, jamais réécrit) et l'entité détectée."""
    r = rec["rule"]
    return {
        "id": r["id"], "kind": r.get("pattern_type", ""), "name": r.get("name", ""), "description": r.get("description"),
        "source": r.get("pattern", ""), "confidence": r.get("confidence"), "article_ids": r.get("article_ids", []),
        "detects": [{"id": t["id"], "name": t["name"], "type": t["type"]} for t in rec["targets"] if t.get("id")],
    }  # fmt: skip


def rules_of_article(article_id: int, store: StixStore | None = None) -> dict[str, Any]:
    store = store or StixStore()
    rows = [_rule_row(r) for r in store.article_rules(article_id)]
    return {"article_id": article_id, "rules": rows, "count": len(rows)}


def article_text(article_id: int, db_path: Path = SOURCE_ARTICLES_DB) -> dict[str, Any] | None:
    """Texte de l'article tel que l'extraction l'a lu : le markdown nettoyé de la classification (SQLite, lecture seule)."""
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=30.0) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT k.id, k.title, k.url, k.site_name, k.publication_date, c.primary_category, c.clean_markdown "
            "FROM knowledge k JOIN article_classifications c ON c.knowledge_id = k.id WHERE k.id = ?",
            (article_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        "id": row["id"], "title": row["title"] or f"Article {row['id']}", "url": row["url"] or "", "site_name": row["site_name"],
        "published": (row["publication_date"] or "")[:10] or None, "category": row["primary_category"], "markdown": row["clean_markdown"] or "",
    }  # fmt: skip


def article_bundle(article_id: int, store: StixStore | None = None, bundles_dir: Path = BUNDLES_DIR) -> tuple[bytes, bool] | None:
    """Bundle STIX 2.1 de l'article, tel que l'extraction l'a écrit (`stix2.Bundle` validé, IOC bénins et objets ATT&CK de support
    compris), et s'il couvre encore le graphe de Neo4j : une ré-extraction en --dry-run réécrit le fichier sans toucher au graphe."""
    path = bundles_dir / f"article_{article_id}.json"
    if not path.is_file():
        return None
    raw = path.read_bytes()
    try:
        ids = {o.get("id") for o in json.loads(raw).get("objects", [])}
    except (ValueError, AttributeError):
        return raw, False
    graph = (store or StixStore()).dashboard_graph(article_id)
    return raw, all(x["id"] in ids for x in graph["nodes"] + graph["edges"])


def articles(store: StixStore | None = None) -> dict[str, Any]:
    store = store or StixStore()
    rows = [
        {
            "id": r["id"], "title": r["title"] or f"Article {r['id']}", "url": r["url"] or "", "site_name": r["site_name"],
            "publication_date": (r["published"] or "")[:10] or None, "category": r["category"],
            "extracted_at": r["extracted_at"], "entities_count": r["entities_count"], "relations_count": r["relations_count"],
            "extraction_seconds": r["duration"] or 0.0,
        }
        for r in store.reports()
    ]  # fmt: skip
    return {"articles": rows, "count": len(rows)}


def stats(store: StixStore | None = None) -> dict[str, Any]:
    store = store or StixStore()
    t = store.totals()
    return {
        "articles_count": t["reports"],
        "entities_count": sum(t["nodes"].values()),
        "relations_count": sum(t["edges"].values()),
        "dual_use_count": t["lolbins"],
        "iocs_count": t.get("iocs", 0),
        "entity_types": t["nodes"],
        "relation_types": {k.lower().replace("_", "-"): v for k, v in t["edges"].items()},
    }


def graph(article_id: int | None, params: dict[str, list[str]], store: StixStore | None = None) -> dict[str, Any]:
    """Graphe d'un seul article."""
    store = store or StixStore()
    reports = {r["id"]: r for r in store.reports()}
    if not reports:
        return {"article_id": None, "article": None, "nodes": [], "edges": []}
    if article_id not in reports:
        article_id = next(iter(reports))
    report = reports[article_id]

    raw = store.dashboard_graph(article_id)
    by_id = {n["id"]: n for n in raw["nodes"]}
    edges = [_edge(e, by_id, article_id) for e in raw["edges"] if e["source"] in by_id and e["target"] in by_id and e["source"] != e["target"]]
    degree: dict[str, int] = {}
    for e in edges:
        degree[e["source"]] = degree.get(e["source"], 0) + 1
        degree[e["target"]] = degree.get(e["target"], 0) + 1
    counts = store.article_ioc_counts(article_id)
    nodes = _filter_nodes([{**_node(n, degree.get(nid, 0)), "ioc_count": counts.get(nid, 0)} for nid, n in by_id.items()], params)
    kept = {n["id"] for n in nodes}
    return {
        "article_id": article_id,
        "article": {"id": article_id, "title": report["title"], "url": report["url"], "site_name": report["site_name"], "category": report["category"], "published": (report["published"] or "")[:10] or None},
        "nodes": nodes,
        "edges": [e for e in edges if e["source"] in kept and e["target"] in kept],
    }  # fmt: skip


def actors(store: StixStore | None = None) -> dict[str, Any]:
    store = store or StixStore()
    rows = [
        {**_node(a, a["relations"]), "relations": a["relations"], "reports": a["reports"]}
        for a in store.actors()
    ]
    return {"actors": rows, "count": len(rows)}


def _profile(actor: dict, nodes: dict[str, dict], edges: list[dict]) -> dict[str, Any]:
    """Organigramme d'un acteur, lu dans ses arêtes directes : qui il est, d'où il vient, ce qu'il emploie, qui il cible.

    Rien n'est déduit : une rubrique vide reste vide (le frontend l'affiche comme « non établi »)."""
    aid = actor["id"]
    out = {k: [] for k in ("origin", "sponsors", "parents", "divisions", "malware", "tools", "infrastructure", "targets", "vulnerabilities")}
    techniques: dict[str, list[dict]] = {}

    def entry(node: dict, edge: dict) -> dict:
        return {"node": node, "relation": edge["type"], "confidence": edge["confidence"], "evidence": edge["evidence"]}

    for e in edges:
        outgoing = e["source"] == aid
        other = nodes.get(e["target"] if outgoing else e["source"])
        if other is None or other["id"] == aid:
            continue
        kind, rel = other["type"], e["type"]
        if outgoing and rel == "originates-from" and kind == "location":
            out["origin"].append(entry(other, e))
        elif outgoing and rel in ("attributed-to", "part-of") and kind == "identity":
            out["sponsors"].append(entry(other, e))
        elif outgoing and rel in ("attributed-to", "part-of") and kind in ACTOR_TYPES:
            out["parents"].append(entry(other, e))
        elif not outgoing and rel in ("attributed-to", "part-of") and kind in ACTOR_TYPES:
            out["divisions"].append(entry(other, e))
        elif outgoing and rel == "uses" and kind == "attack-pattern":
            techniques.setdefault((other["tactics"] or ["unknown"])[0], []).append(entry(other, e))
        elif outgoing and rel in ("uses", "owns", "controls", "hosts", "compromises") and kind in ("malware", "tool", "infrastructure"):
            out[{"malware": "malware", "tool": "tools", "infrastructure": "infrastructure"}[kind]].append(entry(other, e))
        elif outgoing and rel == "targets" and kind == "vulnerability":
            out["vulnerabilities"].append(entry(other, e))
        elif outgoing and rel == "targets" and kind in ("identity", "location"):
            out["targets"].append(entry(other, e))
    return {**out, "techniques": techniques}


def actor_graph(actor_id: str, store: StixStore | None = None, now: datetime | None = None) -> dict[str, Any] | None:
    """Profil d'un acteur : lui, ses voisins directs, et ce que TOUS les articles en disent (preuves comprises)."""
    store = store or StixStore()
    sub = store.actor_subgraph(actor_id)
    if sub is None:
        return None
    by_id = {n["id"]: n for n in sub["nodes"]}
    by_id[sub["actor"]["id"]] = sub["actor"]
    edges = [_edge(e, by_id, None) for e in sub["edges"] if e["source"] in by_id and e["target"] in by_id]
    degree: dict[str, int] = {}
    for e in edges:
        degree[e["source"]] = degree.get(e["source"], 0) + 1
        degree[e["target"]] = degree.get(e["target"], 0) + 1
    nodes = [_node(n, degree.get(nid, 0)) for nid, n in by_id.items()]
    actor = next(n for n in nodes if n["id"] == actor_id)
    return {
        "actor": actor,
        "nodes": nodes,
        "edges": edges,
        "profile": _profile(actor, {n["id"]: n for n in nodes}, edges),
        "iocs": [_ioc_row(r, now or datetime.now(timezone.utc)) for r in store.actor_iocs(actor_id)],
        "reports": [{**r, "published": (r["published"] or "")[:10] or None} for r in sub["reports"]],
    }
