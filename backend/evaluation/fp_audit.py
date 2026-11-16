"""Audit des faux positifs (techniques ATT&CK) d'une exécution de cti-eval, et score « même événement ».

Un faux positif ici : une technique prédite sans équivalent dans le gold (ni la même, ni la même parente). Chacun reçoit un
verdict humain : J juste mais non retenue par le gold, D défendable, F fausse. Les verdicts sont enregistrés dans
<exécution>/fp_audit.json et donnent une précision corrigée du gold (Qian 2026 : 20 % des faux positifs sont des éléments
pertinents que le gold n'a pas retenus).

  uv run python -m backend.evaluation.fp_audit cascade2_a --serve      # interface web locale (http://127.0.0.1:8097)
  uv run python -m backend.evaluation.fp_audit noleak_1 cascade2_a     # score « même événement » (+ verdicts s'il y en a)

« Même événement » : une technique prédite est admise si le gold a, sur une phrase citée commune et dans une tactique
commune, une technique quelconque. Lecture indulgente, affichée à côté du score strict, jamais à sa place.
"""

import argparse
import json
import os
import re
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

root_dir = Path(__file__).resolve().parents[2]
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from backend.config import EVAL_DIR  # noqa: E402
from backend.evaluation.cti_eval import fetch_article, load_manifest  # noqa: E402
from backend.evaluation.gold_carriers import REVISION_DIR, apply_rows, update_row  # noqa: E402
from backend.evaluation.graph_view import graph_of  # noqa: E402
from backend.evaluation.score import LABEL_REQUIRED, load_bundle  # noqa: E402
from backend.extracting.stix.attack import get_attack_kb  # noqa: E402
from backend.preprocessing.cleaning.text.evidence import mentions  # noqa: E402
from backend.preprocessing.cleaning.text.segment import segment  # noqa: E402

PAGE = Path(__file__).with_name("fp_audit.html")
REVISION_PAGE = Path(__file__).with_name("gold_review.html")
_CARRIER_TYPES = ("campaign", "intrusion-set", "threat-actor", "malware", "tool")
VERDICTS = ("J", "D", "F")
_TECH = re.compile(r"\[(T\d{4}(?:\.\d{3})?)\]")
_HALLU = re.compile(r" \(hallucination [^)]*\)$")


def _norm(text: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", (text or "").casefold()))


def _overlap(a: set[str], b: set[str]) -> bool:
    """Une citation de l'un contient l'autre (citations du gold souvent partielles, prédites = phrases entières)."""
    return any(x and y and (x in y or y in x) for x in a for y in b)


def _same_parent(a: str, b: str) -> bool:
    return a.split(".")[0] == b.split(".")[0]


def techniques(bundle: dict, gold: bool) -> dict[str, dict]:
    """technique -> citations (brutes et normalisées), label, porteurs, procédures, de toutes les relations qui la touchent."""
    kb = get_attack_kb()
    ents, rels = load_bundle(bundle, kb, gold=gold)
    objs = {o["id"]: o for o in bundle["objects"]}
    out: dict[str, dict] = {}
    for e in ents.values():
        if e.stix_type == "attack-pattern" and e.technique:
            out.setdefault(e.technique, {"quotes": set(), "raw": [], "label": e.label, "carriers": set(), "procedures": []})
    for r in rels:
        for end, other in ((r.target, r.source), (r.source, r.target)):
            t = ents[end]
            if t.stix_type != "attack-pattern" or not t.technique:
                continue
            d = out[t.technique]
            d["quotes"] |= {_norm(q) for q in r.quotes}
            d["raw"] += [q for q in r.quotes if q not in d["raw"]]
            if r.rel == "uses" and end == r.target:
                d["carriers"].add(ents[other].name)
                desc = objs.get(r.sid, {}).get("description")
                if desc and not gold and desc not in d["procedures"]:
                    d["procedures"].append(desc)
    return out


def _tactics(aid: str) -> set[str]:
    return set((get_attack_kb().get(aid) or {}).get("tactics", []))


def event_match(p: str, pd: dict, g: str, gd: dict) -> bool:
    return _same_parent(p, g) or (_overlap(pd["quotes"], gd["quotes"]) and bool(_tactics(p) & _tactics(g)))


def _technique_card(aid: str) -> dict:
    obj = get_attack_kb().get(aid) or {}
    return {"id": aid, "name": obj.get("full_name") or obj.get("name", ""), "tactics": obj.get("tactics", []), "summary": obj.get("summary", "")}


def entity_items(aid: int, title: str, unmatched: list[str], units) -> list[dict]:
    """Entités prédites non appariées au gold (hors techniques, auditées à part), avec les phrases qui les nomment."""
    items = []
    for raw in unmatched:
        label = _HALLU.sub("", raw)
        kind, _, name = label.partition(":")
        if kind == "attack-pattern":
            continue
        cited = [u.text for u in units if mentions(u.text, {name})][:3]
        items.append({"key": f"{aid}:E:{label}", "kind": "entity", "article": aid, "title": title, "label": label, "quotes": cited})
    return items


def relation_items(aid: int, title: str, unmatched: list[dict], judged: set[str]) -> list[dict]:
    """Relations prédites non appariées, sauf celles vers une technique déjà auditée comme item technique."""
    items = []
    for r in unmatched:
        tech = _TECH.search(r["relation"].split("-->")[-1])
        if tech and tech.group(1) in judged:
            continue
        items.append({"key": f"{aid}:R:{r['relation']}", "kind": "relation", "article": aid, "title": title,
                      "label": r["relation"], "quotes": [r["quote"]] if r.get("quote") else []})  # fmt: skip
    return items


def analyse(run: str) -> dict:
    """Compteurs du score « même événement » et faux positifs à auditer d'une exécution."""
    folder = EVAL_DIR / run
    stats = {"gold": 0, "gold_event": 0, "pred": 0, "pred_family": 0, "pred_event": 0}
    kinds = {"entity": {"pred": 0, "matched": 0}, "relation": {"pred": 0, "matched": 0, "inherited": {}}}
    report_file = folder / "report.json"
    report = {a["article_id"]: a for a in json.loads(report_file.read_text(encoding="utf-8"))["articles"]} if report_file.exists() else {}
    items = []
    runs_file = folder / "runs.json"
    runs = json.loads(runs_file.read_text(encoding="utf-8")) if runs_file.exists() else {}
    trace = {aid: (r.get("trace") or {}).get("behaviors") or [] for aid, r in runs.items()}
    for entry in load_manifest():
        aid = entry["article_id"]
        path = folder / f"article_{aid}.json"
        if not path.exists():
            continue
        gold = techniques(json.loads(entry["gold_path"].read_text(encoding="utf-8")), gold=True)
        pred = techniques(json.loads(path.read_text(encoding="utf-8")), gold=False)
        required = {g: d for g, d in gold.items() if d["label"] == LABEL_REQUIRED}
        stats["gold"] += len(required)
        stats["gold_event"] += sum(any(event_match(p, pd, g, gd) for p, pd in pred.items()) for g, gd in required.items())
        stats["pred"] += len(pred)
        stats["pred_event"] += sum(any(event_match(p, pd, g, gd) for g, gd in gold.items()) for p, pd in pred.items())
        title, by_uid = None, {}
        for p, pd in sorted(pred.items()):
            if any(_same_parent(p, g) for g in gold):
                stats["pred_family"] += 1
                continue
            if title is None:
                art = fetch_article(aid)
                title = art.get("title") or f"Article {aid}"
                by_uid = {u.uid: u.text for u in segment(art["clean_markdown"])}
            # Technique sans relation (pas de porteur nommé) : procédure et phrases tirées de la trace de l'exécution
            for b in trace.get(str(aid), []):
                if p in (b.get("chosen") or []):
                    if b.get("text") and b["text"] not in pd["procedures"]:
                        pd["procedures"].append(b["text"])
                    pd["raw"] += [by_uid[n] for n in b.get("uids", []) if n in by_uid and by_uid[n] not in pd["raw"]]
            near = [g for g, gd in gold.items() if _overlap(pd["quotes"], gd["quotes"])]
            items.append({
                "key": f"{aid}:{p}", "kind": "technique", "label": f"{p} {_technique_card(p)['name']}", "article": aid, "title": title,
                "technique": _technique_card(p), "carriers": sorted(pd["carriers"]), "procedures": pd["procedures"],
                "quotes": pd["raw"], "same_event": any(event_match(p, pd, g, gold[g]) for g in gold),
                "gold_near": [{**_technique_card(g), "carriers": sorted(gold[g]["carriers"]), "quotes": gold[g]["raw"][:2]} for g in near],
                "gold_article": sorted(gold),
            })  # fmt: skip
        rep = report.get(aid)
        if rep:
            title = title or (fetch_article(aid).get("title") or f"Article {aid}")
            units = segment(fetch_article(aid)["clean_markdown"])
            ents, _ = load_bundle(json.loads(path.read_text(encoding="utf-8")), get_attack_kb(), gold=False)
            others = [e for e in ents.values() if e.stix_type != "attack-pattern"]
            new_e = entity_items(aid, title, rep["review_entities"], units)
            kinds["entity"]["pred"] += len(others)
            kinds["entity"]["matched"] += len(others) - len(new_e)
            judged = {i["technique"]["id"] for i in items if i["article"] == aid and i["kind"] == "technique"}
            new_r = relation_items(aid, title, rep["review_relations"], judged)
            kinds["relation"]["pred"] += rep["relations"]["predicted"]
            kinds["relation"]["matched"] += rep["relations"]["predicted"] - len(rep["review_relations"])
            for r in rep["review_relations"]:
                tech = _TECH.search(r["relation"].split("-->")[-1])
                if tech and tech.group(1) in judged:
                    kinds["relation"]["inherited"][f"{aid}:R:{r['relation']}"] = f"{aid}:{tech.group(1)}"
            items += new_e + new_r
    return {"run": run, "stats": stats, "items": items, "kinds": kinds}


def load_verdicts(run: str) -> dict[str, dict]:
    path = EVAL_DIR / run / "fp_audit.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def save_verdicts(run: str, verdicts: dict[str, dict]) -> None:
    """Écriture atomique : un fichier à moitié écrit ne remplace jamais les verdicts déjà enregistrés."""
    path = EVAL_DIR / run / "fp_audit.json"
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(verdicts, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def _pct(a: float, b: float) -> str:
    return f"{100 * a / b:5.1f} %" if b else "  —  "


def summary_line(data: dict, verdicts: dict[str, dict]) -> str:
    s = data["stats"]
    line = (f"{data['run']:12s} même événement : rappel {_pct(s['gold_event'], s['gold'])} ({s['gold_event']}/{s['gold']}) · "
            f"précision {_pct(s['pred_event'], s['pred'])} · précision même famille {_pct(s['pred_family'], s['pred'])}")  # fmt: skip

    def count(keys: set[str], extra: dict[str, str] | None = None) -> dict[str, int]:
        out = {v: sum(1 for k in keys if (verdicts.get(k) or {}).get("verdict") == v) for v in VERDICTS}
        for own, parent in (extra or {}).items():  # relation vers une technique auditée : verdict de la technique
            v = (verdicts.get(parent) or {}).get("verdict")
            if v in out and own not in keys:
                out[v] += 1
        return out

    by_kind = {k: {i["key"] for i in data["items"] if i.get("kind", "technique") == k} for k in ("technique", "entity", "relation")}
    c = count(by_kind["technique"])
    if any(c.values()):
        line += (f"\n{'':12s} techniques {sum(c.values())}/{len(by_kind['technique'])} : J {c['J']} · D {c['D']} · F {c['F']} → précision "
                 f"corrigée {_pct(s['pred_family'] + c['J'], s['pred'])} (J), {_pct(s['pred_family'] + c['J'] + c['D'], s['pred'])} (J+D)")  # fmt: skip
    kinds = data.get("kinds", {})
    for kind, label in (("entity", "entités"), ("relation", "relations")):
        k = kinds.get(kind)
        c = count(by_kind[kind], k.get("inherited") if k else None)
        if k and any(c.values()):
            line += (f"\n{'':12s} {label} {sum(c.values())}/{len(by_kind[kind]) + len(k.get('inherited', {}))} : J {c['J']} · D {c['D']} · F {c['F']} → "
                     f"précision corrigée {_pct(k['matched'] + c['J'], k['pred'])} (J), {_pct(k['matched'] + c['J'] + c['D'], k['pred'])} (J+D)")  # fmt: skip
    return line


def _atomic_json(path: Path, data) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def _gold_of(aid: int) -> dict:
    entry = next(e for e in load_manifest() if e["article_id"] == aid)
    return json.loads(entry["gold_path"].read_text(encoding="utf-8"))


def _carriers(bundle: dict) -> dict[str, str]:
    ents, _ = load_bundle(bundle, get_attack_kb(), gold=True)
    return {sid: f"{e.stix_type}:{e.name}" for sid, e in ents.items() if e.stix_type in _CARRIER_TYPES}


def revision_articles() -> list[dict]:
    """Articles qui ont une feuille de révision des porteurs, avec leurs lignes et les porteurs possibles."""
    out = []
    for entry in load_manifest():
        aid = entry["article_id"]
        sheet = REVISION_DIR / f"{aid}.carriers.json"
        if not sheet.exists():
            continue
        rows = json.loads(sheet.read_text(encoding="utf-8"))
        title = fetch_article(aid).get("title") or f"Article {aid}"
        out.append({"article": aid, "title": title, "rows": rows, "carriers": _carriers(_gold_of(aid))})
    return out


def graph_view(run: str, aid: int, view: str) -> dict:
    """Graphe d'un article : gold d'origine, gold avec la révision en cours appliquée (sans écrire), ou prédiction de l'exécution."""
    if view == "pred":
        path = EVAL_DIR / run / f"article_{aid}.json"
        return graph_of(json.loads(path.read_text(encoding="utf-8")), gold=False) if path.exists() else {"nodes": [], "edges": [], "tactic_order": []}
    gold = _gold_of(aid)
    sheet = REVISION_DIR / f"{aid}.carriers.json"
    if view == "revised" and sheet.exists():
        gold, _ = apply_rows(gold, json.loads(sheet.read_text(encoding="utf-8")))
    return graph_of(gold, gold=True)


def serve(run: str, port: int) -> None:
    data = analyse(run)
    print(f"{len(data['items'])} techniques à auditer — http://127.0.0.1:{port}  (Ctrl+C pour arrêter)")

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, body: bytes, kind: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, data, code: int = 200) -> None:
            self._send(code, json.dumps(data, ensure_ascii=False).encode(), "application/json")

        def do_GET(self):
            url = urlparse(self.path)
            query = parse_qs(url.query)
            if url.path in ("/", "/index.html"):
                self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
            elif url.path == "/revision":
                self._send(200, REVISION_PAGE.read_bytes(), "text/html; charset=utf-8")
            elif url.path == "/api/revision":
                self._json({"run": run, "articles": revision_articles()})
            elif url.path == "/api/graph":
                try:
                    aid, view = int(query["article"][0]), query.get("view", ["revised"])[0]
                    if view not in ("original", "revised", "pred"):
                        raise ValueError(view)
                    self._json(graph_view(run, aid, view))
                except (KeyError, ValueError, StopIteration) as exc:
                    self._send(400, f"requete invalide : {exc}".encode(), "text/plain; charset=utf-8")
            elif self.path == "/api/items":
                body = json.dumps({**data, "verdicts": load_verdicts(run)}, ensure_ascii=False).encode()
                self._send(200, body, "application/json")
            else:
                self._send(404, b"introuvable", "text/plain; charset=utf-8")

        def do_POST(self):
            if self.path == "/api/revision":
                return self._post_revision()
            if self.path != "/api/verdict":
                return self._send(404, b"introuvable", "text/plain; charset=utf-8")
            try:
                msg = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
                key, verdict, comment = msg["key"], msg.get("verdict"), str(msg.get("comment") or "")[:2000]
            except (ValueError, KeyError, TypeError):
                return self._send(400, b"requete invalide", "text/plain; charset=utf-8")
            if key not in {i["key"] for i in data["items"]} or verdict not in (*VERDICTS, None):
                return self._send(400, b"cle ou verdict inconnu", "text/plain; charset=utf-8")
            verdicts = load_verdicts(run)
            if verdict is None and not comment:
                verdicts.pop(key, None)
            else:
                verdicts[key] = {"verdict": verdict, "comment": comment}
            save_verdicts(run, verdicts)
            self._send(200, json.dumps({"ok": True}).encode(), "application/json")

        def _post_revision(self):
            try:
                msg = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
                aid = int(msg["article"])
                sheet = REVISION_DIR / f"{aid}.carriers.json"
                rows = json.loads(sheet.read_text(encoding="utf-8"))
                allowed = set(_carriers(_gold_of(aid)))
                rows = update_row(rows, msg["relation_id"], msg["decision"], msg.get("new_source"), msg.get("reason", ""), allowed)
                apply_rows(_gold_of(aid), rows)  # refuse une relation hors STIX 2.1 avant d'écrire
            except (ValueError, KeyError, TypeError, OSError, StopIteration) as exc:
                return self._send(400, f"refusé : {exc}".encode(), "text/plain; charset=utf-8")
            _atomic_json(sheet, rows)
            self._json({"ok": True})

        def log_message(self, *args):  # pas de journal par requête
            pass

    try:
        ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\n" + summary_line(data, load_verdicts(run)))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("runs", nargs="+", help="dossiers de backend/evaluation/eval/")
    parser.add_argument("--serve", action="store_true", help="interface d'audit du premier dossier")
    parser.add_argument("--port", type=int, default=8097)  # 8080 / 8090 : OpenCTI ; 8095 : dashboard
    args = parser.parse_args()
    if args.serve:
        return serve(args.runs[0], args.port)
    for run in args.runs:
        print(summary_line(analyse(run), load_verdicts(run)))


if __name__ == "__main__":
    main()
