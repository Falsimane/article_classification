"""Gold ramené à STIX 2.1 strict (docs/stix-v2.1-os.pdf ; Annotations/methode_annotation.md, « Types d'entités »).

Trois transformations vérifiables, chacune sur une copie :
- `drop_native_tools` : un binaire natif sans logiciel ATT&CK n'est pas un `tool` ; « X uses outil » + « outil uses T »
  devient « X uses T » (citation de la technique, contexte « via <outil> ») ;
- `invert_tool_techniques` : « tool uses attack-pattern » (hors norme) devient « attack-pattern uses tool » ;
- `strip_software` : plus d'objet `software` ; le produit est nommé dans la description de la vulnérabilité ou de la source.

  uv run python -m backend.evaluation.gold_strict check all     # violations de chaque gold
  uv run python -m backend.evaluation.gold_strict migrate all   # applique les trois transformations

Ajouts validés par l'audit des faux positifs (verdicts J absents du gold) et renommages, relus par l'utilisateur :

  uv run python -m backend.evaluation.gold_strict propose all --run cascade2_a   # Annotations/revision/additions.json
  uv run python -m backend.evaluation.gold_strict add all                         # applique additions.json
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
from backend.config import EVAL_DIR  # noqa: E402
from backend.evaluation.score import LABEL_ACCEPTABLE, LABEL_REQUIRED, _align_operations, _candidates, _greedy, activity_groups, load_bundle  # noqa: E402
from backend.preprocessing.cleaning.text.evidence import normalize_name  # noqa: E402
from backend.extracting.graph.draft import _FILE_NAME, NATIVE_BINARIES  # noqa: E402
from backend.extracting.observables.update_reference import native_name  # noqa: E402
from backend.extracting.stix.attack import AttackKB, attack_id, get_attack_kb  # noqa: E402
from backend.extracting.stix.objects import ALLOWED_RELATIONS, to_stix  # noqa: E402

ADDITIONS = root_dir / "Annotations" / "revision" / "additions.json"
_DROPPED_PROPS = ("created_by_ref", "object_marking_refs", "confidence", "description")


def _rels(bundle: dict) -> list[dict]:
    return [o for o in bundle["objects"] if o.get("type") == "relationship"]


def _has_attack_software(obj: dict, kb: AttackKB) -> bool:
    if (attack_id(obj) or "").upper().startswith("S"):
        return True
    return any(h["status"] == "active" for h in kb.lookup(obj.get("name", ""), ("tool", "malware")))


def _native_tool(obj: dict, kb: AttackKB) -> bool:
    return obj.get("type") == "tool" and native_name(obj.get("name", "")) in NATIVE_BINARIES and not _has_attack_software(obj, kb)


def violations(bundle: dict, kb: AttackKB) -> list[str]:
    """Ce qui sort de STIX 2.1 strict : relation hors norme (sens écrit), `software`, binaire natif en `tool`, nom de fichier
    en malware ou infrastructure."""
    objs = {o["id"]: o for o in bundle["objects"]}
    out = []
    for o in objs.values():
        if o["type"] == "software":
            out.append(f"software {o.get('name')}")
        elif _native_tool(o, kb):
            out.append(f"binaire natif en tool : {o.get('name')}")
        elif o["type"] in ("malware", "infrastructure") and _FILE_NAME.match(o.get("name", "")):
            out.append(f"nom de fichier en {o['type']} : {o.get('name')}")
    for r in _rels(bundle):
        s, t = objs.get(r["source_ref"]), objs.get(r["target_ref"])
        if s is None or t is None:
            continue
        triple = (s["type"], r["relationship_type"], t["type"])
        if triple not in ALLOWED_RELATIONS:
            out.append(f"{' '.join(triple)} ({s.get('name')} → {t.get('name')})")
    return out


def _merge(twin: dict, rel: dict, origin: str) -> None:
    """Fusion d'une relation dans une relation existante de même triplet (comme gold_carriers.apply_rows)."""
    quotes = [q for q in (twin.get("description", "").split(" | ") if twin.get("description") else []) + [rel.get("x_gold_evidence_quote", "")] if q]
    twin["description"] = " | ".join(dict.fromkeys(quotes))
    twin["x_gold_merged_from"] = list(dict.fromkeys([*twin.get("x_gold_merged_from", []), origin]))
    if LABEL_REQUIRED in rel.get("labels", []):
        twin["labels"] = [LABEL_REQUIRED]


def drop_native_tools(bundle: dict, kb: AttackKB) -> tuple[dict, int]:
    out = copy.deepcopy(bundle)
    objs = {o["id"]: o for o in out["objects"]}
    natives = {sid for sid, o in objs.items() if _native_tool(o, kb)}
    if not natives:
        return out, 0
    rels = _rels(out)
    kept = [r for r in rels if not natives & {r["source_ref"], r["target_ref"]}]
    for tool in natives:
        users = [r for r in rels if r["target_ref"] == tool and r["relationship_type"] == "uses"]
        techniques = [r for r in rels if r["source_ref"] == tool and r["relationship_type"] == "uses" and objs[r["target_ref"]]["type"] == "attack-pattern"]
        for u in users:
            for t in techniques:
                if u["source_ref"] in natives:
                    continue
                twin = next((k for k in kept if k["relationship_type"] == "uses" and k["source_ref"] == u["source_ref"] and k["target_ref"] == t["target_ref"]), None)
                if twin:
                    _merge(twin, t, tool)
                    continue
                if any(k["relationship_type"] == "uses" and k["target_ref"] == t["target_ref"] for k in kept):
                    continue  # la technique a déjà un porteur : pas de doublon sur l'utilisateur de l'outil
                new = copy.deepcopy(t)
                new["id"] = f"relationship--{_uuid(u['id'], t['id'])}"
                new["source_ref"] = u["source_ref"]
                new["labels"] = [LABEL_REQUIRED] if LABEL_REQUIRED in u.get("labels", []) + t.get("labels", []) else t.get("labels", [])
                new["x_gold_context"] = " ".join(filter(None, [t.get("x_gold_context", ""), f"(via {objs[tool].get('name')})"]))
                kept.append(new)
    out["objects"] = [o for o in out["objects"] if o.get("type") != "relationship" and o["id"] not in natives] + kept
    return out, len(natives)


def _uuid(*parts: str) -> str:
    import uuid

    return str(uuid.uuid5(uuid.NAMESPACE_URL, "gold-strict|" + "|".join(parts)))


def invert_tool_techniques(bundle: dict) -> tuple[dict, int]:
    out = copy.deepcopy(bundle)
    types = {o["id"]: o["type"] for o in out["objects"]}
    n = 0
    for r in _rels(out):
        if r["relationship_type"] == "uses" and types.get(r["source_ref"]) == "tool" and types.get(r["target_ref"]) == "attack-pattern":
            r["source_ref"], r["target_ref"] = r["target_ref"], r["source_ref"]
            r["x_gold_inverted"] = True
            n += 1
    return out, n


def strip_software(bundle: dict) -> tuple[dict, int]:
    out = copy.deepcopy(bundle)
    objs = {o["id"]: o for o in out["objects"]}
    soft = {sid: o for sid, o in objs.items() if o.get("type") == "software"}
    for r in _rels(out):
        for sid, o in soft.items():
            if sid not in (r["source_ref"], r["target_ref"]):
                continue
            other = objs.get(r["target_ref"] if r["source_ref"] == sid else r["source_ref"])
            if other is None or other.get("type") == "identity":  # éditeur du produit : rien à reporter
                continue
            note = f"Produit visé : {o.get('name')}" + (f" ({o['vendor']})" if o.get("vendor") else "")
            if note not in other.get("description", ""):
                other["description"] = " | ".join(filter(None, [other.get("description", ""), note]))
    touching = [r for r in _rels(out) if soft.keys() & {r["source_ref"], r["target_ref"]}]
    out["objects"] = [o for o in out["objects"] if o["id"] not in soft and o not in touching]
    # Éditeur du produit (identity reliée seulement au software) : orphelin, il quitte le gold avec lui
    linked = {i for r in _rels(out) for i in (r["source_ref"], r["target_ref"])}
    vendors = {i for r in touching for i in (r["source_ref"], r["target_ref"]) if objs.get(i, {}).get("type") == "identity"} - linked
    out["objects"] = [o for o in out["objects"] if o["id"] not in vendors]
    return out, len(soft)


# --- Ajouts validés par l'audit ---------------------------------------------------------------------------------------
def _matches(g_ents: dict, g_rels: list, p_ents: dict, p_rels: list) -> dict[str, str]:
    """{entité prédite: entité du gold} selon l'appariement du score (campagnes comprises, appariées par leurs relations),
    crédit plein seulement : une sous-technique prédite n'est pas sa technique parente."""
    cands = _candidates(g_ents, p_ents)
    _align_operations(g_ents, p_ents, g_rels, p_rels, cands)
    return {p: g for p, (g, credit) in _greedy([(c, p, g) for p, gs in cands.items() for g, c in gs.items()]).items() if credit >= 1.0}


def _entity_copy(obj: dict) -> dict:
    out = {k: v for k, v in obj.items() if k not in _DROPPED_PROPS}
    refs = [r for r in obj.get("external_references", []) if r.get("source_name") in ("mitre-attack", "cve")]
    out.pop("external_references", None)
    if refs:
        out["external_references"] = refs
    return {**out, "labels": [LABEL_ACCEPTABLE], "x_gold_source": "audit J"}


def additions_for_article(gold: dict, pred: dict, keys: list[str], kb: AttackKB) -> list[dict]:
    """Objets à ajouter au gold pour les affirmations jugées J (`keys` : « E:<entité> », « R:<relation> », « T#### ») qu'il
    ne contient pas encore. Chaque objet est copié du bundle prédit, label acceptable. Une relation relie les entités du gold
    (appariées comme au score) ou celles ajoutées ici, et s'écrit dans le sens de la norme. Sont écartés : ce qui sort de STIX
    2.1 strict, une relation que le gold porte déjà depuis une autre entité du même groupe d'activité (le score relâché la
    crédite ; l'ajouter doublerait le porteur), une technique dont aucune relation ne peut être ajoutée."""
    g_ents, g_rels = load_bundle(gold, kb, gold=True)
    p_ents, p_rels = load_bundle(pred, kb, gold=False)
    p_objs = {o["id"]: o for o in pred["objects"]}
    match = _matches(g_ents, g_rels, p_ents, p_rels)
    groups = activity_groups(g_ents, g_rels)
    g_pairs: dict[tuple[str, str], set[str]] = {}
    for r in g_rels:
        g_pairs.setdefault((r.rel, r.target), set()).add(r.source)
    g_triples = {(r.source, r.rel, r.target) for r in g_rels}
    carried = {r.target for r in g_rels if r.rel == "uses" and g_ents[r.target].stix_type == "attack-pattern"}
    added: dict[str, str] = {}  # entité prédite ajoutée -> son identifiant dans le gold enrichi (le même)
    items: list[dict] = []

    def add_entity(pid: str, key: str) -> str | None:
        if pid in added:
            return pid
        obj = _entity_copy(p_objs[pid])
        if violations({"objects": [obj]}, kb):
            return None
        items.append({"key": key, "object": obj})
        added[pid] = pid
        return pid

    for key in sorted(keys, key=lambda k: (not k.startswith("E:"), k.startswith("R:"))):  # entités, techniques, relations
        if key.startswith("E:"):
            pid = next((i for i, e in p_ents.items() if e.describe() == key[2:]), None)
            if pid and pid not in match:
                add_entity(pid, key)
            continue
        if key.startswith("R:"):
            rels = [r for r in p_rels if f"{p_ents[r.source].describe()} --{r.rel}--> {p_ents[r.target].describe()}" == key[2:]]
        else:
            rels = [r for r in p_rels if p_ents[r.target].technique == key and r.rel == "uses"]
        for r in rels:
            ends = []
            for pid in (r.source, r.target):  # une extrémité absente du gold n'est ajoutée que si c'est une technique
                ends.append(match.get(pid) or added.get(pid) or ("new" if p_ents[pid].stix_type == "attack-pattern" else None))
            if None in ends:
                continue
            s, t = ends
            types = {**{i: e.stix_type for i, e in g_ents.items()}, **{i: p_ents[i].stix_type for i in added}, "new": "attack-pattern"}
            if s != "new" and t != "new":
                if (s, r.rel, t) in g_triples:
                    continue
                if groups.get(s, {s}) & g_pairs.get((r.rel, t), set()):
                    continue  # déjà porté dans le gold par une entité du même groupe d'activité
                if r.rel == "uses" and t in carried:
                    continue  # technique déjà portée dans le gold : pas de second porteur
            src_type = types[s] if s != "new" else "attack-pattern"
            dst_type = types[t] if t != "new" else "attack-pattern"
            flip = to_stix(src_type, r.rel, dst_type)
            if ((dst_type, r.rel, src_type) if flip else (src_type, r.rel, dst_type)) not in ALLOWED_RELATIONS:
                continue
            if s == "new":
                s = add_entity(r.source, key)
            if t == "new":
                t = add_entity(r.target, key)
            if not s or not t:
                continue
            src, dst = (t, s) if flip else (s, t)
            g_triples.add((s, r.rel, t))
            if r.rel == "uses" and types.get(t, "attack-pattern") == "attack-pattern":
                carried.add(t)
            items.append({"key": key, "object": {
                "type": "relationship", "spec_version": "2.1", "id": f"relationship--{_uuid(src, r.rel, dst)}",
                "created": p_objs[r.sid].get("created"), "modified": p_objs[r.sid].get("modified"),
                "relationship_type": r.rel, "source_ref": src, "target_ref": dst, "labels": [LABEL_ACCEPTABLE],
                "x_gold_evidence_quote": (r.quotes or [""])[0], "x_gold_source": "audit J"}})  # fmt: skip
    return items


def additions_from_audit(run: str, audits: dict[str, str], kb: AttackKB, manual: dict[int, list[dict]] | None = None) -> dict[int, list[dict]]:
    """`additions_for_article` pour chaque article de l'exécution `run`, sur les clés jugées J de `audits`, comparées au gold
    après les entrées écrites à la main (`manual` : renommages, ajouts), pour ne pas proposer de doublon."""
    out: dict[int, list[dict]] = {}
    for entry in load_manifest():
        aid = entry["article_id"]
        path = EVAL_DIR / run / f"article_{aid}.json"
        keys = [k.split(":", 1)[1] for k, v in audits.items() if v == "J" and k.split(":", 1)[0] == str(aid)]
        if not path.exists() or not keys:
            continue
        gold, _ = apply_additions(json.loads(entry["gold_path"].read_text(encoding="utf-8")), (manual or {}).get(aid, []))
        items = additions_for_article(gold, json.loads(path.read_text(encoding="utf-8")), keys, kb)
        if items:
            out[aid] = items
    return out


def apply_additions(bundle: dict, items: list[dict]) -> tuple[dict, int]:
    """Bundle (copie) avec les objets ajoutés (sans doublon d'identifiant) et les renommages `{"rename": id, "name": …}`."""
    out = copy.deepcopy(bundle)
    objs = {o["id"]: o for o in out["objects"]}
    n = 0
    for item in sorted(items, key=lambda i: "rename" in i):  # objets d'abord : un renommage peut viser un objet ajouté
        if "rename" in item:
            target = objs.get(item["rename"])
            if target is None:
                raise ValueError(f"renommage : {item['rename']} absent du gold")
            if target.get("name") != item["name"]:
                target.setdefault("x_gold_renamed_from", target.get("name"))
                target["name"] = item["name"]
                n += 1
        elif item["object"]["id"] not in objs:
            obj = copy.deepcopy(item["object"])
            out["objects"].append(obj)
            objs[obj["id"]] = obj
            n += 1
    return out, n


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=("check", "migrate", "propose", "add"))
    parser.add_argument("article", help="identifiant d'article, ou « all »")
    parser.add_argument("--run", default="cascade2_a", help="propose : exécution dont fp_audit.json donne les verdicts J")
    args = parser.parse_args()
    kb = get_attack_kb()
    if args.action == "propose":
        audits = {k: v["verdict"] for k, v in json.loads((EVAL_DIR / args.run / "fp_audit.json").read_text(encoding="utf-8")).items() if v.get("verdict")}
        current = json.loads(ADDITIONS.read_text(encoding="utf-8")) if ADDITIONS.exists() else {}
        manual = {int(a): [i for i in items if i.get("key", "").startswith("manuel") or "rename" in i] for a, items in current.items()}
        found = additions_from_audit(args.run, audits, kb, manual)
        for aid in set(manual) | set(found):  # les entrées écrites à la main (renommages, ajouts) sont conservées en tête
            current[str(aid)] = manual.get(aid, []) + found.get(aid, [])
        ADDITIONS.write_text(json.dumps(current, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        for aid, items in sorted(found.items()):
            print(f"{aid} : {len(items)} ajout(s) proposé(s)")
        return
    additions = json.loads(ADDITIONS.read_text(encoding="utf-8")) if args.action == "add" else {}
    for entry in load_manifest():
        if args.article != "all" and entry["article_id"] != int(args.article):
            continue
        path = entry["gold_path"]
        raw = path.read_text(encoding="utf-8")
        bundle = json.loads(raw)
        if args.action == "add":
            bundle, n_added = apply_additions(bundle, additions.get(str(entry["article_id"]), []))
            path.write_text(json.dumps(bundle, ensure_ascii=False, indent=2) + ("\n" if raw.endswith("\n") else ""), encoding="utf-8")
            print(f"{entry['article_id']} : {n_added} ajout(s) ou renommage(s)")
        if args.action == "migrate":
            bundle, n_native = drop_native_tools(bundle, kb)
            bundle, n_inverted = invert_tool_techniques(bundle)
            bundle, n_soft = strip_software(bundle)
            path.write_text(json.dumps(bundle, ensure_ascii=False, indent=2) + ("\n" if raw.endswith("\n") else ""), encoding="utf-8")
            print(f"{entry['article_id']} : {n_native} binaire(s) natif(s) retiré(s), {n_inverted} relation(s) inversée(s), {n_soft} software retiré(s)")
        found = violations(bundle, kb)
        print(f"{entry['article_id']} : " + ("aucune violation" if not found else "; ".join(found)))


if __name__ == "__main__":
    main()
