"""Rapport de qualité du preprocessing sur le corpus (ou sur une seule source).

À lancer avant d'ingérer une nouvelle source :

    uv run python backend/preprocessing/evaluate_cleaning.py
    uv run python backend/preprocessing/evaluate_cleaning.py --site rapid7

Il mesure, sans appeler aucun LLM et sans rien écrire en base :
- les rejets amont et le taux de conservation du texte ;
- la fidélité des IOC (hash, IP, CVE présents dans le brut mais absents du nettoyé) ;
- les résidus de bruit connus (liens sans ancre, `hxxp`, `[.]`, shortcodes, `Related …`) ;
- les propriétés du découpage (sans perte, sans bloc de code coupé, sans titre orphelin) ;
- la fuite de gabarit sur une source inconnue : lignes du gabarit réel du site qui survivent
  quand le gabarit n'est PAS encore appris (leave-one-source-out).
"""

import argparse
import re
import sqlite3
import statistics
import sys
from collections import defaultdict
from pathlib import Path

root_dir = Path(__file__).resolve().parents[2]
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

import cti_core  # noqa: E402

from backend.preprocessing.cleaner import (  # noqa: E402
    BOILERPLATE_MIN_DOCS,
    BOILERPLATE_MIN_RATIO,
    DB_PATH,
    site_key,
)

IOC_PATTERNS = {
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "sha1": r"\b[a-fA-F0-9]{40}\b",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "cve": r"(?i)\bCVE-\d{4}-\d{4,7}\b",
}
RESIDUALS = {
    "lien sans ancre": r"\(\s*(?:https?://|/)\S*\)",
    "hxxp": r"(?i)hxxp",
    "[.] / [at]": r"\[\.\]|(?i:\[at\])",
    "shortcode attribut": r"\[/?[a-z]+_[a-z_]+[^\]]*=",
    "titre Related": r"(?im)^#+\s*related",
    "Share:": r"(?m)^Share:",
}

engine = cti_core.CtiEngine()


def visible(text: str) -> str:
    """Texte lisible du brut : sans images (noms de fichiers hachés) ni URL de liens."""
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", text)
    return re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)


def ioc_set(text: str) -> set:
    text = engine.refang(visible(text))
    return {(k, m.lower()) for k, p in IOC_PATTERNS.items() for m in re.findall(p, text)}


def load(site: str | None):
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    query = "SELECT id, site_name, url, content FROM knowledge WHERE content IS NOT NULL"
    rows = conn.execute(query + " ORDER BY id").fetchall()
    if site:
        rows = [r for r in rows if site_key(r[1], r[2]) == site]
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--site", help="se limiter à une source (site_name ou domaine)")
    ap.add_argument("--chunk-chars", type=int, default=7500)
    args = ap.parse_args()

    rows = load(args.site)
    if not rows:
        sys.exit("Aucun article.")
    by_site: dict[str, list] = defaultdict(list)
    for _, s, u, ct in rows:
        by_site[site_key(s, u) or "?"].append((u, ct))

    # Gabarit appris sur le corpus (cas nominal d'une source déjà connue)
    template = {
        k: engine.learn_boilerplate([c for _, c in v], BOILERPLATE_MIN_DOCS, BOILERPLATE_MIN_RATIO)
        for k, v in by_site.items()
    }

    rejected, ratios, ioc_total, ioc_lost, lost_ex = [], [], 0, 0, []
    resid = {k: [0, 0] for k in RESIDUALS}
    chunks_n = lossy = split_code = orphan = oversized = 0
    for aid, s, u, ct in rows:
        key = site_key(s, u) or "?"
        res = engine.process_article(ct, template.get(key) or None, u)
        if not res.is_processable:
            rejected.append((aid, key, res.reject_reason))
            continue
        md = res.clean_markdown
        ratios.append(len(md) / max(1, len(ct)))
        raw_iocs, clean_iocs = ioc_set(ct), ioc_set(md)
        ioc_total += len(raw_iocs)
        lost = raw_iocs - clean_iocs
        ioc_lost += len(lost)
        if lost:
            lost_ex.append((len(lost), aid, key, sorted(lost)[:2]))
        for name, pat in RESIDUALS.items():
            resid[name][0] += bool(re.search(pat, ct))
            resid[name][1] += bool(re.search(pat, md))
        parts = engine.chunk_markdown(md, args.chunk_chars)
        chunks_n += len(parts)
        rebuilt = "\n\n".join(c.text for c in parts)
        norm = lambda t: re.sub(r"[ \t]+\n", "\n", t)  # noqa: E731 (lignes d'espaces du code indenté)
        lossy += norm(rebuilt) != norm(md)
        for c in parts:
            oversized += c.oversized
            split_code += c.text.count("```") % 2 and md.count("```") % 2 == 0
            orphan += bool(re.search(r"(?m)^#{1,6} [^\n]*\Z", c.text))

    ok = len(rows) - len(rejected)
    print(f"\n== Articles : {len(rows)} | traités : {ok} | rejetés : {len(rejected)}")
    for aid, key, why in rejected[:10]:
        print(f"   rejet {aid} [{key}] : {why}")
    print(f"== Texte conservé : médiane {statistics.median(ratios):.2f} | p10 {sorted(ratios)[len(ratios) // 10]:.2f}")
    pct = 100 * ioc_lost / max(1, ioc_total)
    print(f"== Fidélité IOC : {ioc_lost}/{ioc_total} perdus ({pct:.2f} %)")
    for n, aid, key, ex in sorted(lost_ex, reverse=True)[:5]:
        print(f"   {n} perdus dans {aid} [{key}] ex. {ex}")
    print("== Résidus (articles brut -> nettoyé)")
    for name, (a, b) in resid.items():
        print(f"   {name:20s} {a:5d} -> {b:5d}")
    print(
        f"== Découpage ({args.chunk_chars} car.) : {chunks_n} segments | non reconstructibles : {lossy} | "
        f"code coupé : {split_code} | titres orphelins : {orphan} | blocs atomiques surdimensionnés : {oversized}"
    )

    # Fuite de gabarit sur source inconnue : le gabarit réel de chaque site survit-il sans apprentissage ?
    print("== Source inconnue (gabarit non appris) : lignes de gabarit restantes par article")
    for key, docs in sorted(by_site.items(), key=lambda kv: -len(kv[1])):
        oracle = set(template[key])
        if len(docs) < BOILERPLATE_MIN_DOCS or not oracle:
            continue
        sample = docs[:: max(1, len(docs) // 40)][:40]
        left = []
        for u, ct in sample:
            res = engine.process_article(ct, None, u)
            if res.is_processable:
                lines = {engine.normalize_line(l) for l in res.clean_markdown.split("\n") if l.strip() and l[0] != "#"}
                left.append(len(lines & oracle))
        print(f"   {key:26s} gabarit réel {len(oracle):3d} lignes | restantes : {statistics.mean(left):5.2f}")


if __name__ == "__main__":
    main()
