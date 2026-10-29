"""Rapport de qualité du preprocessing sur le corpus (ou sur une seule source).

À lancer avant d'ingérer une nouvelle source :

    uv run python backend/preprocessing/classifying/evaluate_cleaning.py
    uv run python backend/preprocessing/classifying/evaluate_cleaning.py --site rapid7

Il mesure, sans appeler aucun LLM et sans rien écrire en base, sur les pages HTML des articles :
- les rejets (page absente, vide, page d'erreur, contenu insuffisant) et la part du texte visible conservée ;
- la fidélité des IOC (hash, IP, CVE du texte visible de la page absents du nettoyé : une partie est légitime,
  les CVE des articles liés ou des menus) ;
- les résidus de bruit connus (`hxxp`, `[.]`, shortcodes, `Related …`) ;
- les propriétés du découpage (sans perte, sans bloc de code coupé, sans titre orphelin) ;
- la fuite de gabarit sur une source inconnue : textes du gabarit réel du site qui survivent
  quand le gabarit n'est PAS encore appris.
"""

import argparse
import re
import sqlite3
import statistics
import sys
from pathlib import Path

root_dir = Path(__file__).resolve().parents[3]
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from backend.preprocessing.cleaning.cleaner import (  # noqa: E402
    BOILERPLATE_MIN_DOCS,
    DB_PATH,
    UniversalCTICleaner,
    load_html,
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
    "hxxp": r"(?i)hxxp",
    "[.] / [at]": r"\[\.\]|(?i:\[at\])",
    "shortcode attribut": r"\[/?[a-z]+_[a-z_]+[^\]]*=",
    "titre Related": r"(?im)^#+\s*related",
    "Share:": r"(?m)^Share:",
}

engine = UniversalCTICleaner._engine


def ioc_set(text: str) -> set:
    text = engine.refang(text)
    return {(k, m.lower()) for k, p in IOC_PATTERNS.items() for m in re.findall(p, text)}


def norm(line: str) -> str:
    """Forme d'une clé de gabarit (`html_template_keys`) : minuscules, chiffres -> 0, espaces repliés."""
    return " ".join(re.sub(r"\d", "0", line.lower()).split())


def load(site: str | None):
    """(id, clé de source, url, html ou None) des articles de `knowledge`."""
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    rows = conn.execute("SELECT id, site_name, url FROM knowledge WHERE url IS NOT NULL ORDER BY id").fetchall()
    out = []
    for aid, s, u in rows:
        key = site_key(s, u) or "?"
        if site and key != site:
            continue
        out.append((aid, key, u, load_html(s, u)))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--site", help="se limiter à une source (site_name ou domaine)")
    ap.add_argument("--chunk-chars", type=int, default=7500)
    args = ap.parse_args()

    rows = load(args.site)
    if not rows:
        sys.exit("Aucun article.")

    # Gabarit appris sur le corpus (cas nominal d'une source déjà connue)
    counts: dict[str, tuple] = {}
    for _, key, _, html in rows:
        if html is not None:
            n, c = counts.get(key, (0, {}))
            for k in engine.html_template_keys(html):
                c[k] = c.get(k, 0) + 1
            counts[key] = (n + 1, c)
    from collections import Counter
    template = {k: UniversalCTICleaner.frequent_keys(n, Counter(c)) for k, (n, c) in counts.items()}

    rejected, ratios, ioc_total, ioc_lost, lost_ex = [], [], 0, 0, []
    resid = {k: [0, 0] for k in RESIDUALS}
    chunks_n = lossy = split_code = orphan = oversized = 0
    for aid, key, u, html in rows:
        if html is None:
            rejected.append((aid, key, "Page HTML absente"))
            continue
        res = engine.process_html(html, template.get(key) or None, u)
        if not res.is_processable:
            rejected.append((aid, key, res.reject_reason))
            continue
        md, page = res.clean_markdown, engine.html_text(html)
        ratios.append(len(md) / max(1, len(page)))
        raw_iocs, clean_iocs = ioc_set(page), ioc_set(md)
        ioc_total += len(raw_iocs)
        lost = raw_iocs - clean_iocs
        ioc_lost += len(lost)
        if lost:
            lost_ex.append((len(lost), aid, key, sorted(lost)[:2]))
        for name, pat in RESIDUALS.items():
            resid[name][0] += bool(re.search(pat, page))
            resid[name][1] += bool(re.search(pat, md))
        parts = engine.chunk_markdown(md, args.chunk_chars)
        chunks_n += len(parts)
        rebuilt = "\n\n".join(c.text for c in parts)
        strip = lambda t: re.sub(r"[ \t]+\n", "\n", t)  # noqa: E731 (lignes d'espaces du code indenté)
        lossy += strip(rebuilt) != strip(md)
        for c in parts:
            oversized += c.oversized
            split_code += c.text.count("```") % 2 and md.count("```") % 2 == 0
            orphan += bool(re.search(r"(?m)^#{1,6} [^\n]*\Z", c.text))

    ok = len(rows) - len(rejected)
    print(f"\n== Articles : {len(rows)} | traités : {ok} | rejetés : {len(rejected)}")
    for aid, key, why in rejected[:10]:
        print(f"   rejet {aid} [{key}] : {why}")
    print(f"== Texte visible conservé : médiane {statistics.median(ratios):.2f} | p10 {sorted(ratios)[len(ratios) // 10]:.2f}")
    pct = 100 * ioc_lost / max(1, ioc_total)
    print(f"== IOC du texte visible absents du nettoyé : {ioc_lost}/{ioc_total} ({pct:.2f} %)")
    for n, aid, key, ex in sorted(lost_ex, reverse=True)[:5]:
        print(f"   {n} absents dans {aid} [{key}] ex. {ex}")
    print("== Résidus (pages avec le motif : texte visible -> nettoyé)")
    for name, (a, b) in resid.items():
        print(f"   {name:20s} {a:5d} -> {b:5d}")
    print(
        f"== Découpage ({args.chunk_chars} car.) : {chunks_n} segments | non reconstructibles : {lossy} | "
        f"code coupé : {split_code} | titres orphelins : {orphan} | blocs atomiques surdimensionnés : {oversized}"
    )

    # Fuite de gabarit sur source inconnue : le gabarit réel de chaque site survit-il sans apprentissage ?
    print("== Source inconnue (gabarit non appris) : textes de gabarit restants par article")
    by_site: dict[str, list] = {}
    for _, key, u, html in rows:
        if html is not None:
            by_site.setdefault(key, []).append((u, html))
    for key, docs in sorted(by_site.items(), key=lambda kv: -len(kv[1])):
        oracle = set(template.get(key) or ())
        if len(docs) < BOILERPLATE_MIN_DOCS or not oracle:
            continue
        sample = docs[:: max(1, len(docs) // 40)][:40]
        left = []
        for u, html in sample:
            res = engine.process_html(html, None, u)
            if res.is_processable:
                lines = {norm(l) for l in res.clean_markdown.split("\n") if l.strip() and l[0] != "#"}
                left.append(len(lines & oracle))
        print(f"   {key:26s} gabarit réel {len(oracle):3d} textes | restants : {statistics.mean(left):5.2f}")


if __name__ == "__main__":
    main()
