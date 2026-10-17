"""Données de référence du filtrage des IOC (`reference/tlds.txt`, `reference/popular_domains.txt`).

    uv run python -m backend.ontology.stix.update_ioc_reference

Sources :
- liste officielle des TLD de l'IANA (https://data.iana.org/TLD/tlds-alpha-by-domain.txt) : un « nom.ext » n'est un
  domaine que si `ext` est un TLD réel ;
- Tranco (https://tranco-list.eu), classement agrégé de popularité (Cisco Umbrella, Majestic, Chrome UX, Cloudflare
  Radar, Farsight) conçu pour la recherche : un domaine très populaire est presque toujours un service légitime, donc
  jamais un IOC en tant que domaine (une URL sur ce domaine reste possible : service légitime abusé).

Ce sont des DONNÉES versionnées avec leur date, pas du code : elles se mettent à jour sans toucher à l'extracteur.
"""

import json
import urllib.request
import zipfile
import io
from datetime import date
from pathlib import Path

REFERENCE = Path(__file__).resolve().parent / "reference"
TLD_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
TRANCO_LATEST = "https://tranco-list.eu/api/lists/date/latest"
POPULAR_TOP_N = 5000


def _get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=120) as resp:
        return resp.read()


def update_tlds() -> int:
    lines = _get(TLD_URL).decode().splitlines()
    tlds = sorted({l.strip().lower() for l in lines if l.strip() and not l.startswith("#")})
    header = f"# source: {TLD_URL}\n# {lines[0].lstrip('# ')}\n# mis à jour le {date.today().isoformat()}\n"
    (REFERENCE / "tlds.txt").write_text(header + "\n".join(tlds) + "\n", encoding="utf-8")
    return len(tlds)


def update_popular() -> int:
    meta = json.loads(_get(TRANCO_LATEST))
    raw = _get(meta["download"])
    try:  # le téléchargement est un CSV (rang,domaine), parfois zippé
        raw = zipfile.ZipFile(io.BytesIO(raw)).read(zipfile.ZipFile(io.BytesIO(raw)).namelist()[0])
    except zipfile.BadZipFile:
        pass
    domains = [line.split(",")[1].strip().lower() for line in raw.decode().splitlines()[:POPULAR_TOP_N] if "," in line]
    header = f"# source: Tranco liste {meta['list_id']} ({meta['created_on'][:10]}), {POPULAR_TOP_N} premiers domaines, par rang\n# mis à jour le {date.today().isoformat()}\n"
    (REFERENCE / "popular_domains.txt").write_text(header + "\n".join(domains) + "\n", encoding="utf-8")
    return len(domains)


if __name__ == "__main__":
    print(f"{update_tlds()} TLD, {update_popular()} domaines populaires")
