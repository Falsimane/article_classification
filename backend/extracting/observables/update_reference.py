"""Données de référence du filtrage des IOC (`reference/tlds.txt`, `reference/popular_domains.txt`) et des binaires natifs
(`backend/extracting/stix/reference/native_binaries.txt`).

    uv run python -m backend.extracting.observables.update_reference

Sources :
- liste officielle des TLD de l'IANA (https://data.iana.org/TLD/tlds-alpha-by-domain.txt) : un « nom.ext » n'est un
  domaine que si `ext` est un TLD réel ;
- Tranco (https://tranco-list.eu), classement agrégé de popularité (Cisco Umbrella, Majestic, Chrome UX, Cloudflare
  Radar, Farsight) conçu pour la recherche : un domaine très populaire est presque toujours un service légitime, donc
  jamais un IOC en tant que domaine (une URL sur ce domaine reste possible : service légitime abusé) ;
- LOLBAS (https://lolbas-project.github.io), catégories Binaries, Libraries et Scripts (composants livrés avec Windows ;
  OtherMSBinaries, logiciels Microsoft installés à part, est écarté), plus les interpréteurs et utilitaires réseau livrés avec les systèmes : un
  binaire natif n'est un `tool` que s'il a un logiciel ATT&CK ; sinon seule la technique qui l'emploie est extraite
  (Annotations/methode_annotation.md, « Types d'entités »). GTFOBins n'est pas retenu : il mêle des logiciels tiers (nmap,
  7z, docker) qui restent des outils.

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
LOLBAS_URL = "https://lolbas-project.github.io/api/lolbas.json"
LOLBAS_NATIVE = ("/lolbas/Binaries/", "/lolbas/Libraries/", "/lolbas/Scripts/")
SHELLS = ("powershell", "pwsh", "cmd", "cscript", "wscript", "bash", "sh", "zsh")  # interpréteurs livrés avec le système
# Utilitaires réseau et de script livrés avec Windows 10+ et les Unix courants, absents de LOLBAS (qui ne liste que les binaires
# détournables au-delà de leur usage) ; ceux qu'ATT&CK connaît comme logiciels (ping, ipconfig, netstat…) restent des tools.
UTILITIES = ("curl", "wget", "ping", "tracert", "traceroute", "nslookup", "whoami", "choice", "timeout", "ipconfig", "ifconfig", "netstat")
NATIVE_FILE = Path(__file__).resolve().parents[1] / "stix" / "reference" / "native_binaries.txt"


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


def native_name(name: str) -> str:
    """Forme comparée d'un nom de binaire : minuscules, sans extension Windows d'exécutable."""
    name = name.strip().lower()
    for ext in (".exe", ".dll", ".vbs", ".js", ".ps1", ".cmd", ".bat", ".wsf", ".cpl", ".msc"):
        if name.endswith(ext):
            return name[: -len(ext)]
    return name


def update_native_binaries() -> int:
    entries = json.loads(_get(LOLBAS_URL))
    lolbas = {native_name(x["Name"]) for x in entries if x.get("Name") and any(c in x.get("url", "") for c in LOLBAS_NATIVE)}
    if len(lolbas) < 100:  # format changé : ne pas écrire une liste tronquée
        raise RuntimeError(f"LOLBAS : {len(lolbas)} entrées natives seulement, format à vérifier")
    names = sorted((lolbas | set(SHELLS) | set(UTILITIES)) - {""})
    header = (f"# sources : {LOLBAS_URL} (catégories {', '.join(c.strip('/').split('/')[-1] for c in LOLBAS_NATIVE)} : {len(lolbas)}), interpréteurs {', '.join(SHELLS)}, utilitaires {', '.join(UTILITIES)}\n"
              f"# minuscules, sans extension ; mis à jour le {date.today().isoformat()}\n")  # fmt: skip
    NATIVE_FILE.write_text(header + "\n".join(names) + "\n", encoding="utf-8")
    return len(names)


if __name__ == "__main__":
    import sys

    if sys.argv[1:] == ["native_binaries"]:
        print(f"{update_native_binaries()} binaires natifs")
    else:
        print(f"{update_tlds()} TLD, {update_popular()} domaines populaires, {update_native_binaries()} binaires natifs")
