"""Index des noms de MISP Galaxy (acteurs, familles de malwares, outils malveillants) : type connu et alias d'un nom, comme ATT&CK.

    uv run python -m backend.stix.galaxy          # télécharge les clusters et écrit reference/misp_galaxy.json

Base publique et versionnée (https://github.com/MISP/misp-galaxy), au même titre qu'ATT&CK : ses synonymes désignent la même entité
(« UNC1151 » et « Ghostwriter » ne font plus deux groupes) et ce qu'elle recense est montré au modèle comme un indice ; le type,
lui, reste choisi par le modèle d'après les phrases (un nom recensé peut désigner ailleurs une victime ou un produit légitime).
Un cluster qui partage un nom avec ATT&CK prend l'identifiant ATT&CK, pour ne former qu'un candidat avec lui.
"""

import json
import sys
import urllib.request
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from backend.extracting.evidence import normalize_name

REFERENCE = Path(__file__).resolve().parent / "reference" / "misp_galaxy.json"
BASE_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/{}.json"
SOURCES = {  # cluster MISP -> type STIX ; le cluster « tool » de MISP recense des outils MALVEILLANTS (chevaux de Troie, RAT)
    "threat-actor": "intrusion-set", "malpedia": "malware", "tool": "malware", "ransomware": "malware", "rat": "malware",
}  # fmt: skip
MIN_LENGTH = 4  # « APT » ou « Ace » seuls ne sont pas des noms sûrs


@dataclass(frozen=True)
class Cluster:
    key: str  # « galaxy:<uuid> »
    stix_type: str
    name: str
    synonyms: tuple[str, ...]
    country: str = ""


def build(out: Path = REFERENCE) -> int:
    rows = []
    for source, stix_type in SOURCES.items():
        with urllib.request.urlopen(BASE_URL.format(source), timeout=120) as resp:
            data = json.load(resp)
        for v in data.get("values", []):
            meta = v.get("meta") or {}
            name = (v.get("value") or "").strip()
            if not name:
                continue
            synonyms = sorted({s.strip() for s in meta.get("synonyms", []) if isinstance(s, str) and s.strip() and s.strip() != name})
            country = meta.get("country") if isinstance(meta.get("country"), str) else ""
            rows.append({"uuid": v.get("uuid"), "source": source, "type": stix_type, "name": name, "synonyms": synonyms, "country": country})
    out.write_text(json.dumps({"version": "misp-galaxy main", "clusters": rows}, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    return len(rows)


@lru_cache(maxsize=1)
def names_index() -> dict[str, tuple[Cluster, ...]]:
    """Nom ou synonyme normalisé -> clusters. Vide si l'index n'a pas été construit."""
    if not REFERENCE.exists():
        return {}
    from backend.extracting.places import resolve_location
    from backend.stix.attack import get_attack_kb

    attack = get_attack_kb().names_index()
    index: dict[str, list[Cluster]] = {}
    for row in json.loads(REFERENCE.read_text(encoding="utf-8"))["clusters"]:
        names = [x for x in [row["name"], *row["synonyms"]] if not any(resolve_location(x, ""))]  # « Iran » n'est pas un groupe
        norms = [n for n in dict.fromkeys(normalize_name(x) for x in names) if len(n) >= MIN_LENGTH]
        shared = next((attack[n][0] for n in norms if n in attack), None)  # même entité qu'ATT&CK : même clé de candidat
        cluster = Cluster(shared or f"galaxy:{row['uuid']}", row["type"], row["name"], tuple(row["synonyms"]), row.get("country") or "")
        for n in norms:
            if cluster not in index.setdefault(n, []):
                index[n].append(cluster)
    return {n: tuple(c) for n, c in index.items()}


def lookup(name: str) -> Cluster | None:
    """Le cluster d'un nom, s'il est sans ambiguïté (un seul type et une seule clé)."""
    hits = names_index().get(normalize_name(name), ())
    return hits[0] if len({(c.key, c.stix_type) for c in hits}) == 1 else None


_KIND = {"intrusion-set": "groupe d'attaquants", "malware": "logiciel malveillant"}


def describe(cluster: Cluster) -> str:
    """Indice pour le modèle : ce que la base recense sous ce nom, avec quelques synonymes."""
    also = ", ".join(cluster.synonyms[:4])
    return f"MISP Galaxy recense « {cluster.name} » comme {_KIND.get(cluster.stix_type, cluster.stix_type)}" + (f" (aussi : {also})" if also else "")


def main(argv: list[str]) -> None:
    print(f"{build()} clusters -> {REFERENCE}")


if __name__ == "__main__":
    main(sys.argv[1:])
