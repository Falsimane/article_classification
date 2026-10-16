"""Construit la base de référence ATT&CK locale (`reference/attack_enterprise.json`).

    uv run python -m backend.ontology.stix.update_reference

Source : jeu de données STIX 2.1 officiel de MITRE (https://github.com/mitre-attack/attack-stix-data).
Seuls les champs utiles à la résolution d'entités sont conservés (identifiant ATT&CK, nom, alias, tactiques) :
elle sert à ancrer les entités extraites (technique T1059.001 <-> « PowerShell », groupe G0016 <-> « APT29 »).
Les objets révoqués ou dépréciés sont CONSERVÉS avec leur statut et leur remplaçant (`replaced_by`) : un
article qui cite un identifiant d'une version antérieure (T1086, T1562.001…) doit être corrigé, pas rejeté.
"""

import json
import sys
import tempfile
import urllib.request
from datetime import date
from pathlib import Path

DATA_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
)
OUTPUT = Path(__file__).resolve().parent / "reference" / "attack_enterprise.json"
NOTICE = (
    "© The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE "
    "Corporation. ATT&CK® is a registered trademark of The MITRE Corporation."
)


def attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def status_of(obj: dict) -> str:
    return "revoked" if obj.get("revoked") else "deprecated" if obj.get("x_mitre_deprecated") else "active"


def build(bundle: dict) -> dict:
    objs = bundle["objects"]
    by_id = {o["id"]: o for o in objs}
    collection = next((o for o in objs if o["type"] == "x-mitre-collection"), {})
    # `revoked-by` : identifiant ATT&CK de l'objet qui remplace un objet révoqué
    replaced_by = {
        r["source_ref"]: attack_id(by_id[r["target_ref"]])
        for r in objs
        if r["type"] == "relationship" and r["relationship_type"] == "revoked-by" and r["target_ref"] in by_id
    }

    def entry(o: dict, **extra) -> dict:
        e = {"id": attack_id(o), "name": o["name"], **extra}
        if status_of(o) != "active":
            e["status"] = status_of(o)
            if o["id"] in replaced_by:
                e["replaced_by"] = replaced_by[o["id"]]
        return e

    def aliases(o: dict, key: str) -> list:
        return sorted(set(o.get(key, [])) - {o["name"]})

    def collect(types: tuple, build_entry) -> list:
        return sorted((build_entry(o) for o in objs if o["type"] in types and attack_id(o)), key=lambda e: e["id"])

    tactics = sorted(
        (
            {"id": attack_id(o), "name": o["name"], "shortname": o["x_mitre_shortname"]}
            for o in objs
            if o["type"] == "x-mitre-tactic" and status_of(o) == "active"
        ),
        key=lambda t: t["id"],
    )
    # Triplets (type source, relation, type cible) réellement utilisés par ATT&CK, hors objets propres à MITRE :
    # sert à vérifier que la table de relations de l'ontologie couvre ce que les données publient.
    triplets: dict[tuple[str, str, str], int] = {}
    for r in objs:
        if r["type"] != "relationship" or r.get("revoked") or r.get("x_mitre_deprecated"):
            continue
        src, dst = by_id.get(r["source_ref"], {}), by_id.get(r["target_ref"], {})
        if src.get("type", "x-").startswith("x-") or dst.get("type", "x-").startswith("x-"):
            continue
        key = (src["type"], r["relationship_type"], dst["type"])
        triplets[key] = triplets.get(key, 0) + 1

    return {
        "meta": {
            "source": "https://github.com/mitre-attack/attack-stix-data",
            "attack_version": collection.get("x_mitre_version"),
            "retrieved": date.today().isoformat(),
            "notice": NOTICE,
            "relationship_triplets": [[*k, n] for k, n in sorted(triplets.items())],
        },
        "tactics": tactics,
        "techniques": collect(
            ("attack-pattern",),
            lambda o: entry(
                o,
                tactics=[
                    p["phase_name"] for p in o.get("kill_chain_phases", []) if p["kill_chain_name"] == "mitre-attack"
                ],
                subtechnique=bool(o.get("x_mitre_is_subtechnique")),
            ),
        ),
        "groups": collect(("intrusion-set",), lambda o: entry(o, aliases=aliases(o, "aliases"))),
        "software": collect(
            ("malware", "tool"), lambda o: entry(o, type=o["type"], aliases=aliases(o, "x_mitre_aliases"))
        ),
        "campaigns": collect(("campaign",), lambda o: entry(o, aliases=aliases(o, "aliases"))),
    }


def main(url: str = DATA_URL) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        raw = Path(tmp) / "enterprise-attack.json"
        with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310 (URL fixe, HTTPS)
            raw.write_bytes(resp.read())
        data = build(json.loads(raw.read_text(encoding="utf-8")))
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    n_old = sum(1 for k in ("techniques", "groups", "software", "campaigns") for e in data[k] if "status" in e)
    print(
        f"ATT&CK {data['meta']['attack_version']} : {len(data['tactics'])} tactiques, "
        f"{len(data['techniques'])} techniques, {len(data['groups'])} groupes, "
        f"{len(data['software'])} logiciels, {len(data['campaigns'])} campagnes "
        f"(dont {n_old} révoqués/dépréciés conservés) -> {OUTPUT}"
    )


if __name__ == "__main__":
    main(*sys.argv[1:2])
