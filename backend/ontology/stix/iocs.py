"""IOC en STIX 2.1 : observables, indicateurs, observations datées, infrastructure, et vieillissement.

Modèle (celui d'OpenCTI et de MISP, conforme à la norme) pour une valeur malveillante citée par un article :

    observable (SCO : ipv4-addr, domain-name, url, email-addr, file)    la donnée brute, identifiant déterministe de la norme
      ^ based-on
    indicator  (pattern STIX, valid_from = première observation)        « cette valeur est malveillante »
      -- indicates --> infrastructure | malware | outil | acteur | incident
    sighting   (first_seen = last_seen = date de l'observation)         UNE PAR ARTICLE, jamais écrasée par la suivante
    infrastructure --consists-of--> observable, sujet --uses--> infrastructure   (adresses, domaines, URL, courriel)

La date d'un article n'est pas la date de l'activité, et un indicateur cité de nouveau par un article plus récent est
une nouvelle observation, pas une correction de l'ancienne : c'est pourquoi chaque article produit son `sighting`, et
que `first_seen` / `last_seen` d'un IOC se calculent à la lecture (min / max des sightings).

Le STATUT (actif, vieillissant, périmé) n'est jamais stocké : il se calcule à la lecture, avec la table `LIFETIMES`.
"""

import json
from dataclasses import dataclass
from datetime import datetime, timezone

import stix2

from .identity import stix_id
from .relationships import is_valid_relationship

NETWORK_KINDS = ("ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr")
HASH_ALGOS = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
IOC_OBJECT_TYPES = frozenset({"indicator", "sighting", "ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr", "file"})

ROLES = ("c2", "payload-delivery", "exfiltration", "phishing", "staging-or-proxy", "malware-sample", "other-malicious", "not-malicious", "unknown")
# rôle -> (valeur du vocabulaire infrastructure-type-ov, nom de l'infrastructure dérivée)
ROLE_INFRASTRUCTURE = {
    "c2": ("command-and-control", "Command-and-control infrastructure"),
    "payload-delivery": ("hosting-malware", "Malware hosting infrastructure"),
    "exfiltration": ("exfiltration", "Exfiltration infrastructure"),
    "phishing": ("phishing", "Phishing infrastructure"),
    "staging-or-proxy": ("staging", "Staging infrastructure"),
    "other-malicious": ("unknown", "Attacker infrastructure"),
    "unknown": ("unknown", "Attacker infrastructure"),
}


@dataclass
class IocFinding:
    """Un IOC retenu pour un article, avec son rôle et ce auquel il se rattache."""

    kind: str  # type STIX de l'observable
    value: str  # valeur normalisée ; pour un fichier, le hachage
    algo: str | None  # algorithme du hachage (kind == "file")
    role: str  # un élément de ROLES
    quote: str  # phrase ou ligne où il apparaît : sa preuve
    heading: str = ""
    attach_id: str | None = None  # identifiant STIX de l'entité à laquelle il se rattache
    attach_type: str | None = None
    attach_name: str | None = None
    observed: datetime | None = None  # date explicite dans le texte (sinon : date de l'article)
    confidence: int = 50


# --- Observables et motifs ---------------------------------------------------------------------------------------------
def observable(f: IocFinding) -> dict:
    """Objet observable STIX de l'IOC. L'identifiant est celui que la norme définit (UUIDv5 des propriétés contributrices)."""
    if f.kind == "ipv4-addr":
        obj = stix2.IPv4Address(value=f.value)
    elif f.kind == "ipv6-addr":
        obj = stix2.IPv6Address(value=f.value)
    elif f.kind == "domain-name":
        obj = stix2.DomainName(value=f.value)
    elif f.kind == "url":
        obj = stix2.URL(value=f.value)
    elif f.kind == "email-addr":
        obj = stix2.EmailAddress(value=f.value)
    elif f.kind == "file":
        obj = stix2.File(hashes={f.algo: f.value})
    else:
        raise ValueError(f"type d'observable non géré : {f.kind!r}")
    return json.loads(obj.serialize())


def _quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def pattern(f: IocFinding) -> str:
    if f.kind == "file":
        return f"[file:hashes.'{f.algo}' = '{_quote(f.value)}']"
    return f"[{f.kind}:value = '{_quote(f.value)}']"


def _timestamp(moment: datetime) -> str:
    moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def _relationship(common: dict, rel_type: str, source: tuple[str, str], target: tuple[str, str], *, quote: str | None = None, confidence: int | None = None, article_ref: dict | None = None) -> dict | None:
    """Relation STIX entre deux (identifiant, type) ; None si l'ontologie ne l'admet pas."""
    if not is_valid_relationship(source[1], rel_type, target[1]):
        return None
    rel = {
        **common, "type": "relationship", "id": stix_id("relationship", {"relationship_type": rel_type, "source_ref": source[0], "target_ref": target[0]}),
        "relationship_type": rel_type, "source_ref": source[0], "target_ref": target[0],
    }  # fmt: skip
    if confidence is not None:
        rel["confidence"] = confidence
    if quote:
        rel["description"] = quote
        if article_ref:
            rel["external_references"] = [{**article_ref, "description": quote}]
    return rel


def build_ioc_objects(
    findings: list[IocFinding], *, common: dict, publisher_id: str, article_ref: dict | None, published: datetime | None, now: datetime
) -> list[dict]:
    """Tous les objets STIX des IOC d'un article. `common` : propriétés communes des SDO/SRO (dates, auteur, marquage).

    Les IOC `not-malicious` ne produisent rien (ils ne sont ni des indicateurs ni des observables de l'attaque).
    Sans date d'article ni date explicite, aucune observation n'est émise : une date inventée fausserait le statut."""
    objects: dict[str, dict] = {}
    now_ts = _timestamp(now)

    def add(obj: dict | None) -> None:
        if obj is not None:
            objects.setdefault(obj["id"], obj)

    for f in sorted((f for f in findings if f.role != "not-malicious"), key=lambda f: (f.kind, f.value)):
        sco = observable(f)
        sco["object_marking_refs"] = list(common.get("object_marking_refs", []))
        add(sco)
        seen = f.observed or published
        indicator_pattern = pattern(f)
        indicator = {
            **common, "type": "indicator", "id": stix_id("indicator", {"pattern_type": "stix", "pattern": indicator_pattern}),
            "name": f.value, "indicator_types": ["unknown" if f.role == "unknown" else "malicious-activity"],
            "pattern": indicator_pattern, "pattern_type": "stix", "valid_from": _timestamp(seen) if seen else now_ts,
            "labels": [f.role], "confidence": f.confidence,
        }  # fmt: skip
        add(indicator)
        ind = (indicator["id"], "indicator")
        add(_relationship(common, "based-on", ind, (sco["id"], f.kind)))
        if seen:
            add({
                **common, "type": "sighting", "id": stix_id("sighting", {"sighting_of_ref": indicator["id"], "where_sighted_refs": [publisher_id], "first_seen": _timestamp(seen)}),
                "sighting_of_ref": indicator["id"], "where_sighted_refs": [publisher_id],
                "first_seen": _timestamp(seen), "last_seen": _timestamp(seen), "count": 1, "description": f.quote,
            })  # fmt: skip

        subject = (f.attach_id, f.attach_type) if f.attach_id and f.attach_type else None
        if f.kind == "file" or f.role == "malware-sample":
            if subject:
                add(_relationship(common, "indicates", ind, subject, quote=f.quote, confidence=f.confidence, article_ref=article_ref))
            continue
        # Réseau : l'indicateur désigne une infrastructure, existante (nommée par le texte) ou dérivée du sujet et du rôle
        if subject and subject[1] == "infrastructure":
            infra = subject
        else:
            infra_type, infra_label = ROLE_INFRASTRUCTURE.get(f.role, ROLE_INFRASTRUCTURE["unknown"])
            name = f"{infra_label} — {f.attach_name}" if f.attach_name else infra_label
            obj = {**common, "type": "infrastructure", "id": stix_id("infrastructure", {"name": name}), "name": name, "infrastructure_types": [infra_type]}
            add(obj)
            infra = (obj["id"], "infrastructure")
            if subject:
                add(_relationship(common, "uses", subject, infra, quote=f.quote, confidence=f.confidence, article_ref=article_ref))
        add(_relationship(common, "indicates", ind, infra, quote=f.quote, confidence=f.confidence, article_ref=article_ref))
        add(_relationship(common, "consists-of", infra, (sco["id"], f.kind), quote=f.quote, confidence=f.confidence, article_ref=article_ref))
    return list(objects.values())


# --- Vieillissement ----------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Lifetime:
    active_days: int  # jusqu'à cet âge, depuis la dernière observation : « actif probable »
    stale_days: int  # au-delà : « périmé » ; entre les deux : « vieillissant »


# ATTENTION : valeurs de départ HEURISTIQUES, non calibrées sur des données publiées. Elles reflètent l'ordre de
# grandeur connu en pratique (une adresse IP est réattribuée vite, un domaine dure plus longtemps, un hachage de
# fichier reste vrai mais est trivial à changer pour l'attaquant). À remplacer par des durées mesurées avant de
# fonder une décision de blocage dessus (voir ROADMAP.md, points ouverts).
LIFETIMES: dict[str, Lifetime] = {
    "ipv4-addr": Lifetime(30, 180),
    "ipv6-addr": Lifetime(30, 180),
    "domain-name": Lifetime(90, 365),
    "url": Lifetime(60, 270),
    "email-addr": Lifetime(180, 730),
    "file": Lifetime(365, 1825),
}


def ioc_status(kind: str, last_seen: datetime | None, now: datetime) -> str:
    """`active`, `aging`, `stale` ou `unknown` (aucune date d'observation). Calculé, jamais stocké."""
    if last_seen is None:
        return "unknown"
    life = LIFETIMES[kind]
    age = (now - last_seen).days
    return "active" if age <= life.active_days else "aging" if age <= life.stale_days else "stale"
