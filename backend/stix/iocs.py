"""IOC en STIX 2.1, construits avec `stix2` : observables, indicateurs, observations datées, infrastructure, vieillissement.

    observable (DomainName, IPv4Address, URL, File…)          la donnée brute ; identifiant calculé par stix2 (norme)
      ^ based-on
    Indicator  (motif construit par stix2.patterns)           « cette valeur est malveillante »
      -- indicates --> infrastructure | malware | outil | acteur | campagne
    Sighting   (first_seen = last_seen = date de l'article)   UNE PAR ARTICLE, jamais écrasée par la suivante
    Infrastructure --consists-of--> observable, sujet --uses--> Infrastructure   (adresses, domaines, URL, courriel)

Le motif d'un indicateur n'est pas écrit à la main : il est assemblé avec `ObjectPath`, `EqualityComparisonExpression` et
`ObservationExpression`, et `stix2.Indicator` le valide à la création.

Le STATUT (actif, vieillissant, périmé) n'est jamais stocké : il se calcule à la lecture, avec la table `LIFETIMES`.
"""

from dataclasses import dataclass
from datetime import datetime

from stix2 import (
    URL,
    DomainName,
    EmailAddress,
    EqualityComparisonExpression,
    File,
    HashConstant,
    Indicator,
    Infrastructure,
    IPv4Address,
    IPv6Address,
    ObjectPath,
    ObservationExpression,
    OrBooleanExpression,
    Sighting,
    StringConstant,
)

from .objects import ArticleContext, deterministic_id, relationship

HASH_ALGOS = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
HASH_ORDER = ("MD5", "SHA-1", "SHA-256")  # ordre des hachages d'un motif : l'identifiant de l'indicateur ne dépend pas de l'article
HASH_PRIORITY = HASH_ORDER[::-1]  # valeur affichée d'un fichier : le hachage le plus fort
IOC_OBJECT_TYPES = frozenset({"indicator", "sighting", "ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr", "file"})

# rôle -> valeur du vocabulaire indicator-type-ov (les autres rôles : malicious-activity)
INDICATOR_TYPE = {"unknown": "unknown", "not-malicious": "benign"}
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
_OBSERVABLES = {"ipv4-addr": IPv4Address, "ipv6-addr": IPv6Address, "domain-name": DomainName, "url": URL, "email-addr": EmailAddress}


@dataclass
class IocFinding:
    """Un IOC retenu pour un article, avec son rôle et ce auquel il se rattache."""

    kind: str  # type STIX de l'observable
    value: str  # valeur normalisée ; pour un fichier, son hachage le plus fort
    algo: str | None  # algorithme de ce hachage (kind == "file")
    role: str  # un élément de ROLES
    quote: str  # phrase ou ligne où il apparaît : sa preuve
    heading: str = ""
    attach_id: str | None = None  # identifiant STIX de l'entité à laquelle il se rattache
    attach_type: str | None = None
    attach_name: str | None = None
    observed: datetime | None = None  # date explicite dans le texte (sinon : date de l'article)
    confidence: int = 50
    hashes: dict[str, str] | None = None  # fichier : tous ses hachages (« MD5 », « SHA-1 », « SHA-256 ») ; sinon {algo: value}
    name: str | None = None  # fichier : nom donné avec ses hachages

    def file_hashes(self) -> dict[str, str]:
        known = self.hashes or {self.algo: self.value}
        return {a: known[a] for a in sorted(known, key=lambda a: HASH_ORDER.index(a) if a in HASH_ORDER else len(HASH_ORDER))}


def observable(f: IocFinding, marking: list[str]):
    """Observable `stix2` de l'IOC ; son identifiant est celui que la norme définit (UUIDv5 des propriétés contributrices)."""
    if f.kind == "file":
        return File(hashes=f.file_hashes(), object_marking_refs=marking, **({"name": f.name} if f.name else {}))
    if f.kind not in _OBSERVABLES:
        raise ValueError(f"type d'observable non géré : {f.kind!r}")
    return _OBSERVABLES[f.kind](value=f.value, object_marking_refs=marking)


def pattern(f: IocFinding) -> str:
    """Motif STIX de l'IOC, assemblé par `stix2.patterns`. Un fichier décrit par plusieurs hachages : n'importe lequel le
    désigne ; le nom, lui, n'identifie rien."""
    if f.kind == "file":
        tests = [EqualityComparisonExpression(ObjectPath("file", ["hashes", a]), HashConstant(v, a)) for a, v in f.file_hashes().items()]
        return str(ObservationExpression(tests[0] if len(tests) == 1 else OrBooleanExpression(tests)))
    return str(ObservationExpression(EqualityComparisonExpression(ObjectPath(f.kind, ["value"]), StringConstant(f.value))))


def build_ioc_objects(findings: list[IocFinding], ctx: ArticleContext, published: datetime | None) -> list:
    """Objets `stix2` des IOC d'un article.

    Un IOC `not-malicious` (jugé non malveillant par le modèle) garde son observable, un indicateur `benign` et son observation
    (la phrase qui le cite), sans relation vers l'attaque : il reste auditable. `without_benign` le retire avant Neo4j.
    Sans date d'article ni date explicite, aucune observation n'est émise : une date inventée fausserait le statut."""
    objects: dict[str, object] = {}

    def add(obj) -> None:
        objects.setdefault(obj["id"], obj)

    marking = ctx.common["object_marking_refs"]
    for f in sorted(findings, key=lambda f: (f.kind, f.value)):
        sco = observable(f, marking)
        add(sco)
        seen = f.observed or published
        motif = pattern(f)
        indicator = Indicator(
            id=deterministic_id("indicator", pattern_type="stix", pattern=motif), name=f.value,
            indicator_types=[INDICATOR_TYPE.get(f.role, "malicious-activity")], pattern=motif, pattern_type="stix",
            valid_from=seen or ctx.now, labels=[f.role], confidence=f.confidence, **ctx.common,
        )  # fmt: skip
        add(indicator)
        add(relationship("based-on", indicator.id, sco.id, ctx, []))
        if seen:
            add(Sighting(
                id=deterministic_id("sighting", sighting_of_ref=indicator.id, where_sighted_refs=ctx.publisher.id, first_seen=seen.isoformat()),
                sighting_of_ref=indicator.id, where_sighted_refs=[ctx.publisher.id], first_seen=seen, last_seen=seen, count=1,
                description=f.quote, **ctx.common,
            ))  # fmt: skip

        if f.role == "not-malicious":
            continue  # aucune relation : ni infrastructure de l'attaquant, ni entité indiquée
        subject = f.attach_id if f.attach_id and f.attach_type else None
        if f.kind == "file" or f.role == "malware-sample":
            if subject:
                add(relationship("indicates", indicator.id, subject, ctx, [f.quote], f.confidence))
            continue
        # Réseau : l'indicateur désigne une infrastructure, existante (nommée par le texte) ou dérivée du sujet et du rôle
        if subject and f.attach_type == "infrastructure":
            infra = subject
        else:
            infra_type, infra_label = ROLE_INFRASTRUCTURE.get(f.role, ROLE_INFRASTRUCTURE["unknown"])
            name = f"{infra_label} — {f.attach_name}" if f.attach_name else infra_label
            obj = Infrastructure(id=deterministic_id("infrastructure", name=name.casefold()), name=name, infrastructure_types=[infra_type], **ctx.common)
            add(obj)
            infra = obj.id
            if subject:
                add(relationship("uses", subject, infra, ctx, [f.quote], f.confidence))
        add(relationship("indicates", indicator.id, infra, ctx, [f.quote], f.confidence))
        add(relationship("consists-of", infra, sco.id, ctx, [f.quote], f.confidence))
    return list(objects.values())


def without_benign(objects: list) -> list:
    """Objets d'un article sans les IOC jugés non malveillants (indicateur `benign`, son observation, sa relation `based-on`,
    et l'observable qu'aucun autre objet ne cite). Le bundle de l'article les garde pour l'audit ; le Knowledge Graph non :
    l'indicateur d'une valeur est partagé entre articles, et le verdict d'un article écraserait celui d'un autre.
    Objets `stix2` ou leur forme JSON (accès par clé), sans le `report` : l'appelant le crée ensuite sur ce qui reste."""
    benign = {o["id"] for o in objects if o["type"] == "indicator" and "benign" in (o.get("indicator_types") or [])}
    if not benign:
        return objects
    rels = [o for o in objects if o["type"] == "relationship"]
    gone = benign | {o["id"] for o in objects if o["type"] == "sighting" and o["sighting_of_ref"] in benign}
    gone |= {r["id"] for r in rels if r["source_ref"] in benign or r["target_ref"] in benign}
    cited = {r[k] for r in rels if r["id"] not in gone for k in ("source_ref", "target_ref")}
    gone |= {r["target_ref"] for r in rels if r["source_ref"] in benign and r["relationship_type"] == "based-on" and r["target_ref"] not in cited}
    return [o for o in objects if o["id"] not in gone]


# --- Vieillissement ----------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Lifetime:
    active_days: int  # jusqu'à cet âge, depuis la dernière observation : « actif probable »
    stale_days: int  # au-delà : « périmé » ; entre les deux : « vieillissant »


# ATTENTION : valeurs de départ HEURISTIQUES, non calibrées sur des données publiées (une adresse IP est réattribuée vite, un
# domaine dure plus longtemps, un hachage reste vrai mais se change trivialement). À mesurer avant d'en tirer un blocage.
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
