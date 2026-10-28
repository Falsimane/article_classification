"""Objets STIX 2.1 d'un article, créés avec les classes de la bibliothèque officielle `stix2`.

Chaque objet est une instance de `stix2` (`Malware`, `Relationship`, `Report`…) créée en mode strict : une propriété
obligatoire absente, une valeur invalide ou une propriété inconnue lève une exception de `stix2` dès la création. Le
bundle est un `stix2.Bundle`, sérialisé par `stix2`.

Seul ajout du projet : un identifiant déterministe pour les SDO et les relations (`deterministic_id`). `stix2` tire un
UUIDv4 au hasard, ce qui ferait d'un même malware cité par deux articles deux nœuds distincts dans Neo4j. Les observables
(`Software`, `IPv4Address`…) gardent l'identifiant que `stix2` calcule lui-même selon la norme.
"""

import json
import uuid
from datetime import datetime, timezone

from stix2 import (
    TLP_WHITE,
    Bundle,
    Campaign,
    ExternalReference,
    Identity,
    Infrastructure,
    IntrusionSet,
    Location,
    Malware,
    Relationship,
    Report,
    Software,
    ThreatActor,
    Tool,
    Vulnerability,
)

from backend.preprocessing.cleaning.text.evidence import normalize_name

# Espace de noms fixe du projet : ne jamais le modifier, sous peine de changer tous les identifiants.
PROJECT_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://cti-knowledge-graph.local/stix/2.1")

# Entités que l'agent peut déclarer (couche sémantique) ; les techniques ATT&CK sont les objets officiels de MITRE
ENTITY_CLASSES = {
    "intrusion-set": IntrusionSet,
    "threat-actor": ThreatActor,
    "campaign": Campaign,
    "malware": Malware,
    "tool": Tool,
    "infrastructure": Infrastructure,
    "vulnerability": Vulnerability,
    "identity": Identity,
    "location": Location,
    "software": Software,
}


def deterministic_id(stix_type: str, **key: str) -> str:
    """`<type>--<uuid5>` : réextraire le même fait produit le même identifiant. `key` : propriétés qui fondent l'identité."""
    canonical = "|".join(f"{k}={v}" for k, v in key.items())
    return f"{stix_type}--{uuid.uuid5(PROJECT_NAMESPACE, f'{stix_type}|{canonical}')}"


def _name_key(name: str) -> str:
    return normalize_name(name) or name.casefold()


class ArticleContext:
    """Auteur (éditeur de l'article), marquage TLP:CLEAR et horodatage communs aux objets d'un article."""

    def __init__(self, source_id: int, site_name: str | None, url: str | None, title: str | None, now: datetime | None = None):
        self.source_id = source_id
        self.now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        name = site_name or "unknown-source"
        self.publisher = Identity(
            id=deterministic_id("identity", identity_class="organization", name=_name_key(name)),
            name=name, identity_class="organization", created=self.now, modified=self.now,
        )  # fmt: skip
        self.article_ref = {k: v for k, v in {"source_name": name, "url": url, "description": title}.items() if v}

    @property
    def common(self) -> dict:
        """Propriétés communes des SDO et des relations de l'article."""
        return {"created": self.now, "modified": self.now, "created_by_ref": self.publisher.id, "object_marking_refs": [TLP_WHITE.id]}

    def citations(self, quotes: list[str]) -> list[ExternalReference]:
        """Une référence externe par citation : l'article (source, URL) et le passage qui étaye l'objet."""
        return [ExternalReference(**{**self.article_ref, "description": q}) for q in quotes]


def entity(stix_type: str, name: str, ctx: ArticleContext, **props):
    """Entité nommée, créée par la classe `stix2` de son type. Les exceptions de `stix2` (propriété manquante, valeur
    invalide, propriété inconnue) sont la vérification STIX de l'objet : l'appelant les renvoie au modèle."""
    if stix_type not in ENTITY_CLASSES:
        raise ValueError(f"type « {stix_type} » hors périmètre (types : {', '.join(ENTITY_CLASSES)})")
    if stix_type == "software":  # observable : identifiant calculé par stix2 selon la norme, ni auteur ni dates
        return Software(name=name, object_marking_refs=[TLP_WHITE.id], **props)
    if stix_type == "vulnerability":
        cve = next((r["external_id"] for r in props.get("external_references", []) if r.get("source_name") == "cve"), None)
        key = {"cve": cve.upper()} if cve else {"name": _name_key(name)}
    elif stix_type == "location":
        key = {"country": props["country"].upper()} if props.get("country") else {"region": props.get("region", _name_key(name))}
    elif stix_type == "identity":
        key = {"identity_class": props.get("identity_class", ""), "name": _name_key(name)}
    else:
        key = {"name": _name_key(name)}
    if stix_type == "malware":
        props.setdefault("is_family", True)  # propriété obligatoire ; un article nomme presque toujours une famille
    return ENTITY_CLASSES[stix_type](id=deterministic_id(stix_type, **key), name=name, **ctx.common, **props)


def relationship(rel_type: str, source_ref: str, target_ref: str, ctx: ArticleContext, quotes: list[str], confidence: int | None = None) -> Relationship:
    """`stix2.Relationship` ; ses preuves sont la description et une référence externe par citation."""
    props = {"description": " | ".join(quotes), "external_references": ctx.citations(quotes)} if quotes else {}
    if confidence is not None:
        props["confidence"] = confidence
    return Relationship(
        id=deterministic_id("relationship", relationship_type=rel_type, source_ref=source_ref, target_ref=target_ref),
        relationship_type=rel_type, source_ref=source_ref, target_ref=target_ref, **ctx.common, **props,
    )  # fmt: skip


def report(ctx: ArticleContext, name: str, published: datetime | None, object_refs: list[str], labels: list[str] | None = None) -> Report:
    """L'article : `stix2.Report` dont `object_refs` liste tout ce qui en a été extrait."""
    extra = {"external_references": [ExternalReference(**ctx.article_ref)]} if ctx.article_ref.get("source_name") else {}
    if labels:
        extra["labels"] = labels
    return Report(
        id=deterministic_id("report", source_id=str(ctx.source_id)), name=name or f"article {ctx.source_id}",
        report_types=["threat-report"], published=published or ctx.now, object_refs=object_refs or [ctx.publisher.id],
        **ctx.common, **extra,
    )  # fmt: skip


def bundle(objects: list) -> Bundle:
    """`stix2.Bundle` de l'article. Les objets ATT&CK y figurent tels que MITRE les publie, avec leurs propriétés `x_mitre_*`
    (personnalisées, conformes à la norme) : le bundle les admet ; les objets du projet ont été créés en mode strict."""
    unique = list({o["id"]: o for o in objects}.values())
    return Bundle(objects=unique, allow_custom=True)


def as_dict(obj) -> dict:
    """Forme JSON d'un objet `stix2`, sérialisé par `stix2` (pour Neo4j et les modules qui lisent des dictionnaires)."""
    return json.loads(obj.serialize())
