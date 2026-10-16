"""Sorties de l'ontologie : objets STIX 2.1 conformes avec provenance, bundle, correspondance Neo4j, schéma RDF.

La conformité est vérifiée par la bibliothèque officielle `stix2` : un bundle produit ici s'importe tel quel dans
OpenCTI ou tout outil STIX 2.1.

Provenance, comme dans les plateformes CTI :
- chaque article est un objet `report` dont `object_refs` liste tout ce qui en a été extrait ;
- l'éditeur de l'article est une `identity` référencée par `created_by_ref` (auteur de l'information), jamais un
  nœud de l'attaque ;
- chaque relation garde sa citation et un renvoi vers l'article dans des champs STIX standard : `description`
  et `external_references` (une référence par citation : `source_name`, `url`, `description`), plus `confidence`.
  Aucune propriété personnalisée n'est émise : un outil tiers lit le bundle sans rien ignorer.
"""

import json
from datetime import datetime, timezone

import stix2
from rdflib import Graph, Literal, Namespace, RDF, RDFS, OWL, BNode, URIRef
from rdflib.collection import Collection

from .identity import stix_id
from .relationships import ALL_RELATIONSHIP_TYPES, _INDEX
from .schema import OBJECT_TYPES
from .validate import SanitizedGraph
from .vocab import DEFAULT_TLP

_REMOVE_EMPTY = ("aliases", "labels", "external_references", "sectors")


def _timestamp(now: datetime | None) -> str:
    now = now or datetime.now(timezone.utc)
    return now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _publisher_identity(report: dict, ts: str) -> dict:
    name = report.get("site_name") or "unknown-source"
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": stix_id("identity", {"identity_class": "organization", "name": name}),
        "created": ts,
        "modified": ts,
        "name": name,
        "identity_class": "organization",
    }


def build_stix_objects(graph: SanitizedGraph, report: dict, now: datetime | None = None) -> list[dict]:
    """Objets STIX 2.1 d'une extraction assainie, plus le `report` et l'`identity` de l'éditeur.

    `report` : {"source_id": 597, "title": ..., "url": ..., "site_name": ..., "published": "2026-08-24",
                "category": "operational"} (métadonnées de la table `knowledge` et de la classification).
    """
    ts = _timestamp(now)
    publisher = _publisher_identity(report, ts)
    article_ref = {"source_name": report.get("site_name") or "article", "url": report.get("url"), "description": report.get("title")}
    article_ref = {k: v for k, v in article_ref.items() if v}
    common = {"spec_version": "2.1", "created": ts, "modified": ts, "created_by_ref": publisher["id"], "object_marking_refs": [DEFAULT_TLP]}

    objects: list[dict] = []
    for ent in graph.entities:
        obj = {**common, **{k: v for k, v in ent.items() if v not in (None, "", []) and not k.startswith("_")}}
        for key in _REMOVE_EMPTY:
            if key in obj and not obj[key]:
                del obj[key]
        if obj["type"] == "malware":
            obj.setdefault("is_family", True)  # propriété obligatoire ; un article nomme presque toujours une famille
        objects.append(obj)

    for rel in graph.relationships:
        quotes = [e["quote"] for e in rel["_evidence"]]
        objects.append(
            {
                **common,
                **{k: v for k, v in rel.items() if not k.startswith("_")},
                "description": quotes[0] if len(quotes) == 1 else " | ".join(quotes),
                # une référence par citation : l'article (source_name, url) et le passage qui étaye la relation
                "external_references": [{**article_ref, "description": q} for q in quotes] if article_ref else [],
            }
        )

    published = report.get("published") or ts
    if len(published) == 10:  # AAAA-MM-JJ
        published += "T00:00:00.000Z"
    report_obj = {
        **common,
        "type": "report",
        "id": stix_id("report", {"source_id": report["source_id"]}),
        "name": report.get("title") or f"article {report['source_id']}",
        "report_types": ["threat-report"],
        "published": published,
        "object_refs": [o["id"] for o in objects] or [publisher["id"]],
        "labels": [report["category"]] if report.get("category") else [],
        "external_references": [article_ref] if article_ref else [],
    }
    if not report_obj["labels"]:
        del report_obj["labels"]
    if not report_obj["external_references"]:
        del report_obj["external_references"]
    return [publisher, report_obj, *objects]


def to_bundle(objects: list[dict]) -> str:
    """Bundle STIX 2.1 sérialisé. Lève une exception de `stix2` si un objet n'est pas conforme à la norme.

    Aucune propriété personnalisée n'est tolérée : `stix2` est appelé en mode strict, donc tout champ hors norme
    fait échouer l'export plutôt que d'être émis silencieusement.
    """
    parsed = [stix2.parse(o, version="2.1") for o in objects]
    return stix2.Bundle(objects=parsed).serialize(pretty=True)


# --- Neo4j -------------------------------------------------------------------------------------------------------------
def neo4j_label(stix_type: str) -> str:
    """Étiquette de nœud : `threat-actor` -> `ThreatActor`."""
    return OBJECT_TYPES[stix_type].label if stix_type in OBJECT_TYPES else "".join(p.capitalize() for p in stix_type.split("-"))


def neo4j_relationship_type(relationship_type: str) -> str:
    """Type de relation Neo4j : `attributed-to` -> `ATTRIBUTED_TO`."""
    return relationship_type.upper().replace("-", "_")


def to_neo4j_properties(obj: dict) -> dict:
    """Propriétés plates d'un objet : Neo4j n'accepte pas de structures imbriquées ; elles sont sérialisées en JSON."""
    flat: dict = {}
    for key, value in obj.items():
        if key in ("source_ref", "target_ref", "type"):
            continue
        if isinstance(value, (dict, list)) and any(isinstance(v, (dict, list)) for v in (value.values() if isinstance(value, dict) else value)):
            flat[f"{key}_json"] = json.dumps(value, ensure_ascii=False, sort_keys=True)
        else:
            flat[key] = value
    return flat


# --- RDF ---------------------------------------------------------------------------------------------------------------
CTI = Namespace("https://cti-knowledge-graph.local/stix#")


def ontology_turtle() -> str:
    """Schéma de l'ontologie en RDFS/OWL : une classe par type d'objet, une propriété par type de relation, avec
    domaine et codomaine (union des types autorisés). Généré depuis les mêmes tables que la validation."""
    g = Graph()
    g.bind("cti", CTI)
    g.bind("owl", OWL)
    for t, o in OBJECT_TYPES.items():
        if o.family in ("sro",):
            continue
        cls = CTI[o.label]
        g.add((cls, RDF.type, OWL.Class))
        g.add((cls, RDFS.label, Literal(t)))
        g.add((cls, RDFS.comment, Literal(o.definition, lang="fr")))
    domains: dict[str, set[str]] = {}
    ranges: dict[str, set[str]] = {}
    for (src, rel), targets in _INDEX.items():
        domains.setdefault(rel, set()).add(src)
        ranges.setdefault(rel, set()).update(targets)

    def union(types: set[str]):
        labels = sorted(OBJECT_TYPES[t].label for t in types if t in OBJECT_TYPES)
        if len(labels) == 1:
            return CTI[labels[0]]
        node = BNode()
        items = BNode()
        g.add((node, RDF.type, OWL.Class))
        g.add((node, OWL.unionOf, items))
        Collection(g, items, [CTI[x] for x in labels])
        return node

    for rel in sorted(ALL_RELATIONSHIP_TYPES):
        prop = CTI[neo4j_relationship_type(rel)]
        g.add((prop, RDF.type, OWL.ObjectProperty))
        g.add((prop, RDFS.label, Literal(rel)))
        if rel in domains:
            g.add((prop, RDFS.domain, union(domains[rel])))
            g.add((prop, RDFS.range, union(ranges[rel])))
    return g.serialize(format="turtle")
