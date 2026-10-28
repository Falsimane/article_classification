"""Règles de détection en STIX 2.1 : une règle YARA ou Sigma citée par un article est un `stix2.Indicator` dont `pattern`
est le texte exact de la règle et `pattern_type` son langage (vocabulaire pattern-type-ov).

    Indicator (pattern_type yara | sigma, pattern = texte de la règle)
      -- indicates --> malware | outil | acteur | campagne        (rattachement : réponse fermée du modèle)

Contrairement à un IOC, une règle n'a ni observable ni observation : elle décrit comment reconnaître une menace. L'identifiant
dépend du langage et du texte : la même règle citée par deux articles est un seul objet.
"""

from dataclasses import dataclass
from datetime import datetime

from stix2 import Indicator

from .objects import ArticleContext, deterministic_id, relationship

RULE_KINDS = ("yara", "sigma")


@dataclass
class DetectionRule:
    kind: str  # "yara" | "sigma" (valeur de pattern-type-ov)
    name: str  # nom de la règle YARA, `title` de la règle Sigma
    source: str  # texte exact de la règle, validé (compilé pour YARA, lu en YAML pour Sigma)
    heading: str = ""  # section de l'article où elle figure
    description: str | None = None  # `meta: description` (YARA) ou `description` (Sigma)
    attach_id: str | None = None  # identifiant STIX de l'entité détectée
    attach_type: str | None = None
    attach_name: str | None = None
    confidence: int = 50


def build_rule_objects(rules: list[DetectionRule], ctx: ArticleContext, published: datetime | None) -> list:
    """`stix2.Indicator` de chaque règle et sa relation `indicates`. `valid_from` : date de l'article (à défaut, l'instant
    de l'extraction), la règle étant valable dès sa publication."""
    objects: dict[str, object] = {}
    for rule in rules:
        indicator = Indicator(
            id=deterministic_id("indicator", pattern_type=rule.kind, pattern=rule.source), name=rule.name,
            indicator_types=["malicious-activity"], pattern=rule.source, pattern_type=rule.kind, valid_from=published or ctx.now,
            labels=["detection-rule"], confidence=rule.confidence, **({"description": rule.description} if rule.description else {}),
            **ctx.common,
        )  # fmt: skip
        objects.setdefault(indicator.id, indicator)
        if rule.attach_id and rule.attach_type:
            quote = f"{rule.kind.upper()} « {rule.name} »" + (f" ({rule.heading})" if rule.heading else "")
            rel = relationship("indicates", indicator.id, rule.attach_id, ctx, [quote], rule.confidence)
            objects.setdefault(rel.id, rel)
    return list(objects.values())
