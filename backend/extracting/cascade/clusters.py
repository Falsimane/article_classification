"""Étape 2 : les grappes. Une grappe = un porteur de techniques (campagne, groupe, malware, outil) et les phrases qui décrivent
ce qu'il fait. Le modèle désigne le centre dans la liste fermée des porteurs déclarés à l'étape 1, ou 0 (« non nommé »), et
dit si la grappe relève de l'incident décrit ou du contexte (autres campagnes, historique, travaux cités) : 65 % des faux
positifs d'extraction sont des mentions de contexte (Qian 2026). Seules les grappes « incident » passent par la grille."""

from dataclasses import dataclass, field

from backend.extracting.cascade.graph import Call
from backend.extracting.cascade.schemas import CARRIER_TYPES, cluster_schema
from backend.extracting.graph.draft import DraftGraph

CLUSTER_TOKENS = 6000

CARRIER_RULE = (
    "Une action est portée par l'entité que le texte présente comme son auteur. Ce que fait le code d'un malware ou d'un "
    "outil (se déchiffrer, communiquer avec son serveur, persister, voler des données) appartient au malware ou à l'outil. "
    "Ce que font les opérateurs (envoyer les courriels, choisir les cibles, déployer ou signer le malware, louer ou "
    "compromettre l'infrastructure, exploiter une vulnérabilité) appartient au groupe nommé ou, sans groupe nommé, à la "
    "campagne."
)


@dataclass
class Cluster:
    center: str | None  # identifiant STIX du porteur ; None = attaquant non nommé
    scope: str  # "incident" | "background"
    sentences: list[int] = field(default_factory=list)


def cluster_prompt(text: str, carriers: list[str]) -> str:
    listing = "\n".join(f"{i}. {row}" for i, row in enumerate(carriers, 1)) or "(aucun)"
    return (
        f"{text}\n\n---\nPORTEURS DE TECHNIQUES DÉCLARÉS (numérotés) :\n0. attaquant non nommé\n{listing}\n\n"
        "TÂCHE : regroupe les comportements décrits par le rapport selon leur porteur. Une grappe par porteur qui agit : "
        "« center » = son numéro (0 pour les actions dont le texte ne nomme pas l'auteur) ; « sentences » = toutes les "
        "phrases qui décrivent ce qu'il fait (actions, capacités, techniques) ; une phrase peut appartenir à plusieurs "
        "grappes. « scope » = « incident » pour l'activité que le rapport décrit, « background » pour ce qu'il rappelle "
        "d'autres campagnes, d'opérations passées ou de travaux d'autres chercheurs.\n"
        f"RÈGLE DU PORTEUR : {CARRIER_RULE}"
    )


def build_clusters(draft: DraftGraph, text: str, system: str, sids: list[str], result, call: Call) -> list[Cluster]:
    carriers = [s for s in sids if draft.type_of(s) in CARRIER_TYPES]
    answer = call("clusters", system, cluster_prompt(text, [f"{draft.type_of(s)}: {draft.name_of(s)}" for s in carriers]), cluster_schema(len(carriers)), CLUSTER_TOKENS)
    # Règle du porteur : ce que font les opérateurs appartient au groupe nommé, à la campagne seulement sans groupe. Une
    # campagne attribuée à un seul groupe lui cède donc ses passages (sinon chaque technique est portée deux fois).
    owners: dict[str, set[str]] = {}
    for (s, rel, t) in draft.evidence:
        if rel == "attributed-to" and draft.type_of(s) == "campaign" and draft.type_of(t) in ("intrusion-set", "threat-actor"):
            owners.setdefault(s, set()).add(t)
    groups = {c: next(iter(g)) for c, g in owners.items() if len(g) == 1}
    merged: dict[tuple[str | None, str], Cluster] = {}
    for c in answer.get("clusters", []):  # une réponse tronquée puis réparée peut perdre des champs
        index = c.get("center")
        if not isinstance(index, int) or not 0 <= index <= len(carriers):
            continue
        center = carriers[index - 1] if index else None
        center = groups.get(center, center)
        valid = [n for n in c.get("sentences", []) if isinstance(n, int) and n in draft.by_uid]
        if not valid:
            draft.log.append(f"grappe sans phrase valide écartée : {draft.name_of(center) if center else 'non nommé'}")
            continue
        scope = c.get("scope") if c.get("scope") in ("incident", "background") else "incident"
        cluster = merged.setdefault((center, scope), Cluster(center, scope))
        cluster.sentences += [n for n in valid if n not in cluster.sentences]
    clusters = list(merged.values())
    for c in clusters:
        c.sentences.sort()
        draft.log.append(f"grappe {c.scope} : {draft.name_of(c.center) if c.center else 'non nommé'} ({len(c.sentences)} phrases)")
    return clusters
