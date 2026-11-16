"""Étape 1 : le sous-graphe d'entités typées STIX et de leurs relations, sous grammaire imposée.

Deux appels qui commencent par le même texte (relu depuis le cache du serveur) : les entités, puis les relations entre les
entités numérotées. Le code écrit les lignes que `DraftGraph` vérifie (stix2, table STIX, phrases citées qui nomment les
extrémités) ; le modèle n'écrit aucun mini-langage."""

from collections.abc import Callable

from backend.extracting.cascade.schemas import entity_schema, label_schema, relation_schema
from backend.extracting.graph.draft import DraftGraph
from backend.extracting.stix.attack import attack_id
from backend.extracting.stix.objects import ENTITY_CLASSES

Call = Callable[[str, str, str, dict, int], dict]  # (étape, système, prompt, schéma, tokens) -> réponse
ENTITY_TOKENS = 3500
RELATION_TOKENS = 5000
CORRECTION_TOKENS = 1500
_DETAIL_TYPES = ("location", "identity", "course-of-action", "malware-analysis")


def _clean(value: str) -> str:
    return " ".join(str(value or "").replace("|", "/").split())


def ref(draft: DraftGraph, sid: str) -> str:
    """Extrémité d'une ligne de relation : un objet ATT&CK par son identifiant (« PowerShell » est aussi un outil)."""
    return attack_id(draft.objects[sid]) or _clean(draft.name_of(sid))


def entity_prompt(text: str) -> str:
    return (
        f"{text}\n\n---\nTÂCHE : relève toutes les entités STIX du rapport ENTIER (aucun IOC, aucune technique ATT&CK, aucune "
        "relation). Pour chacune : « type » (registre ci-dessus), « name » tel que le texte l'écrit, « aliases » (autres noms "
        "donnés par le texte, sinon liste vide), « detail » = le troisième champ de la forme du type (code ISO 3166-1 d'un location, « secteur STIX;classe » d'une identity, description d'un course-of-action, verdict "
        "d'une malware-analysis), sinon chaîne vide."
    )


def entity_correction_prompt(prompt: str, refused: list[str]) -> str:
    listing = "\n".join(f"{i}. {r}" for i, r in enumerate(refused, 1))
    return (
        f"{prompt}\n\nCes entités ont été refusées : leur nom est un nom de fichier (un IOC, extrait par ailleurs) :\n{listing}\n\n"
        "TÂCHE : pour CHAQUE numéro, « name » = le libellé que le texte donne à ce composant précis (son rôle ou sa famille, tel "
        "que le rapport le désigne dans une phrase ou un tableau : deux composants différents gardent deux libellés différents), "
        "jamais un nom de fichier."
    )


def relation_prompt(text: str, table: list[str]) -> str:
    listing = "\n".join(f"{i}. {row}" for i, row in enumerate(table, 1))
    return (
        f"{text}\n\n---\nENTITÉS DU RAPPORT (numérotées) :\n{listing}\n\n"
        "TÂCHE : toutes les relations STIX que le texte affirme entre ces entités. « source » et « target » sont des numéros "
        "de la liste ; « sentences » : les numéros [n] des phrases qui affirment la relation et nomment ses deux extrémités "
        "(ou la phrase qui suit de près celle qui les nomme)."
    )


def correction_prompt(prompt: str, refused: list[str]) -> str:
    listing = "\n".join(f"- {r}" for r in refused)
    return (
        f"{prompt}\n\nCes relations ont été refusées par la vérification, avec la raison :\n{listing}\n\n"
        "TÂCHE : réécris seulement celles que le texte affirme vraiment, corrigées (autres phrases citées, autre extrémité) ; "
        "abandonne les autres. Liste vide si aucune."
    )


def declare_entities(draft: DraftGraph, answer: dict, result) -> list[str]:
    sids: list[str] = []
    for e in answer.get("entities", []):
        name = _clean(e.get("name"))
        if not name or e.get("type") not in ENTITY_CLASSES:
            continue
        third = _clean(e.get("detail")) if e["type"] in _DETAIL_TYPES else ";".join(_clean(a) for a in e.get("aliases", []) if _clean(a))
        line = f"{e['type']}|{name}" + (f"|{third}" if third else "")
        sid, err = draft.declare(line)
        if err:
            draft.log.append(f"reject {err}")
            result.refused_entities.append((line, err))
            result.refused += 1
        elif sid not in sids and draft.type_of(sid) != "attack-pattern":
            sids.append(sid)
            result.accepted += 1
    return sids


def apply_relations(draft: DraftGraph, answer: dict, sids: list[str], result) -> list[str]:
    """Relations acceptées par `DraftGraph.relate` ; retourne les refus « relation : raison » pour une correction."""
    refused: list[str] = []
    for r in answer.get("relations", []):
        if not all(k in r for k in ("source", "relation", "target", "sentences")):  # réponse tronquée puis réparée
            continue
        s, t = sids[r["source"] - 1], sids[r["target"] - 1]
        nums = ",".join(str(n) for n in r["sentences"])
        err = draft.relate(f"{ref(draft, s)}|{r['relation']}|{ref(draft, t)}|{nums}")
        if err:
            reason = err.split(" : ", 1)[-1]
            refused.append(f"{r['source']} {r['relation']} {r['target']} (phrases {nums}) : {reason}")
            result.refused_relations.append((s, r["relation"], t, reason))
            result.refused += 1
        else:
            result.accepted += 1
    draft.log += [f"reject {x}" for x in refused]
    return refused


def build_graph(draft: DraftGraph, text: str, system: str, result, call: Call) -> list[str]:
    """Entités puis relations ; retourne les identifiants STIX des entités retenues (sans technique)."""
    prompt = entity_prompt(text)
    seen = len(result.refused_entities)
    sids = declare_entities(draft, call("entities", system, prompt, entity_schema(), ENTITY_TOKENS), result)
    files = [line for line, err in result.refused_entities[seen:] if "nom de fichier" in err]
    if files:  # un refus sans reprise perd le composant et toutes ses relations ; même début de prompt (cache du serveur)
        answer = call("entities:corrections", system, entity_correction_prompt(prompt, files), label_schema(len(files)), CORRECTION_TOKENS)
        labels = {x.get("item"): _clean(x.get("name")) for x in answer.get("labels", []) if isinstance(x, dict)}
        renamed = [{"type": line.split("|")[0], "name": labels[i], "aliases": []} for i, line in enumerate(files, 1) if labels.get(i)]
        sids += [s for s in declare_entities(draft, {"entities": renamed}, result) if s not in sids]
    schema = relation_schema([draft.type_of(s) for s in sids])
    if schema is None:
        return sids
    prompt = relation_prompt(text, [f"{draft.type_of(s)}: {draft.name_of(s)}" for s in sids])
    refused = apply_relations(draft, call("relations", system, prompt, schema, RELATION_TOKENS), sids, result)
    if refused:  # le prompt commence par le précédent : relu depuis le cache du serveur
        apply_relations(draft, call("corrections", system, correction_prompt(prompt, refused), schema, CORRECTION_TOKENS), sids, result)
    return sids


def technique_relations(draft: DraftGraph, text: str, system: str, sids: list[str], result, call: Call) -> None:
    """Relations dont la source est une technique retenue (exploitation --targets--> vulnérabilité et produit, lieu ou
    victime visés ; technique --delivers--> malware). Même préfixe de texte que les appels précédents."""
    techniques = [o["id"] for o in draft.linked(keep_orphans=False) if o["type"] == "attack-pattern"]
    if not techniques:
        return
    every = sids + techniques
    schema = relation_schema([draft.type_of(s) for s in every], sources={"attack-pattern"})
    if schema is None:
        return
    # Le texte ne nomme jamais une technique ATT&CK : chacune est montrée avec la procédure relevée et ses phrases, et la
    # preuve demandée est la phrase qui énonce la procédure et nomme la cible (pas une phrase qui « nomme » la technique)
    cited: dict[str, list[int]] = {}
    for b in getattr(result, "behaviors", []):
        for aid in b.get("chosen", []):
            cited.setdefault(aid, []).extend(n for n in b.get("uids", []) if isinstance(n, int) and n not in cited[aid])

    def row(sid: str) -> str:
        aid = ref(draft, sid)
        proc = " ; ".join(f"« {_clean(p)} »" for p in draft.procedures.get(sid, [])[:3])
        nums = ", ".join(map(str, sorted(cited.get(aid, []))[:8]))
        return f"attack-pattern: {aid} {draft.name_of(sid)}" + (f" — {proc}" if proc else "") + (f" [{nums}]" if nums else "")

    listing = "\n".join(f"{i}. {r}" for i, r in enumerate([f"{draft.type_of(s)}: {draft.name_of(s)}" for s in sids] + [row(s) for s in techniques], 1))
    prompt = (
        f"{text}\n\n---\nENTITÉS DU RAPPORT (numérotées) ; chaque technique est suivie de la procédure relevée dans le texte et "
        f"des numéros de ses phrases :\n{listing}\n\n"
        "TÂCHE : les relations dont la source est une technique (attack-pattern), quand la procédure de cette technique vise "
        "ou livre une autre entité de la liste : une technique d'exploitation --targets--> la vulnérabilité qu'elle exploite ; "
        "une technique --targets--> le lieu ou la victime que cette procédure vise ; une technique --delivers--> le malware qu'elle livre. « source » et « target » "
        "sont des numéros de la liste ; « sentences » : les phrases [n] de la procédure qui nomment la cible. Liste vide si "
        "aucune procédure ne le dit."
    )
    apply_relations(draft, call("relations:techniques", system, prompt, schema, CORRECTION_TOKENS), every, result)
