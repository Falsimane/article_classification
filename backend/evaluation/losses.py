"""Où se perd chaque élément required du gold que le bundle n'a pas : à quelle étape du pipeline (`cti-eval`).

Entités :
    jamais proposée              le modèle ne l'a pas écrite
Techniques jamais proposées (exécutions avec la trace des comportements), trois échecs aux remèdes différents :
    aucun comportement relevé    aucun comportement ne cite les phrases du gold qui décrivent la technique
    absente des candidates       un comportement cite ces phrases, la recherche ne propose pas la technique
    candidate non retenue        la technique était proposée, le modèle ne l'a pas choisie
    refusée par la vérification  proposée, refusée (identifiant ATT&CK inexistant ou mal nommé, IOC, stix2…)
    proposée sous un autre type  même nom, autre classe (software proposé en tool, identity en infrastructure…)
    écartée sans relation        acceptée, puis retirée du bundle faute de relation étayée (`DraftGraph.linked`)
Relations :
    refusée par la vérification  proposée entre les bonnes extrémités, refusée (phrase citée qui ne les nomme pas, stix2…)
    extrémité manquante          une extrémité n'est pas dans le bundle (voir son entité)
    autre relation               les deux extrémités sont reliées autrement (autre type, sens inverse)
    autre source                 même relation vers la même cible, depuis une autre entité (campagne au lieu de l'acteur…)
    jamais proposée

Vérificateur (étape 4) : les relations qu'il a retirées, rapprochées du gold (required, acceptable, absente).

L'appariement est celui de `score.py` ; la trace (propositions refusées, entités écartées, comportements) vient de `runs.json`.
"""

import re

from backend.evaluation.score import (
    LABEL_ACCEPTABLE, LABEL_REQUIRED, _align_operations, _candidates, _entity, _greedy, entity_credit, in_scope, load_bundle,
)  # fmt: skip
from backend.extracting.stix.attack import AttackKB, get_attack_kb
from backend.extracting.stix.objects import as_dict
from backend.preprocessing.cleaning.text.evidence import normalize_name, normalize_quote
from backend.preprocessing.cleaning.text.segment import segment

TECHNIQUE_STAGES = ("aucun comportement relevé", "absente des candidates", "candidate non retenue")
ENTITY_STAGES = ("jamais proposée", *TECHNIQUE_STAGES, "refusée par la vérification", "proposée sous un autre type", "écartée sans relation")
VERIFIED_OUT = "non étayée selon la vérification"  # raison inscrite par `pipeline.verify_relations`
RELATION_STAGES = ("jamais proposée", "refusée par la vérification", "extrémité manquante", "autre relation", "autre source")
_KEEP = ("id", "type", "name", "aliases", "x_mitre_aliases", "external_references", "country", "region")
_TECHNIQUE = re.compile(r"T\d{4}(?:\.\d{3})?", re.I)


def trace_of(result) -> dict:
    """Trace d'une extraction (`ExtractionResult`) pour `runs.json` : entités écartées (propriétés d'appariement seules) et
    propositions refusées."""
    return {
        "unlinked": [{k: v for k, v in as_dict(o).items() if k in _KEEP} for o in result.draft.unlinked()],
        "refused_entities": [list(x) for x in result.refused_entities],
        "refused_techniques": [list(x) for x in result.refused_techniques],
        "refused_relations": [list(x) for x in result.refused_relations],
        "behaviors": result.behaviors,
    }


def _uids_of(quote: str, units) -> set[int]:
    """Unités du texte qui contiennent la citation (ou son début), ou qu'elle contient."""
    q = normalize_quote(quote)
    head = q[:80]
    return {u.uid for u in units if head and (head in normalize_quote(u.text) or (len(u.text) > 30 and normalize_quote(u.text) in q))}


def _technique_stage(g, gold_rels, behaviors: list[dict], units) -> str:
    """Étape où s'est perdue une technique jamais proposée (voir l'en-tête). Seuls comptent les comportements qui citent une
    phrase du gold de la technique : une candidate proposée à un autre comportement ne dit rien du choix."""
    family = g.technique.split(".")[0]
    sentences = set().union(*(_uids_of(q, units) for r in gold_rels if g.sid in (r.source, r.target) for q in r.quotes)) if units else set()
    near = [b for b in behaviors if sentences & set(b["uids"])]
    if not near:
        return "aucun comportement relevé"
    if any(c.split(".")[0] == family for b in near for c in b["candidates"]):
        return "candidate non retenue"
    return "absente des candidates"


def retrieval(gold, gold_rels, behaviors: list[dict], units) -> dict:
    """Rappel de la recherche, indépendamment du choix : parmi les techniques required dont une phrase gold est citée par un
    comportement, celles que la recherche a proposées à ce comportement (même identifiant, ou même famille)."""
    out = {"covered": 0, "exact": 0, "family": 0}
    for g in gold.values():
        if g.stix_type != "attack-pattern" or g.label != LABEL_REQUIRED or not g.technique:
            continue
        sentences = set().union(*(_uids_of(q, units) for r in gold_rels if g.sid in (r.source, r.target) for q in r.quotes))
        near = [b for b in behaviors if sentences & set(b["uids"])]
        if not near:
            continue
        out["covered"] += 1
        cands = {c for b in near for c in b["candidates"]}
        out["exact"] += g.technique in cands
        out["family"] += any(c.split(".")[0] == g.technique.split(".")[0] for c in cands)
    return out


def _refused_entity(g, trace: dict) -> str | None:
    """Raison du refus d'une proposition qui désignait l'entité gold `g`, ou None."""
    if g.stix_type == "attack-pattern":
        for line, reason in trace["refused_techniques"]:
            found = _TECHNIQUE.search(line)
            if found and g.technique and found.group(0).upper().split(".")[0] == g.technique.split(".")[0]:
                return f"« {line} » : {reason}"
        return None
    for line, reason in trace["refused_entities"]:
        parts = line.split("|")
        if len(parts) > 1 and normalize_name(parts[1]) in g.keys:
            return f"« {line} » : {reason}"
    return None


def diagnose(gold_bundle: dict, pred_bundle: dict, trace: dict, kb: AttackKB | None = None, source_text: str | None = None) -> dict:
    """{"entities": [...], "relations": [...], "verifier": {...}, "retrieval": {...}} : chaque élément required du gold absent
    du bundle, avec son étape et un détail ; relations retirées par le vérificateur ; rappel de la recherche des techniques.
    `source_text` (texte nettoyé de l'article) situe les phrases gold parmi celles que citent les comportements."""
    kb = kb or get_attack_kb()
    gold, gold_rels = load_bundle(gold_bundle, kb, gold=True)
    pred, pred_rels = load_bundle(pred_bundle, kb, gold=False)
    dropped = {o["id"]: _entity(o, kb, None) for o in trace["unlinked"] if in_scope(o)}
    cands = _candidates(gold, pred)
    _align_operations(gold, pred, gold_rels, pred_rels, cands)
    to_pred = {g: p for p, (g, _) in _greedy([(c, p, g) for p, gs in cands.items() for g, c in gs.items()]).items()}
    every = _candidates(gold, {**pred, **dropped})  # extrémités des relations refusées, entités écartées comprises
    behaviors = trace.get("behaviors")  # absente des exécutions antérieures à sa trace
    units = segment(source_text) if source_text and behaviors is not None else []

    entities, stage_of = [], {}
    for g in gold.values():
        if g.label != LABEL_REQUIRED or g.sid in to_pred:
            continue
        other = next((p for p in [*pred.values(), *dropped.values()] if p.klass != g.klass and p.keys & g.keys), None)
        refused = _refused_entity(g, trace)
        if any(entity_credit(g, d) for d in dropped.values()):
            stage, detail = "écartée sans relation", ""
        elif other:
            stage, detail = "proposée sous un autre type", other.describe()
        elif refused:
            stage, detail = "refusée par la vérification", refused
        elif g.stix_type == "attack-pattern" and g.technique and behaviors is not None:
            stage, detail = _technique_stage(g, gold_rels, behaviors, units), ""
        else:
            stage, detail = "jamais proposée", ""
        stage_of[g.sid] = stage
        entities.append({"gold": g.describe(), "type": g.stix_type, "stage": stage, "detail": detail})

    # Relations manquées : même appariement que score_article
    pairs = [
        (min(cands.get(pr.source, {}).get(gr.source, 0), cands.get(pr.target, {}).get(gr.target, 0)), str(i), gr.sid)
        for i, pr in enumerate(pred_rels) for gr in gold_rels if gr.rel == pr.rel
    ]  # fmt: skip
    found = {g for g, _ in _greedy(pairs).values()}
    relations = []
    for gr in gold_rels:
        if gr.label != LABEL_REQUIRED or gr.sid in found:
            continue
        text = f"{gold[gr.source].describe()} --{gr.rel}--> {gold[gr.target].describe()}"
        pattern = f"{gold[gr.source].klass} {gr.rel} {gold[gr.target].klass}"
        refused = next(
            (f"{rel} : {reason}" for s, rel, t, reason in trace["refused_relations"]
             if any(gr.source in every.get(a, {}) and gr.target in every.get(b, {}) for a, b in ((s, t), (t, s)))),
            None,
        )  # fmt: skip
        ps, pt = to_pred.get(gr.source), to_pred.get(gr.target)
        between = [pr for pr in pred_rels if {pr.source, pr.target} == {ps, pt}] if ps and pt else []
        elsewhere = [pr for pr in pred_rels if pt and pr.target == pt and pr.rel == gr.rel and pr.source != ps]
        if refused:
            stage, detail = "refusée par la vérification", refused
        elif not (ps and pt):
            missing = [gold[e] for e, p in ((gr.source, ps), (gr.target, pt)) if not p]
            stage, detail = "extrémité manquante", " ; ".join(f"{e.describe()} ({stage_of.get(e.sid, 'acceptable')})" for e in missing)
        elif between:
            stage, detail = "autre relation", ", ".join(f"{pred[pr.source].describe()} --{pr.rel}--> {pred[pr.target].describe()}" for pr in between)
        elif elsewhere:
            stage, detail = "autre source", ", ".join(pred[pr.source].describe() for pr in elsewhere)
        else:
            stage, detail = "jamais proposée", ""
        relations.append({"gold": text, "pattern": pattern, "stage": stage, "detail": detail})

    # Relations retirées par le vérificateur : étaient-elles dans le gold ?
    verifier = {"required": 0, "acceptable": 0, "absente du gold": 0}
    for s, rel, t, reason in trace["refused_relations"]:
        if reason != VERIFIED_OUT:
            continue
        labels = [gr.label for gr in gold_rels if gr.rel == rel and gr.source in every.get(s, {}) and gr.target in every.get(t, {})]
        verifier["required" if LABEL_REQUIRED in labels else "acceptable" if LABEL_ACCEPTABLE in labels else "absente du gold"] += 1
    out = {"entities": entities, "relations": relations, "verifier": verifier}
    if behaviors is not None and units:
        out["retrieval"] = retrieval(gold, gold_rels, behaviors, units)
    return out


def tally(diagnoses: list[dict]) -> dict:
    """Comptes par étape : entités (techniques à part) et relations."""
    out = {
        "techniques": dict.fromkeys(ENTITY_STAGES, 0), "entities": dict.fromkeys(ENTITY_STAGES, 0), "relations": dict.fromkeys(RELATION_STAGES, 0),
        "verifier": {"required": 0, "acceptable": 0, "absente du gold": 0}, "retrieval": {"covered": 0, "exact": 0, "family": 0},
    }  # fmt: skip
    for d in diagnoses:
        for e in d["entities"]:
            out["techniques" if e["type"] == "attack-pattern" else "entities"][e["stage"]] += 1
        for r in d["relations"]:
            out["relations"][r["stage"]] += 1
        for key in ("verifier", "retrieval"):
            for k, v in d.get(key, {}).items():
                out[key][k] += v
    return out
