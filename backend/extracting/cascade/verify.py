"""Vérification par questions fermées (conception 2026-11-12, §6.2).

Une question « la phrase étaye-t-elle l'affirmation ? » est validée par la simple mention d'un nom (Qian 2026 : 92,5 % des
faux positifs de contexte passent l'auto-vérification). Le vérificateur pose donc des questions d'EXTRACTION à réponse
énumérée, sur les phrases citées de chaque affirmation :
  agent      qui effectue l'action décrite (porteur de l'incident, ou 0 = le texte ne le dit pas)
  scope      l'incident du rapport, un fait général établi sur un acteur ou son outil (gardé, sur l'acteur), un événement
             passé, ou une généralité sans acteur
  mechanism  la phrase décrit-elle le mécanisme de la technique, seulement de sa parente, ou aucun
  status     établi, conclusion assumée par l'auteur, spéculation, démenti
La décision (`decide`) est faite par le code, sans appel au modèle : retrait, réattribution, remontée à la parente,
confiance STIX. Les hypothèses et démentis sont retirés, jamais gardés avec une confiance basse."""

from dataclasses import dataclass
from typing import Literal

from backend.extracting.cascade.schemas import CARRIER_TYPES
from backend.extracting.graph.draft import DraftGraph, relationship_type_of
from backend.extracting.stix.attack import attack_id, get_attack_kb

# actor_general : connaissance CTI établie sur un acteur ou son outil (secteurs visés d'habitude, malware employé, capacités
# connues), gardée sur l'acteur, jamais sur la campagne de l'incident ; l'alignement entre articles fusionne (décision du 2026-11-13)
SCOPES = ("incident", "actor_general", "past_event", "generic")
MECHANISMS = ("technique", "parent", "none")
STATUSES = ("established", "assessed", "speculative", "refuted")
CONFIDENCE = {"established": 85, "assessed": 60}
BATCH = 25
QUOTES_SHOWN = 4
SUMMARY_CHARS = 300


@dataclass
class Claim:
    key: tuple[str, str, str]  # (source, relation, cible) ; source "" = technique gardée sans porteur nommé
    kind: Literal["action", "technique", "relation"]
    quotes: list[str]
    procedure: str | None = None
    technique: str | None = None  # identifiant ATT&CK de la cible d'une affirmation « technique »


@dataclass
class Verdict:
    agent: int | None
    scope: str | None
    mechanism: str | None
    status: str | None


@dataclass
class Decision:
    action: Literal["keep", "reassign", "to_parent", "drop"]
    new_source: str | None = None
    confidence: int | None = None
    reason: str = ""


def batches(claims: list[Claim], size: int = BATCH) -> list[list[Claim]]:
    return [claims[i : i + size] for i in range(0, len(claims), size)]


def verify_schema(n_claims: int, n_agents: int) -> dict:
    item = {
        "type": "object",
        "properties": {
            "claim": {"type": "integer", "enum": list(range(1, n_claims + 1))},
            "agent": {"type": "integer", "enum": list(range(0, n_agents + 1))},
            "scope": {"type": "string", "enum": list(SCOPES)},
            "mechanism": {"type": "string", "enum": list(MECHANISMS)},
            "status": {"type": "string", "enum": list(STATUSES)},
        },
        "required": ["claim", "agent", "scope", "mechanism", "status"],
        "additionalProperties": False,
    }
    verdicts = {"type": "array", "items": item, "minItems": 1, "maxItems": n_claims}
    return {"type": "object", "properties": {"verdicts": verdicts}, "required": ["verdicts"], "additionalProperties": False}


def parse_verdicts(answer: dict, n_claims: int, n_agents: int) -> dict[int, Verdict]:
    """{numéro d'affirmation: verdict} ; une ligne tronquée, hors bornes ou hors énumération est ignorée (pas de verdict)."""
    out: dict[int, Verdict] = {}
    for v in answer.get("verdicts") or []:
        if not isinstance(v, dict):
            continue
        k, agent = v.get("claim"), v.get("agent")
        if not (isinstance(k, int) and 1 <= k <= n_claims and isinstance(agent, int) and 0 <= agent <= n_agents):
            continue
        if v.get("scope") not in SCOPES or v.get("mechanism") not in MECHANISMS or v.get("status") not in STATUSES:
            continue
        out.setdefault(k, Verdict(agent, v["scope"], v["mechanism"], v["status"]))
    return out


def decide(claim: Claim, verdict: Verdict | None, agents: list[str]) -> Decision:
    """Décision du code à partir du verdict (pure)."""
    if verdict is None:
        return Decision("keep", reason="pas de verdict")
    confidence = CONFIDENCE.get(verdict.status)
    if verdict.status in ("speculative", "refuted"):
        return Decision("drop", reason=f"présentée comme {'hypothèse' if verdict.status == 'speculative' else 'démentie'}")
    source = claim.key[0]
    if verdict.scope == "actor_general" and source.startswith("campaign--"):
        actor = agents[verdict.agent - 1] if verdict.agent else None
        if not actor or actor.startswith("campaign--"):
            return Decision("drop", reason="fait général sur un acteur, sans acteur nommé pour le porter")
        return Decision("reassign", actor, confidence, "fait général sur l'acteur, pas sur la campagne de l'incident")
    if verdict.scope not in ("incident", "actor_general"):
        return Decision("drop", reason=f"hors de l'incident ({verdict.scope})")
    new_source = None
    if claim.kind in ("action", "technique"):
        if verdict.agent == 0:
            if source:  # une technique au niveau du rapport n'a pas d'auteur nommé : c'est attendu
                return Decision("drop", reason="auteur de l'action non dit")
        elif agents[verdict.agent - 1] != source:
            new_source = agents[verdict.agent - 1]
    if claim.kind == "technique":
        if verdict.mechanism == "none":
            return Decision("drop", reason="mécanisme de la technique absent de la phrase")
        if verdict.mechanism == "parent" and claim.technique and "." in claim.technique:
            return Decision("to_parent", new_source, confidence, "seule la parente est établie")
    if new_source:
        return Decision("reassign", new_source, confidence, "porteur corrigé : l'auteur de l'action est un autre")
    return Decision("keep", confidence=confidence)


def _label(draft: DraftGraph, sid: str) -> str:
    aid = attack_id(draft.objects[sid])
    return f"{draft.type_of(sid)}: {f'{aid} ' if aid else ''}{draft.name_of(sid)}"


def verify_prompt(text: str, draft: DraftGraph, batch: list[Claim], agents: list[str]) -> str:
    """Texte entier en tête (cache de préfixe partagé avec les autres appels), puis les affirmations et les questions."""
    kb = get_attack_kb()
    blocks = []
    for i, c in enumerate(batch, 1):
        s, rel, t = c.key
        head = f"{_label(draft, s)} --{rel}--> {_label(draft, t)}" if s else f"(auteur non nommé) --{rel}--> {_label(draft, t)}"
        lines = [f"{i}. {head}"]
        if c.technique:
            summary = (kb.get(c.technique) or {}).get("summary", "")[:SUMMARY_CHARS]
            lines.append(f"   definition: {summary}")
        if c.procedure:
            lines.append(f"   procedure: {c.procedure}")
        lines += [f"   « {q[:400]} »" for q in c.quotes[:QUOTES_SHOWN]]
        blocks.append("\n".join(lines))
    listing = "\n".join(f"{k}. {_label(draft, a)}" for k, a in enumerate(agents, 1)) or "(aucun)"
    return (
        f"{text}\n\n---\nENTITÉS QUI PEUVENT AGIR (numérotées) :\n0. le texte ne dit pas qui agit\n{listing}\n\n"
        f"AFFIRMATIONS EXTRAITES (avec les phrases citées) :\n" + "\n".join(blocks) + "\n\n"
        "TÂCHE : pour CHAQUE affirmation, lis les phrases citées dans le texte et réponds :\n"
        "- « agent » : le numéro de l'entité qui effectue l'action décrite. Ce que fait le code d'un malware ou d'un outil est "
        "fait par ce malware ou cet outil ; ce que font les opérateurs est fait par le groupe nommé, ou par la campagne si aucun "
        "groupe n'est nommé. 0 si le texte ne dit pas qui agit. Pour une relation qui n'est pas une action, le numéro de sa source.\n"
        "- « scope » : « incident » si les phrases décrivent l'activité que le rapport analyse ; « actor_general » pour un fait "
        "établi sur un acteur ou son outil en général, hors de cet incident (secteurs qu'il vise d'habitude, malware qu'il "
        "emploie, capacités connues d'un malware) ; « past_event » pour une opération antérieure précise rappelée ; « generic » "
        "pour une généralité sans acteur (définition, conseil, description d'une technique).\n"
        "- « mechanism » (techniques seulement, sinon « technique ») : « technique » si la phrase décrit le mécanisme de la "
        "définition donnée ; « parent » si elle n'établit que la technique parente, sans le détail de la sous-technique ; "
        "« none » si elle ne décrit pas ce mécanisme (un mot-clé commun ne suffit pas).\n"
        "- « status » : « established » si le texte l'affirme ; « assessed » si l'auteur l'assume comme conclusion avec un "
        "qualificatif (« we assess », « likely ») ; « speculative » si c'est présenté comme une possibilité (« may », « could », "
        "« possibly », « we could not determine ») ; « refuted » si le texte le dément."
    )


def collect_claims(draft: DraftGraph, behaviors: list[dict]) -> list[Claim]:
    """Les affirmations du graphe : relations acceptées, et techniques gardées sans porteur nommé (phrases de leur
    comportement dans la trace)."""
    claims = []
    for (s, rel, t), quotes in draft.evidence.items():
        if rel == "uses" and draft.type_of(t) == "attack-pattern":
            claims.append(Claim((s, rel, t), "technique", list(quotes), " ; ".join(draft.procedures.get(t, [])) or None, attack_id(draft.objects[t])))
        elif draft.type_of(s) in CARRIER_TYPES and rel in ("uses", "targets"):
            claims.append(Claim((s, rel, t), "action", list(quotes)))
        else:
            claims.append(Claim((s, rel, t), "relation", list(quotes)))
    for sid in sorted(draft.kept):
        aid = attack_id(draft.objects[sid])
        texts = [draft.by_uid[n].text for b in behaviors if aid in (b.get("chosen") or []) and b.get("center") is None
                 for n in b.get("uids", []) if isinstance(n, int) and n in draft.by_uid]  # fmt: skip
        if texts:
            claims.append(Claim(("", "uses", sid), "technique", list(dict.fromkeys(texts)), " ; ".join(draft.procedures.get(sid, [])) or None, aid))
    return claims


# --- Application au graphe ------------------------------------------------------------------------------------------------
def _uids(draft: DraftGraph, quotes: list[str]) -> list[int]:
    by_text = {u.text: u.uid for u in draft.units}
    return [by_text[q] for q in quotes if q in by_text]


def _refuse(draft: DraftGraph, key: tuple[str, str, str], reason: str, result) -> None:
    s, rel, t = key
    if s:
        draft.evidence.pop(key, None)
        draft.confidence.pop(key, None)
        result.refused_relations.append((s, relationship_type_of(rel), t, reason))
        draft.log.append(f"reject {draft.name_of(s)} --{rel}--> {draft.name_of(t)} : {reason}")
    else:
        draft.kept.discard(t)
        result.refused_techniques.append((attack_id(draft.objects[t]) or t, reason))
        draft.log.append(f"reject {draft.name_of(t)} (niveau du rapport) : {reason}")
    result.accepted -= 1
    result.refused += 1


def _move_procedures(draft: DraftGraph, old: str, new: str) -> None:
    still_used = any(t == old for _, _, t in draft.evidence) or old in draft.kept
    moved = draft.procedures.get(old, []) if still_used else draft.procedures.pop(old, [])
    known = draft.procedures.setdefault(new, [])
    known += [p for p in moved if p not in known]


def apply(draft: DraftGraph, claim: Claim, decision: Decision, result) -> tuple[str, str, str] | None:
    """Applique une décision ; retourne la clé finale de l'affirmation (None si retirée). Une réattribution ou une remontée
    passe par `DraftGraph.relate` (les phrases citées doivent nommer le nouveau porteur) ; un refus de `relate` retire
    l'affirmation d'origine (« porteur contesté ») : le vérificateur a dit que l'auteur n'est pas la source."""
    from backend.extracting.cascade.graph import ref  # évite l'import circulaire au chargement du module

    key = claim.key
    s, rel, t = key
    if decision.action == "drop":
        _refuse(draft, key, decision.reason, result)
        return None
    final = key
    nums = ",".join(map(str, _uids(draft, draft.evidence.get(key) or claim.quotes)))
    if decision.action == "reassign" and decision.new_source:
        if not nums:
            return key
        err = draft.relate(f"{ref(draft, decision.new_source)}|{rel}|{ref(draft, t)}|{nums}")
        if err:
            if s:
                _refuse(draft, key, f"porteur contesté : {err.split(' : ', 1)[-1]}", result)
                return None
            return key  # technique au niveau du rapport : elle reste sans porteur
        final = next(k for k in draft.evidence if k[0] == decision.new_source and k[2] == t)
        if s and final != key:
            draft.evidence.pop(key, None)
            draft.confidence.pop(key, None)
        elif not s:
            draft.kept.discard(t)
        draft.log.append(f"fix porteur {draft.name_of(s) if s else 'non nommé'} -> {draft.name_of(decision.new_source)} pour {draft.name_of(t)}")
    elif decision.action == "to_parent" and claim.technique:
        parent = claim.technique.split(".")[0]
        psid, err = draft.technique(parent)
        if err or not psid:
            return key
        source = decision.new_source or s
        if source:
            err = draft.relate(f"{ref(draft, source)}|{rel}|{parent}|{nums}") if nums else "aucune phrase"
            if err:
                _refuse(draft, key, f"remontée à la parente impossible : {err.split(' : ', 1)[-1]}", result)
                return None
            final = (source, rel, psid) if (source, rel, psid) in draft.evidence else next(k for k in draft.evidence if k[0] == source and k[2] == psid)
            if s:
                draft.evidence.pop(key, None)
                draft.confidence.pop(key, None)
            else:
                draft.kept.discard(t)
        else:
            draft.kept.discard(t)
            draft.kept.add(psid)
            final = ("", rel, psid)
        _move_procedures(draft, t, psid)
        draft.log.append(f"fix {claim.technique} -> {parent} (seule la parente est établie)")
    if decision.confidence is not None and final[0]:
        draft.confidence[final] = decision.confidence
    return final


def agents_of(draft: DraftGraph, clusters, claims: list[Claim]) -> list[str]:
    """Porteurs proposés au vérificateur : centres des grappes de l'incident, puis sources des affirmations."""
    out = [c.center for c in clusters if c.scope == "incident" and c.center]
    out += [c.key[0] for c in claims if c.key[0] and draft.type_of(c.key[0]) in CARRIER_TYPES]
    return list(dict.fromkeys(out))


def verify_claims(draft: DraftGraph, text: str, system: str, clusters, result, call, apply_decisions: bool) -> list[dict]:
    """Vérifie toutes les affirmations ; applique les décisions si `apply_decisions` (mode « on »), sinon les trace seulement
    (mode « shadow »). Retourne la trace : affirmation, verdict, décision."""
    from backend.extracting import llm

    claims = collect_claims(draft, result.behaviors)
    agents = agents_of(draft, clusters, claims)
    groups = batches(claims)
    answers = llm.map_parallel(lambda b: call("vérification:questions", system, verify_prompt(text, draft, b, agents),
                                              verify_schema(len(b), len(agents)), 30 + 40 * len(b)), groups)  # fmt: skip
    trace = []
    for batch, answer in zip(groups, answers):
        verdicts = parse_verdicts(answer, len(batch), len(agents))
        for k, claim in enumerate(batch, 1):
            v = verdicts.get(k)
            d = decide(claim, v, agents)
            trace.append({"key": list(claim.key), "kind": claim.kind, "technique": claim.technique,
                          "verdict": vars(v) if v else None, "decision": vars(d)})  # fmt: skip
    if apply_decisions:
        for row, claim in zip(trace, [c for b in groups for c in b]):
            d = Decision(**row["decision"])
            if d.action != "keep" or d.confidence is not None:
                if claim.key[0] and claim.key not in draft.evidence:
                    continue  # déjà fusionnée par une décision précédente
                apply(draft, claim, d, result)
    return trace
