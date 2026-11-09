"""Questions en langage naturel sur le graphe global (panneau « Interroger le graphe » du dashboard).

Le modèle n'écrit pas de Cypher : il appelle des outils en lecture seule aux résultats bornés (`StixStore.search_entities`,
`neighbors`, `paths`, `top_entities`, `entity_summary`). Chaque entité qu'un outil lui montre reçoit un repère court
(E1, E2…) : il cite ces repères, bien moins coûteux à générer qu'un identifiant STIX, et toute citation d'un repère
qu'aucun outil n'a montré est retirée de la réponse. Le code borne et vérifie ; le modèle choisit quoi chercher et ce que
cela signifie.
"""

import json
import re
import threading
from typing import Any, Callable

import requests

from backend.config import ASK_SLOTS, OPENAI_BASE_URL
from backend.database.stix_store import StixStore, neo4j_relationship_type
from backend.extracting import llm

from .stix_dashboard import family_of

MAX_TURNS = 6  # tours avec outils avant d'exiger une réponse
MAX_ROWS = 25  # lignes renvoyées par un outil
MAX_HISTORY = 3  # échanges précédents rejoués
_slots = threading.BoundedSemaphore(ASK_SLOTS)

SYSTEM = """Tu réponds aux questions d'un analyste sur un graphe de connaissances CTI au format STIX 2.1, construit à partir
d'articles de renseignement sur les menaces. Tu ne connais du graphe que ce que les outils te renvoient.

Méthode :
- Trouve d'abord les entités nommées dans la question avec search_entities, puis explore avec neighbors, paths ou top.
- Une entité renvoyée par un outil a un repère court (E1, E2…). Utilise ces repères dans les appels d'outils suivants.
- Fais au plus quelques appels, puis réponds.

Réponse, en français, en quelques phrases courtes :
- Cite chaque entité par son repère entre doubles crochets, par exemple [[E3]] ; jamais un nom seul ni un identifiant STIX.
- N'affirme que ce que les outils ont renvoyé ; donne le nombre d'articles qui étayent une relation quand il compte.
- Si le graphe ne contient pas la réponse, dis-le en une phrase, sans rien supposer.
- Les éditeurs CTI et les chercheurs qui publient un article ne sont pas des acteurs de la menace."""

_TYPES = ["threat-actor", "intrusion-set", "campaign", "malware", "tool", "attack-pattern", "vulnerability", "infrastructure", "identity", "location", "incident", "course-of-action"]


def _fn(name: str, description: str, properties: dict, required: list[str]) -> dict:
    return {"type": "function", "function": {"name": name, "description": description, "parameters": {"type": "object", "properties": properties, "required": required}}}


_ENTITY = {"type": "string", "description": "repère d'une entité déjà renvoyée (E1, E2…)"}
_TYPE = {"type": "string", "enum": _TYPES, "description": "type STIX"}
_RELATION = {"type": "string", "description": "type de relation STIX (uses, targets, attributed-to, indicates…)"}
TOOLS = [
    _fn("search_entities", "Cherche des entités par nom, alias ou identifiant (T####, CVE-…, G####).", {"text": {"type": "string"}, "type": _TYPE}, ["text"]),
    _fn("get_entity", "Attributs d'une entité, ses articles sources et le compte de ses relations par type.", {"entity": _ENTITY}, ["entity"]),
    _fn("neighbors", "Voisins directs d'une entité, filtrables par relation et par type.", {"entity": _ENTITY, "relation": _RELATION, "type": _TYPE}, ["entity"]),
    _fn("paths", "Plus courts chemins (3 relations au plus) entre deux entités.", {"source": _ENTITY, "target": _ENTITY}, ["source", "target"]),
    _fn("top", "Entités les plus reliées (ou les plus citées par les articles), d'un type donné, par une relation donnée.",
        {"type": _TYPE, "relation": _RELATION, "by": {"type": "string", "enum": ["relations", "articles"]}}, []),
]  # fmt: skip


class _Handles:
    """Repères courts des entités montrées au modèle, dans l'ordre où elles apparaissent."""

    def __init__(self):
        self.by_id: dict[str, str] = {}
        self.nodes: dict[str, dict] = {}

    def of(self, node: dict) -> str:
        if node["id"] not in self.by_id:
            handle = f"E{len(self.by_id) + 1}"
            self.by_id[node["id"]] = handle
            self.nodes[handle] = {"id": node["id"], "label": node.get("name") or node["id"], "type": node.get("type", ""), "family": family_of(node.get("type", ""))}
        return self.by_id[node["id"]]

    def line(self, node: dict, extra: str = "") -> str:
        return f"{self.of(node)} | {node.get('type')} | {node.get('name')}{extra}"

    def resolve(self, handle: Any) -> str | None:
        node = self.nodes.get(str(handle or "").strip().strip("[]").upper())
        return node["id"] if node else None


def _relation(value: Any) -> str | None:
    return neo4j_relationship_type(str(value)) if value else None


def _type(value: Any) -> str | None:
    return value if value in _TYPES else None


def _run_tool(name: str, args: dict, store: StixStore, handles: _Handles) -> tuple[str, int]:
    """Texte renvoyé au modèle et nombre d'entités qu'il contient."""
    if name == "search_entities":
        rows = store.search_entities(str(args.get("text") or "").strip(), _type(args.get("type")), MAX_ROWS) if str(args.get("text") or "").strip() else []
        lines = [handles.line(r, f" | {r['sources']} articles | {r['degree']} relations") for r in rows]
        return ("\n".join(lines) or "Aucune entité ne correspond."), len(rows)
    if name == "top":
        rows = store.top_entities(_type(args.get("type")), _relation(args.get("relation")), args.get("by") == "articles", MAX_ROWS)
        lines = [handles.line(r, f" | {r['sources']} articles | {r['degree']} relations") for r in rows]
        return ("\n".join(lines) or "Aucune entité."), len(rows)
    if name == "paths":
        a, b = handles.resolve(args.get("source")), handles.resolve(args.get("target"))
        if not a or not b:
            return "Repère inconnu : utilise un repère renvoyé par un outil (E1, E2…).", 0
        rows = store.paths(a, b, 3, 5)
        lines = []
        for p in rows:
            names = {n["id"]: handles.of(n) for n in p["nodes"]}
            steps = [names[p["nodes"][0]["id"]]]
            for x, n in zip(p["relations"], p["nodes"][1:]):
                arrow = f"-{x['type'].lower()}->" if x["source"] != n["id"] else f"<-{x['type'].lower()}-"
                steps += [arrow, names[n["id"]]]
            lines.append(" ".join(steps))
        legend = [handles.line(n) for n in {n["id"]: n for p in rows for n in p["nodes"]}.values()]
        return ("\n".join(lines + ["", *legend]) if rows else "Aucun chemin de 3 relations au plus."), len(legend)
    entity = handles.resolve(args.get("entity"))
    if not entity:
        return "Repère inconnu : utilise un repère renvoyé par un outil (E1, E2…).", 0
    if name == "neighbors":
        rows, total = store.neighbors(entity, _relation(args.get("relation")), _type(args.get("type")), MAX_ROWS)
        me = handles.by_id[entity]
        lines = [
            f"{me} -{r['relation'].lower()}-> {handles.line(r)}" if r["outgoing"] else f"{handles.line(r)} -{r['relation'].lower()}-> {me}"
            for r in rows
        ]
        lines = [f"{line} | {r['sources']} articles" for line, r in zip(lines, rows)]
        more = f"\n({total - len(rows)} autres non affichés : filtre par relation ou par type)" if total > len(rows) else ""
        return ("\n".join(lines) + more if rows else "Aucun voisin avec ces filtres."), len(rows)
    if name == "get_entity":
        s = store.entity_summary(entity)
        if s is None:
            return "Entité introuvable.", 0
        p = s["p"]
        counts: dict[str, int] = {}
        for rel in s["relations"]:
            counts[rel.lower()] = counts.get(rel.lower(), 0) + 1
        refs = [r.get("external_id") for r in json.loads(p.get("external_references_json") or "[]") if r.get("external_id")]
        fields = [
            ("nom", p.get("name")), ("type", p.get("type")), ("alias", ", ".join(p.get("aliases") or [])), ("identifiants", ", ".join(refs)),
            ("sous-types", ", ".join(p.get(f"{p.get('type', '').replace('-', '_')}_types") or [])), ("pays", p.get("country")),
            ("secteurs", ", ".join(p.get("sectors") or [])), ("description", (p.get("description") or "")[:400]),
            ("relations", ", ".join(f"{k} {v}" for k, v in sorted(counts.items(), key=lambda kv: -kv[1]))),
            ("articles", "; ".join(f"{(r.get('published') or '')[:10]} {r.get('title')}" for r in s["reports"])),
        ]  # fmt: skip
        return f"{handles.by_id[entity]}\n" + "\n".join(f"{k} : {v}" for k, v in fields if v), 1
    return f"Outil inconnu : {name}.", 0


_CITE = re.compile(r"\[\[\s*(E\d+)\s*\]\]", re.IGNORECASE)


def _finalize(text: str, handles: _Handles) -> tuple[str, list[dict]]:
    """Réponse dont les citations de repères inconnus sont retirées, et entités citées dans l'ordre de citation."""
    cited: list[str] = []

    def keep(m: re.Match) -> str:
        handle = m.group(1).upper()
        if handle not in handles.nodes:
            return ""
        if handle not in cited:
            cited.append(handle)
        return f"[[{handle}]]"

    clean = re.sub(r"[ \t]+([.,;:])", r"\1", re.sub(r"[ \t]{2,}", " ", _CITE.sub(keep, text))).strip()
    return clean, [{"handle": h, **handles.nodes[h]} for h in cited]


def answer(question: str, focus: str | None, history: list[dict], emit: Callable[[dict], None], store: StixStore | None = None) -> None:
    """Répond à `question` en envoyant les événements `step` (appel d'outil), puis `answer` ou `error`, à `emit`."""
    if not _slots.acquire(timeout=90):
        emit({"type": "error", "message": "Une autre question est en cours de traitement. Réessayez dans un instant."})
        return
    try:
        store = store or StixStore()
        handles = _Handles()
        messages: list[dict] = [{"role": "system", "content": SYSTEM}]
        for turn in history[-MAX_HISTORY:]:
            if turn.get("question") and turn.get("answer"):
                messages += [{"role": "user", "content": str(turn["question"])}, {"role": "assistant", "content": str(turn["answer"])}]
        prompt = question.strip()
        if focus:
            s = store.entity_summary(focus)
            if s is not None:
                prompt += f"\n\nEntité sélectionnée dans le graphe : {handles.line(s['p'])}"
        messages.append({"role": "user", "content": prompt})

        text = ""
        for turn in range(MAX_TURNS + 1):
            if turn == MAX_TURNS:
                messages.append({"role": "user", "content": "Réponds maintenant avec ce que les outils ont renvoyé, sans nouvel appel."})
            result = llm.chat(messages, TOOLS, max_output_tokens=700, stage="ask")
            messages.append(result.message)
            if not result.tool_calls or turn == MAX_TURNS:
                text = result.content
                break
            for call in result.tool_calls:
                output, count = _run_tool(call["name"], call["arguments"], store, handles)
                emit({"type": "step", "tool": call["name"], "args": call["arguments"], "count": count})
                messages.append({"role": "tool", "tool_call_id": call["id"], "content": output})
        clean, cited = _finalize(text, handles)
        if not clean:
            emit({"type": "error", "message": "Le modèle n'a pas formulé de réponse. Reformulez la question ou nommez une entité."})
            return
        emit({"type": "answer", "text": clean, "entities": cited, "consulted": len(handles.nodes)})
    except (TimeoutError, requests.RequestException) as exc:
        emit({"type": "error", "message": f"Le serveur du modèle ({OPENAI_BASE_URL}) ne répond pas : vérifiez le tunnel SSH. ({type(exc).__name__})"})
    finally:
        _slots.release()
