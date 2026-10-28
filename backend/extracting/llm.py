"""Client Ollama de l'extraction : un appel = une requête, sortie contrainte par un schéma JSON, durées mesurées.

Le coût d'un modèle de langage local est dominé par les tokens GÉNÉRÉS (quelques dizaines par seconde), très loin
devant la lecture du prompt (milliers par seconde). Ce module ne fait donc que trois choses :
- imposer un schéma de sortie (Ollama « structured outputs ») pour qu'aucun appel ne produise de texte libre ;
- désactiver la réflexion de Qwen3 (`think: False`), qui génère des centaines de tokens avant de répondre ;
- rapporter ce que le SERVEUR a mesuré (tokens lus, tokens générés, durées), pour optimiser sur des faits ;
- demander un JSON sur une seule ligne : indenté, le même contenu coûte jusqu'à 1,8 fois plus de tokens générés (mesuré).
"""

import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import dataclass, field

import json_repair
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from backend.config import LLM_BACKEND, LLM_MODEL, LLM_SLOTS, OLLAMA_API_URL, OLLAMA_NUM_CTX, OPENAI_BASE_URL

OPENAI = LLM_BACKEND == "openai"  # SGLang / vLLM : requêtes groupées côté serveur, plusieurs articles peuvent partager le GPU
# Avec « openai », une requête attend son tour dans le lot du serveur (une dizaine d'autres générations en même temps) : délai plus long.
TOTAL_REQUEST_TIMEOUT = float(os.environ.get("CTI_LLM_TIMEOUT", "180" if OPENAI else "55"))
COMPACT = "\nÉcris le JSON sur UNE SEULE LIGNE, sans retour à la ligne ni indentation."
# Réflexion du modèle (Qwen3.x, backend « openai » seulement) : le serveur doit séparer le raisonnement de la réponse
# (`--reasoning-parser qwen3`), le schéma JSON ne s'applique qu'à la réponse. Ses tokens s'ajoutent au budget de chaque appel.
THINKING = os.environ.get("CTI_THINKING", "off").strip().lower() in ("on", "1", "yes", "true")
THINKING_TOKENS = int(os.environ.get("CTI_THINKING_TOKENS") or 8192)

_local = threading.local()
# Une requête n'est envoyée que lorsqu'un slot du serveur est libre. Abandonner une requête restée dans la file du serveur
# (délai dépassé) ne la retire pas toujours : derrière un tunnel SSH, Ollama ne voit pas la fermeture de la connexion et la
# traite quand même, pendant que la requête suivante s'ajoute à la file. L'attente a donc lieu ici, sans délai.
_slots = threading.BoundedSemaphore(LLM_SLOTS)


@dataclass
class LLMResult:
    parsed: dict | list | None
    raw: str
    prompt_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0  # tokens du prompt relus depuis le cache de préfixe du serveur (moteur « openai » seulement)
    seconds: float = 0.0  # durée totale vue du client
    server: dict = field(default_factory=dict)  # durées mesurées par Ollama, en secondes
    error: str | None = None  # appel échoué (délai dépassé, serveur injoignable) : voir `try_generate`

    @property
    def tokens_per_second(self) -> float:
        gen = self.server.get("generate", 0.0)
        return self.output_tokens / gen if gen else 0.0


def _session() -> requests.Session:
    if not hasattr(_local, "session"):
        s = requests.Session()
        s.trust_env = False
        s.mount("http://", HTTPAdapter(max_retries=Retry(total=0)))
        _local.session = s
    return _local.session


def _parse(raw: str):
    text = re.sub(r"<think>.*?</think>", "", raw or "", flags=re.DOTALL).strip()
    start = re.search(r"[\[{]", text)
    if not start:
        return None
    body = text[start.start() :]
    if json_end(body) == -1:
        # Réponse tronquée par `num_predict` : ses éléments complets restent valables, seul le dernier est coupé (« tool|Cobal »).
        # Sans cela, une liste de chaînes n'a aucun crochet fermant et TOUTE la réponse était perdue (article 641, relations#0).
        body = body[: body.rfind(",")] if "," in body else body
    else:
        body = body[: json_end(body)]  # sans ce que le modèle a écrit après la valeur (`}]}}…`)
    parsed = json_repair.loads(body)
    return parsed if isinstance(parsed, (dict, list)) and parsed != {} else None


def json_end(text: str) -> int:
    """Position qui suit la fin de la première valeur JSON complète (objet ou liste) de `text`, ou -1 si elle n'est pas fermée."""
    depth, in_string, escaped = 0, False, False
    for i, c in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                in_string = False
        elif c == '"':
            in_string = True
        elif c in "{[":
            depth += 1
        elif c in "}]" and depth:
            depth -= 1
            if depth == 0:
                return i + 1
    return -1


def _post_stream(url: str, payload: dict):
    """Morceaux JSON d'une réponse en flux. Au plus OLLAMA_NUM_PARALLEL requêtes sont en cours à la fois (voir `_slots`) ; le
    délai court à partir de l'envoi, pas de l'attente d'un slot. Fermer le générateur ferme la connexion et libère le slot."""
    with _slots:
        deadline = time.perf_counter() + TOTAL_REQUEST_TIMEOUT
        try:
            with _session().post(url, json={**payload, "stream": True}, timeout=(10, TOTAL_REQUEST_TIMEOUT), stream=True) as resp:
                resp.raise_for_status()
                for line in resp.iter_lines():
                    if time.perf_counter() >= deadline:
                        raise TimeoutError(f"Ollama n'a pas répondu dans le délai de {TOTAL_REQUEST_TIMEOUT:.0f}s")
                    if line:
                        yield json.loads(line)
        except requests.exceptions.ReadTimeout as exc:
            raise TimeoutError(f"Ollama n'a pas envoyé de fragment dans le délai de {TOTAL_REQUEST_TIMEOUT:.0f}s") from exc


def _stream(payload: dict) -> tuple[str, dict, int, float]:
    """(texte, bilan du serveur, morceaux reçus, instant du premier). La lecture s'arrête dès que la valeur JSON est fermée : sous
    contrainte de schéma, une sortie compacte se poursuit sinon par des accolades (`}]}}]}…`) jusqu'à `num_predict` (mesuré : des
    centaines de tokens, plusieurs dizaines de secondes). Fermer la connexion arrête la génération côté serveur quand il la voit ; le bilan
    est alors vide."""
    text, chunks, first, closed = "", 0, 0.0, False
    with closing(_post_stream(OLLAMA_API_URL, payload)) as stream:
        for chunk in stream:
            if chunk.get("done"):
                return text, chunk, chunks, first
            if closed:  # le modèle écrit encore après la fin de la valeur : on coupe
                break
            chunks += 1
            first = first or time.perf_counter()
            text += chunk.get("response") or ""
            start = min((i for i in (text.find("{"), text.find("[")) if i >= 0), default=-1)
            # valeur fermée : un morceau de plus est lu, le bilan du serveur s'il s'arrête là, sinon de quoi couper
            closed = start >= 0 and json_end(text[start:]) >= 0
    return text, {}, chunks, first


def _openai_post(payload: dict) -> dict:
    """Une requête /v1/chat/completions (sans flux : la réponse arrive d'un bloc, le délai court de l'envoi à la fin). Au plus
    LLM_SLOTS requêtes à la fois, comme pour Ollama. Une erreur HTTP garde le message du serveur (schéma refusé, contexte dépassé)."""
    with _slots:
        try:
            resp = _session().post(f"{OPENAI_BASE_URL}/chat/completions", json=payload, timeout=(10, TOTAL_REQUEST_TIMEOUT))
        except requests.exceptions.ReadTimeout as exc:
            raise TimeoutError(f"Le serveur n'a pas répondu dans le délai de {TOTAL_REQUEST_TIMEOUT:.0f}s") from exc
        if resp.status_code >= 400:
            raise requests.HTTPError(f"{resp.status_code} : {resp.text[:400]}", response=resp)
        return resp.json()


def _openai_payload(model: str, messages: list[dict], max_output_tokens: int) -> dict:
    """Décodage déterministe (température 0, top_k 1, graine fixe) et réflexion de Qwen coupée, comme avec Ollama : le serveur
    applique sinon les paramètres par défaut de la configuration du modèle (température 0,6). Avec CTI_THINKING, l'échantillonnage
    recommandé par Qwen pour la réflexion (un décodage glouton y boucle), graine fixe."""
    if THINKING:
        return {
            "model": model, "messages": messages, "max_tokens": max_output_tokens + THINKING_TOKENS, "temperature": 0.6, "top_p": 0.95,
            "top_k": 20, "seed": 0, "chat_template_kwargs": {"enable_thinking": True},
        }  # fmt: skip
    return {
        "model": model, "messages": messages, "max_tokens": max_output_tokens, "temperature": 0, "top_k": 1, "seed": 0,
        "chat_template_kwargs": {"enable_thinking": False},
    }  # fmt: skip


def _openai_generate(system: str, prompt: str, schema: dict, max_output_tokens: int, model: str) -> LLMResult:
    payload = _openai_payload(model, [{"role": "system", "content": system + COMPACT}, {"role": "user", "content": prompt}], max_output_tokens)
    payload["response_format"] = {"type": "json_schema", "json_schema": {"name": "answer", "strict": True, "schema": schema}}
    t0 = time.perf_counter()
    data = _openai_post(payload)
    seconds = time.perf_counter() - t0
    raw = ((data.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
    usage = data.get("usage") or {}
    return LLMResult(
        parsed=_parse(raw), raw=raw, prompt_tokens=int(usage.get("prompt_tokens") or 0), output_tokens=int(usage.get("completion_tokens") or 0),
        cached_tokens=int((usage.get("prompt_tokens_details") or {}).get("cached_tokens") or 0), seconds=seconds,
        server={"total": seconds, "load": 0.0, "prompt": 0.0, "generate": seconds},  # le serveur ne rapporte pas ses durées
    )  # fmt: skip


def _openai_messages(messages: list[dict]) -> list[dict]:
    """Historique au format d'Ollama (arguments d'outil en dictionnaire, résultat « tool » sans identifiant) -> format OpenAI
    (arguments en texte JSON, `tool_call_id`). Les identifiants dépendent de la position du message : la conversion est la même
    à chaque tour, sans mémoire."""
    out, pending = [], []
    for i, m in enumerate(messages):
        if m["role"] == "assistant" and m.get("tool_calls"):
            calls = []
            for j, call in enumerate(m["tool_calls"]):
                fn = call.get("function") or {}
                args = fn.get("arguments") or {}
                calls.append({
                    "id": f"call_{i}_{j}", "type": "function",
                    "function": {"name": fn.get("name", ""), "arguments": args if isinstance(args, str) else json.dumps(args, ensure_ascii=False)},
                })  # fmt: skip
                pending.append(f"call_{i}_{j}")
            out.append({"role": "assistant", "content": m.get("content") or "", "tool_calls": calls})
        elif m["role"] == "tool":
            out.append({"role": "tool", "tool_call_id": pending.pop(0) if pending else f"call_{i}", "content": m.get("content") or ""})
        else:
            out.append({"role": m["role"], "content": m.get("content") or ""})
    return out


def _openai_chat(messages: list[dict], tools: list[dict], max_output_tokens: int, model: str) -> "ChatResult":
    payload = _openai_payload(model, _openai_messages(messages), max_output_tokens)
    payload["tools"] = tools
    t0 = time.perf_counter()
    data = _openai_post(payload)
    choice = (data.get("choices") or [{}])[0]
    msg = choice.get("message") or {}
    parsed = []
    for call in msg.get("tool_calls") or []:
        fn = call.get("function") or {}
        args = fn.get("arguments") or {}
        if isinstance(args, str):
            args = json_repair.loads(args) if args.strip() else {}
        parsed.append({"name": fn.get("name", ""), "arguments": args if isinstance(args, dict) else {}})
    content = msg.get("content") or ""
    # même forme que le message d'Ollama : l'historique se rejoue tel quel, quel que soit le moteur
    message = {"role": "assistant", "content": content}
    if parsed:
        message["tool_calls"] = [{"function": {"name": c["name"], "arguments": c["arguments"]}} for c in parsed]
    usage = data.get("usage") or {}
    return ChatResult(
        message, content, parsed, int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0),
        time.perf_counter() - t0, choice.get("finish_reason") == "length",
    )  # fmt: skip


def generate(
    system: str,
    prompt: str,
    schema: dict,
    *,
    max_output_tokens: int = 700,
    num_ctx: int = OLLAMA_NUM_CTX,
    model: str = LLM_MODEL,
) -> LLMResult:
    """Un appel contraint. Les options sont fixes (décodage déterministe) pour que deux exécutions donnent la même
    extraction."""
    if OPENAI:
        return _openai_generate(system, prompt, schema, max_output_tokens, model)
    payload = {
        "model": model,
        "system": system + COMPACT,
        "prompt": prompt,
        "format": schema,
        "think": False,
        "keep_alive": -1,
        "options": {"temperature": 0, "seed": 0, "num_ctx": num_ctx, "num_predict": max_output_tokens},
    }
    t0 = time.perf_counter()
    raw, body, chunks, first = _stream(payload)
    parsed = _parse(raw)
    ns = 1e-9
    end = time.perf_counter()
    if not body:  # génération interrompue par le client : le serveur n'a rien rapporté, durées mesurées ici
        return LLMResult(parsed, raw, 0, chunks, end - t0, {"total": end - t0, "load": 0.0, "prompt": first - t0, "generate": end - first})
    return LLMResult(
        parsed=parsed,
        raw=raw,
        prompt_tokens=int(body.get("prompt_eval_count") or 0),
        output_tokens=int(body.get("eval_count") or 0),
        seconds=end - t0,
        server={
            "total": (body.get("total_duration") or 0) * ns,
            "load": (body.get("load_duration") or 0) * ns,
            "prompt": (body.get("prompt_eval_duration") or 0) * ns,
            "generate": (body.get("eval_duration") or 0) * ns,
        },
    )


CHAT_URL = OLLAMA_API_URL.rsplit("/api/", 1)[0] + "/api/chat"


@dataclass
class ChatResult:
    """Un tour d'agent : texte et appels d'outils du modèle, avec les comptes du serveur."""

    message: dict  # message assistant à rejouer dans l'historique (role, content, tool_calls)
    content: str
    tool_calls: list[dict]  # [{"name": ..., "arguments": {...}}]
    prompt_tokens: int = 0
    output_tokens: int = 0
    seconds: float = 0.0
    truncated: bool = False  # la génération a atteint `num_predict`


def chat(
    messages: list[dict],
    tools: list[dict],
    *,
    max_output_tokens: int = 900,
    num_ctx: int = OLLAMA_NUM_CTX,
    model: str = LLM_MODEL,
) -> ChatResult:
    """Un tour de conversation avec appel d'outils natif d'Ollama (`/api/chat`, champ `tools`). Lecture en flux : le délai
    total (`TOTAL_REQUEST_TIMEOUT`) court à partir de l'envoi, comme pour `generate`, et un slot du serveur est attendu. Avec le
    moteur « openai », le serveur doit être lancé avec un analyseur d'appels d'outils (SGLang : `--tool-call-parser qwen3_coder`)."""
    if OPENAI:
        return _openai_chat(messages, tools, max_output_tokens, model)
    payload = {
        "model": model,
        "messages": messages,
        "tools": tools,
        "think": False,
        "keep_alive": -1,
        "options": {"temperature": 0, "seed": 0, "num_ctx": num_ctx, "num_predict": max_output_tokens},
    }
    t0 = time.perf_counter()
    content, calls, body = "", [], {}
    with closing(_post_stream(CHAT_URL, payload)) as stream:
        for chunk in stream:
            msg = chunk.get("message") or {}
            content += msg.get("content") or ""
            calls += msg.get("tool_calls") or []
            if chunk.get("done"):
                body = chunk
                break
    parsed = []
    for call in calls:
        fn = call.get("function") or {}
        args = fn.get("arguments") or {}
        if isinstance(args, str):  # certains modèles renvoient les arguments sérialisés
            args = json_repair.loads(args) if args.strip() else {}
        parsed.append({"name": fn.get("name", ""), "arguments": args if isinstance(args, dict) else {}})
    message = {"role": "assistant", "content": content}
    if calls:
        message["tool_calls"] = calls
    output = int(body.get("eval_count") or 0)
    return ChatResult(
        message, content, parsed, int(body.get("prompt_eval_count") or 0), output, time.perf_counter() - t0,
        output >= max_output_tokens or body.get("done_reason") == "length",
    )  # fmt: skip


def generate_many(calls: list[tuple[str, str, dict, int]], *, workers: int | None = None) -> list[LLMResult | Exception]:
    """Plusieurs appels contraints `(système, prompt, schéma, tokens de sortie)` envoyés en parallèle, résultats dans l'ordre.
    Un appel échoué (délai dépassé, serveur injoignable, schéma refusé) est rendu comme exception à sa place : les autres
    réponses restent valables. Le nombre de requêtes en vol est borné par `_slots` (LLM_SLOTS), tous articles confondus ;
    avec Ollama (un slot) les appels passent donc l'un après l'autre."""

    def one(call: tuple[str, str, dict, int]) -> LLMResult | Exception:
        system, prompt, schema, tokens = call
        try:
            return generate(system, prompt, schema, max_output_tokens=tokens)
        except (TimeoutError, requests.RequestException, ValueError) as exc:
            return exc

    if not calls:
        return []
    with ThreadPoolExecutor(max_workers=workers or max(LLM_SLOTS, 1)) as pool:
        return list(pool.map(one, calls))


def try_generate(system: str, prompt: str, schema: dict, **kwargs) -> LLMResult:
    """`generate` pour une étape qui a une réponse par défaut honnête (IOC : rôle `unknown` ; règle : sans rattachement) :
    un appel échoué ne fait pas échouer l'article, il est rendu avec `error` et compté. Les étapes dont le résultat serait
    faux sans réponse (entités, relations) appellent `generate` et laissent l'article échouer, pour qu'il soit repris."""
    t0 = time.perf_counter()
    try:
        return generate(system, prompt, schema, **kwargs)
    except (TimeoutError, requests.RequestException, ValueError) as exc:
        return LLMResult(parsed=None, raw="", seconds=time.perf_counter() - t0, error=f"{type(exc).__name__}: {exc}")


def map_parallel(fn, items: list) -> list:
    """`fn` appliquée à chaque élément en parallèle, résultats dans l'ordre. Chaque appel au modèle attend un slot (`_slots`) :
    avec Ollama (un slot) ils passent donc l'un après l'autre, avec SGLang ensemble."""
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=min(len(items), max(LLM_SLOTS, 1))) as pool:
        return list(pool.map(fn, items))
