"""Client du serveur d'inférence de l'extraction (API /v1/chat/completions : vLLM, SGLang) : sortie contrainte par un schéma
JSON (`generate`) ou tour de conversation avec outils (`chat`), tokens comptés par le serveur.

Le coût d'un modèle de langage est dominé par les tokens GÉNÉRÉS (quelques dizaines par seconde), très loin devant la lecture
du prompt (milliers par seconde, et presque gratuite quand le prompt commence comme le précédent : cache de préfixe). D'où :
- un schéma de sortie imposé, pour qu'aucun appel ne produise de texte libre ;
- la réflexion de Qwen coupée, qui génère des centaines de tokens avant de répondre ;
- un JSON sur une seule ligne : indenté, le même contenu coûte jusqu'à 1,8 fois plus de tokens générés (mesuré).
"""

import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import json_repair
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from backend.config import LLM_MODEL, LLM_SLOTS, OPENAI_BASE_URL

# Une requête attend son tour dans le lot du serveur (une dizaine d'autres générations en même temps)
TOTAL_REQUEST_TIMEOUT = float(os.environ.get("CTI_LLM_TIMEOUT", "180"))
COMPACT = "\nÉcris le JSON sur UNE SEULE LIGNE, sans retour à la ligne ni indentation."
# Réflexion du modèle (Qwen3.x) : le serveur doit séparer le raisonnement de la réponse (`--reasoning-parser qwen3`), le schéma
# JSON ne s'applique qu'à la réponse. Ses tokens s'ajoutent au budget de chaque appel.
THINKING = os.environ.get("CTI_THINKING", "off").strip().lower() in ("on", "1", "yes", "true")
THINKING_TOKENS = int(os.environ.get("CTI_THINKING_TOKENS") or 8192)

_local = threading.local()
# Au plus LLM_SLOTS requêtes en vol (le --max-running-requests du serveur) : les autres attendent ici, sans délai
_slots = threading.BoundedSemaphore(LLM_SLOTS)


@dataclass
class LLMResult:
    parsed: dict | list | None
    raw: str
    prompt_tokens: int = 0
    output_tokens: int = 0
    seconds: float = 0.0
    error: str | None = None  # appel échoué (délai dépassé, serveur injoignable) : voir `try_generate`


@dataclass
class ChatResult:
    """Un tour de conversation : texte et appels d'outils du modèle, avec les comptes du serveur."""

    message: dict  # message assistant à rejouer dans l'historique (format OpenAI, identifiants d'appel compris)
    content: str
    tool_calls: list[dict]  # [{"id": ..., "name": ..., "arguments": {...}}]
    prompt_tokens: int = 0
    output_tokens: int = 0
    seconds: float = 0.0
    truncated: bool = False  # la génération a atteint `max_tokens`


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
        # Réponse tronquée par `max_tokens` : ses éléments complets restent valables, seul le dernier est coupé (« tool|Cobal »)
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


def _post(payload: dict) -> dict:
    """Une requête /v1/chat/completions (sans flux : le délai court de l'envoi à la fin). Une erreur HTTP garde le message du
    serveur (schéma refusé, contexte dépassé, outils non activés)."""
    with _slots:
        try:
            resp = _session().post(f"{OPENAI_BASE_URL}/chat/completions", json=payload, timeout=(10, TOTAL_REQUEST_TIMEOUT))
        except requests.exceptions.ReadTimeout as exc:
            raise TimeoutError(f"Le serveur n'a pas répondu dans le délai de {TOTAL_REQUEST_TIMEOUT:.0f}s") from exc
        if resp.status_code >= 400:
            raise requests.HTTPError(f"{resp.status_code} : {resp.text[:400]}", response=resp)
        return resp.json()


def _payload(messages: list[dict], max_output_tokens: int, model: str) -> dict:
    """Décodage déterministe (température 0, top_k 1, graine fixe) et réflexion coupée : le serveur applique sinon les paramètres par
    défaut du modèle (température 0,6). Avec CTI_THINKING, l'échantillonnage recommandé par Qwen pour la réflexion (un décodage
    glouton y boucle), graine fixe."""
    if THINKING:
        return {
            "model": model, "messages": messages, "max_tokens": max_output_tokens + THINKING_TOKENS, "temperature": 0.6, "top_p": 0.95,
            "top_k": 20, "seed": 0, "chat_template_kwargs": {"enable_thinking": True},
        }  # fmt: skip
    return {
        "model": model, "messages": messages, "max_tokens": max_output_tokens, "temperature": 0, "top_k": 1, "seed": 0,
        "chat_template_kwargs": {"enable_thinking": False},
    }  # fmt: skip


def generate(system: str, prompt: str, schema: dict, *, max_output_tokens: int = 700, model: str = LLM_MODEL) -> LLMResult:
    """Un appel contraint par `schema`. Décodage fixe : deux exécutions donnent la même extraction."""
    payload = _payload([{"role": "system", "content": system + COMPACT}, {"role": "user", "content": prompt}], max_output_tokens, model)
    payload["response_format"] = {"type": "json_schema", "json_schema": {"name": "answer", "strict": True, "schema": schema}}
    t0 = time.perf_counter()
    data = _post(payload)
    raw = ((data.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
    usage = data.get("usage") or {}
    return LLMResult(_parse(raw), raw, int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0), time.perf_counter() - t0)


def chat(messages: list[dict], tools: list[dict], *, max_output_tokens: int = 900, model: str = LLM_MODEL) -> ChatResult:
    """Un tour de conversation avec appel d'outils natif. Le serveur doit être lancé avec un analyseur d'appels d'outils
    (`--enable-auto-tool-choice --tool-call-parser qwen3_coder` pour Qwen3.5) ; sinon il refuse la requête (erreur HTTP)."""
    payload = _payload(messages, max_output_tokens, model)
    payload["tools"] = tools
    t0 = time.perf_counter()
    data = _post(payload)
    choice = (data.get("choices") or [{}])[0]
    msg = choice.get("message") or {}
    calls = msg.get("tool_calls") or []
    parsed = []
    for call in calls:
        args = (call.get("function") or {}).get("arguments") or {}
        if isinstance(args, str):
            args = json_repair.loads(args) if args.strip() else {}
        parsed.append({"id": call.get("id", ""), "name": (call.get("function") or {}).get("name", ""), "arguments": args if isinstance(args, dict) else {}})
    content = msg.get("content") or ""
    message = {"role": "assistant", "content": content, **({"tool_calls": calls} if calls else {})}
    usage = data.get("usage") or {}
    return ChatResult(
        message, content, parsed, int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0),
        time.perf_counter() - t0, choice.get("finish_reason") == "length",
    )  # fmt: skip


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
    """`fn` appliquée à chaque élément en parallèle, résultats dans l'ordre ; chaque appel au modèle attend un slot (`_slots`)."""
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=min(len(items), LLM_SLOTS)) as pool:
        return list(pool.map(fn, items))
