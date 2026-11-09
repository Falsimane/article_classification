"""Client du serveur d'inférence de l'extraction (API /v1/chat/completions : vLLM, SGLang) : sortie contrainte par un schéma
JSON (`generate`) ou tour de conversation avec outils (`chat`), tokens comptés par le serveur.

Le coût d'un modèle de langage est dominé par les tokens GÉNÉRÉS (quelques dizaines par seconde), très loin devant la lecture
du prompt (milliers par seconde, et presque gratuite quand le prompt commence comme le précédent : cache de préfixe). D'où :
- un schéma de sortie imposé, pour qu'aucun appel ne produise de texte libre ;
- la réflexion de Qwen coupée, qui génère des centaines de tokens avant de répondre ;
- un JSON sur une seule ligne : indenté, le même contenu coûte jusqu'à 1,8 fois plus de tokens générés (mesuré).

Journal (`record_to`) : chaque appel, requête complète (messages, schéma, échantillonnage) et réponse brute du serveur (réflexion,
contenu, raison d'arrêt, tokens), est une ligne JSON du fichier de l'article en cours ; la génération se lit en direct dans
`article_<id>.llm.live.log` (`tail -f`). Les fils de `map_parallel` et de `in_context` héritent du journal de l'article qui
les lance.
"""

import contextvars
import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

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
# Le `--max-model-len` du serveur : vLLM refuse un `max_tokens` plus grand, et réduit lui-même ce qui dépasse avec le prompt
CONTEXT_TOKENS = int(os.environ.get("CTI_MAX_MODEL_LEN") or 32768)
# Profondeur de la réflexion (gabarit Qwen3.8 : xhigh par défaut, medium, low ; une autre valeur fait refuser la requête)
REASONING_EFFORT = os.environ.get("CTI_REASONING_EFFORT", "xhigh").strip().lower()

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


class _Journal:
    """Journal d'un article : `<path>` (une ligne JSON par appel terminé) et `<path>.live.log` (réflexion et réponse au fil de
    la génération, chaque ligne préfixée de l'appel et de l'étape : les appels parallèles s'entrelacent ligne à ligne)."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)  # ouvert avant le premier bundle, qui créait le dossier
        self.file = path.open("w", encoding="utf-8")
        self.live = path.with_name(path.name.removesuffix(".jsonl") + ".live.log").open("w", encoding="utf-8")
        self.lock = threading.Lock()
        self.calls = 0

    def next_call(self) -> int:
        with self.lock:  # les appels d'un article partent de plusieurs fils
            self.calls += 1
            return self.calls

    def write(self, record: dict) -> None:
        with self.lock:
            self.file.write(json.dumps(record, ensure_ascii=False) + "\n")
            self.file.flush()  # un article interrompu garde ses appels terminés

    def say(self, prefix: str, text: str) -> None:
        with self.lock:
            self.live.writelines(f"{prefix} {line}\n" for line in text.split("\n"))
            self.live.flush()

    def close(self) -> None:
        self.file.close()
        self.live.close()


class _Live:
    """Texte d'un appel en cours de génération, écrit ligne par ligne dans le fichier en direct du journal."""

    def __init__(self, journal: _Journal, call: int, stage: str):
        self.journal, self.head, self.pending, self.part = journal, f"[{call} {stage or '?'}", "", None

    def add(self, part: str, text: str) -> None:
        if part != self.part:
            self.flush()
            self.part = part
        self.pending += text
        if "\n" in self.pending:
            done, self.pending = self.pending.rsplit("\n", 1)
            self.journal.say(f"{self.head} · {part}]", done)

    def flush(self) -> None:
        if self.pending:
            self.journal.say(f"{self.head} · {self.part}]", self.pending)
        self.pending = ""


_journal: contextvars.ContextVar[_Journal | None] = contextvars.ContextVar("llm_journal", default=None)


@contextmanager
def record_to(path: Path | None):
    """Écrit chaque appel fait dans ce bloc (fils lancés par `map_parallel` et `in_context` compris) dans `path`, une ligne
    JSON par appel, et la génération en direct dans `<path>.live.log` ; fichiers remplacés. `None` : rien n'est écrit."""
    if path is None:
        yield
        return
    journal = _Journal(path)
    token = _journal.set(journal)
    try:
        yield
    finally:
        _journal.reset(token)
        journal.close()


def _record(journal: _Journal, call: int, stage: str, payload: dict, data: dict | None, seconds: float, error: str | None) -> None:
    choice = ((data or {}).get("choices") or [{}])[0]
    msg = choice.get("message") or {}
    journal.write({
        "call": call, "stage": stage, "seconds": round(seconds, 2), "error": error, "finish_reason": choice.get("finish_reason"),
        "usage": (data or {}).get("usage"), "reasoning": msg.get("reasoning") or msg.get("reasoning_content"),
        "content": msg.get("content"), "tool_calls": msg.get("tool_calls"), "request": payload,
    })  # fmt: skip


def _stream(resp: requests.Response, deadline: float, live: _Live) -> dict:
    """Lit une réponse en flux (SSE) en écrivant réflexion et réponse au fil de l'eau ; rend la même forme qu'une réponse sans
    flux. Fermer la connexion au-delà du délai fait abandonner la génération par le serveur."""
    reasoning, content, finish, usage = [], [], None, None
    resp.encoding = "utf-8"
    for line in resp.iter_lines(decode_unicode=True):
        if time.perf_counter() > deadline:
            resp.close()
            raise TimeoutError(f"Le serveur n'a pas fini dans le délai de {TOTAL_REQUEST_TIMEOUT:.0f}s")
        if not line or not line.startswith("data: ") or line == "data: [DONE]":
            continue
        chunk = json.loads(line[len("data: "):])
        usage = chunk.get("usage") or usage
        for choice in chunk.get("choices") or []:
            delta = choice.get("delta") or {}
            if text := delta.get("reasoning") or delta.get("reasoning_content"):
                reasoning.append(text)
                live.add("réflexion", text)
            if text := delta.get("content"):
                content.append(text)
                live.add("réponse", text)
            finish = choice.get("finish_reason") or finish
    live.flush()
    live.journal.say(f"{live.head}]", f"— fin : {finish}, {(usage or {}).get('completion_tokens')} tokens générés")
    message = {"role": "assistant", "content": "".join(content), "reasoning": "".join(reasoning) or None}
    return {"choices": [{"message": message, "finish_reason": finish}], "usage": usage}


def _post(payload: dict, stage: str = "") -> dict:
    """Une requête /v1/chat/completions ; le délai court de l'envoi à la fin. Une erreur HTTP garde le message du serveur
    (schéma refusé, contexte dépassé, outils non activés). Avec un journal (`record_to`), la requête est suivie en flux (sauf
    avec des outils) et va au journal, réussie ou non."""
    journal = _journal.get()
    call = journal.next_call() if journal else 0
    streamed = journal is not None and "tools" not in payload
    body = {**payload, "stream": True, "stream_options": {"include_usage": True}} if streamed else payload
    t0, data, error = time.perf_counter(), None, None
    try:
        with _slots:
            try:
                resp = _session().post(f"{OPENAI_BASE_URL}/chat/completions", json=body, timeout=(10, TOTAL_REQUEST_TIMEOUT), stream=streamed)
                if resp.status_code >= 400:
                    raise requests.HTTPError(f"{resp.status_code} : {resp.text[:400]}", response=resp)
                if streamed:
                    journal.say(f"[{call} {stage or '?'}]", "— début")
                    data = _stream(resp, time.perf_counter() + TOTAL_REQUEST_TIMEOUT, _Live(journal, call, stage))
                else:
                    data = resp.json()
            except requests.exceptions.ReadTimeout as exc:
                raise TimeoutError(f"Le serveur n'a pas répondu dans le délai de {TOTAL_REQUEST_TIMEOUT:.0f}s") from exc
            return data
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        if journal is not None:
            journal.say(f"[{call} {stage or '?'}]", f"— erreur : {error[:300]}")
        raise
    finally:
        if journal is not None:
            _record(journal, call, stage, payload, data, time.perf_counter() - t0, error)


def _payload(
    messages: list[dict],
    max_output_tokens: int,
    model: str,
    temperature: float | None = None,
    enable_thinking: bool | None = None,
) -> dict:
    """Décodage déterministe (température 0, top_k 1, graine fixe) et réflexion coupée par défaut.
    Avec CTI_THINKING ou enable_thinking=True, l'échantillonnage recommandé pour la réflexion.
    Avec temperature > 0, échantillonnage exploratoire contrôlé (top_p 0.95, seed 0)."""
    thinking = THINKING if enable_thinking is None else enable_thinking
    if thinking:
        return {
            "model": model, "messages": messages, "max_tokens": min(max_output_tokens + THINKING_TOKENS, CONTEXT_TOKENS),
            "temperature": 1.0 if temperature is None else temperature, "top_p": 0.95,
            "top_k": 20, "min_p": 0.0, "presence_penalty": 0.0, "repetition_penalty": 1.0, "seed": 0,
            "chat_template_kwargs": {"enable_thinking": True, "reasoning_effort": REASONING_EFFORT},
        }  # fmt: skip
    if temperature is not None and temperature > 0:
        return {
            "model": model, "messages": messages, "max_tokens": max_output_tokens, "temperature": temperature,
            "top_p": 0.95, "seed": 0, "chat_template_kwargs": {"enable_thinking": False},
        }
    return {
        "model": model, "messages": messages, "max_tokens": max_output_tokens, "temperature": 0, "top_k": 1, "seed": 0,
        "chat_template_kwargs": {"enable_thinking": False},
    }  # fmt: skip


def generate(
    system: str,
    prompt: str,
    schema: dict,
    *,
    max_output_tokens: int = 700,
    model: str = LLM_MODEL,
    stage: str = "",
    temperature: float | None = None,
    enable_thinking: bool | None = None,
) -> LLMResult:
    """Un appel contraint par `schema`. Décodage fixe par défaut : deux exécutions donnent la même extraction.
    `stage` nomme l'appel dans le journal."""
    payload = _payload(
        [{"role": "system", "content": system + COMPACT}, {"role": "user", "content": prompt}],
        max_output_tokens,
        model,
        temperature=temperature,
        enable_thinking=enable_thinking,
    )
    payload["response_format"] = {"type": "json_schema", "json_schema": {"name": "answer", "strict": True, "schema": schema}}
    t0 = time.perf_counter()
    data = _post(payload, stage)
    raw = ((data.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
    usage = data.get("usage") or {}
    return LLMResult(_parse(raw), raw, int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0), time.perf_counter() - t0)


def chat(messages: list[dict], tools: list[dict], *, max_output_tokens: int = 900, model: str = LLM_MODEL, stage: str = "") -> ChatResult:
    """Un tour de conversation avec appel d'outils natif. Le serveur doit être lancé avec un analyseur d'appels d'outils
    (`--enable-auto-tool-choice --tool-call-parser qwen3_coder` pour Qwen3.5) ; sinon il refuse la requête (erreur HTTP)."""
    payload = _payload(messages, max_output_tokens, model)
    payload["tools"] = tools
    t0 = time.perf_counter()
    data = _post(payload, stage)
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


def in_context(fn):
    """`fn`, exécutée dans une copie du contexte de l'appelant (son journal) : à soumettre à un pool de fils."""
    ctx = contextvars.copy_context()
    return lambda *args, **kwargs: ctx.run(fn, *args, **kwargs)


def map_parallel(fn, items: list) -> list:
    """`fn` appliquée à chaque élément en parallèle, résultats dans l'ordre ; chaque appel au modèle attend un slot (`_slots`)."""
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=min(len(items), LLM_SLOTS)) as pool:
        futures = [pool.submit(in_context(fn), item) for item in items]
        return [f.result() for f in futures]
