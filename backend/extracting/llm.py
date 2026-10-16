"""Client Ollama de l'extraction : un appel = une requête, sortie contrainte par un schéma JSON, durées mesurées.

Le coût d'un modèle de langage local est dominé par les tokens GÉNÉRÉS (quelques dizaines par seconde), très loin
devant la lecture du prompt (milliers par seconde). Ce module ne fait donc que trois choses :
- imposer un schéma de sortie (Ollama « structured outputs ») pour qu'aucun appel ne produise de texte libre ;
- désactiver la réflexion de Qwen3 (`think: False`), qui génère des centaines de tokens avant de répondre ;
- rapporter ce que le SERVEUR a mesuré (tokens lus, tokens générés, durées), pour optimiser sur des faits.
"""

import os
import re
import threading
import time
from dataclasses import dataclass, field

import json_repair
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

os.environ["NO_PROXY"] = "localhost,127.0.0.1"

OLLAMA_API_URL = os.environ.get("OLLAMA_API_URL", "http://localhost:11434/api/generate")
MODEL_NAME = "qwen3:32b"
CONTEXT_WINDOW = int(os.environ.get("CTI_EXTRACT_CTX", "12288"))
REQUEST_TIMEOUT = 240

_local = threading.local()


@dataclass
class LLMResult:
    parsed: dict | list | None
    raw: str
    prompt_tokens: int = 0
    output_tokens: int = 0
    seconds: float = 0.0  # durée totale vue du client
    server: dict = field(default_factory=dict)  # durées mesurées par Ollama, en secondes

    @property
    def tokens_per_second(self) -> float:
        gen = self.server.get("generate", 0.0)
        return self.output_tokens / gen if gen else 0.0


def _session() -> requests.Session:
    if not hasattr(_local, "session"):
        s = requests.Session()
        s.trust_env = False
        s.mount("http://", HTTPAdapter(max_retries=Retry(total=2, backoff_factor=1.0, status_forcelist=[500, 502, 503, 504])))
        _local.session = s
    return _local.session


def _parse(raw: str):
    text = re.sub(r"<think>.*?</think>", "", raw or "", flags=re.DOTALL).strip()
    match = re.search(r"[\[{].*[\]}]", text, re.DOTALL)
    if not match:
        return None
    parsed = json_repair.loads(match.group(0))
    return parsed if isinstance(parsed, (dict, list)) and parsed != {} else None


def generate(
    system: str,
    prompt: str,
    schema: dict,
    *,
    max_output_tokens: int = 700,
    num_ctx: int = CONTEXT_WINDOW,
    model: str = MODEL_NAME,
) -> LLMResult:
    """Un appel contraint. Les options sont fixes (décodage déterministe) pour que deux exécutions donnent la même
    extraction. Une sortie illisible est retentée une fois sans contrainte de schéma."""
    payload = {
        "model": model,
        "system": system,
        "prompt": prompt,
        "format": schema,
        "think": False,
        "stream": False,
        "keep_alive": -1,
        "options": {"temperature": 0, "seed": 0, "num_ctx": num_ctx, "num_predict": max_output_tokens},
    }
    t0 = time.perf_counter()
    for attempt in (0, 1):
        resp = _session().post(OLLAMA_API_URL, json=payload, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        body = resp.json()
        raw = body.get("response") or ""
        parsed = _parse(raw)
        if parsed is not None or attempt == 1:
            break
        payload["format"] = "json"  # repli : le serveur n'a peut-être pas appliqué le schéma
    ns = 1e-9
    return LLMResult(
        parsed=parsed,
        raw=raw,
        prompt_tokens=int(body.get("prompt_eval_count") or 0),
        output_tokens=int(body.get("eval_count") or 0),
        seconds=time.perf_counter() - t0,
        server={
            "total": (body.get("total_duration") or 0) * ns,
            "load": (body.get("load_duration") or 0) * ns,
            "prompt": (body.get("prompt_eval_duration") or 0) * ns,
            "generate": (body.get("eval_duration") or 0) * ns,
        },
    )
