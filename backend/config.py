"""Runtime configuration shared by the LLM clients and the article readers."""

import os
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
SOURCE_ARTICLES_DB = ROOT_DIR / "db_outputs" / "cti_knowledge.db"  # articles et classifications (SQLite)

os.environ["NO_PROXY"] = "localhost,127.0.0.1"  # les serveurs d'inférence sont joints par un tunnel local, jamais par un proxy

# Classification (cti-classifier) : serveur Ollama
OLLAMA_API_URL = os.environ.get("OLLAMA_API_URL", "http://127.0.0.1:11434/api/generate")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen3.8:27b")
# Contexte de CHAQUE requête : deux num_ctx différents obligent Ollama à recharger le modèle en attendant les requêtes en cours.
# Pour `ollama run` sur le serveur, lancer `ollama serve` avec OLLAMA_CONTEXT_LENGTH à la même valeur.
OLLAMA_NUM_CTX = int(os.environ.get("OLLAMA_NUM_CTX") or "12288")

# Extraction (cti-extract) : API /v1/chat/completions (vLLM, SGLang). Le contexte (`--max-model-len`) est fixé côté serveur ;
# CTI_LLM_SLOTS = requêtes en vol (son --max-running-requests).
OPENAI_BASE_URL = os.environ.get("CTI_OPENAI_URL", "http://127.0.0.1:8010/v1").rstrip("/")
LLM_MODEL = os.environ.get("CTI_OPENAI_MODEL", "cti-qwen")
LLM_SLOTS = max(1, int(os.environ.get("CTI_LLM_SLOTS") or 10))
