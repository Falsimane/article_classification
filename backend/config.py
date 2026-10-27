"""Runtime configuration shared by the local LLM clients and the article readers."""

import os
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
SOURCE_ARTICLES_DB = ROOT_DIR / "db_outputs" / "cti_knowledge.db"  # articles et classifications (SQLite)

os.environ["NO_PROXY"] = "localhost,127.0.0.1"  # le serveur Ollama est joint par un tunnel local, jamais par un proxy

OLLAMA_API_URL = os.environ.get(
    "OLLAMA_API_URL",
    "http://127.0.0.1:11434/api/generate",
)
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen3.8:27b")

# Contexte de CHAQUE requête, identique pour tous les clients (extracteur, classifieur) : deux requêtes qui demandent des
# num_ctx différents obligent Ollama à recharger le modèle, et ce rechargement attend la fin des requêtes en cours.
# Pour `ollama run` sur le serveur, lancer `ollama serve` avec OLLAMA_CONTEXT_LENGTH à la même valeur.
OLLAMA_NUM_CTX = int(os.environ.get("OLLAMA_NUM_CTX") or os.environ.get("CTI_EXTRACT_CTX") or "12288")

# Requêtes que le serveur traite en même temps (sa variable OLLAMA_NUM_PARALLEL) : un processus client n'en envoie jamais
# davantage, les autres attendent leur tour chez le client plutôt que dans la file du serveur.
OLLAMA_SLOTS = max(1, int(os.environ.get("OLLAMA_NUM_PARALLEL", "1")))

# Moteur d'inférence de l'extraction : « ollama » (défaut) ou « openai » (API /v1/chat/completions : SGLang, vLLM). Avec « openai »,
# le contexte (`--context-length`) et les slots sont fixés côté serveur ; CTI_LLM_SLOTS = requêtes en vol (son --max-running-requests).
LLM_BACKEND = os.environ.get("CTI_LLM_BACKEND", "ollama").strip().lower()
OPENAI_BASE_URL = os.environ.get("CTI_OPENAI_URL", "http://127.0.0.1:8010/v1").rstrip("/")
OPENAI_MODEL = os.environ.get("CTI_OPENAI_MODEL", "cti-qwen")
LLM_MODEL = OPENAI_MODEL if LLM_BACKEND == "openai" else OLLAMA_MODEL
LLM_SLOTS = max(1, int(os.environ.get("CTI_LLM_SLOTS") or 10)) if LLM_BACKEND == "openai" else OLLAMA_SLOTS
