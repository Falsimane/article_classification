"""Runtime configuration shared by the LLM clients and the article readers."""

import os
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
# Données (hors git) : seul endroit où leur emplacement est défini ; CTI_DATA_DIR le déplace en entier
DATA_DIR = Path(os.environ.get("CTI_DATA_DIR") or ROOT_DIR / "backend" / "data")
SOURCE_ARTICLES_DB = DATA_DIR / "sources" / "cti_knowledge.db"  # articles et classifications (SQLite)
HTML_PAGES_DIR = DATA_DIR / "raw" / "html_pages"  # page HTML brute de chaque article : <site_name>/<sha1(url)[:16]>.html
CLEANED_DIR = DATA_DIR / "cleaned"  # copie lisible du texte nettoyé (la source est SQLite) : <site_name>/<sha1(url)[:16]>.md
BUNDLES_DIR = DATA_DIR / "bundles"  # bundle STIX final de chaque article (écrit par cti-extract, lu par le dashboard)
EVAL_DIR = ROOT_DIR / "backend" / "evaluation" / "eval"  # un dossier par exécution de cti-eval (hors DATA_DIR)

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
# Questions du dashboard (graphe global) traitées à la fois : le dashboard a son propre compteur de slots, qui s'ajoute à
# celui d'un cti-extract en cours ; 1 par défaut pour ne pas dépasser le --max-running-requests du serveur.
ASK_SLOTS = max(1, int(os.environ.get("CTI_ASK_SLOTS") or 1))
