import os
import re
import sqlite3
import json
import time
import threading
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import json_repair

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    MofNCompleteColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.prompt import Confirm
import sys
root_dir = Path(__file__).resolve().parents[3]
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from backend.config import OLLAMA_API_URL, OLLAMA_MODEL, OLLAMA_NUM_CTX, SOURCE_ARTICLES_DB
from backend.preprocessing.cleaning.cleaner import UniversalCTICleaner

DB_PATH = SOURCE_ARTICLES_DB

MODEL_NAME = OLLAMA_MODEL
MAX_WORKERS = int(os.environ.get("CTI_CLASSIFIER_WORKERS", "2"))
BATCH_SIZE = 10
# Prompt système (~700 tokens) + contexte (<= ~3 000 tokens) + sortie courte : 6144 suffiraient. Le contexte est pourtant
# celui de l'extracteur : un num_ctx différent oblige Ollama à recharger le modèle (voir backend/config.py).
# Un num_ctx dépassé fait tronquer le DÉBUT du prompt par Ollama, donc le prompt système.
CONTEXT_WINDOW = OLLAMA_NUM_CTX
MAX_OUTPUT_TOKENS = 160
REQUEST_TIMEOUT = 180
POLL_INTERVAL = 10
VALID_CATEGORIES = ("operational", "tactical", "strategic", "out_of_scope")
# Score attribué à la catégorie retenue selon la confiance déclarée (les autres restent à 0.0)
CONFIDENCE_SCORES = {"high": 0.9, "medium": 0.7, "low": 0.5}

console = Console()
thread_local = threading.local()

# =====================================================================
# PROMPT DE CLASSIFICATION : un seul libellé, décidé sur le texte
# (anglais : plus compact en tokens et mieux suivi par Qwen ; les articles sont en anglais ou en français)
# =====================================================================
SYSTEM_PROMPT = """You classify cyber-security articles for a Cyber Threat Intelligence (CTI) pipeline.
You receive the title, the outline and excerpts of one article. Output exactly one label.

LABELS
- out_of_scope: not CTI. No concrete threat information: vendor/product marketing, webinars, events, jobs, company news, generic IT or security how-tos and best-practice advice with no specific threat, patch notes or advisories with no reported exploitation, empty, navigation or error pages.
- operational: a concrete intrusion or campaign told as it happened. Specific victim(s) or observed activity, with the attacker's actions in order (initial access, execution, persistence, lateral movement, exfiltration, impact). DFIR case reports, incident write-ups, campaign tracking with a timeline.
- tactical: how a technique, tool, malware or vulnerability works or is detected, independent of one incident's timeline. Malware reverse engineering, loader or config analysis, exploit and vulnerability analysis, TTP or ATT&CK catalogues, detection and hunting content (Sigma, YARA, Snort, queries).
- strategic: the big picture for decision-makers. Threat landscape, annual, quarterly or sector reports, trends, actor ecosystems and motivations, geopolitics, attribution context, law-enforcement takedowns, policy and regulation, risk and business impact. Little low-level technical detail.

HOW TO DECIDE, IN ORDER
1. Is there a concrete cyber threat (actor, malware, campaign, exploited vulnerability, attack technique)? If not, out_of_scope. A page that mainly promotes a product, service or report download is out_of_scope even if it mentions threats.
2. Otherwise pick by what most of the text is about:
   - Can you reconstruct what the attacker did, step by step, in one specific intrusion or campaign? operational.
   - Does it explain how something technical works or how to detect it? tactical.
   - Is it about trends, goals, targets, geopolitics or impact rather than mechanics? strategic.
3. Mixed articles: follow the dominant part. A sample found during an incident but dissected in depth is tactical. A landscape report quoting a few incidents is strategic. A campaign write-up with a victim timeline and technical appendices is operational.
4. Code blocks and tables (see STRUCTURE) hint at technical depth, so tactical or operational; their absence points to strategic or out_of_scope. They are hints only.
Judge the content, not the publisher's name or promotional wording.

Answer with JSON only:
{"evidence": "<=20 words, the main cue", "category": "operational|tactical|strategic|out_of_scope", "confidence": "high|medium|low"}
Use "low" confidence when two labels are close."""

# Schéma imposé à Ollama (sorties structurées) : catégorie et confiance ne peuvent être qu'une valeur valide.
# `evidence` vient avant `category` : une justification brève précède la décision, ce qui la stabilise.
CLASSIFICATION_SCHEMA = {
    "type": "object",
    "properties": {
        "evidence": {"type": "string"},
        "category": {"type": "string", "enum": list(VALID_CATEGORIES)},
        "confidence": {"type": "string", "enum": list(CONFIDENCE_SCORES)},
    },
    "required": ["evidence", "category", "confidence"],
}


def normalize_llm_payload(raw_dict: dict, article_url: str = "") -> dict:
    """Valide la sortie du LLM et la convertit au format de stockage.

    Une catégorie invalide lève ValueError : l'article est alors marqué 'error' puis retenté, au lieu
    de recevoir silencieusement une catégorie par défaut qui fausserait la distribution.
    Scores : la catégorie retenue reçoit le score de sa confiance, les autres 0.0.
    """
    if not isinstance(raw_dict, dict):
        raise ValueError("sortie LLM non-dictionnaire")

    cat = str(raw_dict.get("category", raw_dict.get("primary_category", ""))).strip().lower()
    if cat not in VALID_CATEGORIES:
        raise ValueError(f"catégorie invalide : {cat!r}")

    conf = raw_dict.get("confidence", "medium")
    if isinstance(conf, (int, float)):
        score = max(0.0, min(1.0, float(conf)))
    else:
        score = CONFIDENCE_SCORES.get(str(conf).strip().lower(), CONFIDENCE_SCORES["medium"])
    if cat == "out_of_scope":
        score = 0.0

    return {
        "primary_category": cat,
        "score_operational": score if cat == "operational" else 0.0,
        "score_tactical": score if cat == "tactical" else 0.0,
        "score_strategic": score if cat == "strategic" else 0.0,
        "rationale": str(raw_dict.get("evidence", raw_dict.get("rationale", ""))).strip(),
        "confidence": str(conf).strip().lower(),
    }

def setup_database(reset_requested: bool = False) -> None:
    """Initialise ou migre la base de données SQLite en mode WAL avec gestion du schéma sans extraction."""
    with sqlite3.connect(DB_PATH, timeout=30.0) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")

        if reset_requested:
            conn.execute("DROP TABLE IF EXISTS article_raw_iocs;")
            conn.execute("DROP TABLE IF EXISTS article_classifications;")
            conn.commit()
            console.print("[bold red]✓ Table 'article_classifications' réinitialisée.[/]")

        # Suppression définitive de l'ancienne table d'IOCs bruts (aucun IOC extrait en preprocessing)
        conn.execute("DROP TABLE IF EXISTS article_raw_iocs;")

        # Table : Décision de classification et document nettoyé complet pour extraction KG
        conn.execute("""
            CREATE TABLE IF NOT EXISTS article_classifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                knowledge_id INTEGER NOT NULL UNIQUE,
                classified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                model_version TEXT NOT NULL,
                primary_category TEXT NOT NULL,
                score_tactical REAL NOT NULL,
                score_operational REAL NOT NULL,
                score_strategic REAL NOT NULL,
                rationale TEXT,
                clean_markdown TEXT,
                sections_meta TEXT,
                is_processable INTEGER DEFAULT 1,
                reject_reason TEXT,
                human_category TEXT DEFAULT NULL,
                is_validated INTEGER DEFAULT 0,
                FOREIGN KEY (knowledge_id) REFERENCES knowledge(id) ON DELETE CASCADE
            );
        """)

        # Migration dynamique : suppression des anciens champs d'extraction et ajout des colonnes requises
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(article_classifications);")
        existing_cols = {col[1] for col in cursor.fetchall()}

        deprecated_cols = [
            "threat_actors",
            "malware_and_tools",
            "infrastructure_channels",
            "skeleton_content",
            "kill_chain_phases",
        ]
        for col_name in deprecated_cols:
            if col_name in existing_cols:
                conn.execute(f"ALTER TABLE article_classifications DROP COLUMN {col_name};")

        expected_columns = [
            ("clean_markdown", "TEXT"),
            ("sections_meta", "TEXT"),
            ("is_processable", "INTEGER DEFAULT 1"),
            ("reject_reason", "TEXT"),
            ("rationale", "TEXT"),
            ("human_category", "TEXT DEFAULT NULL"),
            ("is_validated", "INTEGER DEFAULT 0"),
        ]
        for col_name, col_type in expected_columns:
            if col_name not in existing_cols:
                conn.execute(f"ALTER TABLE article_classifications ADD COLUMN {col_name} {col_type};")

        conn.commit()

def _pending_clause(exclude_ids: set) -> tuple:
    """Articles jamais classés, ou en erreur (retentés une fois par exécution) et pas déjà essayés."""
    clause = "(c.id IS NULL OR c.primary_category = 'error')"
    params: list = []
    if exclude_ids:
        clause += f" AND k.id NOT IN ({','.join('?' * len(exclude_ids))})"
        params = list(exclude_ids)
    return clause, params

def fetch_unclassified_articles(limit: int = BATCH_SIZE, exclude_ids: set = frozenset()) -> list:
    clause, params = _pending_clause(set(exclude_ids))
    with sqlite3.connect(DB_PATH, timeout=30.0) as conn:
        cursor = conn.cursor()
        cursor.execute(f"""
            SELECT k.id, k.title, k.content, k.url, k.site_name
            FROM knowledge k
            LEFT JOIN article_classifications c ON k.id = c.knowledge_id
            WHERE {clause}
            ORDER BY k.id ASC
            LIMIT ?;
        """, (*params, limit))
        return cursor.fetchall()

def count_pending_articles(exclude_ids: set = frozenset()) -> int:
    clause, params = _pending_clause(set(exclude_ids))
    with sqlite3.connect(DB_PATH, timeout=30.0) as conn:
        cursor = conn.cursor()
        cursor.execute(f"""
            SELECT COUNT(*) FROM knowledge k
            LEFT JOIN article_classifications c ON k.id = c.knowledge_id
            WHERE {clause};
        """, params)
        return cursor.fetchone()[0]

def save_pipeline_results(knowledge_id: int, prep_result, llm_data: dict) -> None:
    """Enregistre le document préparé et la classification en base de données sans extraction d'entités."""
    with sqlite3.connect(DB_PATH, timeout=30.0) as conn:
        cursor = conn.cursor()

        is_proc = 1 if llm_data.get("is_processable", True) else 0
        reject_reason = llm_data.get("reject_reason")

        clean_md = ""
        sections_meta = "[]"

        if prep_result is not None and is_proc:
            clean_md = prep_result.clean_markdown or ""
            sections_meta = json.dumps(UniversalCTICleaner.get_sections_metadata(prep_result), ensure_ascii=False)

        # Sauvegarde de la décision de classification et du markdown nettoyé intégral
        cursor.execute("""
            INSERT OR REPLACE INTO article_classifications 
            (knowledge_id, model_version, primary_category, score_tactical, score_operational, score_strategic, 
             clean_markdown, sections_meta, is_processable, reject_reason, rationale)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            knowledge_id,
            MODEL_NAME,
            llm_data.get("primary_category", "out_of_scope"),
            float(llm_data.get("score_tactical", 0.0)),
            float(llm_data.get("score_operational", 0.0)),
            float(llm_data.get("score_strategic", 0.0)),
            clean_md,
            sections_meta,
            is_proc,
            reject_reason,
            llm_data.get("rationale", "")
        ))
        conn.commit()

def get_worker_session() -> requests.Session:
    if not hasattr(thread_local, "session"):
        session = requests.Session()
        session.trust_env = False
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
        )
        adapter = HTTPAdapter(pool_connections=MAX_WORKERS, pool_maxsize=MAX_WORKERS, max_retries=retry_strategy)
        session.mount("http://", adapter)
        thread_local.session = session
    return thread_local.session

def _call_ollama(session: requests.Session, payload: dict) -> tuple:
    res = session.post(OLLAMA_API_URL, json=payload, timeout=REQUEST_TIMEOUT)
    res.raise_for_status()
    body = res.json()
    raw = (body.get("response") or "").strip()
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    parsed = json_repair.loads(match.group(0)) if match else {}
    usage = {"prompt_tokens": body.get("prompt_eval_count", 0), "output_tokens": body.get("eval_count", 0)}
    return (parsed if isinstance(parsed, dict) else {}), raw, usage

def query_qwen_classifier(prompt_payload: str, system_prompt: str = SYSTEM_PROMPT) -> dict:
    """Une seule requête : sortie contrainte par schéma, réflexion Qwen3 désactivée, décodage déterministe."""
    session = get_worker_session()
    payload = {
        "model": MODEL_NAME,
        "system": system_prompt,
        "prompt": prompt_payload,
        "format": CLASSIFICATION_SCHEMA,
        "think": False,
        "stream": False,
        "keep_alive": -1,
        "options": {
            "temperature": 0,
            "seed": 0,
            "num_ctx": CONTEXT_WINDOW,
            "num_predict": MAX_OUTPUT_TOKENS,
        },
    }
    parsed, raw, usage = _call_ollama(session, payload)
    if not parsed.get("category"):
        # Un seul repli, sans contrainte de schéma (au cas où le serveur ne la supporterait pas)
        payload["format"] = "json"
        parsed, raw, usage = _call_ollama(session, payload)
    if not parsed.get("category"):
        raise ValueError(f"Sortie Ollama sans catégorie exploitable: {raw[:150]}")
    parsed["_usage"] = usage
    return parsed

def process_article_worker(article_row: tuple) -> tuple:
    """Retourne (id, prep_result, llm_data, durée, erreur). `prep_result` est conservé même si le LLM échoue :
    le nettoyage est déterministe et ne doit pas être perdu à cause d'une panne du serveur Ollama."""
    article_id, title, raw_content, url, site_name = article_row
    t0 = time.perf_counter()
    prep_result = None

    try:
        # Phase 0 : Fast-Reject déterministe amont (0 ms GPU)
        is_viable, reject_reason = UniversalCTICleaner.check_viability(raw_content)
        if not is_viable:
            fast_data = {
                "primary_category": "out_of_scope",
                "score_operational": 0.0,
                "score_tactical": 0.0,
                "score_strategic": 0.0,
                "rationale": f"Rejet amont déterministe : {reject_reason}",
                "is_processable": False,
                "reject_reason": reject_reason,
            }
            return article_id, None, fast_data, time.perf_counter() - t0, None

        # Phase 1 : nettoyage Rust (millisecondes)
        prep_result = UniversalCTICleaner.process(raw_content, site_name=site_name, source_url=url)
        if not prep_result.is_processable:
            fast_data = {
                "primary_category": "out_of_scope",
                "score_operational": 0.0,
                "score_tactical": 0.0,
                "score_strategic": 0.0,
                "rationale": f"Rejet après nettoyage : {prep_result.reject_reason}",
                "is_processable": False,
                "reject_reason": prep_result.reject_reason,
            }
            return article_id, None, fast_data, time.perf_counter() - t0, None

        # Phase 2 : contexte compact et budgétisé, Phase 3 : un appel LLM, Phase 4 : validation
        prompt_payload = UniversalCTICleaner.build_classifier_context(title, prep_result)
        raw_llm_data = query_qwen_classifier(prompt_payload)
        data = normalize_llm_payload(raw_llm_data, article_url=url)
        data["is_processable"] = True
        data["reject_reason"] = None
        return article_id, prep_result, data, time.perf_counter() - t0, None

    except Exception as e:
        return article_id, prep_result, None, time.perf_counter() - t0, str(e)

def display_dashboard(batch_speed: float = 0.0, worker_count: int = MAX_WORKERS) -> None:
    with sqlite3.connect(DB_PATH, timeout=30.0) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM knowledge;")
        total = cursor.fetchone()[0]

        cursor.execute("""
            SELECT primary_category, COUNT(*),
                   AVG(MAX(score_tactical, score_operational, score_strategic))
            FROM article_classifications
            WHERE primary_category != 'error'
            GROUP BY primary_category
            ORDER BY COUNT(*) DESC;
        """)
        stats = cursor.fetchall()

        cursor.execute("SELECT COUNT(*) FROM article_classifications WHERE primary_category = 'error';")
        errors = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM article_classifications WHERE is_processable = 0;")
        fast_rejected = cursor.fetchone()[0]

    classified_valid = sum(r[1] for r in stats)
    pending = total - (classified_valid + errors)

    table = Table(
        title="📊 État du Preprocessing CTI (Nettoyage Rust + Classification Qwen)",
        header_style="bold magenta",
        border_style="dim"
    )
    table.add_column("Catégorie", style="bold", width=16)
    table.add_column("Articles", justify="right", width=10)
    table.add_column("Part", justify="right", width=9)
    table.add_column("Confiance moy.", justify="center", width=15)
    table.add_column("Distribution", width=30)

    colors = {"operational": "yellow", "tactical": "red", "strategic": "cyan", "out_of_scope": "dim white"}

    for cat, count, avg_conf in stats:
        pct = (count / classified_valid * 100) if classified_valid > 0 else 0
        bar_len = int(pct / 3.33)
        c = colors.get(cat.lower(), "white")
        bar_visual = f"[{c}]{'█' * bar_len}{'░' * (30 - bar_len)}[/]"
        avg_fmt = f"{avg_conf or 0:.2f}"
        table.add_row(cat.capitalize(), str(count), f"{pct:.1f} %", avg_fmt, bar_visual)

    console.print("\n")
    console.print(table)

    pct_done = (classified_valid / total * 100) if total > 0 else 0
    speed_str = f"  │  [cyan]Débit :[/] [bold]{batch_speed:.1f} s/art[/]" if batch_speed > 0 else ""

    console.print(Panel(
        f"[green]Traités :[/] {classified_valid}/{total} ([bold]{pct_done:.1f}%[/])  │  "
        f"[yellow]En attente :[/] {pending}  │  "
        f"[blue]Rejet amont (0ms) :[/] [bold]{fast_rejected}[/]{speed_str}",
        title=f"Progression du Preprocessing ({worker_count} Workers)",
        border_style="green",
        expand=False
    ))
    console.print("\n")

def main(workers: int | None = None) -> None:
    console.print("\n[bold cyan]=== Pipeline CTI : Module de Preprocessing & Annotation ===[/]")
    worker_count = MAX_WORKERS if workers is None else workers
    if worker_count < 1:
        raise ValueError("Le nombre de workers doit être supérieur ou égal à 1.")

    reset = Confirm.ask(
        "[bold yellow]Voulez-vous réinitialiser toutes les tables (supprime aussi les validations humaines) ?[/]",
        default=False
    )
    setup_database(reset_requested=reset)

    # Apprentissage du gabarit de chaque éditeur (menus, bannières, pieds de page) sur le corpus
    learned = UniversalCTICleaner.learn_site_boilerplate(DB_PATH)
    console.print(
        f"[dim]Gabarit appris pour {len(learned)} sites "
        f"({sum(n for _, n in learned.values())} lignes de boilerplate).[/]"
    )
    display_dashboard(worker_count=worker_count)

    attempted: set = set()  # articles déjà essayés dans cette exécution (les erreurs ne sont retentées qu'une fois)
    while True:
        pending_total = count_pending_articles(attempted)
        if pending_total == 0:
            console.print(f"[dim]Tous les articles ont été traités. Surveillance active ({POLL_INTERVAL}s)...[/]")
            time.sleep(POLL_INTERVAL)
            continue

        articles = fetch_unclassified_articles(BATCH_SIZE, attempted)
        if not articles:
            continue
        attempted.update(a[0] for a in articles)

        batch_start = time.perf_counter()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task(f"[cyan]Preprocessing ({worker_count} workers)...", total=len(articles))

            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                future_to_art = {
                    executor.submit(process_article_worker, art): art 
                    for art in articles
                }

                for future in as_completed(future_to_art):
                    art_id, prep_result, llm_data, elapsed, err = future.result()
                    art_row = [a for a in articles if a[0] == art_id][0]
                    short_title = (art_row[1][:30] + "...") if art_row[1] else "Sans titre"

                    if err:
                        console.print(f"[bold red]✗ Art {art_id} ({elapsed:.1f}s) : {err}[/]")
                        # Le texte nettoyé est conservé même si la classification a échoué
                        save_pipeline_results(art_id, prep_result, {
                            "primary_category": "error",
                            "score_operational": 0.0,
                            "score_tactical": 0.0,
                            "score_strategic": 0.0,
                            "rationale": f"Exception: {err}",
                            "is_processable": prep_result is not None,
                        })
                    else:
                        save_pipeline_results(art_id, prep_result, llm_data)
                        cat = llm_data.get("primary_category", "N/A").upper()
                        progress.update(
                            task,
                            description=f"[cyan]✓ Art {art_id} [{cat[:4]}|{elapsed:.1f}s] : {short_title}"
                        )

                    progress.advance(task, 1)

        batch_duration = time.perf_counter() - batch_start
        display_dashboard(batch_speed=batch_duration / len(articles), worker_count=worker_count)

if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description="Classifie les articles CTI avec Ollama.")
        parser.add_argument(
            "--workers",
            type=int,
            default=None,
            help=f"Nombre de classifications en parallèle (défaut : {MAX_WORKERS}, ou CTI_CLASSIFIER_WORKERS).",
        )
        main(workers=parser.parse_args().workers)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Arrêt propre. Données préservées dans SQLite.[/]")