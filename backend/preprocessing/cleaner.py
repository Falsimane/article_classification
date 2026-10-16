from pathlib import Path
import json
import re
import sqlite3
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional, Tuple

import cti_core

DB_PATH = Path(__file__).resolve().parents[2] / "db_outputs" / "cti_knowledge.db"

# Phases d'intrusion reconnues dans les titres de sections (sémantique : côté Python uniquement).
KNOWN_PHASES = {
    "initial access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege escalation": "Privilege Escalation",
    "defense evasion": "Defense Evasion",
    "credential access": "Credential Access",
    "discovery": "Discovery",
    "lateral movement": "Lateral Movement",
    "collection": "Collection",
    "command and control": "Command and Control",
    "c2": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    "ransomware": "Impact (Ransomware)",
    "mitre att&ck": "MITRE ATT&CK Mapping",
    "detection": "Detection & Rules",
    "yara": "Detection (YARA)",
    "sigma": "Detection (Sigma)",
    "suricata": "Detection (Suricata)",
    "snort": "Detection (Snort)",
    "mesure de protection": "Detection & Rules",
    "mesures de protection": "Detection & Rules",
    "indicateurs": "Indicators (IOCs)",
}
_PHASE_PATTERNS = [(re.compile(r"(?<!\w)" + re.escape(k) + r"(?!\w)"), v) for k, v in KNOWN_PHASES.items()]

# Apprentissage du gabarit de chaque site : une ligne en fenêtre tête/queue, présente dans >= 40 % des
# articles d'un même éditeur (et au moins 5 articles), est du boilerplate (menu, bannière, CTA, pied de page).
BOILERPLATE_MIN_DOCS = 5
BOILERPLATE_MIN_RATIO = 0.4

def site_key(site_name: Optional[str], url: Optional[str] = None) -> Optional[str]:
    """Clé d'une source : `site_name` si connu, sinon le domaine de l'URL (nouvelle source sans métadonnée)."""
    if site_name and site_name.strip():
        return site_name.strip()
    if url:
        host = (urlparse(url).netloc or "").lower().split(":")[0]
        if host:
            return host[4:] if host.startswith("www.") else host
    return None


class UniversalCTICleaner:
    """Wrapper Python appelant le moteur déterministe Rust cti_core et gérant la préparation pour le LLM."""

    _engine = cti_core.CtiEngine()

    # Budget maximal de prose narrative envoyé au LLM pour la classification (~5 000 tokens)
    MAX_PROSE_CHARS = 22000

    _boilerplate_cache: Dict[str, List[str]] = {}

    @classmethod
    def process(
        cls,
        raw_markdown: str,
        site_name: Optional[str] = None,
        source_url: Optional[str] = None,
    ) -> cti_core.PreprocessingResult:
        """Exécute la dé-neutralisation, le nettoyage anti-bruit et la segmentation en Rust.

        `site_name` active le gabarit appris pour l'éditeur ; `source_url` sert à reconnaître
        ses liens internes (navigation) et à les distinguer des références externes.
        """
        key = site_key(site_name, source_url)
        boilerplate = cls.get_boilerplate(key) if key else None
        return cls._engine.process_article(raw_markdown or "", boilerplate or None, source_url)

    @classmethod
    def get_boilerplate(cls, site_name: str) -> List[str]:
        """Gabarit appris pour cette source (vide tant qu'elle a moins de BOILERPLATE_MIN_DOCS articles)."""
        if site_name not in cls._boilerplate_cache:
            lines: List[str] = []
            try:
                with sqlite3.connect(DB_PATH, timeout=30.0) as conn:
                    conn.execute("PRAGMA journal_mode=WAL;")
                    row = conn.execute(
                        "SELECT lines_json FROM site_boilerplate WHERE site_name = ?", (site_name,)
                    ).fetchone()
                    if row:
                        lines = json.loads(row[0])
            except sqlite3.OperationalError:
                pass  # table pas encore créée : aucun gabarit appris
            cls._boilerplate_cache[site_name] = lines
        return cls._boilerplate_cache[site_name]

    @classmethod
    def learn_site_boilerplate(cls, db_path: Path = DB_PATH) -> Dict[str, Tuple[int, int]]:
        """(Ré)apprend le gabarit de chaque site depuis la table `knowledge` et le persiste.

        Retourne {site_name: (nb_articles, nb_lignes_de_gabarit)}.
        """
        stats: Dict[str, Tuple[int, int]] = {}
        with sqlite3.connect(db_path, timeout=30.0) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS site_boilerplate (
                    site_name TEXT PRIMARY KEY,
                    n_docs INTEGER NOT NULL,
                    lines_json TEXT NOT NULL,
                    learned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            by_site: Dict[str, List[str]] = {}
            for site, url, content in conn.execute(
                "SELECT site_name, url, content FROM knowledge WHERE content IS NOT NULL ORDER BY id"
            ):
                key = site_key(site, url)
                if key:
                    by_site.setdefault(key, []).append(content)

            def store(key: str, n_docs: int, lines: List[str]) -> None:
                conn.execute(
                    "INSERT OR REPLACE INTO site_boilerplate (site_name, n_docs, lines_json) VALUES (?, ?, ?)",
                    (key, n_docs, json.dumps(lines, ensure_ascii=False)),
                )
                stats[key] = (n_docs, len(lines))

            for key, docs in by_site.items():
                store(key, len(docs), cls._engine.learn_boilerplate(docs, BOILERPLATE_MIN_DOCS, BOILERPLATE_MIN_RATIO))

            conn.commit()
        cls._boilerplate_cache.clear()
        return stats

    @classmethod
    def refang(cls, text: str) -> str:
        """Dé-neutralise une chaîne de caractères via Rust."""
        if not text:
            return ""
        return cls._engine.refang(text)

    @classmethod
    def check_viability(cls, raw_markdown: str) -> Tuple[bool, str | None]:
        """Vérifie en amont si l'article est viable (fast-reject)."""
        if not raw_markdown:
            return False, "Article vide (0 caractère)"
        return cls._engine.check_viability(raw_markdown)

    @classmethod
    def get_sections_metadata(cls, prep_result: cti_core.PreprocessingResult) -> List[Dict[str, Any]]:
        """Extrait la structure des sections sous forme de liste de dictionnaires pour SQLite / JSON."""
        sections_data = []
        for sec in prep_result.sections:
            sections_data.append({
                "section_index": sec.section_index,
                "title": sec.title,
                "level": sec.level,
                "char_count": sec.char_count,
                "is_appendix_ioc": sec.is_appendix_ioc,
                "heading_path": sec.heading_path,
                "kill_chain_phase": cls.phase_for_title(sec.title) or cls.phase_for_title(sec.heading_path),
            })
        return sections_data

    @classmethod
    def chunk(cls, clean_markdown: str, max_chars: int = 7500) -> List[Dict[str, Any]]:
        """Segments d'extraction sans recouvrement : jamais de coupe dans un bloc de code, une table ou
        un paragraphe, chaque titre reste avec son contenu, `heading_path` donne le contexte hiérarchique."""
        return [
            {
                "chunk_index": c.chunk_index,
                "heading_path": c.heading_path,
                "sections_included": list(c.titles),
                "text": c.text,
                "char_count": c.char_count,
                "oversized": c.oversized,
            }
            for c in cls._engine.chunk_markdown(clean_markdown or "", max_chars)
        ]

    @classmethod
    def phase_for_title(cls, title: str) -> Optional[str]:
        """Phase d'intrusion déduite d'un titre de section (mot entier, jamais une sous-chaîne)."""
        t_lower = (title or "").lower()
        for pattern, phase_name in _PHASE_PATTERNS:
            if pattern.search(t_lower):
                return phase_name
        return None

    @classmethod
    def detect_kill_chain_phases(cls, prep_result: cti_core.PreprocessingResult) -> List[str]:
        """Détecte les phases d'intrusion (Kill-Chain / MITRE) présentes dans les titres de sections."""
        found_phases = []
        for sec in prep_result.sections:
            t_lower = (sec.title or "").lower()
            for pattern, phase_name in _PHASE_PATTERNS:
                if pattern.search(t_lower) and phase_name not in found_phases:
                    found_phases.append(phase_name)
        return found_phases

    # Budget de texte envoyé au LLM pour la classification (~2 500 tokens). Classer n'exige pas de lire
    # tout l'article : titre, plan, introduction, un échantillon par section et la conclusion suffisent.
    CLASSIFIER_BUDGET_CHARS = 8000
    _INTRO_CHARS = 2800
    _CONCLUSION_CHARS = 900
    _MIN_SECTION_CHARS = 220
    _MAX_OUTLINE = 40

    @staticmethod
    def _block_kind(block: str) -> str:
        """'code' | 'table' | 'prose' pour un bloc atomique de section."""
        if block.startswith("```") or block.startswith("    ") or block.startswith("\t"):
            return "code"
        lines = [l for l in block.splitlines() if l.strip()]
        if lines and all(l.lstrip().startswith("|") for l in lines):
            return "table"
        return "prose"

    @staticmethod
    def _trim_to_sentence(text: str, limit: int) -> str:
        if len(text) <= limit:
            return text
        cut = text[:limit]
        end = max(cut.rfind(". "), cut.rfind("! "), cut.rfind("? "), cut.rfind("\n"))
        return (cut[: end + 1] if end > limit // 2 else cut.rsplit(" ", 1)[0]).rstrip() + " […]"

    @classmethod
    def _take_prose(cls, blocks: List[str], limit: int) -> Tuple[str, int, int]:
        """Prose d'une section jusqu'à `limit` caractères (blocs entiers) + nb de blocs code/table omis."""
        parts: List[str] = []
        used = 0
        n_code = n_table = 0
        for b in blocks:
            kind = cls._block_kind(b)
            if kind == "code":
                n_code += 1
            elif kind == "table":
                n_table += 1
            elif used < limit:
                room = limit - used
                txt = cls._trim_to_sentence(b, room)
                parts.append(txt)
                used += len(txt)
        return "\n\n".join(parts), n_code, n_table

    @classmethod
    def build_classifier_context(cls, title: str, prep_result: cti_core.PreprocessingResult) -> str:
        """Vue compacte et budgétée de l'article pour la classification (jamais l'article entier).

        Titre + indicateurs structurels + plan complet + introduction + un échantillon de prose par
        section + conclusion. Le code, les tables et les annexes d'IOC ne sont pas envoyés : on signale
        seulement leur présence, qui est un indice de niveau (technique) sans coûter de tokens.
        """
        sections = [s for s in prep_result.sections]
        total_len = len(prep_result.clean_markdown or "")

        n_code = n_table = 0
        for s in sections:
            for b in s.blocks:
                kind = cls._block_kind(b)
                n_code += kind == "code"
                n_table += kind == "table"

        outline_src = [s for s in sections if s.title]
        outline = [f"{'  ' * max(0, s.level - 1)}- {s.title[:80]}" for s in outline_src[: cls._MAX_OUTLINE]]
        if len(outline_src) > cls._MAX_OUTLINE:
            outline.append(f"[+{len(outline_src) - cls._MAX_OUTLINE} more sections]")

        # Allocation du budget : introduction, échantillons réguliers, conclusion
        body: List[str] = []
        prose_secs = [s for s in sections if not s.is_appendix_ioc]
        remaining = cls.CLASSIFIER_BUDGET_CHARS - cls._CONCLUSION_CHARS - sum(len(l) for l in outline)
        intro_budget = min(cls._INTRO_CHARS, max(0, remaining))
        used_intro = 0
        idx = 0
        while idx < len(prose_secs) and used_intro < intro_budget:
            s = prose_secs[idx]
            text, c, t = cls._take_prose(s.blocks, intro_budget - used_intro)
            if text:
                body.append((f"## {s.title}\n" if s.title else "") + text + cls._markers(c, t))
                used_intro += len(text)
            idx += 1

        rest = prose_secs[idx:]
        conclusion = rest[-1] if len(rest) > 1 else None
        middle = rest[:-1] if conclusion is not None else rest
        mid_budget = max(0, remaining - used_intro)
        # Trop de sections pour le budget : on en échantillonne un sous-ensemble réparti sur tout le document
        # (de l'accès initial à l'impact), plutôt que de dépasser le budget ou de couper la fin.
        max_mid = max(1, mid_budget // cls._MIN_SECTION_CHARS)
        if len(middle) > max_mid:
            step = (len(middle) - 1) / max(1, max_mid - 1) if max_mid > 1 else 0
            keep = sorted({round(i * step) for i in range(max_mid)})
            middle = [middle[i] for i in keep]
        per_sec = max(cls._MIN_SECTION_CHARS, mid_budget // max(1, len(middle))) if middle else 0
        for s in middle:
            text, c, t = cls._take_prose(s.blocks, per_sec)
            if text or c or t:
                body.append(f"## {s.title}\n{text}{cls._markers(c, t)}")
        if conclusion is not None:
            text, c, t = cls._take_prose(conclusion.blocks, cls._CONCLUSION_CHARS)
            body.append(f"## {conclusion.title}\n{text}{cls._markers(c, t)}")

        n_appendix = len(sections) - len(prose_secs)
        header = (
            f"TITLE: {title}\n"
            f"STRUCTURE: {len(sections)} sections, {total_len} chars, {n_code} code blocks, {n_table} tables"
            + (f", {n_appendix} indicator-list sections" if n_appendix else "")
            + "\n"
        )
        return (
            f"{header}\nOUTLINE:\n" + "\n".join(outline) + "\n\nTEXT (excerpts, in reading order):\n" + "\n\n".join(body)
        )

    @staticmethod
    def _markers(n_code: int, n_table: int) -> str:
        bits = []
        if n_code:
            bits.append(f"code×{n_code}")
        if n_table:
            bits.append(f"table×{n_table}")
        return f"\n[omitted: {', '.join(bits)}]" if bits else ""
