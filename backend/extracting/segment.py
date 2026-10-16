"""Découpage d'un article en unités numérotées, et regroupement en passes d'extraction.

Pourquoi des phrases numérotées : la preuve d'une relation n'est plus une citation que le modèle doit recopier mot
pour mot (des dizaines de tokens de sortie par relation, et la principale source d'hallucination), mais un NUMÉRO de
phrase. Le texte de la preuve est relu côté code, donc exact par construction.

Les blocs de code et les tables restent des unités entières : ils portent les commandes et les cartographies
ATT&CK, mais seul un extrait est montré au modèle (le texte complet reste disponible comme preuve).
"""

import re
from dataclasses import dataclass

from backend.preprocessing.cleaner import UniversalCTICleaner

MAX_CODE_LINES = 8  # lignes de code montrées au modèle par bloc
MAX_TABLE_ROWS = 14
MAX_UNIT_CHARS = 700  # une « phrase » plus longue (journal, liste continue) est tronquée dans le prompt

# Abréviations dont le point ne termine pas une phrase
_ABBREVIATIONS = ("e.g.", "i.e.", "vs.", "etc.", "Fig.", "Inc.", "Ltd.", "Corp.", "approx.", "cf.", "No.", "Dr.", "Mr.", "Ms.")
_PLACEHOLDER = "․"  # point « énumération » : jamais présent dans le texte nettoyé
_SENTENCE_END = re.compile(r"(?<=[.!?])[\"'»”)\]]*\s+(?=[\"'«“(\[]?[A-Z0-9À-Ý`*_])")
_LIST_ITEM = re.compile(r"^\s*(?:[*+\-•]|\d{1,3}[.)])\s+")


_HASH = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_DOMAIN = re.compile(r"^[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)+(?:[:/].*)?$", re.I)
# Extensions de fichier courantes : un « nom.exe » n'est pas un nom de domaine
_FILE_EXT = frozenset("exe dll sys bat cmd ps1 vbs js jar msi scr lnk so dat tmp bin log txt cfg ini conf json xml hta zip rar 7z iso doc docx xls xlsx pdf py sh".split())


def is_indicator_text(text: str) -> bool:
    """Ligne dominée par des indicateurs techniques (hachages, adresses IP, domaines, URL). Elle n'apporte rien au
    modèle (il ne doit pas extraire d'observables) et pollue son contexte : elle est masquée dans les prompts."""
    tokens = text.split()
    if not tokens:
        return False
    hashes, ips = len(_HASH.findall(text)), len(_IPV4.findall(text))
    domains = sum(1 for t in tokens if _DOMAIN.match(t.strip("|,;()[]")) and t.rsplit(".", 1)[-1].lower().strip("|,;()[]") not in _FILE_EXT)
    return hashes >= 2 or (hashes + ips + domains) / len(tokens) >= 0.4


_CODE_KEYWORDS = re.compile(r"\b(condition|strings|meta)\s*:|\brule\s+\w+\s*\{|\bselection\s*:|\bdetection\s*:", re.I)


_REFERENCE_START = re.compile(r"^\s*\[\d{1,3}\]\s*\S")


def looks_like_reference(text: str) -> bool:
    """Entrée de bibliographie (« [9] Éditeur, Titre, date ») : cite des sources, n'affirme rien sur la menace.
    Un « [1] » en fin de phrase est une citation en ligne et reste une phrase."""
    return bool(_REFERENCE_START.match(text))


def looks_like_code(text: str) -> bool:
    """Règle YARA ou Sigma, script, journal : texte qui n'affirme rien mais peut contenir des noms d'outils. Le
    prendre pour une phrase fabriquerait de fausses relations (« la règle nomme X et Y » n'est pas « X utilise Y »)."""
    if len(text) < 40:
        return False
    symbols = sum(1 for c in text if c in "{}=$;|<>\\")
    return symbols / len(text) >= 0.03 or bool(_CODE_KEYWORDS.search(text))


@dataclass(frozen=True)
class Unit:
    uid: int  # numéro stable dans l'article, à partir de 1
    kind: str  # "sentence" | "item" | "code" | "table"
    text: str  # texte complet : sert de preuve
    heading_path: str

    @property
    def is_indicators(self) -> bool:
        return self.kind in ("sentence", "item") and is_indicator_text(self.text)

    @property
    def is_reference(self) -> bool:
        return self.kind in ("sentence", "item") and looks_like_reference(self.text)

    @property
    def is_evidence_eligible(self) -> bool:
        """Peut-elle étayer une relation ? Ni code, ni table, ni liste d'indicateurs, ni bibliographie."""
        return self.kind in ("sentence", "item") and not self.is_indicators and not self.is_reference

    @property
    def prompt_text(self) -> str:
        """Texte montré au modèle (borné)."""
        if self.is_indicators:
            return "(liste d'indicateurs techniques, omise)"
        if self.is_reference:
            return "(référence bibliographique, omise)"
        if self.kind == "code":
            lines = [l for l in self.text.splitlines() if not l.strip().startswith(("```", "~~~"))]
            head = "\n".join(l.strip() for l in lines[:MAX_CODE_LINES])
            return head + (f"\n[… {len(lines) - MAX_CODE_LINES} lignes]" if len(lines) > MAX_CODE_LINES else "")
        if self.kind == "table":
            rows = self.text.splitlines()
            head = "\n".join(rows[:MAX_TABLE_ROWS])
            return head + (f"\n[… {len(rows) - MAX_TABLE_ROWS} lignes]" if len(rows) > MAX_TABLE_ROWS else "")
        text = " ".join(self.text.split())
        return text if len(text) <= MAX_UNIT_CHARS else text[:MAX_UNIT_CHARS].rsplit(" ", 1)[0] + " […]"


def split_sentences(paragraph: str) -> list[str]:
    """Phrases d'un paragraphe. Les noms de fichier, versions et adresses (« cmd.exe », « v1.2.3 ») ne sont pas
    coupés : le point doit être suivi d'une espace et d'une majuscule ou d'un chiffre."""
    text = " ".join(paragraph.split())
    for abbr in _ABBREVIATIONS:
        text = text.replace(abbr, abbr.replace(".", _PLACEHOLDER))
    parts = _SENTENCE_END.split(text)
    return [p.replace(_PLACEHOLDER, ".").strip() for p in parts if len(p.strip()) >= 3]


def _list_items(block: str) -> list[str] | None:
    """Éléments d'une liste (une ligne de continuation est rattachée à l'élément précédent), ou None si ce n'est pas
    une liste."""
    lines = block.splitlines()
    if not lines or not _LIST_ITEM.match(lines[0]):
        return None
    items: list[str] = []
    for line in lines:
        if _LIST_ITEM.match(line):
            items.append(_LIST_ITEM.sub("", line, count=1).strip())
        elif items:
            items[-1] += " " + line.strip()
    return [i for i in items if len(i) >= 3]


def segment(clean_markdown: str) -> list[Unit]:
    """Unités numérotées d'un `clean_markdown`, dans l'ordre du document. Les titres ne sont pas des unités : ils
    sont portés par `heading_path`."""
    units: list[Unit] = []

    def add(kind: str, text: str, path: str) -> None:
        units.append(Unit(len(units) + 1, kind, text, path))

    for block in UniversalCTICleaner._engine.split_blocks(clean_markdown or ""):
        if block.kind == "heading":
            continue
        if block.kind in ("code", "table"):
            add(block.kind, block.text, block.heading_path)
            continue
        items = _list_items(block.text)
        if items is not None:
            for item in items:
                add("code" if looks_like_code(item) else "item", item, block.heading_path)
        else:
            for sentence in split_sentences(block.text):
                add("code" if looks_like_code(sentence) else "sentence", sentence, block.heading_path)
    return units


@dataclass(frozen=True)
class Pass:
    """Un lot de phrases consécutives envoyé au modèle en un seul appel."""

    index: int
    units: tuple[Unit, ...]

    @property
    def heading_path(self) -> str:
        return self.units[0].heading_path if self.units else ""

    def render(self) -> str:
        """Texte numéroté montré au modèle ; un changement de section est annoncé."""
        lines: list[str] = []
        current = None
        for u in self.units:
            if u.heading_path != current:
                current = u.heading_path
                lines.append(f"## {current}" if current else "##")
            if u.kind in ("code", "table"):
                lines.append(f"[{u.uid}] ({u.kind})\n{u.prompt_text}")
            else:
                lines.append(f"[{u.uid}] {u.prompt_text}")
        return "\n".join(lines)


def make_passes(units: list[Unit], max_chars: int = 9000) -> list[Pass]:
    """Regroupe les unités en passes d'au plus `max_chars` caractères montrés, sans couper une unité. Dès qu'une
    passe dépasse la moitié du budget, elle se ferme au prochain changement de section : on évite de séparer le
    début d'une section de sa fin quand c'est possible."""
    passes: list[Pass] = []
    cur: list[Unit] = []
    size = 0
    for u in units:
        cost = len(u.prompt_text) + 8
        boundary = cur and u.heading_path != cur[-1].heading_path
        if cur and (size + cost > max_chars or (boundary and size > max_chars // 2)):
            passes.append(Pass(len(passes), tuple(cur)))
            cur, size = [], 0
        cur.append(u)
        size += cost
    if cur:
        passes.append(Pass(len(passes), tuple(cur)))
    return passes
