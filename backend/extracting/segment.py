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


@dataclass(frozen=True)
class Unit:
    uid: int  # numéro stable dans l'article, à partir de 1
    kind: str  # "sentence" | "item" | "code" | "table"
    text: str  # texte complet : sert de preuve
    heading_path: str

    @property
    def prompt_text(self) -> str:
        """Texte montré au modèle (borné)."""
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
                add("item", item, block.heading_path)
        else:
            for sentence in split_sentences(block.text):
                add("sentence", sentence, block.heading_path)
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
