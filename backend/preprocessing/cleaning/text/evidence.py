"""Texte de l'article : comparaison de noms, ancrage des preuves, confiance exprimée par l'auteur, dates.

Rien ici ne relève de STIX (les objets sont construits par la bibliothèque `stix2`, voir `backend/extracting/stix/`) : ce sont les
outils qui relient une affirmation extraite au texte qui la porte.
"""

import re
import unicodedata
from datetime import datetime, timezone
from typing import Iterable

MIN_EVIDENCE_CHARS = 15

# --- Noms ----------------------------------------------------------------------------------------------------------------
_GENERIC_SUFFIXES = {"group", "team", "gang", "actor", "actors", "crew", "operators", "threat", "cluster", "apt"}
_LEADING_ARTICLES = {"the"}


def normalize_name(name: str | None) -> str:
    """Forme de comparaison : « APT 29 », « apt-29 » -> « apt29 » ; « Lazarus Group » -> « lazarus »."""
    if not name:
        return ""
    text = unicodedata.normalize("NFKD", str(name))
    text = "".join(c for c in text if not unicodedata.combining(c)).casefold()
    words = re.findall(r"[a-z0-9]+", text)
    while len(words) > 1 and words[0] in _LEADING_ARTICLES:
        words.pop(0)
    while len(words) > 1 and words[-1] in _GENERIC_SUFFIXES:
        words.pop()
    return "".join(words)


# --- Citations ----------------------------------------------------------------------------------------------------------
_QUOTE_MARKS = str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"', "«": '"', "»": '"'})


_LIST_MARKER = re.compile(r"(?m)^[ \t]*(?:[-*+•]|\d{1,3}[.)])[ \t]+")


def normalize_quote(text: str) -> str:
    """Forme de comparaison d'une citation : insensible à la casse, aux guillemets typographiques, aux balises
    de mise en forme Markdown, aux puces de liste (une citation peut enjamber une phrase et la liste qu'elle annonce)
    et aux espaces, y compris devant une ponctuation (« <groupe> , » d'un ancien export)."""
    text = unicodedata.normalize("NFKC", text or "")
    text = text.translate(_QUOTE_MARKS)
    text = _LIST_MARKER.sub("", text)
    text = re.sub(r"[*_`]+", "", text)
    text = re.sub(r"\s+", " ", text)
    return re.sub(r" (?=[,.;:!?)])", "", text).strip().casefold()


def evidence_in_source(evidence: str, source_text: str, *, haystack: str | None = None) -> bool:
    """La citation figure-t-elle dans le texte ? Les coupes « [...] » ou « … » sont admises : chaque fragment doit
    apparaître, et au moins un fragment doit être assez long pour être probant. `haystack` : `normalize_quote(source_text)`
    déjà calculé, quand beaucoup de citations sont testées contre le même texte."""
    parts = [normalize_quote(p) for p in re.split(r"\[\s*\.\.\.\s*\]|\.\.\.|…", evidence or "")]
    parts = [p for p in parts if len(p) >= 8]
    if not parts or max(len(p) for p in parts) < MIN_EVIDENCE_CHARS:
        return False
    haystack = normalize_quote(source_text) if haystack is None else haystack
    return all(p in haystack for p in parts)


def tokens(text: str) -> list[str]:
    """Mots de la forme de comparaison d'une citation (`normalize_quote`)."""
    return re.findall(r"[a-z0-9]+", normalize_quote(text))


def prepare_text(text: str) -> tuple[set[str], set[str]]:
    """Mots du texte et concaténations de 2 à 4 mots consécutifs : à calculer une fois par texte quand on teste
    beaucoup de termes contre lui."""
    words = tokens(text)
    joined = {"".join(words[i : i + n]) for n in (2, 3, 4) for i in range(len(words) - n + 1)}
    return set(words), joined


def mentions_prepared(prepared: tuple[set[str], set[str]], terms: Iterable[str]) -> bool:
    """`mentions` sur un texte déjà préparé (`prepare_text`). Un terme se compare mot à mot, tel quel : un nom de fichier
    temporaire (« ~<nom>.dat ») est un nom comme un autre."""
    vocabulary, joined = prepared
    for term in terms:
        toks = tokens(term)
        if toks and all(t in vocabulary for t in toks):
            return True
        if len(toks) == 1 and len(toks[0]) >= 5 and toks[0] in joined:
            return True
    return False


def mentions(evidence: str, terms: Iterable[str]) -> bool:
    """L'un des termes (nom, alias, identifiant externe) apparaît-il dans la citation ? Comparaison par mots entiers
    (« PsExec » est dans « PsExec.exe », pas dans « psexecuted ») ; « APT29 » est reconnu dans « APT 29 »."""
    return mentions_prepared(prepare_text(evidence), terms)


# --- Confiance (échelles normatives de STIX 2.1, Annexe A) ----------------------------------------------------------------
CONFIDENCE_SCALE = {"none": 0, "low": 15, "medium": 50, "high": 85}
WEP_SCALE = {"impossible": 0, "highly unlikely": 10, "unlikely": 30, "even chance": 50, "likely": 70, "highly likely": 90, "certain": 100}
DEFAULT_CONFIDENCE = CONFIDENCE_SCALE["high"]  # fait affirmé sans réserve par les auteurs du rapport

_CONFIDENCE_LEVEL_CUES = (
    (r"\b(high|strong)\s+confidence\b|confiance\s+(élevée|haute|forte)|(haut|fort)\s+niveau\s+de\s+confiance", "high"),
    (r"\b(moderate|medium)\s+confidence\b|confiance\s+(moyenne|modérée)|niveau\s+de\s+confiance\s+(moyen|modéré)", "medium"),
    (r"\blow\s+confidence\b|confiance\s+faible|faible\s+(niveau\s+de\s+)?confiance", "low"),
)
_WEP_CUES = (
    (r"\b(almost\s+certain(ly)?|highly\s+likely|very\s+likely)\b|quasi[- ]certain|très\s+probable", "highly likely"),
    (r"\b(highly\s+unlikely|almost\s+certainly\s+not|very\s+unlikely)\b|très\s+improbable", "highly unlikely"),
    (r"\b(unlikely|probably\s+not)\b|\bimprobable\b", "unlikely"),
    (r"\b(likely|probably)\b|\bprobablement\b|\bprobable\b", "likely"),
    (r"\beven\s+chance\b|une\s+chance\s+sur\s+deux", "even chance"),
)
_HEDGE_CUES = r"\b(possibly|possible|suspected|may\s+have|might|could\s+be)\b|\b(peut-être|pourrait|potentiellement|présumé|supposé)\b"
_CLAIM_CUES = r"\b(allegedly|reportedly|claims?|claimed)\b|\b(selon\s+les\s+(rapports|affirmations)|prétendument)\b"


def confidence_from_text(text: str | None) -> int:
    """Valeur de confiance STIX (0-100) déduite de la phrase qui énonce un fait. Priorité : niveau de confiance explicite >
    mot d'estimation (WEP) > affirmation d'un tiers > réserve > affirmation non nuancée (85)."""
    t = (text or "").lower()
    for pattern, level in _CONFIDENCE_LEVEL_CUES:
        if re.search(pattern, t):
            return CONFIDENCE_SCALE[level]
    for pattern, word in _WEP_CUES:
        if re.search(pattern, t):
            return WEP_SCALE[word]
    if re.search(_CLAIM_CUES, t):
        return WEP_SCALE["unlikely"]
    if re.search(_HEDGE_CUES, t):
        return WEP_SCALE["even chance"]
    return DEFAULT_CONFIDENCE


# --- Dates ---------------------------------------------------------------------------------------------------------------
_DATE_FORMATS = ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%B %d, %Y", "%b %d, %Y", "%d %B %Y", "%d %b %Y", "%Y/%m/%d", "%d/%m/%Y")


def parse_date(value: str | None) -> datetime | None:
    """Date de publication d'un article depuis les formats rencontrés dans la base (« 2020-08-03 », « April 22, 2026 »…).
    None si elle n'est pas reconnue : l'appelant choisit alors un repli plutôt que de produire une date fausse."""
    text = (value or "").strip().rstrip("Z")
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None
