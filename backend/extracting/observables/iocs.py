"""Extraction des IOC d'un article : valeurs par règles, rôle et rattachement par le modèle (réponses fermées).

    unités numérotées --règles--> valeurs candidates (adresses, domaines, URL, courriels, hachages)
        --filtres--> écartées : adresses privées ou réservées, domaines populaires, éditeur, extensions de fichier…
        --regroupement--> éléments (une phrase, ou une section d'annexe)
        --LLM, réponse fermée--> rôle (c2, payload-delivery…) + entité de rattachement parmi des candidats

Les VALEURS ne sont jamais générées par le modèle : il ne ferait que les recopier (lent, et source d'erreurs d'un
caractère qui fabriquent un faux IOC). Il ne répond que par un rôle et un identifiant d'entité : quelques tokens par
élément, ce qui respecte le débit mesuré du serveur Ollama.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from backend.extracting.stix.iocs import HASH_ALGOS, HASH_PRIORITY, ROLES, IocFinding

from backend.preprocessing.cleaning.text.evidence import mentions_prepared, parse_date, prepare_text

from backend.extracting import llm
from backend.preprocessing.cleaning.text.segment import FILE_EXT, Unit

REFERENCE = Path(__file__).resolve().parent / "reference"
ATTACH_TYPES = frozenset({"malware", "tool", "threat-actor", "intrusion-set", "campaign", "infrastructure", "incident"})
MAX_ITEMS_PER_CALL = 10
MAX_IOC_TOKENS = 24 * MAX_ITEMS_PER_CALL + 20  # une réponse {"item", "role", "to"} ≈ 22 tokens ; 180 tronquait un lot plein
MAX_ATTACH_CANDIDATES = 6
NARRATIVE_SPLIT = 4  # une phrase qui cite plus d'IOC que cela forme UN seul élément (même rôle pour tous)
MAX_SHOWN_VALUES = 5
MAX_CONTEXT_CHARS = 420
EXPLICIT_DATE_MAX_AGE = timedelta(days=5 * 365)  # une date plus ancienne est une référence historique, pas l'observation


# --- Données de référence -----------------------------------------------------------------------------------------------
def _read_list(name: str) -> list[str]:
    path = REFERENCE / name
    return [l.strip().lower() for l in path.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")] if path.exists() else []


@lru_cache(maxsize=1)
def tlds() -> frozenset[str]:
    return frozenset(_read_list("tlds.txt"))


@lru_cache(maxsize=1)
def popular_domains() -> frozenset[str]:
    return frozenset(_read_list("popular_domains.txt"))


# Extensions de fichier qui sont AUSSI des TLD réels (`.py`, `.sh`, `.zip`…) : « install.sh » n'est un domaine que dans une
# liste d'indicateurs
_CODE_EXTENSIONS = FILE_EXT | frozenset("py pl rs go rb php java cs cpp md h c asp aspx jsp cgi gz tar sql yml yaml toml html htm css png jpg gif svg pdf".split())
_DOCUMENTATION_DOMAINS = frozenset({"example.com", "example.org", "example.net"})
# Liens d'un tweet cité : raccourcisseur et images de Twitter, jamais l'indicateur lui-même (l'IOC est derrière, ou dans l'image)
_SOCIAL_LINK_HOSTS = frozenset({"t.co", "pic.twitter.com", "pbs.twimg.com"})
# Hébergeurs de code : un lien vers un dépôt est une référence, sauf dans une liste d'indicateurs ou s'il télécharge un fichier
_CODE_HOSTS = frozenset({"github.com", "gist.github.com", "gitlab.com", "bitbucket.org"})
_CODE_DOWNLOAD = re.compile(r"/(?:releases/download|raw|archive)/|\.(?:exe|dll|zip|rar|7z|iso|js|ps1|vbs|bat|hta|msi|lnk|sh|bin)(?:[?#]|$)", re.I)
_INDICATOR_HEADING = re.compile(r"indicator|\bioc|compromise|network|domain|\bc2\b|c&c|infrastructure|\bip\b|address|hash|artifact|observable", re.I)

# --- Motifs ---------------------------------------------------------------------------------------------------------------
_URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`\]\)}]+", re.I)
_EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}\b")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
_IPV6 = re.compile(r"(?<![\w:])[0-9A-Fa-f:]{3,39}(?![\w:])")
_DOMAIN = re.compile(r"(?<![\w@/\\.\-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,24})(?![\w-]|\.\w)")
_HASH = re.compile(r"(?<![A-Za-z0-9])(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})(?![A-Za-z0-9])")
_VERSION_BEFORE = re.compile(r"(?:\bv|\bversion\s|\bver\.?\s|\bbuild\s|\brelease\s)\s*$|[A-Za-z]/$", re.I)  # « v1.2.3.4 », « Chrome/118.0.0.0 »
_RULE_OR_DOC_URL = re.compile(r"\.(?:ya?ra?|ya?ml|sigma|rules?|md|rst|txt)(?:[?#]|$)", re.I)
_MD_LINK_TARGET = re.compile(r"\]\($")
_QUOTE_LINE = re.compile(r"^\s*>")  # ligne d'une citation Markdown (tweet, extrait d'un autre rapport)
# Empreinte TLS ou de certificat, de même longueur qu'un MD5 ou un SHA-1 : « JA3: 72a5… », « JA3S: … », « Thumbprint: … »
_FINGERPRINT_LABEL = re.compile(r"\b(?:JA3S?|JA4S?|JARM|imphash|thumbprint|fingerprint|serial(?:\s+number)?|cert(?:ificate)?|x509)\b[^\n]{0,24}$", re.I)
_FINGERPRINT_AFTER = re.compile(r"^[*`'\"\s]*\|\s*(?:JA3S?|JA4S?|JARM)\b", re.I)  # table « **72a5…** | JA3 | Cobalt Strike »
_FILE_NAME_EXTENSIONS = _CODE_EXTENSIONS | frozenset("xlsm xlsb docm dotm one img vhd vhdx cab apk elf jse wsf psm1 chm rtf".split())
_FILE_NAME = re.compile(rf"^[\w\-.()\[\]{{}}$~@+]{{1,200}}\.(?:{'|'.join(sorted(_FILE_NAME_EXTENSIONS))})$", re.I)

_MONTHS = "January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec"
_DATE_PATTERNS = (
    re.compile(r"\b20\d{2}-\d{2}-\d{2}\b"),
    re.compile(rf"\b(?:{_MONTHS})\.? \d{{1,2}}(?:st|nd|rd|th)?,? 20\d{{2}}\b"),
    re.compile(rf"\b\d{{1,2}}(?:st|nd|rd|th)? (?:{_MONTHS})\.?,? 20\d{{2}}\b"),
)


@dataclass
class Candidate:
    kind: str
    value: str  # pour un fichier : son hachage le plus fort
    algo: str | None
    uids: list[int] = field(default_factory=list)
    observed: datetime | None = None
    popular_subdomain: bool = False
    hashes: dict[str, str] = field(default_factory=dict)  # fichier : tous ses hachages connus, par algorithme
    name: str | None = None  # fichier : nom donné à côté de ses hachages (« info_1805.xls »)
    record: str = ""  # fichier : le paragraphe ou la ligne de table qui le décrit (preuve)


@dataclass(frozen=True)
class Dropped:
    kind: str
    value: str
    reason: str


def _host(url_or_host: str) -> str:
    """Hôte d'une URL ; vide si elle est malformée (crochets IPv6 orphelins, port invalide…) : un article mal formé ne doit pas
    interrompre l'extraction."""
    try:
        return (urlsplit(url_or_host if "://" in url_or_host else f"//{url_or_host}").hostname or "").lower().removeprefix("www.")
    except ValueError:
        return ""


def publisher_hosts(url: str | None) -> frozenset[str]:
    """Hôtes de l'éditeur de l'article : ce qu'il cite de lui-même n'est jamais un IOC."""
    return frozenset({h for h in (_host(url or ""),) if h})


def _is_publisher(host: str, publishers: frozenset[str]) -> bool:
    return any(host == p or host.endswith("." + p) for p in publishers)


def _popular_parent(host: str) -> tuple[bool, bool]:
    """(hôte lui-même populaire, sous-domaine d'un domaine populaire)."""
    popular = popular_domains()
    if host in popular:
        return True, False
    parts = host.split(".")
    return False, any(".".join(parts[i:]) in popular for i in range(1, len(parts) - 1))


def explicit_dates(text: str) -> set[datetime]:
    found = set()
    for pattern in _DATE_PATTERNS:
        for m in pattern.finditer(text):
            raw = re.sub(r"(\d)(?:st|nd|rd|th)", r"\1", m.group(0)).replace(".", "").replace("Sept", "Sep")
            if (d := parse_date(raw)) is not None:
                found.add(d)
    return found


def _observed(text: str, published: datetime | None) -> datetime | None:
    """Date explicite de l'unité si elle est unique et plausible comme date d'observation (pas future, pas ancienne)."""
    dates = explicit_dates(text)
    if len(dates) != 1:
        return None
    (d,) = dates
    if published and (d > published + timedelta(days=1) or published - d > EXPLICIT_DATE_MAX_AGE):
        return None
    return d if published or d <= datetime.now(timezone.utc) else None


# --- Extraction des valeurs ---------------------------------------------------------------------------------------------
# Mots-clés d'une règle YARA ou Sigma, sensibles à la casse (les deux langages les écrivent en minuscules) : la ligne « Strings: »
# d'une configuration de malware déchiffrée n'est pas une règle, et ses adresses C2 sont des IOC
_RULE_KEYWORDS = re.compile(r"\b(?:condition|strings|meta)\s*:|\brule\s+\w+\s*\{|\bselection\s*:|\bdetection\s*:")


def _unit_scan_text(unit: Unit) -> str | None:
    """Texte à fouiller : les règles YARA et Sigma sont du contenu de détection, pas une liste d'IOC (voir rules.py)."""
    if unit.is_reference:
        return None
    if unit.kind in ("code", "table") and _RULE_KEYWORDS.search(unit.text):
        return None
    return unit.text


def _line_before(text: str, pos: int) -> str:
    return text[text.rfind("\n", 0, pos) + 1 : pos]


def _on_quote_line(text: str, pos: int) -> bool:
    return bool(_QUOTE_LINE.match(_line_before(text, pos)))


def _records(text: str, kind: str) -> list[str]:
    """Enregistrements d'un bloc d'indicateurs : une ligne de table, ou un paragraphe (séparé par une ligne vide), lui-même coupé
    à chaque nom de fichier qui suit des hachages (listes « nom / MD5 / SHA-1 / SHA-256 » sans ligne vide)."""
    if kind == "table":
        return text.splitlines()
    out: list[str] = []
    for chunk in re.split(r"\n\s*\n", text):
        current: list[str] = []
        for line in chunk.splitlines():
            if current and _file_name(line) and any(_HASH.search(l) for l in current):
                out.append("\n".join(current))
                current = []
            current.append(line)
        if current:
            out.append("\n".join(current))
    return out


def _file_name(record: str) -> str | None:
    """Nom de fichier unique d'un enregistrement, sinon None (deux noms : on ne sait pas lequel porte les hachages)."""
    names = {t for t in re.split(r"[\s|,;`'\"]+", record) if _FILE_NAME.match(t) and not _HASH.fullmatch(t.rsplit(".", 1)[0])}
    return names.pop() if len(names) == 1 else None


def _merge_files(cands: list[Candidate]) -> list[Candidate]:
    """Un hachage cité seul (dans le récit) et le fichier complet qui le contient (annexe) sont un seul fichier."""
    files = sorted((c for c in cands if c.kind == "file"), key=lambda c: -len(c.hashes))
    kept: list[Candidate] = []
    by_hash: dict[str, list[Candidate]] = {}  # hachage -> fichiers retenus qui le contiennent
    for c in files:
        values = set(c.hashes.values())
        host = next((k for k in by_hash.get(next(iter(values)), ()) if values <= set(k.hashes.values())), None)
        if host is None:
            kept.append(c)
            for v in values:
                by_hash.setdefault(v, []).append(c)
            continue
        host.uids += [u for u in c.uids if u not in host.uids]
        host.observed = host.observed or c.observed
        host.name, host.record = host.name or c.name, host.record or c.record
    kept_ids = {id(k) for k in kept}
    return [c for c in cands if c.kind != "file" or id(c) in kept_ids]


def _refang(text: str) -> str:
    """Filet de sécurité : le prétraitement refange déjà, mais un article mal nettoyé ne doit pas perdre ses IOC."""
    text = re.sub(r"\[(?:\.|dot)\]|\((?:\.|dot)\)", ".", text, flags=re.I)
    text = re.sub(r"\bhxxp(s?)://", r"http\1://", text, flags=re.I)
    return re.sub(r"\[:\]|\[://\]", ":", text)


def find_iocs(units: list[Unit], *, publishers: frozenset[str] = frozenset(), published: datetime | None = None) -> tuple[list[Candidate], list[Dropped]]:
    """Valeurs candidates de l'article, dédoublonnées (une entrée par valeur, avec toutes les unités qui la citent),
    et celles qui ont été écartées avec la raison."""
    by_key: dict[tuple[str, str], Candidate] = {}
    dropped: dict[tuple[str, str, str], Dropped] = {}
    tld_set = tlds()
    ambiguous_tlds = tld_set & _CODE_EXTENSIONS

    def keep(kind: str, value: str, unit: Unit, algo: str | None = None, popular_subdomain: bool = False, observed: datetime | None = None) -> Candidate:
        cand = by_key.setdefault((kind, value), Candidate(kind, value, algo, popular_subdomain=popular_subdomain))
        if unit.uid not in cand.uids:
            cand.uids.append(unit.uid)
        cand.observed = cand.observed or observed
        return cand

    def keep_file(hashes: dict[str, str], unit: Unit, observed: datetime | None, name: str | None = None, record: str = "") -> None:
        algo = next(a for a in HASH_PRIORITY if a in hashes)
        cand = by_key.setdefault(("file", "|".join(hashes[a] for a in HASH_PRIORITY if a in hashes)), Candidate("file", hashes[algo], algo, hashes=dict(hashes)))
        if unit.uid not in cand.uids:
            cand.uids.append(unit.uid)
        cand.observed = cand.observed or observed
        cand.name, cand.record = cand.name or name, cand.record or record

    def drop(kind: str, value: str, reason: str) -> None:
        dropped.setdefault((kind, value, reason), Dropped(kind, value, reason))

    for unit in units:
        raw = _unit_scan_text(unit)
        if raw is None:
            continue
        text = _refang(raw)
        observed = _observed(text, published)
        indicator_list = unit.is_indicators or bool(_INDICATOR_HEADING.search(unit.heading_path))
        indicator_context = indicator_list or unit.kind in ("code", "table")

        # URL : leurs hôtes ne sont pas comptés à part (l'URL est l'indicateur), et on les retire du texte avant la suite
        for m in _URL.finditer(text):
            url = m.group(0).rstrip(".,;:!?)")
            host = _host(url)
            if not host:
                continue
            is_md_link = bool(_MD_LINK_TARGET.search(text[max(0, m.start() - 2) : m.start()]))
            popular, _ = _popular_parent(host)
            if _is_publisher(host, publishers):
                drop("url", url, "publisher")
            elif host in _SOCIAL_LINK_HOSTS:
                drop("url", url, "social-media-link")
            elif _RULE_OR_DOC_URL.search(urlsplit(url).path if "[" not in url else url):
                drop("url", url, "detection-rule-or-document")
            elif _on_quote_line(text, m.start()) and (popular or _popular_parent(host)[1]):
                drop("url", url, "quoted-citation")  # un service connu cité dans un tweet ou un autre rapport
            elif is_md_link and (popular or _popular_parent(host)[1]):
                drop("url", url, "reference-link")
            elif host in _CODE_HOSTS and not indicator_list and not _CODE_DOWNLOAD.search(url):
                drop("url", url, "code-repository-reference")
            elif popular and not indicator_context and not re.search(r"\.(?:exe|dll|zip|rar|7z|iso|js|ps1|vbs|bat|hta|msi|lnk|sh|py|bin|dat)\b|/[^/\s]{24,}", url, re.I):
                drop("url", url, "popular-host-without-payload")  # lien vers un site connu cité dans le récit
            else:
                _, sub = _popular_parent(host)
                keep("url", url, unit, popular_subdomain=sub or popular, observed=observed)
        text = _URL.sub(" ", text)

        for m in _EMAIL.finditer(text):
            email = m.group(0).lower()
            domain = email.rsplit("@", 1)[1]
            if domain.rsplit(".", 1)[-1] not in tld_set:
                continue
            if _is_publisher(domain, publishers) or domain in _DOCUMENTATION_DOMAINS:
                drop("email-addr", email, "publisher-or-documentation")
            else:
                keep("email-addr", email, unit, observed=observed)
        text = _EMAIL.sub(" ", text)

        # Hachages. Dans un bloc ou une table d'indicateurs, un enregistrement qui donne au plus un hachage par algorithme décrit UN
        # fichier : un seul observable, un seul indicateur. Une phrase ou un élément de liste aussi, mais seulement s'il nomme le fichier
        # (« Samples: <md5>, <sha256> » peut citer deux échantillons). Sinon, ou si un algorithme se répète : un fichier par hachage.
        for record in _records(text, unit.kind) if indicator_context else [text]:
            digests: list[tuple[str, str]] = []
            for m in _HASH.finditer(record):
                digest = m.group(0).lower()
                if len(set(digest)) <= 2 or (len(digest) < 64 and (digest.isdigit() or digest.isalpha())):
                    drop("file", digest, "not-a-hash")
                elif _FINGERPRINT_LABEL.search(_line_before(record, m.start())) or _FINGERPRINT_AFTER.match(record[m.end() :]):
                    drop("file", digest, "tls-or-certificate-fingerprint")  # empreinte réseau, pas un fichier
                else:
                    digests.append((HASH_ALGOS[len(digest)], digest))
            algos = [a for a, _ in digests]
            if indicator_context and digests and len(set(algos)) == len(algos) and (unit.kind in ("code", "table") or _file_name(record)):
                lines = [l.strip(" |`") for l in record.splitlines() if l.strip(" |`")]
                keep_file(dict(digests), unit, observed, _file_name(record), " ".join(lines))
            else:
                for algo, digest in digests:
                    keep_file({algo: digest}, unit, observed)
        text = _HASH.sub(" ", text)

        for m in _IPV4.finditer(text):
            before = text[max(0, m.start() - 14) : m.start()]
            try:
                addr = ipaddress.IPv4Address(m.group(0))
            except ValueError:
                continue
            if _VERSION_BEFORE.search(before) or m.group(0).endswith(".0.0"):
                drop("ipv4-addr", str(addr), "version-like")
            elif not addr.is_global:
                drop("ipv4-addr", str(addr), "private-or-reserved")
            else:
                keep("ipv4-addr", str(addr), unit, observed=observed)
        text = _IPV4.sub(" ", text)

        for m in _IPV6.finditer(text):
            token = m.group(0)
            if token.count(":") < 2 or not re.search(r"[0-9A-Fa-f]{2}", token):
                continue
            try:
                addr6 = ipaddress.IPv6Address(token)
            except ValueError:
                continue
            if not addr6.is_global:
                drop("ipv6-addr", str(addr6), "private-or-reserved")
            else:
                keep("ipv6-addr", addr6.compressed, unit, observed=observed)

        for m in _DOMAIN.finditer(text):
            domain = m.group(0).lower().rstrip(".")
            tld_text = m.group(1)
            tld = tld_text.lower()
            labels = domain.split(".")
            if tld not in tld_set or not (tld_text.islower() or tld_text.isupper()) or all(l.isdigit() for l in labels[:-1]):
                continue  # « fin.Il » (espace oubliée), « 10.0.19041.dll », mot quelconque
            if tld in ambiguous_tlds and not indicator_list:  # dans du code, « OgnlValueStack.java » ou « libhax.so » est un fichier
                drop("domain-name", domain, "file-name-or-ambiguous")
                continue
            host = domain.removeprefix("www.")
            popular, sub = _popular_parent(host)
            if _is_publisher(host, publishers):
                drop("domain-name", domain, "publisher")
            elif host in _SOCIAL_LINK_HOSTS:
                drop("domain-name", domain, "social-media-link")
            elif _on_quote_line(text, m.start()) and (popular or sub):
                drop("domain-name", domain, "quoted-citation")
            elif host in _DOCUMENTATION_DOMAINS:
                drop("domain-name", domain, "documentation")
            elif popular:
                drop("domain-name", domain, "popular-domain")
            else:
                keep("domain-name", domain, unit, popular_subdomain=sub, observed=observed)

    return _merge_files(list(by_key.values())), list(dropped.values())


# --- Éléments soumis au modèle ------------------------------------------------------------------------------------------
@dataclass
class Item:
    index: int  # numéro dans l'article (à partir de 1)
    family: str  # "network" | "file"
    cands: list[Candidate]
    heading: str
    context: str
    attach_ids: list[str]  # identifiants locaux (E1…) proposés pour le rattachement


@dataclass(frozen=True)
class Attachable:
    eid: str
    stix_id: str
    stix_type: str
    name: str
    terms: tuple[str, ...]


def attachables(entities: list[dict]) -> list[Attachable]:
    """Entités d'un article auxquelles un IOC peut se rattacher, numérotées pour le prompt."""
    out = []
    for ent in entities:
        if ent["type"] in ATTACH_TYPES:
            out.append(Attachable(f"E{len(out) + 1}", ent["id"], ent["type"], ent["name"], (ent["name"], *ent.get("aliases", []))))
    return out


def _trim(text: str, limit: int = MAX_CONTEXT_CHARS) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit].rsplit(" ", 1)[0] + " […]"


def build_items(candidates: list[Candidate], units: list[Unit], entities: list[Attachable]) -> list[Item]:
    by_uid = {u.uid: u for u in units}
    section_units: dict[str, list[Unit]] = {}
    for u in units:
        section_units.setdefault(u.heading_path, []).append(u)

    def narrative(cand: Candidate) -> Unit | None:
        """Phrase du récit qui cite la valeur ou, pour un fichier nommé de l'annexe, son nom (« find.bat a lancé AdFind ») : c'est
        elle qui dit à quel logiciel ou acteur l'IOC appartient."""
        unit = next((by_uid[i] for i in cand.uids if by_uid[i].kind in ("sentence", "item") and not by_uid[i].is_indicators), None)
        if unit is None and cand.name:
            named = re.compile(rf"(?<![\w.\\/-]){re.escape(cand.name)}(?![\w-])", re.I)  # « 1.dll », pas « x1.dll »
            unit = next((u for u in units if u.is_evidence_eligible and named.search(u.text)), None)
        return unit

    def lead(unit: Unit) -> Unit | None:
        """Phrase qui annonce un bloc d'indicateurs (« Cobalt Strike: » puis le bloc) : sans elle, tous les blocs d'une section
        recevraient le même rattachement."""
        siblings = section_units[unit.heading_path]
        pos = next(i for i, u in enumerate(siblings) if u.uid == unit.uid)
        prev = siblings[pos - 1] if pos else None
        return prev if prev is not None and unit.kind in ("code", "table") and prev.is_evidence_eligible else None

    groups: dict[tuple, list[Candidate]] = {}
    contexts: dict[tuple, Unit] = {}
    leads: dict[tuple, Unit | None] = {}
    for cand in candidates:
        family = "file" if cand.kind == "file" else "network"
        unit = narrative(cand)
        block = by_uid[cand.uids[0]]
        intro = None if unit else lead(block)
        key = ("u", unit.uid, family) if unit else ("s", block.heading_path, intro.uid if intro else None, family)
        groups.setdefault(key, []).append(cand)
        contexts.setdefault(key, unit or block)
        leads.setdefault(key, intro)

    incident = next((e for e in entities if e.stix_type == "incident"), None)
    items: list[Item] = []
    for key, cands in groups.items():
        first = contexts[key]
        if key[0] == "u":
            prose = [first.text]
            siblings = section_units[first.heading_path]
            pos = next(i for i, u in enumerate(siblings) if u.uid == first.uid)
            if pos and siblings[pos - 1].is_evidence_eligible:
                prose.insert(0, siblings[pos - 1].text)  # la phrase précédente porte souvent le sujet
            context = _trim(" ".join(prose))
            splits = [[c] for c in cands] if len(cands) <= NARRATIVE_SPLIT else [cands]
        elif leads[key] is not None:
            context = _trim(leads[key].text)
            splits = [cands]
        else:
            intro = [u.text for u in section_units.get(first.heading_path, []) if u.is_evidence_eligible][:2]
            context = _trim(" ".join(intro)) if intro else ""
            splits = [cands]
        # Le titre de l'article (« … An Emotet Story ») est en tête de chaque chemin de titres : ce qu'il nomme n'est proposé que si rien
        # de plus proche (section, phrase) ne nomme de sujet. Sinon Emotet était proposé, et choisi, pour find.bat lancé avec AdFind.
        title, _, below = first.heading_path.partition(" > ")
        mentioned = []
        for scope in (prepare_text(f"{below} {context}"), prepare_text(title)):
            mentioned = [e for e in entities if e.stix_type != "incident" and mentions_prepared(scope, e.terms)][:MAX_ATTACH_CANDIDATES]
            if mentioned:
                break
        ids = [e.eid for e in mentioned] + ([incident.eid] if incident else [])
        for part in splits:
            items.append(Item(0, "file" if part[0].kind == "file" else "network", part, first.heading_path, context, ids))
    for i, item in enumerate(items, 1):
        item.index = i
    return items


# --- Prompts et réponses ------------------------------------------------------------------------------------------------
def ioc_system() -> str:
    return (
        "Tu es analyste en renseignement sur la menace (CTI). Chaque ÉLÉMENT regroupe des indicateurs techniques "
        "(adresses IP, domaines, URL, courriels, hachages de fichiers) cités par un rapport, avec leur contexte. Pour "
        "chaque élément, donne `role` : ce que ces indicateurs sont dans l'attaque décrite, et `to` : l'entité à laquelle "
        "ils se rattachent, choisie parmi celles proposées pour CET élément (ou none).\n\n"
        "RÔLES : c2 (serveur de commande et contrôle) ; payload-delivery (héberge ou distribue la charge utile) ; "
        "exfiltration (destination des données volées) ; phishing (leurre, page ou expéditeur d'hameçonnage) ; "
        "staging-or-proxy (relais, proxy, hébergement intermédiaire de l'attaquant) ; malware-sample (fichier malveillant "
        "ou hachage d'un échantillon) ; other-malicious (malveillant, rôle non précisé) ; not-malicious ; unknown.\n"
        "not-malicious : la victime, un service légitime simplement cité, une ressource de l'éditeur ou du chercheur, un "
        "outil de sécurité, une adresse de test, un exemple, une source citée. Un service légitime ABUSÉ par l'attaquant "
        "(il y héberge ou y publie quelque chose) est malveillant : choisis le rôle selon l'usage. unknown : le contexte ne "
        "permet pas de trancher.\n"
        "`to` : l'entité que le texte désigne comme utilisant, possédant, hébergeant ou contactée par ces indicateurs. "
        "none si le texte ne le dit pas : n'en choisis pas une par défaut.\n\n"
        "FORMAT : un objet JSON {\"answers\": [{\"item\": \"3\", \"role\": \"c2\", \"to\": \"E2\"}]} avec UNE réponse par "
        "élément. Aucun commentaire."
    )


def ioc_user(title: str, items: list[Item], entities: list[Attachable]) -> str:
    by_eid = {e.eid: e for e in entities}
    lines = [f"Rapport : {title}", ""]
    for it in items:
        shown = [(f"{c.name} ({c.value})" if c.name else c.value) + (" (sous-domaine d'un domaine populaire)" if c.popular_subdomain else "") for c in it.cands[:MAX_SHOWN_VALUES]]
        more = f" (+ {len(it.cands) - MAX_SHOWN_VALUES} autres)" if len(it.cands) > MAX_SHOWN_VALUES else ""
        who = " ; ".join(f"{eid} {by_eid[eid].name} ({by_eid[eid].stix_type})" for eid in it.attach_ids) or "aucune"
        lines += [
            f"[{it.index}] indicateurs ({'hachages de fichiers' if it.family == 'file' else 'réseau'}) : {', '.join(shown)}{more}",
            f"    section : {it.heading or '(sans titre)'}",
            f"    contexte : {it.context or '(aucune phrase d’introduction)'}",
            f"    entités possibles : {who}",
        ]
    return "\n".join(lines)


def ioc_schema(items: list[Item], entities: list[Attachable]) -> dict:
    return {
        "type": "object",
        "properties": {
            "answers": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "item": {"type": "string", "enum": [str(i.index) for i in items]},
                        "role": {"type": "string", "enum": list(ROLES)},
                        "to": {"type": "string", "enum": ["none", *[e.eid for e in entities]]},
                    },
                    "required": ["item", "role", "to"],
                },
            }
        },
        "required": ["answers"],
    }


def parse_ioc_answers(parsed, items: list[Item]) -> dict[int, tuple[str, str | None]]:
    """`{numéro d'élément: (rôle, eid ou None)}`. Réponse hors du lot, rôle inconnu, entité non proposée : ignorées."""
    by_index = {i.index: i for i in items}
    answers: dict[int, tuple[str, str | None]] = {}
    raw = parsed.get("answers", []) if isinstance(parsed, dict) else []
    for entry in raw if isinstance(raw, list) else []:
        if not isinstance(entry, dict):
            continue
        try:
            index = int(str(entry.get("item")).strip())
        except ValueError:
            continue
        role, to = str(entry.get("role", "")).strip(), str(entry.get("to", "none")).strip()
        if index in by_index and role in ROLES and index not in answers:
            answers[index] = (role, to if to in by_index[index].attach_ids else None)
    return answers


# --- Assemblage ---------------------------------------------------------------------------------------------------------
@dataclass
class IocResult:
    findings: list[IocFinding] = field(default_factory=list)
    dropped: list[Dropped] = field(default_factory=list)
    n_candidates: int = 0
    n_items: int = 0
    n_not_malicious: int = 0
    calls: list[llm.LLMResult] = field(default_factory=list)


def _quote_for(cand: Candidate, unit_by_uid: dict[int, Unit]) -> str:
    """Preuve : la phrase (unité narrative) qui contient la valeur, l'enregistrement d'un fichier (nom et hachages), ou la ligne exacte."""
    unit = next((unit_by_uid[i] for i in cand.uids if unit_by_uid[i].kind in ("sentence", "item") and not unit_by_uid[i].is_indicators), unit_by_uid[cand.uids[0]])
    if unit.kind in ("sentence", "item") and not unit.is_indicators:
        return _trim(unit.text, 500)
    if cand.record:
        return _trim(cand.record, 300)
    line = next((l for l in unit.text.splitlines() if cand.value.lower() in l.lower() or (cand.kind != "file" and cand.value in l)), unit.text)
    return _trim(line.strip("|` "), 300)


def extract_iocs(
    title: str,
    units: list[Unit],
    entities: list[dict],
    *,
    url: str | None = None,
    published: datetime | None = None,
) -> IocResult:
    """IOC d'un article, avec rôle et rattachement. `entities` : entités finales de l'article (avec leur identifiant STIX).

    Un élément que le modèle n'a pas classé (réponse tronquée) reste `unknown` : conservé comme observable, jamais
    présenté comme malveillant. Un élément jugé `not-malicious` est conservé sans rattachement, pour être audité : il devient
    un indicateur `benign` (voir `build_ioc_objects`), jamais une infrastructure de l'attaquant."""
    result = IocResult()
    candidates, result.dropped = find_iocs(units, publishers=publisher_hosts(url), published=published)
    result.n_candidates = len(candidates)
    if not candidates:
        return result
    attach = attachables(entities)
    by_eid = {a.eid: a for a in attach}
    items = build_items(candidates, units, attach)
    result.n_items = len(items)
    unit_by_uid = {u.uid: u for u in units}
    system = ioc_system()
    batches = [items[start : start + MAX_ITEMS_PER_CALL] for start in range(0, len(items), MAX_ITEMS_PER_CALL)]

    def classify_batch(batch: list[Item]) -> tuple[llm.LLMResult, dict[int, tuple[str, str | None]]]:
        used = sorted({eid for it in batch for eid in it.attach_ids})
        res = llm.try_generate(system, ioc_user(title, batch, attach), ioc_schema(batch, [by_eid[e] for e in used]), max_output_tokens=MAX_IOC_TOKENS)
        return res, parse_ioc_answers(res.parsed, batch)

    answers: dict[int, tuple[str, str | None]] = {}
    for res, parsed in llm.map_parallel(classify_batch, batches):
        result.calls.append(res)
        answers.update(parsed)

    for it in items:
        role, to = answers.get(it.index, ("unknown", None))
        if role == "not-malicious":
            result.n_not_malicious += len(it.cands)
            to = None
        if it.family == "file" and role not in ("unknown", "not-malicious", "malware-sample"):
            role = "malware-sample"  # un fichier n'est ni un C2 ni un relais : la nature de l'objet prime
        if it.family == "network" and role == "malware-sample":
            role = "other-malicious"
        target = by_eid.get(to) if to else None
        if target is None and role not in ("unknown", "not-malicious"):
            target = next((a for a in attach if a.stix_type == "incident"), None)  # IOC sans sujet explicite : ceux de l'intrusion décrite
        confidence = 35 if role == "unknown" else 75 if target and target.stix_type != "incident" else 55
        for cand in it.cands:
            result.findings.append(
                IocFinding(
                    kind=cand.kind, value=cand.value, algo=cand.algo, hashes=cand.hashes or None, name=cand.name, role=role, quote=_quote_for(cand, unit_by_uid), heading=it.heading,
                    attach_id=target.stix_id if target else None, attach_type=target.stix_type if target else None, attach_name=target.name if target else None,
                    observed=cand.observed, confidence=confidence,
                )
            )
    return result
