"""MITRE ATT&CK v20.0 : le bundle STIX officiel, lu par `stix2`, et un index de recherche pour l'agent.

    uv run python -m backend.extracting.stix.attack [chemin/enterprise-attack-20.0.json]   # construit l'index (≈ 10 s, une fois)

Le bundle officiel (52 Mo) est chargé par `stix2.MemoryStore` et interrogé par `stix2.Filter`. Chaque objet ATT&CK utile
(technique, groupe, logiciel, campagne, tactique, mitigation) est rangé dans un fichier SQLite (`reference/attack_v20.sqlite`,
non versionné) avec sa sérialisation `stix2` : l'agent reçoit l'objet officiel (`stix2.parse`), identifiant MITRE compris,
et le bundle de l'article le contient tel que MITRE le publie.

`stix2` n'offre pas de recherche plein texte (et `MemoryStore.related_to` prend ~8 s sur ce bundle) : la recherche d'une
technique à partir d'un comportement passe par SQLite FTS5. Classement : fusion des rangs (RRF) de deux recherches BM25,
l'une sur le nom et la description des techniques, l'autre sur leurs 17 636 exemples de procédures (« APT29 used
systeminfo to… »), meilleur pont lexical entre un article et ATT&CK. Chaque procédure garde la clé des rapports qu'elle cite
(`report_key`) : l'extraction d'un article écarte celles qui en sont tirées, sans quoi la recherche retrouverait une paraphrase
de l'article lui-même (un rapport neuf n'est pas encore dans ATT&CK).
"""

import json
import re
import sqlite3
import sys
import threading
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from stix2 import Filter, MemoryStore, parse

from backend.preprocessing.cleaning.text.evidence import normalize_name

REFERENCE_DIR = Path(__file__).resolve().parent / "reference"
INDEX_FILE = REFERENCE_DIR / "attack_v20.sqlite"
ATTACK_VERSION = "20.0"
# Le bundle officiel n'est pas versionné : on le cherche dans ces emplacements, dans l'ordre
BUNDLE_CANDIDATES = (
    REFERENCE_DIR / "enterprise-attack-20.0.json",
    Path(__file__).resolve().parents[3] / "Annotations" / "enterprise-attack-20.0.json",
)
BUNDLE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.0.json"

_RRF_K = 60
_SUMMARY_CHARS = 240
_STOPWORDS = frozenset(
    "a an the of to in on for by with from and or as at is are was were be been being it its this that these those their "
    "they them he she his her which who whom then than into onto via using used use uses also has have had can could may "
    "might will would such other another some any all each both more most not no".split()
)
_ID = re.compile(r"^(T\d{4}(?:\.\d{3})?|TA\d{4}|G\d{4}|S\d{4}|C\d{4}|M\d{4})$", re.I)
_DROPPED = frozenset({"description", "created_by_ref", "object_marking_refs"})  # propriétés d'un objet ATT&CK non reprises
_TYPES = ("attack-pattern", "intrusion-set", "malware", "tool", "campaign", "x-mitre-tactic", "course-of-action")


def clean_description(text: str) -> str:
    """Description ATT&CK lisible : sans « (Citation: …) », liens Markdown réduits à leur texte, balises retirées."""
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"</?code>", "`", text)
    text = re.sub(r"<[^>]+>", "", text)
    return re.sub(r"\s+", " ", text).strip()


def summary(text: str, limit: int = _SUMMARY_CHARS) -> str:
    """Première phrase (ou début) d'une description nettoyée."""
    first = re.split(r"(?<=[.!?])\s+(?=[A-Z])", text, maxsplit=1)[0]
    return first if len(first) <= limit else first[: limit - 1].rsplit(" ", 1)[0] + "…"


def fts_query(text: str) -> str:
    """Requête FTS5 sûre : mots du texte (sans mots vides) reliés par OR, chacun entre guillemets."""
    words = [w for w in re.findall(r"[a-z0-9]+", (text or "").casefold()) if len(w) > 1 and w not in _STOPWORDS]
    return " OR ".join(f'"{w}"' for w in dict.fromkeys(words))


def report_key(url: str | None) -> str | None:
    """Clé d'un rapport tirée de son URL, stable entre ses copies (http/https, www, langue, barre finale, extension) : le dernier
    segment significatif du chemin (« scattered-spider-attempts-to-avoid-detection… »), sinon l'hôte et le chemin."""
    url = re.sub(r"^[a-z]+://(www\.)?", "", (url or "").strip().lower()).split("?")[0].split("#")[0].rstrip("/")
    if not url:
        return None
    host, _, path = url.partition("/")
    parts = [re.sub(r"\.(html?|php|aspx?|pdf)$", "", p) for p in path.split("/") if p]
    parts = [p for p in parts if not re.fullmatch(r"[a-z]{2}(-[a-z]{2})?|blogs?|posts?|\d+|index", p)]
    return parts[-1] if parts and len(parts[-1]) >= 12 else f"{host}/{'/'.join(parts)}"


def attack_id(obj) -> str | None:
    """Identifiant ATT&CK (T1059.001, G0082…) d'un objet STIX : sa référence externe `mitre-attack`."""
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _status(obj) -> str:
    return "revoked" if obj.get("revoked") else "deprecated" if obj.get("x_mitre_deprecated") else "active"


def _serialize(obj) -> str:
    return obj.serialize() if hasattr(obj, "serialize") else json.dumps(obj, ensure_ascii=False)


# --- Construction ------------------------------------------------------------------------------------------------------
_SCHEMA = """
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE objects(
    attack_id TEXT PRIMARY KEY, stix_id TEXT, type TEXT, name TEXT, full_name TEXT, status TEXT, replaced_by TEXT,
    tactics TEXT, platforms TEXT, parent TEXT, aliases TEXT, description TEXT, summary TEXT, stix TEXT);
CREATE TABLE support(stix_id TEXT PRIMARY KEY, stix TEXT);
CREATE TABLE names(norm TEXT, attack_id TEXT);
CREATE INDEX names_norm ON names(norm);
CREATE TABLE uses(source_id TEXT, target_id TEXT);
CREATE INDEX uses_source ON uses(source_id);
CREATE VIRTUAL TABLE tech_fts USING fts5(attack_id UNINDEXED, name, description, tokenize='porter unicode61');
CREATE VIRTUAL TABLE proc_fts USING fts5(attack_id UNINDEXED, sources UNINDEXED, text, tokenize='porter unicode61');
"""


def load_store(objects: list) -> MemoryStore:
    """Bundle ATT&CK dans un `stix2.MemoryStore` (les types propres à MITRE, `x-mitre-*`, sont admis comme personnalisés)."""
    return MemoryStore(stix_data=objects, allow_custom=True)


def build_index(store: MemoryStore, out: Path = INDEX_FILE) -> dict:
    """Construit l'index SQLite depuis un `MemoryStore` ATT&CK. Retourne des comptes, pour le journal."""
    collection = store.query([Filter("type", "=", "x-mitre-collection")])
    version = collection[0].get("x_mitre_version") if collection else None
    if version != ATTACK_VERSION:
        raise ValueError(f"bundle ATT&CK {version!r}, {ATTACK_VERSION} attendu (version figée de l'évaluation)")
    # Un identifiant ATT&CK désigne un seul objet. Les anciennes mitigations (`course-of-action` dépréciées) reprennent
    # l'identifiant de leur technique (« System Information Discovery Mitigation » = T1082) : l'objet du type le plus haut
    # dans `_TYPES` l'emporte, puis l'objet actif.
    rank = {t: i for i, t in enumerate(_TYPES)}
    by_aid: dict[str, object] = {}
    found = [o for t in _TYPES for o in store.query([Filter("type", "=", t)]) if attack_id(o)]
    for o in sorted(found, key=lambda o: (rank[o["type"]], _status(o) != "active")):
        by_aid.setdefault(attack_id(o), o)
    objs = list(by_aid.values())
    by_stix = {o["id"]: o for o in objs}
    replaced = {r["source_ref"]: attack_id(by_stix[r["target_ref"]]) for r in store.query([Filter("type", "=", "relationship"), Filter("relationship_type", "=", "revoked-by")]) if r["target_ref"] in by_stix}
    names = {attack_id(o): o["name"] for o in objs}

    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".tmp")
    tmp.unlink(missing_ok=True)
    db = sqlite3.connect(tmp)
    db.executescript(_SCHEMA)
    db.executemany("INSERT INTO meta VALUES (?, ?)", [("attack_version", version), ("source", BUNDLE_URL)])
    # Auteur et marquage que référencent les objets ATT&CK : joints au bundle d'un article qui cite ces objets
    support = store.query([Filter("type", "=", "identity")]) + store.query([Filter("type", "=", "marking-definition")])
    db.executemany("INSERT OR REPLACE INTO support VALUES (?, ?)", [(o["id"], _serialize(o)) for o in support])
    counts: dict[str, int] = {}
    for o in objs:
        aid, kind = attack_id(o), o["type"]
        aliases = sorted(set(o.get("aliases", []) or []) | set(o.get("x_mitre_aliases", []) or []) - {o["name"]})
        desc = clean_description(o.get("description", ""))
        parent = aid.split(".")[0] if "." in aid else None
        full = f"{names[parent]}: {o['name']}" if parent and parent in names else o["name"]
        if kind == "x-mitre-tactic":
            tactics = [o["x_mitre_shortname"]]
        else:
            tactics = [p["phase_name"] for p in o.get("kill_chain_phases", []) or [] if p["kill_chain_name"] == "mitre-attack"]
        status = _status(o)
        db.execute(
            "INSERT OR REPLACE INTO objects VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (aid, o["id"], kind, o["name"], full, status, replaced.get(o["id"]), json.dumps(tactics),
             json.dumps(list(o.get("x_mitre_platforms", []) or [])), parent, json.dumps(aliases), desc, summary(desc), _serialize(o)),
        )  # fmt: skip
        counts[kind] = counts.get(kind, 0) + 1
        for label in {o["name"], *aliases}:
            if normalize_name(label):
                db.execute("INSERT INTO names VALUES (?, ?)", (normalize_name(label), aid))
        if kind == "attack-pattern" and status == "active":
            db.execute("INSERT INTO tech_fts VALUES (?, ?, ?)", (aid, full, desc))

    n_proc = 0
    for r in store.query([Filter("type", "=", "relationship"), Filter("relationship_type", "=", "uses")]):
        src, dst = by_stix.get(r["source_ref"]), by_stix.get(r["target_ref"])
        if src is None or dst is None or _status(r) != "active" or _status(src) != "active" or _status(dst) != "active":
            continue
        db.execute("INSERT INTO uses VALUES (?, ?)", (attack_id(src), attack_id(dst)))
        if dst["type"] == "attack-pattern" and r.get("description"):
            text = clean_description(r["description"])
            # le nom de l'auteur de la procédure n'aide pas à reconnaître la technique : il est retiré
            for label in {src["name"], *(src.get("aliases", []) or []), *(src.get("x_mitre_aliases", []) or [])}:
                text = re.sub(rf"\b{re.escape(label)}\b", "", text)
            sources = " ".join(filter(None, {report_key(ref.get("url")) for ref in r.get("external_references", []) or []}))
            db.execute("INSERT INTO proc_fts VALUES (?, ?, ?)", (attack_id(dst), sources, text))
            n_proc += 1
    counts["procedures"] = n_proc
    db.commit()
    db.execute("INSERT INTO proc_fts(proc_fts) VALUES ('optimize')")
    db.execute("INSERT INTO tech_fts(tech_fts) VALUES ('optimize')")
    db.commit()
    db.close()
    tmp.replace(out)
    return counts


# --- Requêtes ----------------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class TechniqueHit:
    attack_id: str
    name: str  # « Parent: Sous-technique » pour une sous-technique
    tactics: tuple[str, ...]
    summary: str

    def line(self) -> str:
        return f"{self.attack_id} {self.name} [{', '.join(self.tactics)}] — {self.summary}"


class AttackKB:
    """Accès en lecture à l'index. Une connexion par fil d'exécution (sqlite3 ne partage pas une connexion entre fils)."""

    def __init__(self, path: Path = INDEX_FILE):
        if not path.exists():
            raise FileNotFoundError(f"{path} introuvable. Construire avec : uv run python -m backend.extracting.stix.attack")
        self.path = path
        self._local = threading.local()
        self.version = self._db().execute("SELECT value FROM meta WHERE key = 'attack_version'").fetchone()[0]

    def _db(self) -> sqlite3.Connection:
        if not hasattr(self._local, "db"):
            self._local.db = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, check_same_thread=False)
            self._local.db.row_factory = sqlite3.Row
        return self._local.db

    # --- Objets ---------------------------------------------------------------------------------------------------------
    def get(self, attack_id: str) -> dict | None:
        """Fiche d'un objet par identifiant ATT&CK (technique, groupe, logiciel, campagne, tactique, mitigation)."""
        row = self._db().execute("SELECT * FROM objects WHERE attack_id = ?", ((attack_id or "").strip().upper(),)).fetchone()
        if row is None:
            return None
        out = dict(row)
        for key in ("tactics", "platforms", "aliases"):
            out[key] = json.loads(out[key] or "[]")
        return out

    def stix_object(self, attack_id: str):
        """L'objet ATT&CK de MITRE (même identifiant) réduit à ce qu'un rapport en retient : nom, alias, tactiques et la référence
        `mitre-attack` (identifiant, page). La description, les dizaines de sources qu'elle cite, l'auteur, le marquage et les
        propriétés `x_mitre_*` (sauf les alias) restent dans ATT&CK."""
        row = self._db().execute("SELECT stix FROM objects WHERE attack_id = ?", ((attack_id or "").strip().upper(),)).fetchone()
        if row is None:
            return None
        data = {k: v for k, v in json.loads(row[0]).items() if k not in _DROPPED and (not k.startswith("x_mitre_") or k == "x_mitre_aliases")}
        data["external_references"] = [r for r in data.get("external_references", []) if r.get("source_name") == "mitre-attack"]
        return parse(data, allow_custom=True)

    def support_objects(self, refs: set[str]) -> list:
        """Objets que référencent les objets ATT&CK cités (identité de MITRE, marquage), par `stix2.parse`."""
        if not refs:
            return []
        marks = ",".join("?" * len(refs))
        return [parse(r[0], allow_custom=True) for r in self._db().execute(f"SELECT stix FROM support WHERE stix_id IN ({marks})", sorted(refs))]

    def status(self, attack_id: str) -> tuple[str, str | None]:
        """("active" | "revoked" | "deprecated" | "unknown", remplaçant). « unknown » : absent de la v20.0 (hallucination)."""
        obj = self.get(attack_id)
        return (obj["status"], obj["replaced_by"]) if obj else ("unknown", None)

    def subtechniques(self, attack_id: str) -> list[tuple[str, str]]:
        rows = self._db().execute(
            "SELECT attack_id, name FROM objects WHERE parent = ? AND status = 'active' ORDER BY attack_id", (attack_id.upper(),)
        )
        return [(r[0], r[1]) for r in rows]

    def lookup(self, name: str, types: tuple[str, ...] = ("intrusion-set", "malware", "tool", "campaign")) -> list[dict]:
        """Objets dont le nom ou un alias se normalise comme `name` (« Stardust Chollima » -> G0082 APT38). Actifs d'abord."""
        rows = self._db().execute(
            "SELECT DISTINCT o.attack_id FROM names n JOIN objects o ON o.attack_id = n.attack_id WHERE n.norm = ?",
            (normalize_name(name),),
        )
        hits = [self.get(r[0]) for r in rows]
        hits = [h for h in hits if h and h["type"] in types]
        return sorted(hits, key=lambda h: (h["status"] != "active", h["attack_id"]))

    def search_techniques(self, query: str, tactic: str | None = None, limit: int = 8, exclude_source: str | None = None) -> list[TechniqueHit]:
        """Techniques actives qui correspondent le mieux à une description de comportement. `tactic` restreint aux
        techniques de cette tactique (nom court ATT&CK : « discovery », « command-and-control »…) ; `exclude_source` (clé
        `report_key` de l'article analysé) écarte les procédures tirées de ce rapport."""
        query = (query or "").strip()
        if _ID.match(query):
            obj = self.get(query)
            return [self._hit(obj)] if obj and obj["type"] == "attack-pattern" else []
        match = fts_query(query)
        if not match:
            return []
        db = self._db()
        pool = max(limit * 6, 40)
        tech = [r[0] for r in db.execute(
            "SELECT attack_id FROM tech_fts WHERE tech_fts MATCH ? ORDER BY bm25(tech_fts, 0, 8.0, 1.0) LIMIT ?", (match, pool)
        )]  # fmt: skip
        proc: list[str] = []
        for tid, sources in db.execute("SELECT attack_id, sources FROM proc_fts WHERE proc_fts MATCH ? ORDER BY rank LIMIT ?", (match, pool * 8)):
            if exclude_source and exclude_source in sources.split():
                continue
            if tid not in proc:
                proc.append(tid)
            if len(proc) >= pool:
                break
        scores: dict[str, float] = {}
        for ranking in (tech, proc):
            for rank, tid in enumerate(ranking):
                scores[tid] = scores.get(tid, 0.0) + 1.0 / (_RRF_K + rank)
        hits = []
        for tid in sorted(scores, key=lambda t: -scores[t]):
            obj = self.get(tid)
            if obj is None or obj["status"] != "active" or (tactic and tactic not in obj["tactics"]):
                continue
            hits.append(self._hit(obj))
            if len(hits) >= limit:
                break
        return hits

    @staticmethod
    def _hit(obj: dict) -> TechniqueHit:
        return TechniqueHit(obj["attack_id"], obj["full_name"], tuple(obj["tactics"]), obj["summary"])

    def tactics(self) -> list[tuple[str, str]]:
        """(nom court, nom) des tactiques actives, dans l'ordre ATT&CK."""
        rows = self._db().execute("SELECT tactics, name FROM objects WHERE type = 'x-mitre-tactic' AND status = 'active' ORDER BY attack_id")
        return [(json.loads(r[0])[0], r[1]) for r in rows]


def find_bundle() -> Path | None:
    return next((p for p in BUNDLE_CANDIDATES if p.exists()), None)


def build_from_file(path: Path, out: Path = INDEX_FILE) -> dict:
    return build_index(load_store(json.loads(path.read_text(encoding="utf-8"))["objects"]), out)


@lru_cache(maxsize=1)
def get_attack_kb() -> AttackKB:
    """Index ATT&CK v20.0, construit au premier appel si le bundle officiel est présent localement."""
    if not INDEX_FILE.exists():
        bundle = find_bundle()
        if bundle is None:
            raise FileNotFoundError(
                f"{INDEX_FILE} introuvable et aucun bundle ATT&CK 20.0 local ({', '.join(map(str, BUNDLE_CANDIDATES))}). "
                f"Télécharger {BUNDLE_URL} puis : uv run python -m backend.extracting.stix.attack <bundle>"
            )
        build_from_file(bundle)
    return AttackKB(INDEX_FILE)


def main(argv: list[str]) -> None:
    path = Path(argv[0]) if argv else find_bundle()
    if path is None or not path.exists():
        raise SystemExit(f"bundle introuvable : télécharger {BUNDLE_URL}")
    counts = build_from_file(path)
    print(f"ATT&CK {ATTACK_VERSION} : {counts} -> {INDEX_FILE} ({INDEX_FILE.stat().st_size / 1e6:.1f} Mo)")


if __name__ == "__main__":
    main(sys.argv[1:])
