"""Extraction à questions fermées : le code propose, de petits appels indépendants choisissent (pour des modèles de taille réduite).

    uv run cti-eval --system closed --run --workers 4
    uv run cti-agent --closed --article-id 1553 --dry-run --show-log

Un petit modèle échoue aux tâches ouvertes sur un long texte (inventorier tous les noms, relier des entités) et réussit les choix
fermés sur un contexte court. Chaque appel est donc une question à réponse numérotée ou énumérée, posée sur quelques phrases :

    [Rapport] -> phrases numérotées
      1. CANDIDATS (code, sans modèle) : noms (index ATT&CK, CVE, lieux, motifs de nom propre) et, pour chaque phrase,
         ses techniques ATT&CK candidates (index FTS5)
      2. LOT 1 (appels parallèles) : type de chaque nom que le code ne connaît pas ; « quelle technique, ou aucune ? » par phrase ;
         y a-t-il une campagne ?
      3. LOT 2 (appels parallèles) : qui réalise l'action (une entité de la fenêtre, ou l'opération) ; quel lien affirment les phrases
         qui nomment deux entités (paires permises par la table des relations STIX)
      4. vérification STIX de `DraftGraph` (stix2 strict, ATT&CK v20.0, phrases citées), puis IOC et règles comme `fast_extract`

Tout appel produit quelques tokens (un numéro, un mot d'une liste) : le temps est celui de la lecture des prompts, que le serveur
traite par lots (SGLang, vLLM) et met en cache pour le préfixe commun ; le débit croît avec le nombre d'articles en parallèle.
"""

import os
import re
import time
from collections import Counter
from dataclasses import dataclass, field

from backend.extracting import llm
from backend.extracting.agent_tools import CONTEXT_SENTENCES, DraftGraph
from backend.extracting.evidence import mentions_prepared, normalize_name, parse_date, prepare_text
from backend.extracting.iocs import extract_iocs
from backend.extracting.places import resolve_location
from backend.extracting.rules import extract_rules
from backend.extracting.segment import Unit, segment
from backend.extracting.stix_agent import AgentResult, TurnStat, clean_title
from backend.stix import galaxy
from backend.stix.attack import AttackKB
from backend.stix.objects import ArticleContext

MAX_TYPING = int(os.environ.get("CTI_MAX_TYPING") or 150)  # noms inconnus du code soumis au modèle, par article
MAX_BEHAVIOR_CALLS = int(os.environ.get("CTI_MAX_BEHAVIORS") or 300)  # phrases soumises au choix d'une technique
CANDIDATES = 6  # techniques candidates par phrase
MAX_PAIRS = int(os.environ.get("CTI_MAX_PAIRS") or 300)  # paires d'entités soumises au modèle, par article
MAX_EVIDENCE = 3  # phrases montrées (et citées) pour un lien entre deux entités
LEAD_SENTENCES = 8  # phrases de début de rapport montrées pour reconnaître une campagne
TYPE_TOKENS, CHOICE_TOKENS, CAMPAIGN_TOKENS = 16, 12, 48

# --- Noms candidats (code seul) -------------------------------------------------------------------------------------------
_WORD = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._\-]*[A-Za-z0-9])?")
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_CODE_NAME = re.compile(r"\b[A-Z]{2,5}[- ]?\d{2,5}\b")  # APT29, UNC2452, TA505, UAC-0057
_MIXED_CASE = re.compile(r"\b(?=[A-Za-z0-9]*[a-z])(?=(?:[a-z0-9]*[A-Z]){2})[A-Za-z0-9]{4,}\b")  # PowerShell, FortiOS : deux majuscules ou plus
_BINARY = re.compile(r"\b[\w-]+\.(?:exe|dll|ps1|bat|vbs|hta|scr|jar|msi)\b", re.I)
_TRIGGER = re.compile(
    r"(?:called|named|dubbed|known as|tracked as|referred to as|nomm[ée]e?|appel[ée]e?|baptis[ée]e?|surnomm[ée]e?)\s+[\"'“‘«]?"
    r"([A-Z][\w.\-]+(?:\s[A-Z][\w.\-]+){0,2})"
)  # fmt: skip
_TITLE_CASE = re.compile(r"[A-Z][A-Za-z0-9]{2,}")
_TYPES = {  # réponse du modèle -> type STIX
    "malware": "malware", "tool": "tool", "group": "intrusion-set", "infrastructure": "infrastructure",
    "vulnerability": "vulnerability", "software": "software", "victim": "identity", "location": "location",
}  # fmt: skip

TYPING_SYSTEM = """Tu classes un nom propre rencontré dans un rapport de menace (cyber threat intelligence). Réponds par UNE valeur :
- malware : code malveillant nommé (famille, implant, ransomware, backdoor, loader).
- tool : logiciel légitime, outil d'administration ou outil offensif public que l'attaquant détourne ou emploie (binaire du système, framework de test d'intrusion).
- group : groupe d'attaquants nommé, ou code de suivi donné par le rapport ou un éditeur.
- infrastructure : service ou infrastructure nommé que l'attaquant utilise (hébergement, service de partage, canal de commande).
- vulnerability : une vulnérabilité nommée ou une CVE.
- software : produit légitime visé par l'attaque, vulnérable ou compromis.
- victim : organisation, entreprise ou secteur victime.
- location : pays ou région.
- none : l'auteur du rapport, un chercheur ou un éditeur de sécurité, une personne, un mot courant, un nom de fichier ordinaire, un concept, tout le reste.
malware, tool, group, infrastructure et software désignent UNE entité précise, par son nom. Une désignation générique (« l'implant », « le groupe », « les outils de l'attaquant », « le serveur C2 », « un pilote signé ») est none. victim admet un secteur ou une population précisément désignés (« les entreprises fintech »), pas « les organisations » ou « les victimes » seuls.
Un indice tiré d'une base publique peut accompagner le nom : il dit ce que ce nom désigne ailleurs, pas ce qu'il désigne ici. Seules les phrases du rapport décident (un même nom peut y être une victime, un produit légitime ou un mot courant)."""
TECHNIQUE_SYSTEM = """Tu rattaches une phrase d'un rapport de menace à une technique MITRE ATT&CK. On te donne UNE phrase et des techniques candidates numérotées.
Réponds par le numéro de la technique que la phrase décrit comme action de l'attaquant ou de son logiciel malveillant (la plus précise : la sous-technique quand le mécanisme est nommé), ou 0 si la phrase ne décrit aucune de ces actions (contexte, analyse, défense, victime, chronologie, indicateur)."""
ACTOR_SYSTEM = """Tu dis qui réalise une action décrite dans une phrase d'un rapport de menace. Réponds par le numéro de l'entité dont la phrase décrit la capacité ou l'action, ou 0 si la phrase décrit une étape de l'opération dans son ensemble sans la prêter à une de ces entités.
Une action exécutée par un programme (collecte d'informations, chiffrement, communication, persistance, exécution de commandes, téléchargement) est celle de ce programme, même quand la phrase le désigne par « il », « l'implant », « la charge » ou que seuls le titre de la section ou les phrases précédentes le nomment."""
PAIR_SYSTEM = """Tu lis quelques phrases d'un rapport de menace et dis quel lien entre deux entités elles AFFIRMENT explicitement. Réponds par le numéro de l'option, ou 0 si les phrases n'affirment aucun de ces liens (simple voisinage, hypothèse, négation). N'invente rien."""
CAMPAIGN_LINK_SYSTEM = """Tu lis quelques phrases d'un rapport de menace qui décrit une opération malveillante, puis une affirmation sur cette opération. Réponds 1 si les phrases affirment explicitement ce que dit l'affirmation (ou le disent sans ambiguïté en d'autres mots), 0 sinon (simple voisinage, hypothèse, négation, fait sans lien avec l'opération). N'invente rien."""
CAMPAIGN_CLAIMS = {
    "uses": "« {name} » est employé par l'opération décrite par le rapport (« {op} »).",
    "targets": "« {name} » est une cible de l'opération décrite par le rapport (« {op} »).",
    "attributed-to": "Le rapport attribue l'opération (« {op} ») à « {name} ».",
}
CAMPAIGN_SYSTEM = """Tu lis le début d'un rapport de menace. S'il décrit une opération malveillante précise (une campagne : des cibles, une période, un objectif), donne-lui un nom descriptif court de la forme « <acteur ou famille> contre <cible>, <période> » ; sinon réponds « aucune »."""

# Table des relations STIX 2.1 retenue (source, cible) -> relations : celle du prompt de l'agent
_ADV = ("intrusion-set", "threat-actor", "campaign", "malware", "tool")
_RELATION_RULES = [
    (("campaign",), ("intrusion-set", "threat-actor"), ("attributed-to",)),
    (("intrusion-set",), ("threat-actor",), ("attributed-to",)),
    (_ADV, ("malware", "tool", "infrastructure"), ("uses",)),
    (("intrusion-set", "threat-actor", "campaign"), ("identity", "location", "vulnerability"), ("targets",)),
    (("malware", "tool"), ("identity", "location"), ("targets",)),
    (("malware",), ("vulnerability",), ("exploits",)),
    (("software",), ("vulnerability",), ("has",)),
    (("software",), ("identity",), ("related-to",)),
    (("malware", "tool"), ("malware", "tool"), ("drops",)),
    (("malware",), ("malware", "tool"), ("downloads",)),
    (("malware",), ("malware",), ("variant-of",)),
    (("malware",), ("infrastructure",), ("communicates-with", "beacons-to", "exfiltrates-to")),
]  # fmt: skip
ALLOWED: dict[tuple[str, str], tuple[str, ...]] = {}
for _sources, _targets, _relations in _RELATION_RULES:
    for _s in _sources:
        for _t in _targets:
            ALLOWED[(_s, _t)] = tuple(dict.fromkeys(ALLOWED.get((_s, _t), ()) + _relations))
_ACTORS = ("intrusion-set", "threat-actor", "malware", "tool")  # entités à qui une technique peut être prêtée


def _schema_choice(values: list[str]) -> dict:
    return {"type": "object", "properties": {"answer": {"type": "string", "enum": values}}, "required": ["answer"]}


def _numbers(n: int) -> dict:
    return _schema_choice([str(i) for i in range(n + 1)])


@dataclass
class Candidate:
    key: str  # clé de fusion : identifiant ATT&CK, sinon nom normalisé
    name: str = ""
    uids: list[int] = field(default_factory=list)
    surfaces: Counter = field(default_factory=Counter)
    strong: int = 0  # indices de nom propre (motif, casse mixte, déclencheur) : sert à classer
    stix_type: str | None = None  # connu du code (ATT&CK, CVE, lieu) ; sinon le modèle le choisit
    extra: str = ""
    attack_ids: tuple[str, ...] = ()
    known: str = ""  # ce qu'une base publique (MISP Galaxy) dit du nom : un indice montré au modèle, pas un type imposé

    def score(self) -> int:
        return 3 * self.strong + min(len(set(self.uids)), 5) + (3 if self.attack_ids else 0)


def _name_like(surface: str, common: set[str]) -> bool:
    """Un nom d'ATT&CK rencontré dans le texte n'est retenu que s'il s'écrit comme un nom propre : « net » ou « at » en minuscules sont
    des mots, « Net » en début de phrase aussi, « PowerShell » ou « APT29 » non."""
    if any(c.isdigit() for c in surface) or sum(c.isupper() for c in surface) >= 2:
        return True
    return surface[:1].isupper() and surface.casefold() not in common


def find_candidates(units: list[Unit], kb: AttackKB, publisher: str = "") -> list[Candidate]:
    """Noms que le code repère sans modèle : noms et alias d'ATT&CK (type connu), CVE, lieux, puis motifs de nom propre dont le type
    reste à choisir (codes de suivi, casse mixte, binaires, noms introduits par « called », séquences capitalisées en cours de phrase)."""
    eligible = [u for u in units if u.kind in ("sentence", "item") and u.is_evidence_eligible]
    common = {w for u in eligible for w in re.findall(r"\b[a-z][a-z'\-]{2,}\b", u.text)}  # mots vus en minuscules : pas des noms
    names = kb.names_index()
    listed = galaxy.names_index()
    found: dict[str, Candidate] = {}

    def add(surface: str, uid: int, *, strong: int = 0, stix_type: str | None = None, extra: str = "", attack_ids: tuple[str, ...] = ()):
        surface = surface.strip(" .,;:-")  # « dubbed Zorblax. » : le point de fin de phrase n'est pas dans le nom
        norm = normalize_name(surface)
        if not norm or len(norm) < 3 or (publisher and norm == publisher):
            return
        key, known = (attack_ids[0] if attack_ids else norm), ""
        if not attack_ids and stix_type is None and (cluster := galaxy.lookup(surface)):  # MISP Galaxy : alias réunis sous une clé
            key = cluster.key
            if not key.startswith("galaxy:"):  # même entité qu'un nom d'ATT&CK : traitée comme lui
                attack_ids = (key,)
            else:
                known = galaxy.describe(cluster)
        c = found.setdefault(key, Candidate(key, stix_type=stix_type, extra=extra, attack_ids=attack_ids))
        c.known = c.known or known
        c.uids.append(uid)
        c.surfaces[surface] += 1
        c.strong = max(c.strong, strong)
        c.stix_type = c.stix_type or stix_type

    for u in eligible:
        text = u.text
        for m in _CVE.finditer(text):
            add(m.group(0).upper(), u.uid, strong=3, stix_type="vulnerability")
        words = _WORD.findall(text)
        i = 0
        while i < len(words):  # noms d'ATT&CK, le plus long d'abord
            for n in (3, 2, 1):
                surface = " ".join(words[i : i + n])
                norm = normalize_name(surface)
                if len(words[i : i + n]) == n and len(norm) >= 4 and (norm in names or norm in listed) and _name_like(surface, common):
                    add(surface, u.uid, strong=3, attack_ids=names.get(norm, ()))
                    i += n - 1
                    break
            i += 1
        for pattern, strong in ((_CODE_NAME, 3), (_MIXED_CASE, 2), (_BINARY, 1)):
            for m in pattern.finditer(text):
                add(m.group(0).lower() if pattern is _BINARY else m.group(0), u.uid, strong=strong)
        for m in _TRIGGER.finditer(text):
            add(m.group(1), u.uid, strong=3)
        # séquences capitalisées (3 mots au plus) : lieux reconnus par le code, sinon noms propres hors début de phrase
        tokens = [(m.group(0), m.start()) for m in re.finditer(r"[A-Za-z0-9][A-Za-z0-9'’\-]*", text)]
        j = 0
        while j < len(tokens):
            run = []
            while j < len(tokens) and _TITLE_CASE.fullmatch(tokens[j][0]) and len(run) < 3:
                run.append(tokens[j])
                j += 1
            if not run:
                j += 1
                continue
            located = False
            for lo in range(len(run)):
                for hi in range(len(run), lo, -1):
                    phrase = " ".join(t for t, _ in run[lo:hi])
                    country, region = resolve_location(phrase, "")
                    if country or region:
                        add(phrase, u.uid, strong=1, stix_type="location", extra=country or "")
                        located = True
                        break
                if located:
                    break
            if not located:
                first, start = run[0]
                if start > 0 and first.casefold() not in common:
                    add(" ".join(t for t, _ in run), u.uid, strong=1)
    out = list(found.values())
    for c in out:
        c.name = c.surfaces.most_common(1)[0][0]
        if c.attack_ids:
            hit = kb.get(c.attack_ids[0])
            c.stix_type = hit["type"] if hit and hit["type"] in ("intrusion-set", "malware", "tool") else None
    # « Cobalt » vu dans les phrases où « Cobalt Strike » figure déjà : le nom court est écarté
    drop = {
        c.key for c in out if c.stix_type is None and not c.attack_ids
        and any(o is not c and c.key in o.key and c.key != o.key and set(c.uids) <= set(o.uids) for o in out)
    }  # fmt: skip
    return [c for c in out if c.key not in drop]


# --- Questions ---------------------------------------------------------------------------------------------------------------
def _answer(r) -> str | None:
    parsed = getattr(r, "parsed", None)
    return str(parsed.get("answer", "")).strip() if isinstance(parsed, dict) else None


def _index(r, size: int) -> int | None:
    """Numéro choisi (0 = aucune) parmi `size` options, ou None si la réponse manque ou sort de la liste."""
    raw = _answer(r)
    return int(raw) if raw and raw.isdigit() and 0 <= int(raw) <= size else None


def _window(draft: DraftGraph, uid: int) -> list[Unit]:
    """La phrase et les précédentes de sa section (référent d'un pronom, sujet d'une section d'analyse), la plus proche d'abord."""
    unit = draft.by_uid[uid]
    out = [unit]
    for prev in range(uid - 1, uid - 1 - CONTEXT_SENTENCES, -1):
        before = draft.by_uid.get(prev)
        if before is None or before.heading_path != unit.heading_path:
            break
        out.append(before)
    return out


def section_actors(draft: DraftGraph, uid: int, mentioned: dict[int, list[str]], actors: list[str], heading: list[str], k: int = 4) -> list[str]:
    """Entités à qui l'action d'une phrase peut être prêtée, la plus probable d'abord : celles de la phrase et des précédentes
    (`_window`), celles que nomme le titre de la section (« First stage C# DLL implants »), puis la dernière nommée plus haut dans la
    section, référent probable de « il » ou de « l'implant »."""
    near = [s for w in _window(draft, uid) for s in mentioned.get(w.uid, []) if s in actors] + heading
    path = draft.by_uid[uid].heading_path
    for prev in range(uid - len(_window(draft, uid)), -1, -1):
        before = draft.by_uid.get(prev)
        if before is None or before.heading_path != path:
            break
        if hits := [s for s in mentioned.get(prev, []) if s in actors]:
            near += hits
            break
    return list(dict.fromkeys(near))[:k]


def best_evidence(uids, mentioned: dict[int, list[str]], k: int = MAX_EVIDENCE) -> list[int]:
    """Au plus `k` phrases de preuve : la première mention (où l'entité est présentée) et celles qui nomment le plus d'autres entités,
    où son rôle se dit. Sans cela, les premières venues (souvent un titre ou une liste) occupent la place."""
    uids = sorted(set(uids))
    if len(uids) <= k:
        return uids
    rest = sorted(uids[1:], key=lambda u: (-len(mentioned.get(u, [])), u))[: k - 1]
    return sorted([uids[0], *rest])


def _quote(unit: Unit, limit: int = 380) -> str:
    text = " ".join(unit.text.split())
    return f"[{unit.uid}] " + (text if len(text) <= limit else text[:limit].rsplit(" ", 1)[0] + " […]")


@dataclass
class Call:
    stage: str
    system: str
    prompt: str
    schema: dict
    tokens: int
    meta: dict = field(default_factory=dict)


def _run(calls: list[Call], result: AgentResult) -> list:
    """Envoie les appels en parallèle ; compte jetons, durées et échecs (une réponse perdue laisse la question sans réponse)."""
    replies = llm.generate_many([(c.system, c.prompt, c.schema, c.tokens) for c in calls])
    failures: Counter = Counter()
    for call, r in zip(calls, replies):
        if isinstance(r, Exception):
            failures[f"{call.stage} : {type(r).__name__}"] += 1
            continue
        result.turns.append(TurnStat(0, len(result.turns), r.prompt_tokens, r.output_tokens, r.seconds, [call.stage], r.output_tokens >= call.tokens))
    result.failed_passages += [f"{n} appel(s) {what}" for what, n in failures.items()]
    return replies


def extract_article(art: dict, *, with_iocs: bool = True, with_rules: bool = True, **_) -> AgentResult:
    """Même contrat que `stix_agent.extract_article` (un `AgentResult`)."""
    t0 = time.perf_counter()
    title = clean_title(art["title"] or f"Article {art['id']}", art.get("site_name"))
    units = segment(art["clean_markdown"])
    draft = DraftGraph(units, ArticleContext(art["id"], art.get("site_name"), art.get("url"), art.get("title")))
    result = AgentResult(art["id"], draft, len(units), 1)
    kb = draft.attack
    eligible = [u for u in units if u.kind in ("sentence", "item") and u.is_evidence_eligible]
    lead = f"Titre : {title}\n"

    # 1. candidats (code)
    candidates = sorted(find_candidates(units, kb, draft.publisher_key), key=lambda c: -c.score())
    typed = [c for c in candidates if c.stix_type]
    untyped = [c for c in candidates if not c.stix_type][:MAX_TYPING]
    behaviors = []
    for u in eligible:
        if len(u.text) < 50 or len(behaviors) >= MAX_BEHAVIOR_CALLS:
            continue
        hits = kb.search_techniques(u.text, limit=CANDIDATES)
        if hits:
            behaviors.append((u, hits))

    # 2. lot 1 : type des noms inconnus, technique de chaque phrase, campagne
    calls: list[Call] = []
    for c in untyped:
        shown = "\n".join(_quote(draft.by_uid[uid], 300) for uid in dict.fromkeys(c.uids[:3]))
        calls.append(Call("type", TYPING_SYSTEM, f"{lead}Phrases où « {c.name} » apparaît :\n{shown}\n" + (f"\nIndice (base publique, à confirmer par les phrases) : {c.known}\n" if c.known else "") + f"\nQue désigne « {c.name} » dans ce rapport ?",
                          _schema_choice([*_TYPES, "none"]), TYPE_TOKENS, {"c": c}))  # fmt: skip
    for u, hits in behaviors:
        options = "\n".join(f"{i}. {h.attack_id} {h.name} ({', '.join(h.tactics[:2])}) — {h.summary[:110]}" for i, h in enumerate(hits, 1))
        calls.append(Call("technique", TECHNIQUE_SYSTEM, f"{lead}Section : {u.heading_path or '—'}\n{_quote(u)}\n\nTechniques candidates :\n{options}\n0. aucune\n\nQuel numéro ?",
                          _numbers(len(hits)), CHOICE_TOKENS, {"u": u, "hits": hits}))  # fmt: skip
    opening = "\n".join(_quote(u, 300) for u in eligible[:LEAD_SENTENCES])
    if opening:
        calls.append(Call("campaign", CAMPAIGN_SYSTEM, f"{lead}Début du rapport :\n{opening}", {"type": "object", "properties": {"campaign": {"type": "string"}}, "required": ["campaign"]}, CAMPAIGN_TOKENS))  # fmt: skip
    replies = _run(calls, result)

    campaign_sid = None
    chosen: list[tuple[Unit, str]] = []
    for call, r in zip(calls, replies):
        if isinstance(r, Exception):
            continue
        if call.stage == "type" and (answer := _answer(r)) in _TYPES:
            call.meta["c"].stix_type = _TYPES[answer]
            typed.append(call.meta["c"])
        elif call.stage == "technique" and (k := _index(r, len(call.meta["hits"]))):
            chosen.append((call.meta["u"], call.meta["hits"][k - 1].attack_id))
        elif call.stage == "campaign" and isinstance(r.parsed, dict):
            name = re.sub(r"\s+", " ", str(r.parsed.get("campaign", ""))).replace("|", "/").strip(" .\"'«»")
            if name and not re.match(r"(?i)^(aucune?|none|non|n/?a)\b", name) and len(name) <= 140:
                campaign_sid, err = draft.declare(f"campaign|{name}")
                if err:
                    draft.log.append(f"reject {err}")
                    campaign_sid = None

    sid_units: dict[str, set[int]] = {}
    for c in typed:
        others = ";".join(x for x in c.surfaces if x != c.name)
        extra = c.extra if c.stix_type in ("location", "software") else others  # lieu : code pays ; sinon : autres graphies = alias
        sid, err = draft.declare(f"{c.stix_type}|{c.name}" + (f"|{extra}" if extra else ""))
        if err:
            draft.log.append(f"reject {err}")
            result.refused += 1
            continue
        sid_units.setdefault(sid, set()).update(c.uids)
        result.accepted += 1
    entities = [s for s in sid_units if draft.type_of(s) not in ("attack-pattern", "campaign")]
    prepared = {u.uid: prepare_text(u.text) for u in eligible}
    mentioned = {u.uid: [s for s in entities if mentions_prepared(prepared[u.uid], draft.terms[s])] for u in eligible}
    clean = lambda name: name.replace("|", "/")  # noqa: E731

    # 3. lot 2 : qui agit, et le lien de chaque paire d'entités
    calls, relations = [], []  # relations : (ligne « source|relation|cible|phrases », origine)
    actors = [s for s in entities if draft.type_of(s) in _ACTORS]
    in_heading = {
        path: [s for part in reversed(path.split(" > ")) for s in actors if mentions_prepared(prepare_text(part), draft.terms[s])]
        for path in {u.heading_path for u, _ in chosen if u.heading_path}
    }  # fmt: skip
    for u, tid in chosen:
        near = section_actors(draft, u.uid, mentioned, actors, in_heading.get(u.heading_path, []))
        if near:
            context = "\n".join(_quote(w, 260) for w in reversed(_window(draft, u.uid)[1:]))
            opts = "\n".join(f"{i}. « {draft.name_of(s)} » ({draft.type_of(s)})" for i, s in enumerate(near, 1))
            zero = "l'opération dans son ensemble" if campaign_sid else "aucune de ces entités"
            calls.append(Call("actor", ACTOR_SYSTEM, f"{lead}Section : {u.heading_path or '—'}\n" + (f"Phrases précédentes :\n{context}\n" if context else "")
                              + f"Phrase :\n{_quote(u)}\n\nAction : {draft.attack.get(tid)['full_name']}\n\nQui la réalise ?\n{opts}\n0. {zero}\n",
                              _numbers(len(near)), CHOICE_TOKENS, {"u": u, "tid": tid, "near": near}))  # fmt: skip
            continue
        if campaign_sid:
            relations.append((f"{clean(draft.name_of(campaign_sid))}|uses|{tid}|{u.uid}", "technique"))

    seen_pairs: set[frozenset] = set()
    kind = lambda s: "campaign" if s == campaign_sid else draft.type_of(s)  # noqa: E731

    def add_pair(bucket: list, a: str, b: str, uids: list[int]) -> None:
        """Une paire n'entre au budget que si la table des relations permet de la relier, dans un sens ou dans l'autre."""
        key = frozenset((a, b))
        if key in seen_pairs or not uids or not (ALLOWED.get((kind(a), kind(b))) or ALLOWED.get((kind(b), kind(a)))):
            return
        seen_pairs.add(key)
        bucket.append((a, b, uids))

    # Budget : d'abord les entités nommées ensemble dans le texte, puis la campagne (qu'aucune phrase ne nomme) avec chaque entité ;
    # dans l'ordre inverse, les paires de la campagne remplissaient le budget dès qu'un article cite beaucoup de noms.
    local, with_campaign = [], []
    for u in eligible:
        own = mentioned.get(u.uid, [])
        if not own:
            continue
        around = list(dict.fromkeys(own + [s for w in _window(draft, u.uid)[1:] for s in mentioned.get(w.uid, [])]))
        for a in own:
            for b in around:
                if a != b:
                    add_pair(local, a, b, best_evidence([w.uid for w in _window(draft, u.uid) if a in mentioned.get(w.uid, []) or b in mentioned.get(w.uid, [])], mentioned))
    if campaign_sid:
        for s in entities:
            add_pair(with_campaign, campaign_sid, s, best_evidence(sid_units[s] & {u.uid for u in eligible}, mentioned))
    pairs = (local + with_campaign)[:MAX_PAIRS]
    for a, b, uids in pairs:
        if campaign_sid in (a, b):  # la campagne n'est nommée dans aucune phrase : affirmation à confirmer, pas un lien à deviner
            other = b if a == campaign_sid else a
            rels = ALLOWED.get(("campaign", draft.type_of(other)), ())
            if rels and uids:
                shown = "\n".join(_quote(draft.by_uid[uid], 320) for uid in sorted(dict.fromkeys(uids)))
                claim = CAMPAIGN_CLAIMS[rels[0]].format(name=draft.name_of(other), op=draft.name_of(campaign_sid))
                calls.append(Call("campaign-link", CAMPAIGN_LINK_SYSTEM, f"{lead}Phrases :\n{shown}\n\nAffirmation : {claim}\n\nLes phrases l'affirment-elles ?\n1. oui\n0. non\n",
                                  _numbers(1), CHOICE_TOKENS, {"options": [(campaign_sid, rels[0], other)], "uids": sorted(set(uids))}))  # fmt: skip
            continue
        options = [(a, r, b) for r in ALLOWED.get((draft.type_of(a), draft.type_of(b)), ())] + [(b, r, a) for r in ALLOWED.get((draft.type_of(b), draft.type_of(a)), ())]
        if not options or not uids:
            continue
        shown = "\n".join(_quote(draft.by_uid[uid], 320) for uid in sorted(dict.fromkeys(uids)))
        menu = "\n".join(f"{i}. « {draft.name_of(s)} » {r} « {draft.name_of(t)} »" for i, (s, r, t) in enumerate(options, 1))
        calls.append(Call("relation", PAIR_SYSTEM, f"{lead}Phrases :\n{shown}\n\nQuel lien ces phrases affirment-elles ?\n{menu}\n0. aucun lien affirmé\n",
                          _numbers(len(options)), CHOICE_TOKENS, {"options": options, "uids": sorted(set(uids))}))  # fmt: skip
    replies = _run(calls, result)
    for call, r in zip(calls, replies):
        if isinstance(r, Exception):
            continue
        if call.stage == "actor":
            k = _index(r, len(call.meta["near"]))
            who = call.meta["near"][k - 1] if k else campaign_sid
            if who:
                relations.append((f"{clean(draft.name_of(who))}|uses|{call.meta['tid']}|{call.meta['u'].uid}", "technique"))
        elif call.stage in ("relation", "campaign-link") and (k := _index(r, len(call.meta["options"]))):
            s, rel, t = call.meta["options"][k - 1]
            relations.append((f"{clean(draft.name_of(s))}|{rel}|{clean(draft.name_of(t))}|{','.join(map(str, call.meta['uids']))}", "relation"))

    # 4. vérification STIX
    for line, _ in relations:
        err = draft.relate(line)
        if err:
            draft.log.append(f"reject {err}")
            result.refused += 1
        else:
            result.accepted += 1
    rows = draft.entity_rows()
    if with_iocs:
        result.iocs = extract_iocs(title, units, rows, url=art.get("url"), published=parse_date(art.get("publication_date")))
    if with_rules:
        result.rules = extract_rules(title, art["clean_markdown"], rows)
    result.seconds = time.perf_counter() - t0
    return result
