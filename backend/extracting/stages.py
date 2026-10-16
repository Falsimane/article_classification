"""Les deux étapes LLM de l'extraction : entités, puis relations. Sorties volontairement minimales.

Étape 1 (entités), par passe : le modèle liste `type|Nom|alias;alias`, une courte chaîne par entité.
Étape 2 (relations), par passe : le modèle écrit `numéro_de_phrase|E3|relation|E7`. Les identifiants d'entité et
les types de relation viennent de listes fermées et la preuve est le NUMÉRO d'une phrase : aucune citation à recopier.

Entre les deux, tout le reste est déterministe : rapprochement avec ATT&CK, fusion des alias, filtrage des phrases
utiles, vérification que chaque relation est valide en STIX et étayée par la phrase citée (`ontology.stix.validate`).
"""

import re
from dataclasses import dataclass
from functools import lru_cache

from backend.ontology.stix import PROFILES, get_reference_kb
from backend.ontology.stix.profiles import render_entity_card, render_relation_card
from backend.ontology.stix.validate import mentions_prepared, prepare_text

from .segment import Pass, Unit

# Types demandés au modèle. `indicator` (le motif d'une règle) et `course-of-action` exigent de recopier un contenu
# long : hors de cette première version, qui vise la rapidité (voir README).
SKIPPED_TYPES = frozenset({"indicator", "course-of-action"})
ADVERSARY = frozenset({"threat-actor", "intrusion-set", "campaign"})
MAX_ENTITY_TOKENS = 450
MAX_RELATION_TOKENS = 550


def llm_entity_types(profile_name: str) -> tuple[str, ...]:
    """Types demandés au modèle : ni ceux qu'il ne peut pas produire brièvement, ni ceux que le pipeline dérive."""
    from backend.ontology.stix import OBJECT_TYPES

    return tuple(
        t for t in PROFILES[profile_name].entity_types if t not in SKIPPED_TYPES and OBJECT_TYPES[t].extraction == "llm"
    )


# --- Étape 1 : entités ---------------------------------------------------------------------------------------------
ENTITY_SCHEMA = {
    "type": "object",
    "properties": {"entities": {"type": "array", "items": {"type": "string"}}},
    "required": ["entities"],
}

_ENTITY_FORMAT = (
    "FORMAT DE RÉPONSE : un objet JSON {\"entities\": [...]} dont chaque élément est UNE chaîne "
    "\"type|Nom|alias1;alias2\" (alias facultatifs). Exemples : \"malware|Qakbot|QBot\", \"intrusion-set|APT29\", "
    "\"vulnerability|CVE-2023-4966\", \"tool|PsExec\". Chaque entité une seule fois. Aucun commentaire."
)


_ENTITY_EXAMPLE = """EXEMPLE
Extrait :
## Recommandations
[1] Activez Sensor Tampering Protection et HVCI sur tous les hôtes.
## Intrusion
[2] En 2022, SCATTERED SPIDER a visé des opérateurs télécoms et utilisé KDMapper pour charger un pilote Intel vulnérable (CVE-2015-2291).
Réponse : {"entities": ["intrusion-set|SCATTERED SPIDER", "identity|telecommunications", "tool|KDMapper", "vulnerability|CVE-2015-2291"]}
Sensor Tampering Protection et HVCI sont des mesures de DÉFENSE recommandées : ils ne sont pas des entités. Un secteur
visé s'écrit avec un terme du vocabulaire ci-dessous."""


def entity_system(profile_name: str) -> str:
    from backend.ontology.stix.vocab import OPEN_VOCABULARIES

    sectors = ", ".join(OPEN_VOCABULARIES["industry-sector-ov"])
    return (
        "Tu es analyste en renseignement sur la menace (CTI). Tu lis un extrait numéroté d'un rapport et tu listes "
        "les ENTITÉS précises qui y sont nommées, selon l'ontologie STIX 2.1 ci-dessous.\n\n"
        + render_entity_card(profile_name)
        + f"\n\nSECTEURS D'ACTIVITÉ (type identity, vocabulaire STIX) : {sectors}.\n\n"
        + _ENTITY_EXAMPLE
        + "\n\n"
        + _ENTITY_FORMAT
    )


@lru_cache(maxsize=1)
def _kb_labels() -> dict[str, tuple[str, str]]:
    """{libellé exact: (nom canonique, type STIX)} des groupes, logiciels et campagnes ATT&CK actifs. Le libellé est
    comparé avec sa casse : « Net » (commande) et « net group » ne se confondent pas avec un acteur."""
    kb = get_reference_kb()
    labels: dict[str, tuple[str, str]] = {}
    for matches in kb._by_name.values():
        for m in matches:
            if m.status != "active":
                continue
            for label in (m.name, *m.aliases):
                if len(label) >= 4 and not label.islower():
                    labels.setdefault(label, (m.name, m.stix_type))
    return labels


_WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.\-+#]*[A-Za-z0-9]|[A-Za-z0-9]")


def kb_hints(units: tuple[Unit, ...] | list[Unit]) -> list[tuple[str, str]]:
    """Candidats ATT&CK repérés dans les phrases, par correspondance exacte (casse comprise) : [(nom, type)].
    Ce sont des INDICES soumis au modèle, jamais des entités acceptées d'office."""
    labels = _kb_labels()
    found: dict[str, str] = {}
    for u in units:
        if u.kind in ("code", "table"):
            continue
        words = _WORD.findall(u.text)
        for i in range(len(words)):
            for n in (3, 2, 1):
                if i + n <= len(words):
                    surface = " ".join(words[i : i + n])
                    if surface in labels:
                        name, stix_type = labels[surface]
                        found.setdefault(name, stix_type)
                        break
    return sorted(found.items())


def entity_user(title: str, category: str, pass_: Pass, hints: list[tuple[str, str]]) -> str:
    hint = ""
    if hints:
        hint = (
            "\nCANDIDATS REPÉRÉS DANS LA BASE ATT&CK (à confirmer par le contexte, ignore-les s'ils ne désignent pas "
            "une menace ici) :\n" + "\n".join(f"- {n} ({t})" for n, t in hints) + "\n"
        )
    return f"RAPPORT : {title}\nCATÉGORIE : {category}\n{hint}\nEXTRAIT :\n{pass_.render()}"


def parse_entities(items: list, allowed: tuple[str, ...]) -> tuple[list[dict], int]:
    """Entités depuis les chaînes du modèle. Retourne (entités, nombre de chaînes illisibles ou hors type)."""
    out, dropped = [], 0
    for item in items or []:
        parts = [p.strip() for p in str(item).split("|")]
        if len(parts) < 2 or parts[0] not in allowed or len(parts[1]) < 2:
            dropped += 1
            continue
        ent = {"type": parts[0], "name": parts[1]}
        if len(parts) > 2 and parts[2]:
            ent["aliases"] = [a.strip() for a in re.split(r"[;,]", parts[2]) if a.strip()]
        out.append(ent)
    return out, dropped


# --- Étape 2 : relations, par classification de candidats fermés -------------------------------------------------------
# Demander au modèle d'ÉCRIRE des relations entre identifiants d'entités le conduit à en inventer (mesuré : une
# trentaine proposées pour trois vraies, la plupart mal typées). Le code énumère donc, phrase par phrase, les paires
# d'entités réellement nommées dans la phrase et ne garde que les relations que l'ontologie autorise entre leurs
# types. Le modèle ne répond que pour les candidats que la phrase AFFIRME : `15a:variant-of`.
# Tout candidat est valide en STIX et étayé par sa phrase par construction.


@dataclass(frozen=True)
class EntityRow:
    eid: str  # "E1"
    stix_type: str
    name: str
    terms: tuple[str, ...]  # nom + alias, pour repérer l'entité dans une phrase


@dataclass(frozen=True)
class Candidate:
    cid: str  # "15a" : numéro de phrase + lettre
    uid: int
    source: str
    target: str
    options: tuple[str, ...]  # relations autorisées entre les types de la source et de la cible
    prev_uid: int | None = None  # phrase précédente (même section), si l'une des extrémités n'y est nommée que là


def entity_hits(units: tuple[Unit, ...] | list[Unit], rows: list[EntityRow]) -> dict[int, set[str]]:
    """{numéro de phrase: identifiants des entités nommées dedans}. Chaque phrase n'est tokenisée qu'une fois."""
    hits: dict[int, set[str]] = {}
    for u in units:
        prepared = prepare_text(u.text)
        found = {r.eid for r in rows if mentions_prepared(prepared, r.terms)}
        if found:
            hits[u.uid] = found
    return hits


def pair_options(profile_name: str) -> dict[tuple[str, str], tuple[str, ...]]:
    """{(type source, type cible): relations que le profil autorise}."""
    options: dict[tuple[str, str], set[str]] = {}
    for s, r, t in PROFILES[profile_name].pairs():
        options.setdefault((s, t), set()).add(r)
    return {k: tuple(sorted(v)) for k, v in options.items()}


def _letters(i: int) -> str:
    return chr(97 + i) if i < 26 else chr(97 + i // 26 - 1) + chr(97 + i % 26)


def build_candidates(
    units: list[Unit],
    rows: list[EntityRow],
    profile_name: str,
    implicit: EntityRow | None = None,
    max_per_unit: int = 10,
) -> list[tuple[Unit, list[Candidate]]]:
    """Candidats de relation par phrase, dans l'ordre du texte. Trois façons de réunir deux entités :

    1. toutes deux nommées dans la même phrase ;
    2. l'une nommée dans la phrase précédente de la même section, l'autre dans la courante : la preuve est alors la
       fenêtre de deux phrases, citées toutes les deux ;
    3. la phrase nomme une capacité mais aucun acteur : sujet de section (dernier acteur nommé DANS CETTE SECTION),
       à défaut `implicit` (l'incident d'un récit d'intrusion). Le sujet ne traverse jamais une section : une
       phrase sur une tendance générale n'a aucun rapport avec l'acteur nommé plus haut.
    """
    options = pair_options(profile_name)
    last_adversary: EntityRow | None = None
    last_section = ""
    previous: tuple[Unit, list[EntityRow]] | None = None
    out: list[tuple[Unit, list[Candidate]]] = []
    for u in units:
        if not u.is_evidence_eligible:
            continue
        prepared = prepare_text(u.text)
        named = [r for r in rows if mentions_prepared(prepared, r.terms)]
        if u.heading_path != last_section:
            last_adversary, last_section, previous = None, u.heading_path, None
        prev_unit, prev_named = previous if previous else (None, [])
        adversaries = [r for r in named if r.stix_type in ADVERSARY]

        seen: set[tuple[str, str]] = set()
        cands: list[Candidate] = []

        def add(a: EntityRow, b: EntityRow, prev_uid: int | None) -> None:
            opts = options.get((a.stix_type, b.stix_type))
            if a.eid != b.eid and opts and (a.eid, b.eid) not in seen:
                seen.add((a.eid, b.eid))
                cands.append(Candidate(f"{u.uid}{_letters(len(cands))}", u.uid, a.eid, b.eid, opts, prev_uid))

        for a in named:  # 1. même phrase
            for b in named:
                add(a, b, None)
        if not adversaries and named:  # 3. sujet de section ou incident
            subject = last_adversary or implicit
            if subject is not None:
                for b in named:
                    add(subject, b, None)
        if prev_unit is not None:  # 2. fenêtre de deux phrases
            in_prev = {r.eid for r in prev_named}
            for a in prev_named + named:
                for b in prev_named + named:
                    if (a.eid in in_prev) != (b.eid in in_prev):  # une extrémité dans chaque phrase
                        add(a, b, prev_unit.uid)
        if adversaries:
            last_adversary = adversaries[-1]
        previous = (u, named)
        if cands:
            out.append((u, cands[:max_per_unit]))
    return out


def group_candidate_units(items: list[tuple[Unit, list[Candidate]]], max_chars: int = 7000) -> list[list[tuple[Unit, list[Candidate]]]]:
    groups: list[list[tuple[Unit, list[Candidate]]]] = []
    cur: list[tuple[Unit, list[Candidate]]] = []
    size = 0
    for u, cands in items:
        cost = len(u.prompt_text) + 40 * len(cands)
        if cur and size + cost > max_chars:
            groups.append(cur)
            cur, size = [], 0
        cur.append((u, cands))
        size += cost
    if cur:
        groups.append(cur)
    return groups


def relation_schema(group: list[tuple[Unit, list[Candidate]]]) -> dict:
    """Schéma de la réponse : les seules valeurs admises sont les couples `candidat:relation` proposés dans CE prompt.
    Le serveur applique les `enum` mais ignore les motifs (`pattern`) : un enum fermé garantit des réponses valides."""
    answers = [f"{c.cid}:{rel}" for _, cands in group for c in cands for rel in c.options]
    return {
        "type": "object",
        "properties": {"relations": {"type": "array", "items": {"type": "string", "enum": answers}}},
        "required": ["relations"],
    }


def relation_system(profile_name: str) -> str:
    return (
        "Tu es analyste en renseignement sur la menace (CTI). On te donne des ENTITÉS numérotées (E1, E2…), puis des "
        "phrases numérotées. Sous chaque phrase, des CANDIDATS de relation entre deux entités, chacun avec les relations "
        "possibles : `15a E5 -> E1 : variant-of | drops`.\n\n"
        "TA TÂCHE : pour chaque candidat que la phrase AFFIRME explicitement, écris `identifiant:relation` en choisissant "
        "UNE relation parmi celles proposées pour ce candidat. N'écris RIEN pour les autres. La grande majorité des "
        "candidats est fausse : entités simplement citées ensemble, liste, contexte. En cas de doute, ne retiens pas.\n\n"
        + render_relation_card(profile_name)
        + "\n\nFORMAT DE RÉPONSE : un objet JSON {\"relations\": [...]} dont chaque élément est UNE chaîne "
        "\"15a:variant-of\". Aucun commentaire. Liste vide si aucun candidat n'est affirmé."
    )


def relation_user(title: str, category: str, rows: list[EntityRow], group: list[tuple[Unit, list[Candidate]]]) -> str:
    used = {c.source for _, cs in group for c in cs} | {c.target for _, cs in group for c in cs}
    table = "\n".join(f"{r.eid} {r.stix_type} {r.name}" for r in rows if r.eid in used)
    lines = []
    for u, cands in group:
        lines.append(f"[{u.uid}] {u.prompt_text}")
        lines += [
            f"  {c.cid} {c.source} -> {c.target} : {' | '.join(c.options)}" + (f"  [preuve : phrases {c.prev_uid} et {c.uid}]" if c.prev_uid else "")
            for c in cands
        ]
    return f"RAPPORT : {title}\nCATÉGORIE : {category}\n\nENTITÉS :\n{table}\n\nPHRASES ET CANDIDATS :\n" + "\n".join(lines)


_ANSWER = re.compile(r"^\s*([0-9]+[a-z]{1,2})\b.*?([a-z]+(?:-[a-z]+)*)\s*$")


def parse_answers(items: list, group: list[tuple[Unit, list[Candidate]]]) -> tuple[list[tuple[Unit, Candidate, str]], int]:
    """Réponses du modèle -> (phrase, candidat, relation). Écarte ce qui n'est pas un candidat proposé ou une relation
    hors des options de ce candidat. Retourne aussi le nombre de chaînes écartées."""
    index = {c.cid: (u, c) for u, cands in group for c in cands}
    out, dropped, seen = [], 0, set()
    for item in items or []:
        m = _ANSWER.match(str(item))
        if not m or m.group(1) not in index or m.group(2) not in index[m.group(1)][1].options:
            dropped += 1
            continue
        if (m.group(1), m.group(2)) in seen:
            continue
        seen.add((m.group(1), m.group(2)))
        unit, cand = index[m.group(1)]
        out.append((unit, cand, m.group(2)))
    return out, dropped


# --- Étape 3 : vérification des relations retenues ------------------------------------------------------------------
# Filet de précision : pour chaque relation, une question fermée posée avec la SEULE phrase citée et la définition
# de la relation. Coût : environ 4 tokens générés par relation.
from backend.ontology.stix import SEMANTICS  # noqa: E402

MAX_VERIFY_TOKENS = 220
VERIFY_BATCH = 30


def verify_system() -> str:
    return (
        "Tu vérifies des relations extraites d'un rapport de cybermenace. Pour chaque ligne tu reçois une PHRASE et une "
        "AFFIRMATION. Réponds `o` UNIQUEMENT si la phrase, lue seule, affirme explicitement l'affirmation à propos de "
        "l'attaque décrite ; sinon `n`.\n"
        "Réponds `n` quand la phrase : recommande ou décrit une mesure de défense ou un paramètre de configuration ; "
        "décrit une règle de détection, un journal ou une liste ; énonce une généralité ou une tendance sans lien avec "
        "ces deux éléments ; cite les deux éléments sans les relier.\n"
        "Quand l'affirmation désigne « l'intrusion décrite » ou « l'acteur » sans qu'ils soient nommés dans la phrase, "
        "la phrase doit quand même décrire une action de l'attaquant dans cette intrusion : une commande ou un fichier "
        "exécuté pendant l'intrusion (`vssadmin delete shadows /all`) affirme l'usage de l'outil. Quand la preuve réunit "
        "deux phrases (séparées par [...]), lis-les ensemble.\n"
        "FORMAT : un objet JSON {\"verdicts\": [...]} avec une chaîne `numéro:o` ou `numéro:n` par ligne, dans l'ordre."
    )


def _claim(source_name: str, source_type: str, rel: str, target_name: str, target_type: str) -> str:
    return f"[{source_type}] {source_name}  --{rel}-->  [{target_type}] {target_name}. Sens de `{rel}` : {SEMANTICS[rel].definition}"


def verify_user(items: list[tuple[int, str, str]]) -> str:
    """items : [(numéro, phrase, affirmation)]"""
    return "\n\n".join(f"{n}. PHRASE : {sentence}\n   AFFIRMATION : {claim}" for n, sentence, claim in items)


def verify_schema(numbers: list[int]) -> dict:
    answers = [f"{n}:{v}" for n in numbers for v in ("o", "n")]
    return {"type": "object", "properties": {"verdicts": {"type": "array", "items": {"type": "string", "enum": answers}}}, "required": ["verdicts"]}


def parse_verdicts(items: list, numbers: list[int]) -> set[int]:
    """Numéros confirmés (`o`). Une relation sans verdict n'est pas confirmée : le doute écarte."""
    ok = set()
    for item in items or []:
        m = re.match(r"^\s*(\d+)\s*:\s*([on])\s*$", str(item))
        if m and int(m.group(1)) in numbers and m.group(2) == "o":
            ok.add(int(m.group(1)))
    return ok


# --- Vérification des entités ---------------------------------------------------------------------------------------------
# Avant de fabriquer des candidats, chaque entité est jugée avec sa première phrase et sa section, d'après la définition
# de son type. Elle retire les mesures de défense, produits recommandés et termes génériques que le modèle a typés à tort.
MAX_ENTITY_VERIFY_TOKENS = 300
ENTITY_VERIFY_BATCH = 40


def first_mentions(units: list[Unit], rows: list[EntityRow]) -> dict[str, Unit]:
    """Première phrase éligible qui nomme chaque entité. Une entité absente de toute phrase n'est pas dans le texte."""
    found: dict[str, Unit] = {}
    for u in units:
        if not u.is_evidence_eligible or len(found) == len(rows):
            continue
        prepared = prepare_text(u.text)
        for r in rows:
            if r.eid not in found and mentions_prepared(prepared, r.terms):
                found[r.eid] = u
    return found


def entity_verify_system(profile_name: str) -> str:
    return (
        "Tu vérifies des entités extraites d'un rapport de cybermenace. Pour chaque ligne tu reçois un TYPE, un NOM, la "
        "SECTION et une PHRASE où il apparaît. Réponds `o` UNIQUEMENT si, dans cette phrase et cette section, le nom est "
        "bien une entité du type indiqué au sens de ces définitions ET fait partie de l'attaque décrite (adversaire, "
        "capacité employée par l'adversaire, victime, infrastructure).\n\n"
        + render_entity_card(profile_name).split("\n\nRÈGLES")[0]
        + "\n\nRéponds `n` pour : une mesure de défense, un paramètre de configuration, un produit ou une fonction "
        "recommandés ou décrits comme protection ; une source citée ; un terme générique ; une fonction d'API, un "
        "algorithme, un certificat ; un nom qui n'a pas ce type dans cette phrase.\n"
        "FORMAT : un objet JSON {\"verdicts\": [...]} avec une chaîne `numéro:o` ou `numéro:n` par ligne, dans l'ordre."
    )


def entity_verify_user(items: list[tuple[int, EntityRow, Unit]]) -> str:
    return "\n".join(
        f"{n}. TYPE : {r.stix_type} | NOM : {r.name} | SECTION : {u.heading_path.split(' > ')[-1][:60]} | PHRASE : {u.prompt_text[:260]}"
        for n, r, u in items
    )
