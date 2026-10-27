"""Extraction rapide : le code propose, le modèle choisit, en deux appels contraints par partie d'article (plus un de correction).

    uv run cti-agent --fast --article-id 854 --dry-run
    uv run cti-eval --system fast --run

Le coût d'un modèle local est celui des tokens GÉNÉRÉS (58 tokens/s mesurés), la lecture d'un prompt est rapide
(~1 200 tokens/s) et presque gratuite quand le prompt commence comme le précédent (cache du serveur : 0,2 s pour
8 400 tokens). L'agent fait écrire au modèle ses requêtes de recherche, ses vérifications et ses corrections (16 700
tokens et 59 tours pour un article de 36 000 caractères). Ici, il n'écrit que des numéros et des identifiants :

    [Rapport brut] -> phrases numérotées -> parties (texte d'au plus PART_CHARS)
        pour chaque partie, deux appels qui commencent par le même texte (lu une fois, puis en cache) :
          1. inventaire : entités (« type|nom|alias ») et numéros des phrases qui décrivent un comportement de l'attaquant ;
          2. le code cherche, pour chacune de ces phrases, ses techniques ATT&CK candidates (index FTS5, sans modèle) ;
             le modèle choisit, phrase par phrase, l'entité qui agit et la technique parmi les candidates, et relie les
             entités entre elles (numéros de phrases en preuve).
    -> vérification STIX de `DraftGraph` (stix2 strict, ATT&CK v20.0, phrases citées). Les lignes refusées reviennent au modèle
       UNE fois avec leur raison (le prompt commence par le précédent : relu depuis le cache) ; un second refus les écarte
    -> IOC, règles et bundle : ceux de l'agent (`stix_agent`)
"""

import os
import re
import time

from backend.extracting import llm
from backend.extracting.agent_tools import DraftGraph
from backend.extracting.iocs import extract_iocs
from backend.extracting.evidence import parse_date
from backend.extracting.rules import extract_rules
from backend.extracting.segment import Pass, Unit, make_passes, segment
from backend.extracting.stix_agent import AgentResult, TurnStat, clean_title
from backend.stix.objects import ENTITY_CLASSES, ArticleContext

PART_CHARS = int(os.environ.get("CTI_PART_CHARS") or 18000)  # texte d'article par partie : avec ses candidates et la réponse, tient dans num_ctx
CANDIDATES = 6  # techniques candidates par phrase
MAX_PER_SENTENCE = 2  # techniques gardées par phrase : le modèle en cocherait sinon presque toutes les candidates (mesuré)
MAX_BEHAVIORS = 45  # phrases de comportement par partie (au-delà, les candidates ne tiennent plus dans num_ctx)
INVENTORY_TOKENS = 900
RELATION_TOKENS = 1600
CORRECTION_TOKENS = 700

_TECHNIQUE = re.compile(r"T\d{4}(?:\.\d{3})?", re.I)


def system_prompt() -> str:
    return f"""Tu es analyste CTI. Tu construis la couche sémantique STIX 2.1 d'un rapport de menace : qui (acteurs, campagnes), avec quoi (malwares, outils, infrastructures nommées), comment (techniques MITRE ATT&CK v20.0), contre quoi (vulnérabilités, produit visé, victimes). Le rapport est découpé en phrases numérotées [n].

ENTITÉS (types : {', '.join(ENTITY_CLASSES)}) :
- intrusion-set : groupe d'attaquants nommé (nom ou code de suivi donné par le rapport ou un éditeur). threat-actor : personne ou organisation réelle identifiée.
- campaign : l'activité malveillante que le rapport décrit (une opération contre des cibles sur une période). UNE campagne par vague distincte (cibles ou périodes différentes), nom descriptif (« Campagne <acteur> contre <cible>, <période> »). Pas de campagne si le texte ne décrit aucune opération.
- malware : code malveillant nommé, ou composant que l'article désigne par un libellé descriptif (reprendre ce libellé).
- tool : logiciel légitime détourné par l'attaquant (binaire natif du système, outil d'administration, packer, obfuscateur). Jamais une fonction, un appel système ou une bibliothèque de programmation.
- infrastructure : service ou infrastructure NOMMÉ utilisé par l'attaquant. Jamais une IP, un domaine ou une URL.
- vulnerability : une CVE. software : produit légitime visé (« software|<produit>|<éditeur> »).
- identity : victime (organisation, secteur) ou éditeur du produit visé. location : pays ou région ciblés (« location|<pays>|<code ISO 3166-1> »).
JAMAIS : l'auteur du rapport, les chercheurs ou éditeurs de sécurité comme acteur ou victime ; un hachage, une IP, un domaine, une URL ou un nom de fichier ordinaire (ce sont des IOC, hors périmètre) ; ce que le rapport cite d'autres opérations passées comme activité de la campagne décrite.

RELATIONS (STIX 2.1, source --relation--> cible) :
- campaign --attributed-to--> intrusion-set | threat-actor ; intrusion-set --attributed-to--> threat-actor
- intrusion-set | threat-actor | campaign | malware | tool --uses--> attack-pattern | malware | tool | infrastructure
- intrusion-set | threat-actor | campaign --targets--> identity | location | vulnerability ; malware | tool --targets--> identity | location
- malware --exploits--> vulnerability ; software --has--> vulnerability ; software --related-to--> identity (éditeur)
- malware | tool --drops--> malware | tool ; malware --downloads--> malware | tool ; malware --variant-of--> malware
- malware --communicates-with | beacons-to | exfiltrates-to--> infrastructure
Qui emploie une technique : le malware ou l'outil qui l'exécute quand le texte décrit sa capacité ; la campagne quand c'est une étape de l'opération.
N'invente rien que le texte ne dise."""


def inventory_prompt(text: str, known: list[str]) -> str:
    seen = "\n".join(known) or "(aucune)"
    return (
        f"{text}\n\n---\nENTITÉS DÉJÀ RELEVÉES DANS LES PARTIES PRÉCÉDENTES (ne pas les répéter, réutiliser exactement ces noms) :\n{seen}\n\n"
        "TÂCHE : 1) « entities » : TOUTES les entités NOUVELLES de ce texte, séparées par « ; », chacune « type|nom » ou "
        "« type|nom|alias1,alias2 », le nom tel que le texte l'écrit (« malware|<nom>;tool|<nom>;intrusion-set|<nom>|<alias> »). "
        "2) « behaviors » : les numéros des phrases qui décrivent un comportement de l'attaquant ou d'un logiciel malveillant "
        "(exécution, persistance, découverte, communication, chiffrement, exfiltration, livraison, obfuscation…), séparés par des virgules."
    )


def relation_prompt(text: str, entities: list[str], behaviors: str) -> str:
    table = "\n".join(f"{i}. {e}" for i, e in enumerate(entities, 1)) or "(aucune)"
    return (
        f"{text}\n\n---\nENTITÉS (numérotées) :\n{table}\n\nPHRASES DE COMPORTEMENT ET TECHNIQUES CANDIDATES :\n{behaviors}\n\n"
        "TÂCHE (éléments séparés par « ; ») : 1) « techniques » : pour chaque phrase de comportement, « numéro de phrase|numéro "
        f"d'entité qui agit|identifiant » (« 12|3|T####.###;14|2|T#### »). UNE technique par phrase, la plus précise, choisie parmi "
        f"les candidates de CETTE phrase (la sous-technique quand le texte nomme le mécanisme précis) ; au plus {MAX_PER_SENTENCE} si "
        "la phrase décrit des comportements distincts ; aucune si aucune ne convient. 2) « relations » : tous les liens entre entités "
        "que le texte affirme, « numéro source|relation|numéro cible|numéros de phrases » (« 3|uses|2|12,13;3|attributed-to|1|5 »). "
        "La phrase citée (ou les 3 précédentes de sa section, ou son titre) nomme le malware, l'outil, la CVE ou la victime reliés."
    )


def _schema(*fields: str) -> dict:
    """Un champ texte par liste : une chaîne JSON ne contient pas de retour à la ligne brut, la sortie est donc compacte (une liste
    JSON est écrite indentée par le modèle : 4 à 5 tokens par numéro au lieu de 1 à 2, mesuré)."""
    return {"type": "object", "properties": {f: {"type": "string"} for f in fields}, "required": list(fields)}


INVENTORY_SCHEMA = _schema("entities", "behaviors")
RELATION_SCHEMA = _schema("techniques", "relations")


def rows(value) -> list[str]:
    """Éléments d'un champ texte, séparés par « ; » ou des retours à la ligne (une liste est aussi admise)."""
    items = value if isinstance(value, list) else re.split(r"[;\n]", str(value or ""))
    return [str(i).strip() for i in items if str(i).strip()]


def behaviors_block(units: list[Unit], cands: dict[int, list]) -> str:
    """Candidates de chaque phrase de comportement ; la phrase elle-même est dans le texte au-dessus, elle n'est pas répétée."""
    return "\n".join(f"[{u.uid}] " + " ; ".join(f"{h.attack_id} {h.name}" for h in cands[u.uid]) for u in units) or "(aucune)"


def _clean(value: str) -> str:
    return str(value).replace("|", "/").strip()


def _index(raw: str, size: int) -> int | None:
    found = re.fullmatch(r"\s*[A-Za-z#]*\s*(\d+)\s*", str(raw))
    i = int(found.group(1)) if found else 0
    return i - 1 if 1 <= i <= size else None


def _call(result, part: int, stage: str, system: str, prompt: str, schema: dict, max_tokens: int) -> dict:
    r = llm.generate(system, prompt, schema, max_output_tokens=max_tokens)
    result.turns.append(TurnStat(part, len(result.turns), r.prompt_tokens, r.output_tokens, r.seconds, [stage], r.output_tokens >= max_tokens))
    return r.parsed if isinstance(r.parsed, dict) else {}


def run_part(draft: DraftGraph, part: Pass, entities: list[str], sids: list[str], result) -> None:
    """Les deux appels d'une partie. `entities` (lignes « type|nom ») et `sids` (identifiants STIX) s'allongent des entités
    acceptées : les parties suivantes les réutilisent."""
    system, text = system_prompt(), part.render()
    inv = _call(result, part.index, "inventory", system, inventory_prompt(text, entities), INVENTORY_SCHEMA, INVENTORY_TOKENS)

    for line in rows(inv.get("entities")):
        fields = line.split("|")
        if len(fields) > 2 and fields[0].strip().lower() not in ("software", "location"):
            fields[2] = fields[2].replace(",", ";")  # alias séparés par des virgules dans la réponse, par « ; » pour `declare`
        sid, err = draft.declare("|".join(fields))
        if err:
            draft.log.append(f"reject {err}")
            result.refused += 1
        elif sid not in sids and draft.type_of(sid) != "attack-pattern":  # une technique se choisit parmi les candidates
            sids.append(sid)
            entities.append(f"{draft.type_of(sid)}|{draft.name_of(sid)}")
            result.accepted += 1

    by_uid = {u.uid: u for u in part.units}
    wanted = [int(n) for n in re.findall(r"\d+", " ".join(rows(inv.get("behaviors"))))]
    units = [by_uid[n] for n in dict.fromkeys(wanted) if n in by_uid and by_uid[n].is_evidence_eligible][:MAX_BEHAVIORS]
    cands = {u.uid: draft.attack.search_techniques(u.text, limit=CANDIDATES) for u in units}
    if not entities or not (units or len(entities) > 1):
        return
    prompt = relation_prompt(text, entities, behaviors_block(units, cands))
    rel = _call(result, part.index, "relations", system, prompt, RELATION_SCHEMA, RELATION_TOKENS)
    per_sentence: dict[int, int] = {}
    refused = apply_relations(draft, rel, sids, cands, per_sentence, result)
    if refused:  # un tour de correction, comme l'agent : le prompt commence par le précédent, relu depuis le cache du serveur
        fix = _call(result, part.index, "corrections", system, correction_prompt(prompt, rel, refused), RELATION_SCHEMA, CORRECTION_TOKENS)
        apply_relations(draft, fix, sids, cands, per_sentence, result)


def correction_prompt(prompt: str, answer: dict, refused: list[tuple[str, str]]) -> str:
    previous = f"techniques : {answer.get('techniques', '')}\nrelations : {answer.get('relations', '')}"
    reasons = "\n".join(f"- « {row} » : {reason}" for row, reason in refused)
    return (
        f"{prompt}\n\nTA RÉPONSE :\n{previous}\n\nLIGNES REFUSÉES :\n{reasons}\n\n"
        "TÂCHE : renvoie SEULEMENT les lignes refusées corrigées, mêmes formats (citer la phrase qui nomme l'entité, choisir "
        "l'entité qui agit ou une candidate de la phrase) ; omets celles que le texte n'étaye pas."
    )


def apply_relations(draft: DraftGraph, answer: dict, sids: list[str], cands: dict[int, list], per_sentence: dict[int, int], result) -> list[tuple[str, str]]:
    """Ajoute les lignes valides d'une réponse ; retourne les lignes refusées avec leur raison."""
    refused: list[tuple[str, str]] = []
    lines: list[tuple[str, str]] = []  # (ligne de la réponse, ligne « source|relation|cible|phrases » pour `relate`)
    for row in rows(answer.get("techniques")):
        parts = [p.strip() for p in row.split("|")]
        if len(parts) != 3 or not parts[0].isdigit():
            refused.append((row, "format attendu phrase|entité|technique"))
            continue
        uid, who = int(parts[0]), _index(parts[1], len(sids))
        tech = _TECHNIQUE.search(parts[2])
        if who is None or tech is None or tech.group(0).upper() not in {h.attack_id for h in cands.get(uid, [])}:
            refused.append((row, f"entité inconnue ou technique hors des candidates de la phrase {uid}"))
            continue
        per_sentence[uid] = per_sentence.get(uid, 0) + 1
        if per_sentence[uid] > MAX_PER_SENTENCE:
            draft.log.append(f"reject « {row} » : plus de {MAX_PER_SENTENCE} techniques pour la phrase {uid}")
            result.refused += 1
            continue
        lines.append((row, f"{_clean(draft.name_of(sids[who]))}|uses|{tech.group(0).upper()}|{uid}"))
    for row in rows(answer.get("relations")):
        parts = [p.strip() for p in row.split("|")]
        src, dst = (_index(parts[0], len(sids)), _index(parts[2], len(sids))) if len(parts) == 4 else (None, None)
        if src is None or dst is None:
            refused.append((row, "format attendu numéro source|relation|numéro cible|numéros de phrases"))
            continue
        lines.append((row, f"{_clean(draft.name_of(sids[src]))}|{parts[1]}|{_clean(draft.name_of(sids[dst]))}|{parts[3]}"))
    for row, line in lines:
        err = draft.relate(line)
        if err:
            refused.append((row, err.split(" : ", 1)[-1]))
        else:
            result.accepted += 1
    draft.log += [f"reject « {row} » : {reason}" for row, reason in refused]
    result.refused += len(refused)
    return refused


def extract_article(art: dict, *, part_chars: int = PART_CHARS, with_iocs: bool = True, with_rules: bool = True, **_):
    """Même contrat que `stix_agent.extract_article` (un `AgentResult`), sans boucle d'outils."""
    t0 = time.perf_counter()
    title = clean_title(art["title"] or f"Article {art['id']}", art.get("site_name"))
    units = segment(art["clean_markdown"])
    parts = [p for p in make_passes(units, part_chars) if any(u.is_evidence_eligible for u in p.units)]
    draft = DraftGraph(units, ArticleContext(art["id"], art.get("site_name"), art.get("url"), art.get("title")))
    result = AgentResult(art["id"], draft, len(units), len(parts))
    entities: list[str] = []
    sids: list[str] = []
    for part in parts:
        try:
            run_part(draft, part, entities, sids, result)
        except (TimeoutError, llm.requests.RequestException) as exc:  # une partie perdue n'arrête pas l'article
            result.failed_passages.append(f"partie {part.index + 1} : {type(exc).__name__}: {exc}")
    rows = draft.entity_rows()
    if with_iocs:
        result.iocs = extract_iocs(title, units, rows, url=art.get("url"), published=parse_date(art.get("publication_date")))
    if with_rules:
        result.rules = extract_rules(title, art["clean_markdown"], rows)
    result.seconds = time.perf_counter() - t0
    return result
