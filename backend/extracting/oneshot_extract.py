"""Extraction en un appel, comme un grand modèle de chat : l'article entier, une réponse avec toutes les entités, techniques et relations.

    uv run cti-eval --system oneshot --run --bundles db_outputs/eval/oneshot

Référence sans décomposition pour `fast` et `closed` : aucune candidate n'est calculée par le code, le modèle écrit lui-même les
identifiants ATT&CK de mémoire. La vérification STIX de `DraftGraph` (stix2 strict, ATT&CK v20.0, phrases citées) trie la réponse ;
les lignes refusées reviennent au modèle UNE fois avec leur raison (le prompt commence par le précédent : relu depuis le cache).
Aucun IOC n'est demandé au modèle ; ceux du bundle viennent des règles (`iocs`), comme pour les autres systèmes.

L'article entier doit tenir dans le contexte du serveur (~11 000 tokens pour le plus long article annoté) : prévu pour SGLang/vLLM
(CTI_LLM_BACKEND=openai), pas pour le num_ctx d'Ollama.
"""

import os
import re
import time

from backend.extracting import llm
from backend.extracting.agent_tools import DraftGraph
from backend.extracting.evidence import parse_date
from backend.extracting.fast_extract import _call, _schema, rows, system_prompt
from backend.extracting.iocs import extract_iocs
from backend.extracting.rules import extract_rules
from backend.extracting.segment import Pass, segment
from backend.extracting.stix_agent import AgentResult, clean_title
from backend.stix.objects import ArticleContext

ANSWER_TOKENS = int(os.environ.get("CTI_ONESHOT_TOKENS") or 6000)
CORRECTION_TOKENS = 2000
CANDIDATES = 6  # techniques proposées au tour de correction pour un identifiant inexistant, comme une recherche dans ATT&CK
FIELDS = ("entities", "techniques", "relations")
SCHEMA = _schema(*FIELDS)
_ARROW = re.compile(r"\s*-+\s*([a-z][a-z-]*?)\s*-+>\s*")  # « a --uses--> b » : la notation du prompt système, recopiée par le modèle


def task_prompt(text: str) -> str:
    return (
        f"{text}\n\n---\nTÂCHE : extrais du rapport ENTIER, en une seule réponse, sa couche sémantique STIX (aucun IOC). "
        "Éléments séparés par « ; » :\n"
        "1) « entities » : toutes les entités, chacune « type|nom » ou « type|nom|alias1,alias2 » (« software|<produit>|<éditeur> », "
        "« location|<pays>|<code ISO 3166-1> »), le nom tel que le texte l'écrit.\n"
        "2) « techniques » : chaque comportement de l'attaquant ou d'un logiciel malveillant, « nom de l'entité qui agit|identifiant "
        "ATT&CK v20.0|numéros des phrases qui le décrivent » (« <malware>|T####.###|12,13 »). UNE technique par comportement, la plus "
        "précise que le texte justifie : la sous-technique quand le texte nomme le mécanisme, sinon la technique parente.\n"
        "3) « relations » : les liens entre entités que le texte affirme, « nom source|relation|nom cible|numéros de phrases » "
        "(« <malware>|uses|<outil>|14;<campagne>|targets|<pays>|3 »). Le nom seul, sans son type, tel qu'écrit dans « entities » ; "
        "la phrase citée nomme les deux entités reliées."
    )


def correction_prompt(prompt: str, answer: dict, refused: list[str]) -> str:
    previous = "\n".join(f"{f} : {answer.get(f, '')}" for f in FIELDS)
    reasons = "\n".join(f"- {r}" for r in refused)
    return (
        f"{prompt}\n\nTA RÉPONSE :\n{previous}\n\nLIGNES REFUSÉES :\n{reasons}\n\n"
        "TÂCHE : renvoie SEULEMENT les lignes refusées corrigées, dans leur champ et leur format (identifiant ATT&CK v20.0 existant, "
        "entité déclarée dans « entities », phrase qui nomme les entités reliées) ; omets celles que le texte n'étaye pas."
    )


def unknown_technique(draft: DraftGraph, line: str, attack_id: str, numbers: str) -> str:
    """Refus d'un identifiant absent d'ATT&CK v20.0, avec les techniques les plus proches des phrases citées (index FTS5)."""
    text = " ".join(draft.by_uid[int(n)].text for n in re.findall(r"\d+", numbers) if int(n) in draft.by_uid)
    hits = draft.attack.search_techniques(text, limit=CANDIDATES) if text else []
    near = " ; ".join(f"{h.attack_id} {h.name}" for h in hits) or "aucune"
    return f"« {line} » : {attack_id} n'existe pas dans ATT&CK v20.0 ; techniques proches des phrases citées : {near}"


def apply(draft: DraftGraph, answer: dict, result) -> list[str]:
    """Ajoute les lignes valides d'une réponse (entités d'abord : les relations les nomment) ; retourne les refus avec leur raison."""
    refused: list[str] = []
    for line in rows(answer.get("entities")):
        fields = line.split("|")
        if len(fields) > 2 and fields[0].strip().lower() not in ("software", "location"):
            fields[2] = fields[2].replace(",", ";")  # alias séparés par des virgules dans la réponse, par « ; » pour `declare`
        _, err = draft.declare("|".join(fields))
        refused += [err] if err else []
    techniques = []
    for line in rows(answer.get("techniques")):
        parts = [p.strip() for p in _ARROW.sub("|uses|", line).split("|")]
        parts = [parts[0], *parts[2:]] if len(parts) == 4 and parts[1] == "uses" else parts
        if len(parts) != 3:
            refused.append(f"« {line} » : format attendu entité|technique|numéros de phrases")
        elif draft.attack.get(parts[1].upper()) is None:
            refused.append(unknown_technique(draft, line, parts[1].upper(), parts[2]))
        else:
            techniques.append(f"{parts[0]}|uses|{parts[1].upper()}|{parts[2]}")
    for line in techniques + [_ARROW.sub(r"|\1|", r) for r in rows(answer.get("relations"))]:
        err = draft.relate(line)
        refused += [err] if err else []
    draft.log += [f"reject {r}" for r in refused]
    result.refused += len(refused)
    return refused


def extract_article(art: dict, *, with_iocs: bool = True, with_rules: bool = True, **_):
    """Même contrat que `stix_agent.extract_article` (un `AgentResult`) : un appel, puis au plus un tour de correction."""
    t0 = time.perf_counter()
    title = clean_title(art["title"] or f"Article {art['id']}", art.get("site_name"))
    units = segment(art["clean_markdown"])
    draft = DraftGraph(units, ArticleContext(art["id"], art.get("site_name"), art.get("url"), art.get("title")))
    result = AgentResult(art["id"], draft, len(units), 1)
    system, prompt = system_prompt(), task_prompt(Pass(0, tuple(units)).render())
    try:
        answer = _call(result, 0, "oneshot", system, prompt, SCHEMA, ANSWER_TOKENS)
        refused = apply(draft, answer, result)
        if refused:
            fix = _call(result, 0, "corrections", system, correction_prompt(prompt, answer, refused), SCHEMA, CORRECTION_TOKENS)
            apply(draft, fix, result)
    except (TimeoutError, llm.requests.RequestException) as exc:
        result.failed_passages.append(f"article : {type(exc).__name__}: {exc}")
    entity_rows = draft.entity_rows()
    if with_iocs:
        result.iocs = extract_iocs(title, units, entity_rows, url=art.get("url"), published=parse_date(art.get("publication_date")))
    if with_rules:
        result.rules = extract_rules(title, art["clean_markdown"], entity_rows)
    result.accepted = len(draft.objects) + len(draft.evidence)
    result.seconds = time.perf_counter() - t0
    return result
