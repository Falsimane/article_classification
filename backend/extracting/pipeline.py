"""Extraction d'un article en trois étapes sur le texte entier : entités, vérification des techniques (avec outils), relations.

    [Rapport] -> phrases numérotées
      1. ENTITÉS (un appel contraint) : toutes les entités nommées, et les techniques ATT&CK écrites par le modèle
         (« identifiant|nom ATT&CK|numéros de phrases ») ;
      2. VÉRIFICATION DES TECHNIQUES (code) : l'identifiant existe dans ATT&CK v20.0 et y porte le nom que le modèle lui donne.
         Les refusées reviennent au modèle dans une courte conversation avec outils (`search_attack`, `get_attack`) : il cherche
         la bonne technique et la soumet ; une technique encore refusée est écartée ;
      3. RELATIONS (un appel contraint) : l'article et la liste numérotée des entités et techniques retenues ; le modèle répond
         « numéro source|relation|numéro cible|numéros de phrases ». Un appel de correction pour les lignes refusées.
    -> vérification STIX de `DraftGraph` (stix2 strict, phrases citées)
    -> IOC (valeurs par règles) et règles YARA / Sigma (texte par analyse syntaxique), rattachés aux entités retenues

Les appels 1 et 3 commencent par le même texte : le serveur le relit depuis son cache de préfixe. L'article entier doit tenir
dans le contexte du serveur (`--max-model-len`) ; sinon le serveur refuse l'appel et l'article est marqué en échec avec sa raison.
"""

import re
import time
from dataclasses import dataclass, field

from backend.extracting import llm
from backend.extracting.draft import DraftGraph, get_attack, search_attack_many
from backend.extracting.evidence import normalize_name, parse_date
from backend.extracting.iocs import IocResult, extract_iocs
from backend.extracting.rules import RuleResult, extract_rules
from backend.extracting.segment import render, segment
from backend.stix.attack import attack_id, get_attack_kb
from backend.stix.objects import ENTITY_CLASSES, ArticleContext

ENTITY_TOKENS = 4000
RELATION_TOKENS = 3000
CORRECTION_TOKENS = 1200
FIX_TURNS = 6  # tours de la conversation de correction des techniques
FIX_TOKENS = 1400
_TECHNIQUE = re.compile(r"T\d{4}(?:\.\d{3})?", re.I)


@dataclass
class CallStat:
    stage: str  # entities, techniques (un tour de la conversation avec outils), relations, corrections
    prompt_tokens: int
    output_tokens: int
    seconds: float
    truncated: bool


@dataclass
class ExtractionResult:
    article_id: int
    draft: DraftGraph
    n_units: int
    calls: list[CallStat] = field(default_factory=list)
    accepted: int = 0
    refused: int = 0
    failures: list[str] = field(default_factory=list)  # étapes perdues (délai dépassé, serveur injoignable, contexte dépassé)
    iocs: IocResult = field(default_factory=IocResult)
    rules: RuleResult = field(default_factory=RuleResult)
    seconds: float = 0.0

    @property
    def output_tokens(self) -> int:
        return sum(c.output_tokens for c in self.calls) + sum(c.output_tokens for c in self.iocs.calls + self.rules.calls)


def clean_title(title: str, site_name: str | None) -> str:
    """Titre sans le suffixe de l'éditeur (« Rapport - The DFIR Report » -> « Rapport »)."""
    for sep in (" - ", " | ", " – ", " — "):
        head, _, tail = title.rpartition(sep)
        if head and site_name and normalize_name(tail) == normalize_name(site_name):
            return head.strip()
    return title


# --- Réponses du modèle ---------------------------------------------------------------------------------------------------
def _schema(*fields: str) -> dict:
    """Un champ texte par liste : une chaîne JSON ne contient pas de retour à la ligne brut, la sortie est donc compacte (une liste
    JSON est écrite indentée par le modèle : 4 à 5 tokens par numéro au lieu de 1 à 2, mesuré)."""
    return {"type": "object", "properties": {f: {"type": "string"} for f in fields}, "required": list(fields)}


ENTITY_SCHEMA = _schema("entities", "techniques")
RELATION_SCHEMA = _schema("relations")


def rows(value) -> list[str]:
    """Éléments d'un champ texte, séparés par « ; » ou des retours à la ligne (une liste est aussi admise)."""
    items = value if isinstance(value, list) else re.split(r"[;\n]", str(value or ""))
    return [str(i).strip() for i in items if str(i).strip()]


def _index(raw: str, size: int) -> int | None:
    found = re.fullmatch(r"\s*[A-Za-z#]*\s*(\d+)\s*", str(raw))
    i = int(found.group(1)) if found else 0
    return i - 1 if 1 <= i <= size else None


def _call(result: ExtractionResult, stage: str, system: str, prompt: str, schema: dict, max_tokens: int) -> dict:
    r = llm.generate(system, prompt, schema, max_output_tokens=max_tokens)
    result.calls.append(CallStat(stage, r.prompt_tokens, r.output_tokens, r.seconds, r.output_tokens >= max_tokens))
    return r.parsed if isinstance(r.parsed, dict) else {}


# --- Prompts --------------------------------------------------------------------------------------------------------------
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


def entity_prompt(text: str) -> str:
    return (
        f"{text}\n\n---\nTÂCHE : relève les entités du rapport ENTIER (aucun IOC, aucune relation). Éléments séparés par « ; » :\n"
        "1) « entities » : toutes les entités, chacune « type|nom » ou « type|nom|alias1,alias2 » (« software|<produit>|<éditeur> », "
        "« location|<pays>|<code ISO 3166-1> »), le nom tel que le texte l'écrit. Pas de technique ici.\n"
        "2) « techniques » : chaque comportement de l'attaquant ou d'un logiciel malveillant (exécution, persistance, découverte, "
        "communication, chiffrement, exfiltration, livraison, obfuscation…), « identifiant ATT&CK v20.0|nom ATT&CK de la "
        "technique|numéros des phrases qui le décrivent » (« T####.###|<nom>|12,13 »). UNE technique par comportement, la plus "
        "précise que le texte justifie : la sous-technique quand le texte nomme le mécanisme, sinon la technique parente."
    )


def relation_prompt(text: str, table: list[str]) -> str:
    numbered = "\n".join(f"{i}. {e}" for i, e in enumerate(table, 1)) or "(aucune)"
    return (
        f"{text}\n\n---\nENTITÉS ET TECHNIQUES DU RAPPORT (numérotées) :\n{numbered}\n\n"
        "TÂCHE : « relations » : tous les liens que le texte affirme entre ces éléments, séparés par « ; », chacun « numéro "
        "source|relation|numéro cible|numéros de phrases » (« 3|uses|2|12,13;3|attributed-to|1|5 »). Chaque technique est reliée à "
        "l'entité qui l'exécute (« numéro de l'entité|uses|numéro de la technique|phrases ») : le malware ou l'outil quand le texte "
        "décrit sa capacité, la campagne quand c'est une étape de l'opération. La phrase citée (ou les 3 précédentes de sa section, "
        "ou son titre) nomme le malware, l'outil, la CVE ou la victime reliés."
    )


def correction_prompt(prompt: str, answer: dict, refused: list[tuple[str, str]]) -> str:
    reasons = "\n".join(f"- « {row} » : {reason}" for row, reason in refused)
    return (
        f"{prompt}\n\nTA RÉPONSE :\nrelations : {answer.get('relations', '')}\n\nLIGNES REFUSÉES :\n{reasons}\n\n"
        "TÂCHE : renvoie SEULEMENT les lignes refusées corrigées, même format (citer la phrase qui nomme les entités reliées) ; "
        "omets celles que le texte n'étaye pas."
    )


# --- Étape 1 : entités ----------------------------------------------------------------------------------------------------
def declare_entities(draft: DraftGraph, answer: dict, result: ExtractionResult) -> list[str]:
    """Entités acceptées (identifiants STIX, sans les techniques), dans l'ordre de la réponse."""
    sids: list[str] = []
    for line in rows(answer.get("entities")):
        fields = line.split("|")
        if len(fields) > 2 and fields[0].strip().lower() not in ("software", "location"):
            fields[2] = fields[2].replace(",", ";")  # alias séparés par des virgules dans la réponse, par « ; » pour `declare`
        sid, err = draft.declare("|".join(fields))
        if err:
            draft.log.append(f"reject {err}")
            result.refused += 1
        elif sid not in sids and draft.type_of(sid) != "attack-pattern":
            sids.append(sid)
            result.accepted += 1
    return sids


# --- Étape 2 : vérification des techniques --------------------------------------------------------------------------------
def same_name(given: str, obj: dict) -> bool:
    """Le nom donné par le modèle est celui de l'identifiant (« PowerShell » ou « Command and Scripting Interpreter: PowerShell »)."""
    g, short, full = normalize_name(given), normalize_name(obj["name"]), normalize_name(obj["full_name"])
    return bool(g) and (g in (short, full) or short in g or g in full)


def check_technique(draft: DraftGraph, line: str) -> tuple[str | None, list[int], str | None]:
    """« identifiant|nom|numéros » -> (identifiant STIX, phrases citées, refus). L'identifiant doit exister dans ATT&CK v20.0 et y
    porter le nom donné : un identifiant voisin écrit de mémoire (bon concept, mauvais numéro) est refusé comme un inexistant."""
    parts = [p.strip() for p in str(line).split("|")]
    found = _TECHNIQUE.search(parts[0]) if parts else None
    if not found:
        return None, [], "format attendu identifiant ATT&CK|nom|numéros de phrases"
    aid, name = found.group(0).upper(), parts[1] if len(parts) > 1 else ""
    uids = [n for n in map(int, re.findall(r"\d+", " ".join(parts[2:]))) if n in draft.by_uid]
    status, replaced = draft.attack.status(aid)
    if status == "unknown":
        draft.hallucinated.append(aid)
        return None, uids, f"{aid} n'existe pas dans ATT&CK v{draft.attack.version}"
    obj = draft.attack.get(replaced if status == "revoked" and replaced else aid)
    if name and obj and not same_name(name, obj):
        return None, uids, f"{obj['attack_id']} est « {obj['full_name']} » dans ATT&CK v{draft.attack.version}, pas « {name} »"
    sid, err = draft.technique(aid)
    return sid, uids, err


def accept_techniques(draft: DraftGraph, lines: list, techniques: dict[str, list[int]], result: ExtractionResult) -> list[tuple[str, list[int], str]]:
    """Ajoute les techniques valides à `techniques` (identifiant STIX -> phrases citées) ; retourne les refus."""
    refused = []
    for line in lines:
        sid, uids, err = check_technique(draft, str(line))
        if err:
            refused.append((str(line), uids, err))
            draft.log.append(f"reject « {line} » : {err}")
            result.refused += 1
        else:
            known = techniques.setdefault(sid, [])
            known += [n for n in uids if n not in known]
            result.accepted += 1
    return refused


FIX_SYSTEM = """Tu es analyste CTI. Des techniques MITRE ATT&CK v20.0 proposées pour un rapport de menace ont été refusées (identifiant inexistant, ou identifiant qui ne porte pas le nom donné). Pour chacune, trouve la technique qui correspond au comportement décrit par les phrases citées : appelle search_attack (une requête en anglais par comportement, toutes en un appel), get_attack pour départager deux techniques voisines, puis submit avec les lignes corrigées « identifiant|nom ATT&CK|numéros de phrases ». N'écris qu'un identifiant renvoyé par un outil. Omets un comportement qu'aucune technique ne décrit. Quand submit accepte tout, réponds « FIN »."""


def fix_tools() -> list[dict]:
    tactics = [t for t, _ in get_attack_kb().tactics()]

    def fn(name: str, description: str, properties: dict, required: list[str]) -> dict:
        return {"type": "function", "function": {"name": name, "description": description, "parameters": {"type": "object", "properties": properties, "required": required}}}

    return [
        fn(
            "search_attack",
            "Cherche dans MITRE ATT&CK v20.0 les techniques qui correspondent aux comportements de l'attaquant. Donner en UN appel "
            "la liste de TOUS les comportements, une requête par comportement, en anglais avec les mots du comportement (commande, "
            "mécanisme, but), pas le nom d'un acteur. Retourne, pour chaque requête, identifiant, nom, tactiques et définition des "
            "techniques candidates.",
            {"queries": {"type": "array", "description": "une entrée par comportement", "items": {"type": "object", "properties": {
                "query": {"type": "string", "description": "comportement en anglais : « <action> <mécanisme> to <but> »"},
                "tactic": {"type": "string", "enum": tactics, "description": "facultatif : restreindre à une tactique"}},
                "required": ["query"]}}},
            ["queries"],
        ),  # fmt: skip
        fn(
            "get_attack",
            "Fiche ATT&CK v20.0 d'un identifiant (T####, T####.###) : définition complète, tactiques, sous-techniques. À utiliser "
            "pour départager deux techniques voisines ou choisir la sous-technique.",
            {"id": {"type": "string"}},
            ["id"],
        ),
        fn(
            "submit",
            "Soumet les techniques corrigées ; chacune est vérifiée contre ATT&CK v20.0, les refus reviennent avec leur raison.",
            {"techniques": {"type": "array", "items": {"type": "string"}, "description": "« T####.###|nom ATT&CK|numéros de phrases »"}},
            ["techniques"],
        ),
    ]


def fix_prompt(draft: DraftGraph, refused: list[tuple[str, list[int], str]]) -> str:
    blocks = []
    for line, uids, reason in refused:
        quotes = "\n".join(f"  [{n}] {draft.by_uid[n].text}" for n in uids) or "  (aucune phrase valide citée)"
        blocks.append(f"- « {line} » : {reason}\n{quotes}")
    return "TECHNIQUES REFUSÉES ET PHRASES CITÉES :\n" + "\n".join(blocks)


def fix_techniques(draft: DraftGraph, refused: list[tuple[str, list[int], str]], techniques: dict[str, list[int]], result: ExtractionResult) -> None:
    """Conversation avec outils : le modèle cherche et soumet les techniques corrigées ; les acceptées rejoignent `techniques`."""
    kb, tools = draft.attack, fix_tools()
    messages = [{"role": "system", "content": FIX_SYSTEM}, {"role": "user", "content": fix_prompt(draft, refused)}]
    for _ in range(FIX_TURNS):
        r = llm.chat(messages, tools, max_output_tokens=FIX_TOKENS)
        messages.append(r.message)
        result.calls.append(CallStat("techniques", r.prompt_tokens, r.output_tokens, r.seconds, r.truncated))
        if not r.tool_calls:
            if not any(m.get("role") == "tool" for m in messages):
                draft.log.append("techniques : le modèle n'a appelé aucun outil, les refusées sont écartées")
            return
        done = False
        for call in r.tool_calls:
            name, args = call["name"], call["arguments"]
            if name == "search_attack":
                queries = args.get("queries") or [{"query": args.get("query", ""), "tactic": args.get("tactic")}]
                out = search_attack_many(kb, queries if isinstance(queries, list) else [queries])
            elif name == "get_attack":
                out = get_attack(kb, str(args.get("id", "")))
            elif name == "submit":
                lines = args.get("techniques") or []
                errors = accept_techniques(draft, lines if isinstance(lines, list) else [lines], techniques, result)
                out = "Tout est accepté." if not errors else "Refusées :\n" + "\n".join(f"- « {line} » : {err}" for line, _, err in errors)
                done = not errors
            else:
                out = f"outil inconnu : {name}"
            draft.log.append(f"outil {name} {args}")
            messages.append({"role": "tool", "tool_call_id": call["id"], "content": out})
        if done:
            return


# --- Étape 3 : relations --------------------------------------------------------------------------------------------------
def apply_relations(draft: DraftGraph, answer: dict, sids: list[str], result: ExtractionResult) -> list[tuple[str, str]]:
    """Ajoute les relations valides ; une technique ou un objet ATT&CK est désigné par son identifiant, pas par son nom (« PowerShell »
    est aussi un outil)."""

    def ref(sid: str) -> str:
        return attack_id(draft.objects[sid]) or draft.name_of(sid).replace("|", "/").strip()

    refused: list[tuple[str, str]] = []
    for row in rows(answer.get("relations")):
        parts = [p.strip() for p in row.split("|")]
        src, dst = (_index(parts[0], len(sids)), _index(parts[2], len(sids))) if len(parts) == 4 else (None, None)
        if src is None or dst is None:
            refused.append((row, "format attendu numéro source|relation|numéro cible|numéros de phrases"))
            continue
        err = draft.relate(f"{ref(sids[src])}|{parts[1]}|{ref(sids[dst])}|{parts[3]}")
        if err:
            refused.append((row, err.split(" : ", 1)[-1]))
        else:
            result.accepted += 1
    draft.log += [f"reject « {row} » : {reason}" for row, reason in refused]
    result.refused += len(refused)
    return refused


def extract_article(art: dict) -> ExtractionResult:
    """Extrait un article (ligne de `knowledge` jointe à sa classification) : graphe vérifié, IOC et règles."""
    t0 = time.perf_counter()
    title = clean_title(art["title"] or f"Article {art['id']}", art.get("site_name"))
    units = segment(art["clean_markdown"])
    draft = DraftGraph(units, ArticleContext(art["id"], art.get("site_name"), art.get("url"), art.get("title")))
    result = ExtractionResult(art["id"], draft, len(units))
    system, text = system_prompt(), render(units)
    try:
        inv = _call(result, "entities", system, entity_prompt(text), ENTITY_SCHEMA, ENTITY_TOKENS)
        sids = declare_entities(draft, inv, result)  # avant les techniques : un nom d'entité (« PowerShell ») prime sur celui d'une technique
        techniques: dict[str, list[int]] = {}
        refused = accept_techniques(draft, rows(inv.get("techniques")), techniques, result)
        if refused:
            try:
                fix_techniques(draft, refused, techniques, result)
            except (TimeoutError, llm.requests.RequestException) as exc:  # sans correction, les techniques valides restent
                result.failures.append(f"correction des techniques : {type(exc).__name__}: {exc}")

        table = [f"{draft.type_of(s)}|{draft.name_of(s)}" for s in sids]
        for sid, uids in techniques.items():
            table.append(f"attack-pattern|{attack_id(draft.objects[sid])} {draft.name_of(sid)} (phrases {','.join(map(str, uids)) or '?'})")
        sids += list(techniques)
        if len(sids) > 1:
            prompt = relation_prompt(text, table)
            rel = _call(result, "relations", system, prompt, RELATION_SCHEMA, RELATION_TOKENS)
            refused_rel = apply_relations(draft, rel, sids, result)
            if refused_rel:  # le prompt commence par le précédent : relu depuis le cache du serveur
                fix = _call(result, "corrections", system, correction_prompt(prompt, rel, refused_rel), RELATION_SCHEMA, CORRECTION_TOKENS)
                apply_relations(draft, fix, sids, result)
    except (TimeoutError, llm.requests.RequestException) as exc:
        result.failures.append(f"article : {type(exc).__name__}: {exc}")
    entity_rows = draft.entity_rows()
    result.iocs = extract_iocs(title, units, entity_rows, url=art.get("url"), published=parse_date(art.get("publication_date")))
    result.rules = extract_rules(title, art["clean_markdown"], entity_rows)
    result.seconds = time.perf_counter() - t0
    return result
