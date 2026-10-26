"""Règles de détection d'un article (YARA, Sigma) : texte par règles, rattachement par le modèle (réponse fermée).

    clean_markdown --analyse syntaxique--> règles candidates
        --validation--> YARA compilée par libyara, Sigma lue en YAML avec title, logsource et detection.condition
        --LLM, réponse fermée--> entité que la règle détecte, parmi les entités nommées par la règle ou sa section

Les règles sont lues dans le texte nettoyé complet, pas dans les unités de `segment` : une unité est une phrase dont les
espaces sont fusionnés, ce qui détruit le YAML d'une règle Sigma et coupe une règle YARA en morceaux.

Une règle qui ne se valide pas (souvent abîmée par le scraping : antislash perdu, adresse masquée par Cloudflare) n'est
jamais réparée ni émise : elle est comptée parmi les écartées, avec la raison.
"""

import re
import textwrap
from dataclasses import dataclass, field

import yaml
import yara

from backend.stix.rules import DetectionRule

from .evidence import mentions_prepared, prepare_text

from . import llm
from .iocs import Attachable, _trim, attachables

MAX_RULES_PER_CALL = 10
MAX_RULE_TOKENS = 120
MAX_ATTACH_CANDIDATES = 6
MAX_SHOWN_CHARS = 300

_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_FENCE = re.compile(r"^\s*(```|~~~)")
_YARA_START = re.compile(r"^[ \t]*(?:(?:private|global)\s+)*rule\s+([A-Za-z_]\w{0,127})\s*(?::[\w \t]+)?\s*\{", re.M)
_YARA_IMPORT = re.compile(r'^[ \t]*import\s+"(\w+)"', re.M)
_SIGMA_START = re.compile(r"^([ \t]*)title:[ \t]*\S", re.M)


@dataclass(frozen=True)
class DroppedRule:
    kind: str  # "yara" | "sigma"
    name: str
    reason: str


# --- Sections -------------------------------------------------------------------------------------------------------------
def _heading_paths(text: str) -> list[tuple[int, str]]:
    """(position, chemin de titres) de chaque titre ATX hors bloc de code, dans l'ordre du document."""
    out: list[tuple[int, str]] = []
    stack: list[tuple[int, str]] = []
    pos, in_fence = 0, False
    for line in text.splitlines(keepends=True):
        if _FENCE.match(line):
            in_fence = not in_fence
        elif not in_fence and (m := _HEADING.match(line)):
            level = len(m.group(1))
            while stack and stack[-1][0] >= level:
                stack.pop()
            stack.append((level, m.group(2).strip()))
            out.append((pos, " > ".join(t for _, t in stack)))
        pos += len(line)
    return out


def _section_at(paths: list[tuple[int, str]], pos: int) -> str:
    current = ""
    for start, path in paths:
        if start > pos:
            break
        current = path
    return current


# --- YARA -----------------------------------------------------------------------------------------------------------------
def _yara_end(text: str, start: int) -> int:
    """Position qui suit l'accolade fermant la règle ouverte à `start` (la première `{`), ou -1. Chaînes, commentaires et
    chaînes hexadécimales sont respectés ; les expressions régulières ne le sont pas (une accolade non équilibrée dans une
    regex est rare, la compilation l'écarterait)."""
    depth, i, n = 0, text.index("{", start), len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n and text[i] not in '"\n':
                i += 2 if text[i] == "\\" else 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                return -1
            i = end + 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end < 0 else end
            continue
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def _yara_meta(source: str, key: str) -> str | None:
    m = re.search(rf'^\s*{key}\s*=\s*"((?:[^"\\]|\\.)*)"', source, re.M | re.I)
    return m.group(1) if m else None


def find_yara(text: str, paths: list[tuple[int, str]]) -> tuple[list[DetectionRule], list[DroppedRule]]:
    imports = list(dict.fromkeys(_YARA_IMPORT.findall(text)))
    rules: list[DetectionRule] = []
    dropped: list[DroppedRule] = []
    for m in _YARA_START.finditer(text):
        name = m.group(1)
        end = _yara_end(text, m.start())
        if end < 0:
            dropped.append(DroppedRule("yara", name, "unclosed"))
            continue
        body = textwrap.dedent(text[m.start() : end].lstrip("\n"))
        used = [mod for mod in imports if re.search(rf"\b{mod}\.", body)]
        source = "".join(f'import "{mod}"\n' for mod in used) + ("\n" if used else "") + body
        if not re.search(r"\bcondition\s*:", body):
            dropped.append(DroppedRule("yara", name, "no-condition"))
            continue
        try:
            yara.compile(source=source)
        except yara.Error as exc:  # syntaxe, règle qui en appelle une autre absente de l'article, module indisponible…
            dropped.append(DroppedRule("yara", name, f"does-not-compile: {exc}"))
            continue
        rules.append(DetectionRule("yara", name, source, _section_at(paths, m.start()), _yara_meta(body, "description")))
    return rules, dropped


# --- Sigma ----------------------------------------------------------------------------------------------------------------
def _yaml_block(text: str, start: int, indent: str) -> str:
    """Lignes d'un document YAML qui commence à `start` : celles indentées au moins comme la première, lignes vides comprises
    tant que le document continue après elles. Au niveau de la première ligne, seuls une clé, un élément de liste ou un
    commentaire continuent le document ; un titre Markdown, une clôture de bloc ou une phrase l'arrêtent."""
    kept: list[str] = []
    blank = 0
    for line in text[start:].splitlines():
        if not line.strip():
            blank += 1
            continue
        if _FENCE.match(line) or not line.startswith(indent) or (not indent and _HEADING.match(line)):
            break
        rest = line[len(indent) :]
        if not rest[:1].isspace() and not re.match(r"(?:[^\s#\-][^:]*?:(?:\s|$)|-(?:\s|$)|#)", rest):  # clé (`Image|endswith:`), élément, commentaire
            break
        kept += [""] * blank + [line]
        blank = 0
    return textwrap.dedent("\n".join(kept))


def find_sigma(text: str, paths: list[tuple[int, str]]) -> tuple[list[DetectionRule], list[DroppedRule]]:
    rules: list[DetectionRule] = []
    dropped: list[DroppedRule] = []
    starts = list(_SIGMA_START.finditer(text))
    for i, m in enumerate(starts):
        # Une règle Sigma, même abîmée, a ses sections `logsource` et `detection` avant la règle suivante : décidé sur le
        # texte brut, pour qu'une règle dont le YAML ne se lit pas soit écartée et comptée, et non ignorée
        window = text[m.start() : starts[i + 1].start() if i + 1 < len(starts) else m.start() + 4000]
        if not (re.search(r"^\s*logsource\s*:", window, re.M) and re.search(r"^\s*detection\s*:", window, re.M)):
            continue  # un simple « title: » dans du texte ou une autre configuration : pas une règle Sigma
        source = _yaml_block(text, m.start(), m.group(1))
        title = source.splitlines()[0].split(":", 1)[1].strip().strip("'\"")
        try:
            doc = yaml.safe_load(source)
        except yaml.YAMLError as exc:
            dropped.append(DroppedRule("sigma", title, f"invalid-yaml: {str(exc).splitlines()[0]}"))
            continue
        detection = doc.get("detection") if isinstance(doc, dict) else None
        if not (isinstance(doc, dict) and isinstance(doc.get("title"), str) and isinstance(doc.get("logsource"), dict) and isinstance(detection, dict) and detection.get("condition")):
            dropped.append(DroppedRule("sigma", title, "missing-title-logsource-or-condition"))
            continue
        description = doc.get("description") if isinstance(doc.get("description"), str) else None
        rules.append(DetectionRule("sigma", doc["title"].strip(), source.rstrip() + "\n", _section_at(paths, m.start()), description and description.strip()))
    return rules, dropped


def find_rules(clean_markdown: str) -> tuple[list[DetectionRule], list[DroppedRule]]:
    """Règles YARA et Sigma valides de l'article, sans doublon (même type, même texte), et celles qui ont été écartées."""
    text = clean_markdown or ""
    paths = _heading_paths(text)
    yara_rules, yara_dropped = find_yara(text, paths)
    sigma_rules, sigma_dropped = find_sigma(text, paths)
    unique: dict[tuple[str, str], DetectionRule] = {}
    for rule in yara_rules + sigma_rules:
        unique.setdefault((rule.kind, rule.source), rule)
    return list(unique.values()), yara_dropped + sigma_dropped


# --- Rattachement : le modèle choisit l'entité détectée parmi des candidats --------------------------------------------
INDICATED_TYPES = frozenset({"malware", "tool", "threat-actor", "intrusion-set", "campaign", "incident"})  # cibles admises de `indicates`


@dataclass
class RuleResult:
    rules: list[DetectionRule] = field(default_factory=list)
    dropped: list[DroppedRule] = field(default_factory=list)
    calls: list[llm.LLMResult] = field(default_factory=list)


def _candidates(rule: DetectionRule, entities: list[Attachable]) -> list[Attachable]:
    """Entités nommées par la règle (nom, description) ou par le titre de sa section : « case_14373_bumblebee_document_iso »
    sous « Detections > YARA » propose BumbleBee."""
    scope = prepare_text(re.sub(r"[_\-]+", " ", f"{rule.heading} {rule.name} {rule.description or ''}"))
    return [e for e in entities if e.stix_type != "incident" and mentions_prepared(scope, e.terms)][:MAX_ATTACH_CANDIDATES]


def rule_system() -> str:
    return (
        "Tu es analyste en renseignement sur la menace (CTI). Chaque RÈGLE est une règle de détection (YARA ou Sigma) "
        "publiée par un rapport. Pour chaque règle, donne `to` : l'entité dont la règle détecte les fichiers ou l'activité, "
        "choisie parmi celles proposées pour CETTE règle. Choisis l'intrusion décrite (incident) si la règle détecte une "
        "activité de cette intrusion sans viser une des entités nommées, et none si elle ne vise rien de l'attaque décrite "
        "(détection générique d'un outil d'administration légitime, par exemple).\n\n"
        "FORMAT : un objet JSON {\"answers\": [{\"rule\": \"2\", \"to\": \"E3\"}]} avec UNE réponse par règle. Aucun commentaire."
    )


def rule_user(title: str, numbered: list[tuple[int, DetectionRule, list[Attachable]]]) -> str:
    lines = [f"Rapport : {title}", ""]
    for n, rule, cands in numbered:
        excerpt = _trim(rule.source, MAX_SHOWN_CHARS)
        lines += [
            f"[{n}] règle {rule.kind.upper()} « {rule.name} »" + (f" : {rule.description}" if rule.description else ""),
            f"    section : {rule.heading or '(sans titre)'}",
            f"    début : {excerpt}",
            "    entités possibles : " + " ; ".join(f"{e.eid} {e.name} ({e.stix_type})" for e in cands),
        ]
    return "\n".join(lines)


def rule_schema(numbered: list[tuple[int, DetectionRule, list[Attachable]]]) -> dict:
    eids = sorted({e.eid for _, _, cands in numbered for e in cands})
    return {
        "type": "object",
        "properties": {
            "answers": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {"rule": {"type": "string", "enum": [str(n) for n, _, _ in numbered]}, "to": {"type": "string", "enum": ["none", *eids]}},
                    "required": ["rule", "to"],
                },
            }
        },
        "required": ["answers"],
    }


def parse_rule_answers(parsed, numbered: list[tuple[int, DetectionRule, list[Attachable]]]) -> dict[int, str | None]:
    """`{numéro de règle: eid ou None}`. Règle hors du lot, entité non proposée pour CETTE règle : ignorées."""
    allowed = {n: {e.eid for e in cands} for n, _, cands in numbered}
    answers: dict[int, str | None] = {}
    raw = parsed.get("answers", []) if isinstance(parsed, dict) else []
    for entry in raw if isinstance(raw, list) else []:
        if not isinstance(entry, dict):
            continue
        try:
            n = int(str(entry.get("rule")).strip())
        except ValueError:
            continue
        to = str(entry.get("to", "none")).strip()
        if n in allowed and n not in answers and (to == "none" or to in allowed[n]):
            answers[n] = None if to == "none" else to
    return answers


def extract_rules(title: str, clean_markdown: str, entities: list[dict]) -> RuleResult:
    """Règles de détection de l'article et l'entité que chacune détecte. `entities` : entités finales (identifiant STIX).

    Une règle qui ne nomme aucune entité de l'article est rattachée à l'intrusion décrite sans appel au modèle. Une règle
    restée sans réponse (réponse tronquée) est conservée sans rattachement."""
    result = RuleResult()
    result.rules, result.dropped = find_rules(clean_markdown)
    if not result.rules:
        return result
    attach = [a for a in attachables(entities) if a.stix_type in INDICATED_TYPES]
    by_eid = {a.eid: a for a in attach}
    incident = next((a for a in attach if a.stix_type == "incident"), None)

    def bind(rule: DetectionRule, target: Attachable | None, confidence: int) -> None:
        if target is not None:
            rule.attach_id, rule.attach_type, rule.attach_name = target.stix_id, target.stix_type, target.name
        rule.confidence = confidence

    numbered: list[tuple[int, DetectionRule, list[Attachable]]] = []
    for rule in result.rules:
        cands = _candidates(rule, attach)
        if cands:
            numbered.append((len(numbered) + 1, rule, cands + ([incident] if incident else [])))
        else:
            bind(rule, incident, 55)
    batches = [numbered[i : i + MAX_RULES_PER_CALL] for i in range(0, len(numbered), MAX_RULES_PER_CALL)]
    system = rule_system()

    def classify(batch):
        res = llm.try_generate(system, rule_user(title, batch), rule_schema(batch), max_output_tokens=MAX_RULE_TOKENS)
        return res, parse_rule_answers(res.parsed, batch)

    answers: dict[int, str | None] = {}
    for res, parsed in map(classify, batches):  # Ollama traite les requêtes l'une après l'autre
        result.calls.append(res)
        answers.update(parsed)
    for n, rule, _ in numbered:
        if n not in answers:
            continue  # sans réponse : la règle reste, sans relation
        target = by_eid.get(answers[n]) if answers[n] else None
        bind(rule, target, 75 if target and target.stix_type != "incident" else 55 if target else 50)
    return result
