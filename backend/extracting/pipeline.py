"""Extraction d'un article en trois étapes sur le texte entier : entités et comportements, techniques choisies parmi des candidates
ATT&CK, relations.

    [Rapport] -> phrases numérotées
      1. ENTITÉS (un appel contraint) : toutes les entités nommées, et chaque comportement de l'attaquant décrit en anglais
         (« numéros de phrases|comportement|identifiant ATT&CK présumé ») ;
         1 bis. (CTI_SECTION_PASS=on, expérimental) mêmes comportements, relevés bloc par bloc d'environ 1 500 tokens ;
         1 ter. (CTI_OPERATIONS=on) OPÉRATIONS (un appel contraint) : les campagnes que décrit le rapport, décidées à part
         (phrases, nom descriptif, groupe auquel le texte les attribue) ; elles remplacent celles de l'appel 1 ;
      2. TECHNIQUES : le code cherche dans ATT&CK v20.0 (FTS5 sur les définitions et les exemples de procédures, sans ceux
         tirés de l'article lui-même) les techniques candidates de chaque comportement, plus l'identifiant présumé ; le modèle
         choisit, par lettres, celles dont la définition décrit le même comportement que les phrases citées (un appel
         contraint par lot). Une technique retenue existe donc toujours ; elle n'est plus écrite de mémoire. Avec
         CTI_CARRIER=on, il désigne aussi l'entité qui exécute le comportement (« numéro:lettres:porteur ») et le code crée
         la relation « uses ». Le comportement en anglais devient la description (la procédure) de cette relation ;
      3. RELATIONS (un appel contraint) : l'article et la liste numérotée des entités et techniques retenues ; le modèle répond
         « numéro source|relation|numéro cible|numéros de phrases ». Un appel de correction pour les lignes refusées, un pour
         relier les îlots ;
      4. VÉRIFICATION (un appel contraint par lot) : le modèle juge chaque relation acceptée contre le texte (« o » / « n ») ; les
         non étayées sont retirées, et avec elles les entités qui n'ont plus de relation.
    -> vérification STIX de `DraftGraph` à chaque relation (stix2 strict, table `RELATIONS`, phrases citées)
    -> IOC (valeurs par règles) et règles YARA / Sigma (texte par analyse syntaxique), rattachés aux entités retenues

Les appels 1, 2 et 3 commencent par le même texte : le serveur le relit depuis son cache de préfixe. L'article entier doit tenir
dans le contexte du serveur (`--max-model-len`) ; sinon le serveur refuse l'appel et l'article est marqué en échec avec sa raison.
"""

import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from backend.extracting import llm
from backend.extracting.agents import CarrierDisambiguationAgent, RelationWeaverAgent, TargetSpecialistAgent, ThreatModelerAgent, TTPHunterAgent
from backend.extracting.graph.draft import DraftGraph, relationship_type_of
from backend.preprocessing.cleaning.text.evidence import mentions, normalize_name, parse_date
from backend.extracting.observables.iocs import IocResult, extract_iocs
from backend.extracting.observables.rules import RuleResult, extract_rules
from backend.preprocessing.cleaning.text.segment import Unit, render, segment
from backend.extracting.stix.attack import TechniqueHit, attack_id, report_key
from backend.extracting.stix.objects import ENTITY_CLASSES, ArticleContext, relation_table

ENTITY_TOKENS = 4000
RELATION_TOKENS = 3000
CORRECTION_TOKENS = 1200
CHOICE_TOKENS = 600
# Techniques proposées par la recherche pour un comportement, en plus de l'identifiant présumé par le modèle et de sa parente.
# Rappel de la recherche mesuré hors ligne (comportements de v2_base_1) : 72 % à 6, 83 % à 15, 87 % à 20 (CTI_CANDIDATES).
CANDIDATES = max(1, int(os.environ.get("CTI_CANDIDATES") or 6))
_LETTERS = "abcdefghijklmnopqrst"
MAX_OPTIONS = min(len(_LETTERS), CANDIDATES + 4)  # lettres d'un comportement : recherche + identifiant présumé et parente
# Comportements par appel de choix : au plus ~120 lignes de candidates, pour que la liste tienne dans le contexte avec l'article
CHOICE_BATCH = max(4, 120 // MAX_OPTIONS)
VERIFY_QUOTES = 10  # phrases citées montrées au vérificateur par relation
VERIFY_BATCH = 40  # relations jugées par appel de vérification
VERIFY_TOKENS_PER_ROW = 8  # « 12:o:b; »
_TECHNIQUE = re.compile(r"T\d{4}(?:\.\d{3})?", re.I)


def _flag(name: str) -> bool:
    return os.environ.get(name, "off").strip().lower() in ("on", "1", "yes", "true")


# Passe par bloc (expérimentale, CTI_SECTION_PASS=on) : après l'appel « entités », un appel par bloc d'environ 1 500 tokens relève
# les comportements de ce bloc seul. L'article entier reste en tête du prompt (même préfixe, relu depuis le cache du serveur) ;
# seule la consigne finale désigne le bloc. Mesure : les entités citées tard dans l'article sont moins souvent trouvées.
SECTION_PASS = _flag("CTI_SECTION_PASS")
BLOCK_CHARS = 6000
SECTION_TOKENS = 1500
# Porteur de chaque technique choisi avec elle (CTI_CARRIER=on) : un choix fermé parmi les entités numérotées, au lieu d'une
# décision implicite au milieu de l'appel « relations ». Mesure : 33 relations du gold ont la bonne technique et la mauvaise source.
# CTI_CARRIER=separate : même choix, mais dans un appel à part après celui des techniques, dont le prompt reste inchangé (mesure :
# demandé avec les lettres, le porteur coûte 2 à 3 techniques choisies).
CARRIER_MODE = os.environ.get("CTI_CARRIER", "off").strip().lower()
CARRIER = CARRIER_MODE in ("on", "1", "yes", "true")
CARRIER_SEPARATE = CARRIER_MODE == "separate"
CARRIER_BATCH = 30  # techniques retenues par appel « porteurs »
CARRIER_TOKENS = 3  # « :12 » par comportement
# Opérations décidées par un appel à part (CTI_OPERATIONS=on) : la campagne est l'extrémité de près de la moitié des relations,
# et l'appel « entités » en crée trop peu (ou une de trop) quand elle est sans nom.
OPERATIONS = _flag("CTI_OPERATIONS")
OPERATION_TOKENS = 400  # une opération tient en ~40 tokens ; la consigne borne les phrases citées (mesure : une liste de 70 numéros
# avait épuisé le budget avant la seconde opération)
# Victimes décidées par un appel à part (CTI_VICTIMS=on) : nom copié du texte, secteur STIX, pays, attaquant. Mesure : les
# victimes sont la catégorie la plus oubliée (jamais proposées, ou leur « targets » refusé faute d'être nommées dans la phrase).
VICTIMS = _flag("CTI_VICTIMS")
VICTIM_TOKENS = 600
# Rattrapage des noms (CTI_MENTIONS=on) : CVE et noms ATT&CK écrits dans l'article mais absents de la liste ; le modèle dit pour
# chacun s'il appartient à l'activité décrite. Le code repère, le modèle décide.
MENTIONS = _flag("CTI_MENTIONS")
MAX_MENTIONS = 25
# Seconde lecture des comportements (CTI_SECOND_LOOK=on) : après le choix, le modèle relit les phrases de chaque comportement face
# aux techniques retenues et relève les mécanismes qu'elles décrivent sans qu'aucune ne les couvre ; chacun devient un comportement
# cherché et choisi comme les autres. Mesure (v5_base_1/2) : les 16 techniques du gold « absentes des candidates » sont toutes
# dans un comportement composite (plusieurs mécanismes sur une ligne) dont la recherche n'a suivi que le mécanisme principal.
SECOND_LOOK = _flag("CTI_SECOND_LOOK")
SECOND_LOOK_TOKENS = 1500
# Décomposition multi-agents (CTI_MULTI_AGENT=on par défaut)
MULTI_AGENT = os.environ.get("CTI_MULTI_AGENT", "on").strip().lower() in ("on", "1", "yes", "true")
# Échantillonnage multi-températures pour l'agent TTP (CTI_MULTI_TEMP=on)
MULTI_TEMP = _flag("CTI_MULTI_TEMP")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
_CARRIER_TYPES = ("campaign", "intrusion-set", "threat-actor", "malware", "tool")
_GROUP_TYPES = ("intrusion-set", "threat-actor")


@dataclass
class CallStat:
    stage: str  # entities, techniques (un lot de choix), relations, corrections, îlots
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
    # Propositions refusées par la vérification, pour situer la perte d'un élément du gold (cti-eval) : (ligne, raison) ;
    # relations : (source, relation, cible, raison), extrémités en identifiants STIX
    refused_entities: list[tuple[str, str]] = field(default_factory=list)
    refused_techniques: list[tuple[str, str]] = field(default_factory=list)
    refused_relations: list[tuple[str, str, str, str]] = field(default_factory=list)
    # Chaque comportement relevé : phrases, candidates proposées et techniques choisies (rappel de la recherche à l'évaluation)
    behaviors: list[dict] = field(default_factory=list)
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


ENTITY_SCHEMA = _schema("entities", "behaviors")
OPERATION_SCHEMA = _schema("operations")
VICTIM_SCHEMA = _schema("victims")
MENTION_SCHEMA = _schema("mentions")
CHOICE_SCHEMA = _schema("choices")
VERIFY_SCHEMA = _schema("verdicts")
RELATION_SCHEMA = _schema("relations")


def rows(value) -> list[str]:
    """Éléments d'un champ texte, séparés par « ; » ou des retours à la ligne (une liste est aussi admise)."""
    items = value if isinstance(value, list) else re.split(r"[;\n]", str(value or ""))
    return [str(i).strip() for i in items if str(i).strip()]


def _numbers(raw: str) -> list[int]:
    """Numéros de phrases d'un champ : « 4,5,9 » ou plages « 14-20 »."""
    out: list[int] = []
    for a, b in re.findall(r"(\d+)(?:\s*-\s*(\d+))?", raw):
        out += list(range(int(a), int(b) + 1)) if b and int(b) >= int(a) else [int(a)]
    return list(dict.fromkeys(out))


def _index(raw: str, size: int) -> int | None:
    found = re.fullmatch(r"\s*[A-Za-z#]*\s*(\d+)\s*", str(raw))
    i = int(found.group(1)) if found else 0
    return i - 1 if 1 <= i <= size else None


def _call(
    result: ExtractionResult,
    stage: str,
    system: str,
    prompt: str,
    schema: dict,
    max_tokens: int,
    temperature: float | None = None,
    enable_thinking: bool | None = None,
) -> dict:
    r = llm.generate(system, prompt, schema, max_output_tokens=max_tokens, stage=stage, temperature=temperature, enable_thinking=enable_thinking)
    result.calls.append(CallStat(stage, r.prompt_tokens, r.output_tokens, r.seconds, r.output_tokens >= max_tokens))
    return r.parsed if isinstance(r.parsed, dict) else {}


# --- Prompts --------------------------------------------------------------------------------------------------------------
def system_prompt() -> str:
    return f"""Tu es analyste CTI. Tu construis la couche sémantique STIX 2.1 d'un rapport de menace : qui (acteurs, campagnes), avec quoi (malwares, outils, infrastructures nommées), comment (techniques MITRE ATT&CK v20.0), contre quoi (vulnérabilités, produit visé, victimes). Le rapport est découpé en phrases numérotées [n].

ENTITÉS (types : {', '.join(ENTITY_CLASSES)}) :
- intrusion-set : groupe d'attaquants nommé (nom ou code de suivi donné par le rapport ou un éditeur). threat-actor : personne ou organisation réelle identifiée.
- campaign : seulement une opération que le rapport décrit (une vague ou un ensemble d'intrusions contre des cibles, sur une période ; une intrusion racontée de bout en bout en est une). UNE campagne par vague distincte (cibles ou périodes différentes), nom descriptif (« Campagne <acteur> contre <cible>, <période> »). Ne crée jamais de campagne ni d'intrusion-set pour relier les éléments : un rapport qui analyse un malware, un outil, une vulnérabilité ou une capacité d'un acteur sans décrire d'opération n'a pas de campagne, et un intrusion-set n'existe que si le texte nomme le groupe.
- malware : code malveillant nommé, ou composant que l'article désigne par un libellé descriptif (reprendre ce libellé).
- tool : logiciel légitime détourné par l'attaquant (binaire natif du système, outil d'administration, packer, obfuscateur). Jamais une fonction, un appel système ou une bibliothèque de programmation.
- infrastructure : service ou infrastructure NOMMÉ utilisé par l'attaquant. Jamais une IP, un domaine ou une URL.
- vulnerability : une CVE. software : produit légitime visé (« software|<produit>|<éditeur> »).
- identity : victime (organisation, secteur) ou éditeur du produit visé. location : pays ou région ciblés (« location|<pays>|<code ISO 3166-1> »).
JAMAIS : l'auteur du rapport, les chercheurs ou éditeurs de sécurité comme acteur ou victime ; un hachage, une IP, un domaine, une URL ou un nom de fichier ordinaire (ce sont des IOC, hors périmètre) ; ce que le rapport cite d'autres opérations passées comme activité de la campagne décrite.

RELATIONS (STIX 2.1, source --relation--> cible ; aucune autre n'est admise) :
{relation_table()}
« targets » mène à une victime, un lieu visé, la vulnérabilité ou le produit attaqués : jamais à l'auteur du rapport, à une agence ou un éditeur qui publie une alerte, à un chercheur. Une technique d'exploitation --targets--> la vulnérabilité et le produit qu'elle exploite. software --related-to--> identity : l'éditeur du produit.
Qui emploie une technique : le malware quand le texte décrit sa capacité propre ; sinon celui à qui le texte attribue l'action : la campagne décrite ou, sans campagne, l'acteur nommé (y compris avec un outil, qui est alors relié à lui par « uses »). Sans campagne ni acteur, la technique reste reliée à ce qui la porte (malware, vulnérabilité et produit visés).
N'invente rien que le texte ne dise."""


def entity_prompt(text: str) -> str:
    return (
        f"{text}\n\n---\nTÂCHE : relève les entités du rapport ENTIER (aucun IOC, aucune relation). Éléments séparés par « ; » :\n"
        "1) « entities » : toutes les entités, chacune « type|nom » ou « type|nom|alias1,alias2 » (« software|<produit>|<éditeur> », "
        "« location|<pays>|<code ISO 3166-1> »), le nom tel que le texte l'écrit. Pas de technique ici.\n"
        "2) « behaviors » : chaque comportement de l'attaquant ou d'un logiciel malveillant (accès initial, exécution, persistance, "
        "élévation, évasion, accès aux identifiants, découverte, mouvement latéral, collecte, communication, exfiltration, impact…), "
        "« numéros des phrases qui le décrivent|le comportement en anglais, avec les mots du mécanisme (action, moyen, but), sans "
        "nom d'acteur ni IOC|identifiant ATT&CK v20.0 présumé ou rien » (« 12,13|<action> <mechanism> to <goal>|T####.### »). "
        "UN comportement par ligne, écrit une seule fois même si plusieurs phrases le décrivent."
    )


def section_prompt(text: str, block: list[Unit]) -> str:
    first, last = block[0].uid, block[-1].uid
    titles = " ; ".join(dict.fromkeys(u.heading_path for u in block if u.heading_path)) or "début du rapport"
    return (
        f"{text}\n\n---\nTÂCHE : relis les phrases [{first}] à [{last}] SEULEMENT (sections : {titles}) et relève chaque "
        "comportement de l'attaquant ou d'un logiciel malveillant qu'elles décrivent (accès initial, exécution, persistance, "
        "dissimulation/évasion, découverte, C2, exfiltration, impact...). "
        "Ce qui a été observé ou attribué à l'attaquant, jamais ce que le défenseur devrait faire.\n"
        "« behaviors » : éléments séparés par « ; », chacun sous la forme d'un tuple comportemental atomique :\n"
        "« numéros_phrases | outil_ou_vecteur_ou_- | action_et_but_en_anglais | tactique_mitre | T####.###_présumé_ou_- »\n"
        "Tactiques admises : initial-access, execution, persistence, privilege-escalation, stealth, defense-impairment, "
        "credential-access, discovery, lateral-movement, collection, command-and-control, exfiltration, impact.\n"
        "UN comportement par ligne ; rien si ces phrases n'en décrivent aucun."
    )


def operation_prompt(text: str, groups: list[str], known: list[str]) -> str:
    numbered = "\n".join(f"{i}. {g}" for i, g in enumerate(groups, 1)) or "(aucun)"
    return (
        f"{text}\n\n---\nGROUPES D'ATTAQUANTS NOMMÉS (numérotés) :\n{numbered}\n"
        f"CAMPAGNES PROPOSÉES À L'ÉTAPE PRÉCÉDENTE : {' ; '.join(known) or '(aucune)'}\n\n"
        "TÂCHE : décide des opérations que le rapport décrit. Une opération est une activité OBSERVÉE de l'attaquant contre des "
        "cibles, située dans le temps ou par ses victimes : une vague de diffusion, une série d'intrusions, une compromission "
        "racontée de bout en bout, même si le rapport ne lui donne pas de nom. N'en est PAS une : l'analyse d'un malware, d'un "
        "outil ou d'une vulnérabilité sans activité observée, le profil ou les habitudes d'un groupe, une tendance générale, une "
        "opération passée que le rapport ne fait que rappeler. « operations » : la liste définitive, éléments séparés par « ; », "
        "chacun « numéros des phrases qui la décrivent le mieux (5 au plus)|nom descriptif|numéro du groupe auquel le texte l'attribue ou - » "
        "(« 4,5,9|Campagne <acteur> contre <cible>, <période>|1 »). UNE opération par vague distincte (cibles ou périodes "
        "différentes) ; reprends le nom exact d'une campagne proposée si c'est la même. Chaîne vide si le rapport n'en décrit aucune."
    )


def victim_prompt(text: str, attackers: list[str]) -> str:
    from stix2.v21.vocab import INDUSTRY_SECTOR

    numbered = "\n".join(f"{i}. {a}" for i, a in enumerate(attackers, 1)) or "(aucun)"
    return (
        f"{text}\n\n---\nATTAQUANTS (numérotés) :\n{numbered}\n\n"
        "TÂCHE : « victims » : les victimes que le rapport dit visées par l'activité décrite, au grain où il les décrit : un "
        "groupe de victimes par type d'organisation et par pays (dix hôpitaux d'un même pays = UNE victime « hospitals ») ; "
        "une organisation nommée seulement si le texte la nomme comme victime. Éléments séparés par « ; », chacun « numéros des "
        "phrases qui l'affirment (5 au plus)|nom copié du texte, dans sa langue, sans le traduire|classe|secteur ou -|code pays "
        "ISO 3166-1 de la victime ou -|numéro de l'attaquant ou - » (« 7,8|<victimes>|class|healthcare|<code>|1 »). Classe : "
        "organization (organisation nommée), class (ensemble d'organisations, secteur), group (population, groupe de "
        f"personnes), individual (personne). Secteurs : {', '.join(sorted(INDUSTRY_SECTOR))}. Une ville, une région ou un pays "
        "n'est jamais une victime : c'est le code pays de la victime. JAMAIS : l'auteur du rapport, une agence ou un éditeur qui "
        "publie une alerte, un chercheur ; une marque ou un service usurpé dans un leurre ; un fournisseur dont l'infrastructure "
        "est détournée par l'attaquant (hébergeur, cloud, CDN, messagerie, dépôt de code) ; une cible seulement évoquée, supposée "
        "ou menacée ; la victime d'une autre opération que celle décrite. Chaîne vide si le rapport n'en nomme aucune."
    )


def mention_prompt(text: str, items: list[str]) -> str:
    numbered = "\n".join(f"{i}. {x}" for i, x in enumerate(items, 1))
    return (
        f"{text}\n\n---\nNOMS ÉCRITS DANS LE RAPPORT ET ABSENTS DE TA LISTE :\n{numbered}\n\n"
        "TÂCHE : « mentions » : pour chacun, « numéro:o » si le rapport le décrit comme employé, déployé, exploité ou visé dans "
        "l'activité décrite, « numéro:n » sinon (simple comparaison, contexte, autre opération, recommandation, homonyme). "
        "Séparés par « ; » (« 1:o;2:n »)."
    )


def carrier_prompt(text: str, authors: list[str], items: list[str]) -> str:
    numbered = "\n".join(f"{i}. {a}" for i, a in enumerate(authors, 1))
    listed = "\n".join(f"{i}. {x}" for i, x in enumerate(items, 1))
    return (
        f"{text}\n\n---\nAUTEURS POSSIBLES (numérotés) :\n{numbered}\n\nTECHNIQUES RETENUES (comportement relevé et phrases) :\n{listed}\n\n"
        "TÂCHE : « carriers » : pour chaque technique, le numéro de l'auteur qui l'exécute, « numéro:auteur » séparés par « ; » "
        "(« 1:2;2:1;3:- »).\n\n"
        "RÈGLES D'ATTRIBUTION STIX NON NÉGOCIABLES :\n"
        "- Si la technique est exécutée par un malware ou un outil : attribue-la au MALWARE ou à l'OUTIL (jamais au groupe ni à la campagne).\n"
        "- Si la technique est une action opératoire générale ou la phase initiale d'une opération : attribue-la à la CAMPAGNE.\n"
        "- N'attribue au GROUPE (intrusion-set) que si le texte ne nomme ni malware, ni outil, ni campagne pour cette action.\n"
        "- « - » si aucun auteur de la liste ne porte cette technique. Deux auteurs (« 1:2,4 ») seulement si le texte attribue explicitement le geste à chacun."
    )


def choice_prompt(text: str, behaviors: list["Behavior"], carriers: list[str] | None = None) -> str:
    blocks = []
    for i, b in enumerate(behaviors, 1):
        options = "\n".join(f"   {_LETTERS[j]}) {h.attack_id} {h.name} : {h.summary}" for j, h in enumerate(b.candidates))
        blocks.append(f"{i}. [phrases {','.join(map(str, b.uids)) or '?'}] {b.query}\n{options}")
    task = (
        "TÂCHE : « choices » : pour chaque comportement, les lettres des techniques dont la définition décrit ce que les phrases "
        "citées disent, « numéro:lettres » séparés par « ; » (« 1:b;2:a,c;3:- »).\n\n"
        "RÈGLES D'ARBITRAGE ET ÉLIMINATION NÉGATIVE (CRUCIALES) :\n"
        "1. Priorité à l'action et à l'effet final sur l'outil/interpréteur : si une candidate décrit le conteneur d'exécution "
        "(un interpréteur de commandes ou de scripts) et qu'une autre candidate décrit l'action sous-jacente ou l'effet technique "
        "(un transfert de fichier, un décodage, une découverte…), ÉLIMINE le conteneur d'exécution et retiens la technique d'action spécifique !\n"
        "2. Spécificité : choisis la sous-technique lorsque le texte décrit son mécanisme précis, sinon la technique parente.\n"
        "3. Plusieurs lettres uniquement si les phrases citées décrivent distinctement plusieurs actions autonomes.\n"
        "4. Réponds « - » si aucune candidate ne décrit fidèlement l'action affirmée par le texte."
    )
    if carriers is None:
        return f"{text}\n\n---\nCOMPORTEMENTS RELEVÉS ET TECHNIQUES ATT&CK v20.0 CANDIDATES :\n" + "\n".join(blocks) + "\n\n" + task
    numbered = "\n".join(f"{i}. {c}" for i, c in enumerate(carriers, 1))
    return (
        f"{text}\n\n---\nAUTEURS POSSIBLES (numérotés) :\n{numbered}\n\nCOMPORTEMENTS RELEVÉS ET TECHNIQUES ATT&CK v20.0 "
        "CANDIDATES :\n" + "\n".join(blocks) + "\n\n" + task + "\n\nAjoute à chaque comportement retenu le numéro de l'auteur qui "
        "l'exécute : « numéro:lettres:auteur » (« 1:b:2;2:a,c:1;3:- »). L'auteur : le malware ou l'outil quand le texte décrit "
        "sa capacité propre ; sinon la campagne décrite, ou sans campagne le groupe nommé à qui le texte attribue l'action ; "
        "« - » si aucun auteur de la liste. Deux auteurs (« 1:b:2,4 ») seulement si le texte attribue le comportement à chacun."
    )


def second_look_prompt(text: str, behaviors: list[dict], names: dict[str, str]) -> str:
    listed = []
    for i, b in enumerate(behaviors, 1):
        query = (b["line"].split("|") + [""])[1].strip() or b["line"]
        chosen = ", ".join(f"{aid} {names.get(aid, '')}".strip() for aid in b["chosen"]) or "aucune"
        listed.append(f"{i}. [phrases {','.join(map(str, b['uids'])) or '?'}] {query} -> {chosen}")
    return (
        f"{text}\n\n---\nCOMPORTEMENTS RELEVÉS ET TECHNIQUES ATT&CK v20.0 RETENUES :\n" + "\n".join(listed) + "\n\n"
        "TÂCHE : relis les phrases citées par chaque comportement. Une ligne en regroupe souvent plusieurs : outre le mécanisme "
        "retenu, ses phrases décrivent parfois d'autres actions de l'attaquant ou du logiciel malveillant (accès initial, "
        "exécution, persistance, élévation, évasion, accès aux identifiants, découverte, mouvement latéral, collecte, "
        "communication, exfiltration, impact…) qu'aucune technique retenue ne couvre. « behaviors » : chacun de ces mécanismes "
        "laissés de côté, éléments séparés par « ; », chacun « numéros des phrases qui le décrivent|le comportement en anglais, "
        "avec les mots du mécanisme (action, moyen, but), sans nom d'acteur ni IOC|identifiant ATT&CK v20.0 présumé ou rien » "
        "(« 12|<action> <mechanism> to <goal>|T####.### »). UN mécanisme par ligne, seulement ce que les phrases disent ; jamais "
        "un mécanisme qu'une technique retenue couvre déjà ; rien si tout est couvert."
    )


def relation_prompt(text: str, table: list[str], carried: bool = False) -> str:
    numbered = "\n".join(f"{i}. {e}" for i, e in enumerate(table, 1)) or "(aucune)"
    already = (
        " Une technique marquée « déjà employée par … » est reliée à cet auteur : n'écris pour elle un autre « uses » que si le "
        "texte l'attribue aussi à une autre entité."
        if carried
        else ""
    )
    return (
        f"{text}\n\n---\nENTITÉS ET TECHNIQUES DU RAPPORT (numérotées) :\n{numbered}\n\n"
        "TÂCHE : « relations » : tous les liens que le texte affirme entre ces éléments, séparés par « ; », chacun « numéro "
        "source|relation|numéro cible|numéros de phrases » (« 3|uses|2|12,13;3|attributed-to|1|5 »). Chaque technique est reliée à "
        "l'entité qui l'exécute (« numéro de l'entité|uses|numéro de la technique|phrases ») : le malware quand le texte décrit sa "
        "capacité propre, sinon la campagne décrite ou, sans campagne, l'acteur nommé à qui le texte attribue l'action (y compris "
        "avec un outil) ; chaque malware, outil et victime est relié à la campagne, à l'acteur ou à l'entité qui le déploie ou le subit. "
        "Sans malware, outil, campagne ni acteur (ex: analyse d'une vulnérabilité) : la technique d'exploitation cible directement "
        "la vulnérabilité et le produit attaqué (« numéro technique|targets|numéro vulnérabilité ou produit|phrases »). "
        "software --related-to--> identity relie un produit logiciel à son éditeur. "
        "La phrase citée (ou les 3 précédentes de sa section, ou son titre) nomme le malware, l'outil, la CVE ou la victime reliés." + already
    )


def correction_prompt(prompt: str, answer: dict, refused: list[tuple[str, str]]) -> str:
    reasons = "\n".join(f"- « {row} » : {reason}" for row, reason in refused)
    return (
        f"{prompt}\n\nTA RÉPONSE :\nrelations : {answer.get('relations', '')}\n\nLIGNES REFUSÉES :\n{reasons}\n\n"
        "TÂCHE : renvoie SEULEMENT les lignes refusées corrigées, même format (citer la phrase qui nomme les entités reliées) ; "
        "omets celles que le texte n'étaye pas."
    )


def island_prompt(prompt: str, answer: dict, islands: list[list[str]]) -> str:
    groups = "\n".join(f"- îlot {i} : {', '.join(g)}" for i, g in enumerate(islands, 1))
    return (
        f"{prompt}\n\nTA RÉPONSE :\nrelations : {answer.get('relations', '')}\n\nLe graphe est en îlots sans lien entre eux :\n{groups}\n\n"
        "TÂCHE : renvoie SEULEMENT des relations supplémentaires (même format, numéros de la liste) que le texte affirme entre des "
        "éléments d'îlots différents (qui déploie, utilise ou subit quoi) ; la phrase citée nomme les deux éléments ou, avec les "
        "3 précédentes de sa section, l'entité qui les relie. N'invente aucun lien : sans phrase qui l'étaye, n'écris rien."
    )


def verify_prompt(text: str, draft: DraftGraph, keys: list[tuple[str, str, str]]) -> str:
    def label(sid: str) -> str:
        aid = attack_id(draft.objects[sid])
        return f"{draft.type_of(sid)}:{f'{aid} ' if aid else ''}{draft.name_of(sid)}"

    blocks = []
    for i, key in enumerate(keys, 1):
        quotes = "\n".join(f"   {_LETTERS[j]}) « {q[:300]} »" for j, q in enumerate(draft.evidence[key][:VERIFY_QUOTES]))
        blocks.append(f"{i}. {label(key[0])} --{key[1]}--> {label(key[2])}\n{quotes}")
    return (
        f"{text}\n\n---\nRELATIONS PROPOSÉES (avec les phrases citées) :\n" + "\n".join(blocks) + "\n\n"
        "TÂCHE : « verdicts » : pour chaque relation, « numéro:o:lettre » si le texte l'affirme (explicitement ou par implication "
        "directe du récit), la lettre désignant LA phrase citée qui l'établit le mieux ; « numéro:n » sinon. Séparés par « ; » "
        "(« 1:o:b;2:n;3:o:a »). Seul le texte compte : une relation plausible que le texte ne dit pas est « n ». « n » aussi quand "
        "la cible de « targets » n'est pas visée par l'attaque (auteur du rapport, agence ou éditeur qui publie une alerte, "
        "chercheur) ou quand la relation relève d'une autre opération que celle décrite."
    )


def verify_relations(draft: DraftGraph, text: str, system: str, result: ExtractionResult) -> None:
    """Le modèle juge chaque relation acceptée contre le texte (monde clos) : celles qu'il dit non étayées sont retirées, les
    autres ne gardent que la phrase qu'il désigne comme preuve. Une relation sans verdict (réponse tronquée) est gardée telle quelle."""
    keys = list(draft.evidence)
    for k in range(0, len(keys), VERIFY_BATCH):
        batch = keys[k : k + VERIFY_BATCH]
        answer = _call(result, "vérification", system, verify_prompt(text, draft, batch), VERIFY_SCHEMA, VERIFY_TOKENS_PER_ROW * len(batch) + 50)
        for row in rows(answer.get("verdicts")):
            num, _, verdict = row.partition(":")
            i = _index(num, len(batch))
            verdict, _, letter = verdict.strip().lower().partition(":")
            quotes = draft.evidence.get(batch[i], []) if i is not None else []
            if verdict.startswith("o") and letter.strip()[:1] in _LETTERS and _LETTERS.index(letter.strip()[:1]) < len(quotes):
                draft.evidence[batch[i]] = [quotes[_LETTERS.index(letter.strip()[:1])]]
            elif i is not None and verdict.startswith("n"):
                s, rel, t = batch[i]
                draft.evidence.pop(batch[i], None)
                draft.log.append(f"reject {draft.name_of(s)} --{rel}--> {draft.name_of(t)} : non étayée selon la vérification")
                result.refused_relations.append((s, relationship_type_of(rel), t, "non étayée selon la vérification"))
                result.accepted -= 1
                result.refused += 1


def islands(draft: DraftGraph, sids: list[str]) -> list[list[str]]:
    """Composantes connexes (de plus d'un élément ou isolées) des éléments numérotés, les plus petites d'abord."""
    parent = {s: s for s in sids}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for s, _, t in draft.evidence:
        if s in parent and t in parent:
            parent[find(s)] = find(t)
    groups: dict[str, list[str]] = {}
    for i, s in enumerate(sids, 1):
        groups.setdefault(find(s), []).append(f"{i} {draft.name_of(s)}")
    return sorted(groups.values(), key=len)


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
            result.refused_entities.append((line, err))
            result.refused += 1
        elif sid not in sids and draft.type_of(sid) != "attack-pattern":
            sids.append(sid)
            result.accepted += 1
    return sids


# --- Étape 1 quater : noms écrits dans le texte (CTI_MENTIONS) -----------------------------------------------------------
def recover_mentions(draft: DraftGraph, units: list[Unit], text: str, system: str, sids: list[str], result: ExtractionResult) -> list[str]:
    """CVE et noms ATT&CK (groupes, logiciels, campagnes) présents dans le texte mais pas parmi les entités : le modèle garde
    ceux qui appartiennent à l'activité décrite. Les phrases masquées au modèle (dominées par des indicateurs) sont lues aussi :
    une CVE peut n'y être écrite qu'une fois ; la phrase est alors montrée avec le nom."""
    eligible = [u for u in units if u.kind in ("sentence", "item") and not u.is_reference]
    body = "\n".join(u.text for u in eligible)
    known = set(draft.names)
    items: list[tuple[str, str, int]] = []  # (ligne à déclarer, libellé montré, première phrase)

    def first_uid(pattern: re.Pattern) -> int | None:
        return next((u.uid for u in eligible if pattern.search(u.text)), None)

    for label, aid, kind in draft.attack.mentioned(body):
        if aid in known or normalize_name(label) in known:
            continue
        uid = first_uid(re.compile(rf"(?<![\w-]){re.escape(label)}(?![\w-])", 0 if len(label) <= 4 else re.I))
        if uid:
            items.append((f"{'tool' if kind == 'tool' else kind}|{label}", f"{label} ({kind} d'ATT&CK) : « {draft.by_uid[uid].text[:200]} »", uid))
    for cve in dict.fromkeys(m.upper() for m in _CVE.findall(body)):
        if normalize_name(cve) not in known and cve not in known:
            uid = first_uid(re.compile(re.escape(cve), re.I))
            if uid:
                items.append((f"vulnerability|{cve}", f"{cve} (vulnérabilité) : « {draft.by_uid[uid].text[:200]} »", uid))
    items = items[:MAX_MENTIONS]
    if not items:
        return sids
    try:
        answer = _call(result, "mentions", system, mention_prompt(text, [x[1] for x in items]), MENTION_SCHEMA, 8 * len(items) + 50)
    except (TimeoutError, llm.requests.RequestException) as exc:
        result.failures.append(f"mentions : {type(exc).__name__}: {exc}")
        return sids
    for row in rows(answer.get("mentions")):
        num, _, verdict = row.partition(":")
        i = _index(num, len(items))
        if i is None or not verdict.strip().lower().startswith("o"):
            continue
        sid, err = draft.declare(items[i][0])
        if err:
            result.refused_entities.append((items[i][0], err))
            result.refused += 1
        elif sid not in sids:
            sids.append(sid)
            result.accepted += 1
    return sids


# --- Étape 1 quinquies : victimes (CTI_VICTIMS) -------------------------------------------------------------------------
def decide_victims(draft: DraftGraph, text: str, system: str, sids: list[str], result: ExtractionResult) -> list[str]:
    """Victimes décidées à part : identité (classe et secteur STIX), pays, et « targets » depuis l'attaquant désigné ; sans
    attaquant désigné, la campagne s'il n'y en a qu'une, sinon le groupe s'il n'y en a qu'un. Deux victimes non nommées de même
    clé (classe, secteur, pays) sont une seule identité, reconnue sous chacun de ses noms (« <pays> citizens » et « <pays>
    population ») ; une organisation nommée garde la sienne. Le modèle fixe la clé, le code ne fait que regrouper."""
    attackers = [s for s in sids if draft.type_of(s) in _CARRIER_TYPES]
    try:
        answer = _call(result, "victimes", system, victim_prompt(text, [f"{draft.type_of(s)}|{draft.name_of(s)}" for s in attackers]), VICTIM_SCHEMA, VICTIM_TOKENS)
    except (TimeoutError, llm.requests.RequestException) as exc:
        result.failures.append(f"victimes : {type(exc).__name__}: {exc}")
        return sids
    campaigns = [s for s in attackers if draft.type_of(s) == "campaign"]
    groups = [s for s in attackers if draft.type_of(s) in _GROUP_TYPES]
    default = campaigns[0] if len(campaigns) == 1 else groups[0] if not campaigns and len(groups) == 1 else None
    merged: dict[tuple[str, str, str], str] = {}  # (classe, secteur, pays) d'une victime non nommée -> son identité
    for line in rows(answer.get("victims")):
        parts = [p.strip() for p in line.split("|")] + ["-"] * 5
        uids = [n for n in _numbers(parts[0]) if n in draft.by_uid][:5]
        if not parts[1] or not uids:
            result.refused_entities.append((line, "format attendu phrases|victime|classe|secteur|pays|attaquant"))
            result.refused += 1
            continue
        klass, sector, country = parts[2].lower(), parts[3].lower(), parts[4].upper()
        i = _index(parts[5], len(attackers)) if parts[5] != "-" else None
        who = attackers[i] if i is not None else default
        targets = []
        key = (klass, sector, country)
        if klass not in ("organization", "individual") and key in merged:
            sid, err = merged[key], None
            draft.add_terms(sid, {parts[1]})
            draft.log.append(f"fusion « {parts[1]} » -> « {draft.name_of(sid)} »")
        else:
            sid, err = draft.declare(f"identity|{parts[1]}|{'' if sector == '-' else sector};{klass}")
        if err:
            result.refused_entities.append((line, err))
            result.refused += 1
        else:
            targets.append(sid)
            if klass not in ("organization", "individual"):
                merged.setdefault(key, sid)
        if re.fullmatch(r"[A-Z]{2}", country):
            lsid, err = draft.declare(f"location|{country}|{country}")
            if not err:
                targets.append(lsid)
        for t in targets:
            if t not in sids:
                sids.append(t)
                result.accepted += 1
            if who:
                err = draft.relate(f"{_ref(draft, who)}|targets|{_ref(draft, t)}|{','.join(map(str, uids))}")
                if err:
                    draft.log.append(f"reject {err}")
                    result.refused_relations.append((who, "targets", t, err.split(" : ", 1)[-1]))
                    result.refused += 1
    return sids


# --- Étape 1 ter : opérations (CTI_OPERATIONS) ----------------------------------------------------------------------------
def decide_operations(draft: DraftGraph, text: str, system: str, sids: list[str], result: ExtractionResult) -> list[str]:
    """Le modèle décide des campagnes (phrases, nom, groupe) ; elles remplacent celles de l'appel « entités ». Le rattachement
    au groupe devient une relation « attributed-to » étayée par les phrases de l'opération."""
    groups = [s for s in sids if draft.type_of(s) in _GROUP_TYPES]
    known = [draft.name_of(s) for s in sids if draft.type_of(s) == "campaign"]
    try:
        answer = _call(result, "opérations", system, operation_prompt(text, [f"{draft.type_of(s)}|{draft.name_of(s)}" for s in groups], known), OPERATION_SCHEMA, OPERATION_TOKENS)
    except (TimeoutError, llm.requests.RequestException) as exc:  # sans réponse, les campagnes de l'appel « entités » restent
        result.failures.append(f"opérations : {type(exc).__name__}: {exc}")
        return sids
    campaigns: list[str] = []
    for line in rows(answer.get("operations")):
        parts = [p.strip() for p in line.split("|")]
        uids = [n for n in _numbers(parts[0]) if n in draft.by_uid]
        if len(parts) < 2 or not parts[1] or not uids:
            result.refused_entities.append((line, "format attendu numéros de phrases|nom|groupe"))
            result.refused += 1
            continue
        sid, err = draft.declare(f"campaign|{parts[1]}")
        if err:
            draft.log.append(f"reject {err}")
            result.refused_entities.append((line, err))
            result.refused += 1
            continue
        if sid not in campaigns:
            campaigns.append(sid)
            result.accepted += 1
        g = _index(parts[2], len(groups)) if len(parts) > 2 else None
        if g is not None:  # preuve : les phrases de l'opération qui nomment le groupe, sinon les premières
            naming = [n for n in uids if mentions(draft.by_uid[n].text, draft.terms.get(groups[g], set()))] or uids[:3]
            err = draft.relate(f"{_ref(draft, sid)}|attributed-to|{_ref(draft, groups[g])}|{','.join(map(str, naming[:3]))}")
            if err:
                draft.log.append(f"reject {err}")
                result.refused_relations.append((sid, "attributed-to", groups[g], err.split(" : ", 1)[-1]))
                result.refused += 1
    return [s for s in sids if draft.type_of(s) != "campaign"] + campaigns


# --- Étape 1 bis : comportements bloc par bloc (CTI_SECTION_PASS) ---------------------------------------------------------
def blocks_of(units: list[Unit], limit: int = BLOCK_CHARS) -> list[list[Unit]]:
    """Unités consécutives par blocs d'au plus `limit` caractères montrés au modèle ; un changement de section (deux premiers
    niveaux de titres) ferme le bloc s'il est déjà à moitié plein."""
    out: list[list[Unit]] = []
    cur: list[Unit] = []
    size = 0

    def section(u: Unit) -> str:
        return " > ".join(u.heading_path.split(" > ")[:2])

    for u in units:
        n = len(u.prompt_text) + 8
        if cur and (size + n > limit or (section(u) != section(cur[-1]) and size >= limit // 2)):
            out.append(cur)
            cur, size = [], 0
        cur.append(u)
        size += n
    if cur:
        out.append(cur)
    return out


def _behavior_key(line: str) -> tuple[frozenset[int], str]:
    parts = line.split("|")
    guess = _TECHNIQUE.search(" ".join(parts[2:]))
    return frozenset(map(int, re.findall(r"\d+", parts[0]))), guess.group(0).upper() if guess else ""


def section_behaviors(units: list[Unit], text: str, system: str, known: list[str], result: ExtractionResult) -> list[str]:
    """Comportements relevés bloc par bloc, sans ceux de l'appel global (même technique présumée sur des phrases communes) ni
    doublons ; les phrases citées hors du bloc sont retirées de la ligne."""
    seen = [_behavior_key(line) for line in known]

    def ask(block: list[Unit]) -> list[str]:
        try:
            answer = _call(result, "sections", system, section_prompt(text, block), _schema("behaviors"), SECTION_TOKENS)
        except (TimeoutError, llm.requests.RequestException) as exc:  # un bloc perdu n'empêche pas les autres
            result.failures.append(f"comportements du bloc [{block[0].uid}-{block[-1].uid}] : {type(exc).__name__}: {exc}")
            return []
        inside = {u.uid for u in block}
        lines = []
        for line in rows(answer.get("behaviors")):
            parts = line.split("|")
            uids = [n for n in map(int, re.findall(r"\d+", parts[0])) if n in inside]
            if len(parts) >= 2 and uids:
                lines.append("|".join([",".join(map(str, uids)), *parts[1:]]))
        return lines

    out: list[str] = []
    for lines in llm.map_parallel(ask, blocks_of(units)):
        for line in lines:
            uids, guess = _behavior_key(line)
            if any(guess == g and (uids & u) for u, g in seen) or (uids, guess) in seen:
                continue
            seen.append((uids, guess))
            out.append(line)
    return out


def second_look(text: str, system: str, known: list[str], names: dict[str, str], result: ExtractionResult) -> list[str]:
    """Mécanismes laissés de côté par les comportements déjà choisis (voir SECOND_LOOK), sans ceux qui reprennent sur des phrases
    communes une technique présumée ou retenue."""
    try:
        answer = _call(result, "seconde lecture", system, second_look_prompt(text, result.behaviors, names), _schema("behaviors"), SECOND_LOOK_TOKENS)
    except (TimeoutError, llm.requests.RequestException) as exc:  # sans seconde lecture, les techniques choisies restent
        result.failures.append(f"seconde lecture des comportements : {type(exc).__name__}: {exc}")
        return []
    seen = [_behavior_key(line) for line in known] + [(frozenset(b["uids"]), aid) for b in result.behaviors for aid in b["chosen"]]
    out: list[str] = []
    for line in rows(answer.get("behaviors")):
        uids, guess = _behavior_key(line)
        if len(line.split("|")) < 2 or (uids, guess) in seen or any(guess and guess == g and uids & u for u, g in seen):
            continue
        seen.append((uids, guess))
        out.append(line)
    return out


# --- Étape 2 : techniques choisies parmi des candidates -------------------------------------------------------------------
@dataclass
class Behavior:
    line: str
    uids: list[int]  # phrases citées
    query: str  # comportement en anglais, requête de la recherche
    candidates: list[TechniqueHit]


def find_candidates(draft: DraftGraph, lines: list[str], result: ExtractionResult) -> list[Behavior]:
    """« phrases|outil|action_et_but|tactique|identifiant présumé » -> candidates : l'identifiant présumé (et sa technique parente)
    s'il est actif dans ATT&CK v20.0, puis les meilleures techniques de la recherche sur l'action fondamentale filtrées par tactique.
    Le code propose, le modèle choisira. Les procédures d'ATT&CK tirées de l'article lui-même ne servent pas à la recherche."""
    kb, out = draft.attack, []
    own = report_key(draft.ctx.article_ref.get("url"))
    for line in lines:
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 2 or not parts[1]:
            result.refused_techniques.append((line, "format attendu numéros de phrases|comportement|identifiant présumé"))
            result.refused += 1
            continue

        if len(parts) >= 4:
            carrier_hint = parts[1] if parts[1] not in ("-", "") else ""
            action_query = parts[2]
            tactic = parts[3] if parts[3] not in ("-", "") else None
            guess = _TECHNIQUE.search(" ".join(parts[4:])) if len(parts) >= 5 else None
        elif len(parts) == 3:
            carrier_hint = ""
            action_query = parts[1]
            tactic = None
            guess = _TECHNIQUE.search(parts[2])
        else:
            carrier_hint = ""
            action_query = parts[1]
            tactic = None
            guess = None

        hits: list[TechniqueHit] = []
        if guess:
            status, replaced = kb.status(guess.group(0).upper())
            aid = replaced if status == "revoked" and replaced else guess.group(0).upper() if status == "active" else None
            for a in (aid, aid.split(".")[0]) if aid else ():
                hits += kb.search_techniques(a)  # un identifiant seul renvoie sa fiche

        # Recherche ciblée sur l'action fondamentale avec filtrage par tactique
        hits += kb.search_techniques(action_query, tactic=tactic, limit=CANDIDATES, exclude_source=own)
        unique = list({h.attack_id: h for h in hits}.values())[:MAX_OPTIONS]
        uids = [n for n in map(int, re.findall(r"\d+", parts[0])) if n in draft.by_uid]
        display_query = f"[{carrier_hint}] {action_query}" if carrier_hint else action_query
        if unique:
            out.append(Behavior(line, uids, display_query, unique))
        else:
            result.refused_techniques.append((line, "aucune technique ATT&CK candidate"))
            result.refused += 1
    return out


def accept_choices(
    draft: DraftGraph, answer: dict, behaviors: list[Behavior], techniques: dict[str, list[int]], result: ExtractionResult,
    carriers: list[str] | None = None, carried: dict[str, list[str]] | None = None,
) -> None:  # fmt: skip
    """« numéro:lettres[:auteurs] » -> techniques retenues (identifiant STIX -> phrases citées) ; un comportement sans choix est
    noté refusé. Avec `carriers` (identifiants STIX des auteurs numérotés), la relation « auteur uses technique » est créée ici,
    vérifiée comme toute autre (le texte doit nommer le malware ou l'outil) ; `carried` reçoit technique -> auteurs reliés."""
    chosen: dict[int, list[str]] = {}
    authors: dict[int, list[str]] = {}
    for row in rows(answer.get("choices")):
        num, _, rest = row.partition(":")
        letters, _, who = rest.partition(":")
        i = _index(num, len(behaviors))
        if i is not None:
            cands = behaviors[i].candidates
            chosen.setdefault(i, []).extend(cands[_LETTERS.index(c)].attack_id for c in re.findall(rf"[{_LETTERS}]", letters.lower()) if _LETTERS.index(c) < len(cands))
            if carriers:
                authors.setdefault(i, []).extend(carriers[k] for k in (_index(n, len(carriers)) for n in re.findall(r"\d+", who)) if k is not None)
    # Subsomption ontologique locale : si une sous-technique T####.### est retenue, on élague son parent T####
    for i in list(chosen):
        subs = {a for a in chosen[i] if "." in a}
        sub_parents = {a.split(".")[0] for a in subs}
        if sub_parents:
            chosen[i] = [a for a in chosen[i] if a not in sub_parents]
    for i, b in enumerate(behaviors):
        result.behaviors.append({"line": b.line, "uids": b.uids, "candidates": [h.attack_id for h in b.candidates], "chosen": chosen.get(i, [])})
        if not chosen.get(i):
            reason = "aucune candidate retenue parmi " + ", ".join(h.attack_id for h in b.candidates)
            draft.log.append(f"reject « {b.line} » : {reason}")
            result.refused_techniques.append((b.line, reason))
            result.refused += 1
        for aid in chosen.get(i, []):
            sid, err = draft.technique(aid)
            if err:
                draft.log.append(f"reject {aid} : {err}")
                result.refused += 1
                continue
            known = techniques.setdefault(sid, [])
            known += [n for n in b.uids if n not in known]
            draft.procedures.setdefault(sid, [])
            if b.query not in draft.procedures[sid]:
                draft.procedures[sid].append(b.query)
            result.accepted += 1
            for who in dict.fromkeys(authors.get(i, [])):
                err = draft.relate(f"{_ref(draft, who)}|uses|{aid}|{','.join(map(str, b.uids))}")
                if err:
                    draft.log.append(f"reject {err}")
                    result.refused_relations.append((who, "uses", sid, err.split(" : ", 1)[-1]))
                    result.refused += 1
                elif carried is not None and who not in carried.setdefault(sid, []):
                    carried[sid].append(who)
                    result.accepted += 1


def assign_carriers(draft: DraftGraph, text: str, system: str, behaviors: list[dict], authors: list[str], carried: dict[str, list[str]], result: ExtractionResult) -> None:
    """CTI_CARRIER=separate : l'auteur de chaque technique retenue, dans un appel à part ; « auteur uses technique » est créée
    et vérifiée comme toute relation. `behaviors` : la trace des comportements (`result.behaviors`)."""
    items = [(aid, b) for b in behaviors for aid in b["chosen"]]
    if not items or not authors:
        return
    labels = [f"{draft.type_of(s)}|{draft.name_of(s)}" for s in authors]
    for k in range(0, len(items), CARRIER_BATCH):
        batch = items[k : k + CARRIER_BATCH]
        shown = [f"{aid} {draft.name_of(draft.names.get(aid, '')) if draft.names.get(aid) else ''} ← « {b['line'].split('|')[1] if '|' in b['line'] else b['line']} » (phrases {','.join(map(str, b['uids']))})" for aid, b in batch]
        try:
            answer = _call(result, "porteurs", system, carrier_prompt(text, labels, shown), _schema("carriers"), CARRIER_TOKENS * 2 * len(batch) + 50)
        except (TimeoutError, llm.requests.RequestException) as exc:
            result.failures.append(f"porteurs : {type(exc).__name__}: {exc}")
            continue
        for row in rows(answer.get("carriers")):
            num, _, who = row.partition(":")
            i = _index(num, len(batch))
            if i is None:
                continue
            aid, b = batch[i]
            sid = draft.names.get(aid)
            for j in (_index(n, len(authors)) for n in re.findall(r"\d+", who)):
                if j is None or sid is None:
                    continue
                err = draft.relate(f"{_ref(draft, authors[j])}|uses|{aid}|{','.join(map(str, b['uids']))}")
                if err:
                    draft.log.append(f"reject {err}")
                    result.refused_relations.append((authors[j], "uses", sid, err.split(" : ", 1)[-1]))
                    result.refused += 1
                elif authors[j] not in carried.setdefault(sid, []):
                    carried[sid].append(authors[j])
                    result.accepted += 1


# --- Étape 3 : relations --------------------------------------------------------------------------------------------------
def _ref(draft: DraftGraph, sid: str) -> str:
    """Extrémité d'une ligne de relation : une technique ou un objet ATT&CK est désigné par son identifiant, pas par son nom
    (« PowerShell » est aussi un outil)."""
    return attack_id(draft.objects[sid]) or draft.name_of(sid).replace("|", "/").strip()


def apply_relations(draft: DraftGraph, answer: dict, sids: list[str], result: ExtractionResult) -> list[tuple[str, str]]:
    """Ajoute les relations valides."""
    refused: list[tuple[str, str]] = []
    for row in rows(answer.get("relations")):
        parts = [p.strip() for p in row.split("|")]
        src, dst = (_index(parts[0], len(sids)), _index(parts[2], len(sids))) if len(parts) == 4 else (None, None)
        if src is None or dst is None:
            refused.append((row, "format attendu numéro source|relation|numéro cible|numéros de phrases"))
            continue
        err = draft.relate(f"{_ref(draft, sids[src])}|{parts[1]}|{_ref(draft, sids[dst])}|{parts[3]}")
        if err:
            refused.append((row, err.split(" : ", 1)[-1]))
            result.refused_relations.append((sids[src], relationship_type_of(parts[1]), sids[dst], refused[-1][1]))
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
        if MULTI_AGENT:
            # 1. Micro-Agents de perception exécutés en parallèle avec cache de préfixe vLLM
            def run_threat():
                return _call(result, "threat_modeler", system, ThreatModelerAgent.prompt(text), ThreatModelerAgent.SCHEMA, 2500)

            def run_targets():
                return _call(result, "target_specialist", system, TargetSpecialistAgent.prompt(text), TargetSpecialistAgent.SCHEMA, 2000)

            def run_ttps():
                return TTPHunterAgent.extract(text, system, lambda s, sys, p, sch, tok, **kw: _call(result, s, sys, p, sch, tok, **kw), multi_temp=MULTI_TEMP)

            with ThreadPoolExecutor(max_workers=3) as pool:
                f_threat = pool.submit(llm.in_context(run_threat))
                f_targets = pool.submit(llm.in_context(run_targets))
                f_ttps = pool.submit(llm.in_context(run_ttps))
                res_threat = f_threat.result()
                res_targets = f_targets.result()
                lines = f_ttps.result()

            sids: list[str] = []
            # Déclaration des entités offensives avec registre canonique
            for line in rows(res_threat.get("threat_entities")):
                fields = [f.strip() for f in line.split("|")]
                if len(fields) < 2 or not fields[1]:
                    continue
                stype, name = fields[0].lower(), fields[1]
                extra = fields[2] if len(fields) > 2 else ""

                # Normalisation des parenthèses descriptives : « <malware> (<fichier>) »
                # -> base_name = « <malware> », alias = « <fichier> », « <malware> (<fichier>) »
                match = re.match(r"^([^(]+)\s*\(([^)]+)\)\s*$", name)
                if match and stype in ("malware", "tool", "intrusion-set", "threat-actor"):
                    base_name = match.group(1).strip()
                    detail = match.group(2).strip()
                    name = base_name
                    aliases = [a.strip() for a in extra.replace(",", ";").split(";") if a.strip()]
                    aliases.extend([detail, fields[1]])
                    extra = ";".join(dict.fromkeys(aliases))
                elif len(fields) > 2 and stype not in ("software", "location"):
                    extra = extra.replace(",", ";")

                decl = f"{stype}|{name}|{extra}" if extra else f"{stype}|{name}"
                sid, err = draft.declare(decl)
                if err:
                    draft.log.append(f"reject {err}")
                    result.refused_entities.append((line, err))
                    result.refused += 1
                elif sid not in sids and draft.type_of(sid) != "attack-pattern":
                    sids.append(sid)
                    result.accepted += 1

            # Déclaration des cibles, vulnérabilités et victimes
            for line in rows(res_targets.get("targets")):
                fields = [f.strip() for f in line.split("|")]
                if len(fields) < 2 or not fields[1]:
                    continue
                stype = fields[0].lower()
                decl = None
                target_uids = [n for n in _numbers(fields[0]) if n in draft.by_uid] or [1]
                vendor, v_sid = None, None
                if stype == "identity":
                    name = fields[1]
                    klass = fields[2] if len(fields) > 2 and fields[2] != "-" else "organization"
                    sector = fields[3] if len(fields) > 3 and fields[3] != "-" else ""
                    country = fields[4] if len(fields) > 4 and fields[4] != "-" else ""
                    decl = f"identity|{name}|{sector};{klass}"
                    if country and re.fullmatch(r"[A-Z]{2}", country.upper()):
                        loc_sid, _ = draft.declare(f"location|{country.upper()}|{country.upper()}")
                        if loc_sid and loc_sid not in sids:
                            sids.append(loc_sid)
                elif stype == "location":
                    decl = f"location|{fields[1]}|{fields[2] if len(fields) > 2 else ''}"
                elif stype == "software":
                    decl = f"software|{fields[1]}|{fields[2] if len(fields) > 2 else ''}"
                    vendor = fields[2].strip() if len(fields) > 2 and fields[2].strip() not in ("-", "") else None
                    if vendor:
                        v_sid, _ = draft.declare(f"identity|{vendor}|organization")
                        if v_sid and v_sid not in sids:
                            sids.append(v_sid)
                elif stype == "vulnerability":
                    decl = f"vulnerability|{fields[1]}"
                else:
                    decl = "|".join(fields[:3])

                if decl:
                    sid, err = draft.declare(decl)
                    if err:
                        draft.log.append(f"reject {err}")
                        result.refused_entities.append((line, err))
                        result.refused += 1
                    elif sid not in sids and draft.type_of(sid) != "attack-pattern":
                        sids.append(sid)
                        result.accepted += 1
                        if stype == "software" and vendor and v_sid:
                            v_err = draft.relate(f"{_ref(draft, sid)}|related-to|{_ref(draft, v_sid)}|{','.join(map(str, target_uids[:3]))}")
                            if not v_err:
                                result.accepted += 1

            # Extraction déterministe des vulnérabilités (CVE) citées dans le texte
            known_names = set(draft.names)
            src_corpus = f"{text}\n{art.get('clean_markdown', '')}\n{art.get('content', '')}"
            for cve_match in dict.fromkeys(m.upper() for m in _CVE.findall(src_corpus)):
                if normalize_name(cve_match) not in known_names and cve_match not in known_names:
                    sid, err = draft.declare(f"vulnerability|{cve_match}")
                    if not err and sid not in sids:
                        sids.append(sid)
                        result.accepted += 1

            # Déclaration des opérations/campagnes et attribution
            groups = [s for s in sids if draft.type_of(s) in _GROUP_TYPES]
            for line in rows(res_threat.get("campaigns")):
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 2 and parts[1]:
                    uids = [n for n in _numbers(parts[0]) if n in draft.by_uid]
                    sid, err = draft.declare(f"campaign|{parts[1]}")
                    if err:
                        draft.log.append(f"reject {err}")
                        result.refused_entities.append((line, err))
                        result.refused += 1
                        continue
                    if sid not in sids:
                        sids.append(sid)
                        result.accepted += 1
                    g_ref = parts[2] if len(parts) > 2 else None
                    if g_ref and g_ref != "-":
                        matched_g = next((g for g in groups if normalize_name(draft.name_of(g)) == normalize_name(g_ref) or g_ref.lower() in draft.name_of(g).lower()), None)
                        if not matched_g and groups and len(groups) == 1:
                            matched_g = groups[0]
                        if matched_g and uids:
                            naming = [n for n in uids if mentions(draft.by_uid[n].text, draft.terms.get(matched_g, set()))] or uids[:3]
                            err = draft.relate(f"{_ref(draft, sid)}|attributed-to|{_ref(draft, matched_g)}|{','.join(map(str, naming[:3]))}")
                            if not err:
                                result.accepted += 1

            # Phase 2 bis : Tissage des relations structurelles conditionné sur le registre canonique d'entités (RelationWeaver)
            canonical_sids = [s for s in sids if draft.type_of(s) != "attack-pattern"]
            if len(canonical_sids) > 1:
                labels = [f"{draft.type_of(s)}|{draft.name_of(s)}" for s in canonical_sids]
                ans_weave = _call(result, "relation_weaver", system, RelationWeaverAgent.prompt(text, labels), RelationWeaverAgent.SCHEMA, 2500)
                apply_relations(draft, ans_weave, canonical_sids, result)
        else:
            inv = _call(result, "entities", system, entity_prompt(text), ENTITY_SCHEMA, ENTITY_TOKENS)
            sids = declare_entities(draft, inv, result)  # avant les techniques : un nom d'entité (« PowerShell ») prime sur celui d'une technique
            if OPERATIONS:
                sids = decide_operations(draft, text, system, sids, result)
            if MENTIONS:
                sids = recover_mentions(draft, units, text, system, sids, result)
            if VICTIMS:
                sids = decide_victims(draft, text, system, sids, result)
            lines = rows(inv.get("behaviors"))
        techniques: dict[str, list[int]] = {}
        if SECTION_PASS or len(units) > 60:
            lines += section_behaviors(units, text, system, lines, result)
        behaviors = find_candidates(draft, lines, result)
        carriers = [s for s in sids if draft.type_of(s) in _CARRIER_TYPES] if (CARRIER or MULTI_AGENT) else []
        carried: dict[str, list[str]] = {}

        def choose(behaviors: list[Behavior]) -> None:
            for k in range(0, len(behaviors), CHOICE_BATCH):  # chaque lot commence par l'article : relu depuis le cache du serveur
                batch = behaviors[k : k + CHOICE_BATCH]
                try:
                    prompt = choice_prompt(text, batch, [f"{draft.type_of(s)}|{draft.name_of(s)}" for s in carriers] if (carriers and CARRIER) else None)
                    tokens = CHOICE_TOKENS + (CARRIER_TOKENS * len(batch) if (carriers and CARRIER) else 0)
                    accept_choices(draft, _call(result, "techniques", system, prompt, CHOICE_SCHEMA, tokens), batch, techniques, result, carriers if CARRIER else None, carried)
                except (TimeoutError, llm.requests.RequestException) as exc:  # un lot perdu n'empêche pas les autres
                    result.failures.append(f"choix des techniques : {type(exc).__name__}: {exc}")

        choose(behaviors)
        if SECOND_LOOK and result.behaviors:
            names = {h.attack_id: h.name for b in behaviors for h in b.candidates}
            start = len(result.behaviors)
            choose(find_candidates(draft, second_look(text, system, lines, names, result), result))
            for b in result.behaviors[start:]:  # trace : comportements nés de la seconde lecture
                b["second_look"] = True
        if CARRIER_SEPARATE or MULTI_AGENT:
            assign_carriers(draft, text, system, result.behaviors, [s for s in sids if draft.type_of(s) in _CARRIER_TYPES], carried, result)

        table = [f"{draft.type_of(s)}|{draft.name_of(s)}" for s in sids]
        for sid, uids in techniques.items():
            by = f" ; déjà employée par {', '.join(draft.name_of(w) for w in carried[sid])}" if carried.get(sid) else ""
            table.append(f"attack-pattern|{attack_id(draft.objects[sid])} {draft.name_of(sid)} (phrases {','.join(map(str, uids)) or '?'}{by})")
        sids += list(techniques)
        if len(sids) > 1:
            prompt = relation_prompt(text, table, carried=bool(carried))
            rel = _call(result, "relations", system, prompt, RELATION_SCHEMA, RELATION_TOKENS)
            refused_rel = apply_relations(draft, rel, sids, result)
            if refused_rel:  # le prompt commence par le précédent : relu depuis le cache du serveur
                fix = _call(result, "corrections", system, correction_prompt(prompt, rel, refused_rel), RELATION_SCHEMA, CORRECTION_TOKENS)
                apply_relations(draft, fix, sids, result)
            groups = islands(draft, sids)
            if len(groups) > 1:  # le modèle relie, le code ne fait que repérer les îlots
                link = _call(result, "îlots", system, island_prompt(prompt, rel, groups), RELATION_SCHEMA, CORRECTION_TOKENS)
                apply_relations(draft, link, sids, result)
            try:
                verify_relations(draft, text, system, result)
            except (TimeoutError, llm.requests.RequestException) as exc:  # sans vérification, les relations acceptées restent
                result.failures.append(f"vérification des relations : {type(exc).__name__}: {exc}")
            draft.prune_subsumed_techniques()
    except (TimeoutError, llm.requests.RequestException) as exc:
        result.failures.append(f"article : {type(exc).__name__}: {exc}")
    entity_rows = draft.entity_rows()
    with ThreadPoolExecutor(max_workers=2) as pool:  # indépendants : tous deux ne lisent que les entités
        iocs = pool.submit(llm.in_context(extract_iocs), title, units, entity_rows, url=art.get("url"), published=parse_date(art.get("publication_date")))
        rules = pool.submit(llm.in_context(extract_rules), title, art["clean_markdown"], entity_rows)
        result.iocs, result.rules = iocs.result(), rules.result()
    result.seconds = time.perf_counter() - t0
    return result
