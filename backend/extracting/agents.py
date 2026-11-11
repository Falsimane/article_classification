"""Micro-agents spécialisés pour l'extraction CTI sémantique STIX 2.1.

Topologie coopérative de micro-agents (décomposition de la charge cognitive) :
1. ThreatModelerAgent : acteurs de la menace, campagnes/opérations, malwares et outils.
2. TargetSpecialistAgent : victimologie (identités, secteurs, pays) et cibles techniques (logiciels, CVE).
3. TTPHunterAgent : comportements et procédures d'attaque avec support multi-température (MTPE).
4. CarrierDisambiguationAgent : désambiguïsation stricte du porteur de chaque technique (malware vs campagne vs acteur).
5. GraphLinkerAgent : formation des arêtes structurelles (attribution, cibles, arsenal).
"""

import os
import re
from dataclasses import dataclass
from typing import Any

from stix2.v21.vocab import INDUSTRY_SECTOR

from backend.extracting import llm
from backend.extracting.graph.draft import DraftGraph, relationship_type_of
from backend.extracting.stix.attack import TechniqueHit, attack_id
from backend.extracting.stix.objects import ENTITY_CLASSES, relation_table
from backend.extracting.stix.specs import TYPE_SPECS, relation_definitions
from backend.preprocessing.cleaning.text.evidence import mentions, normalize_name
from backend.preprocessing.cleaning.text.segment import Unit

_TECHNIQUE = re.compile(r"T\d{4}(?:\.\d{3})?", re.I)
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
_LETTERS = "abcdefghijklmnopqrst"


def _schema(*fields: str) -> dict:
    return {"type": "object", "properties": {f: {"type": "string"} for f in fields}, "required": list(fields)}


def rows(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(i).strip() for i in value if str(i).strip()]
    return [str(i).strip() for i in re.split(r"[;\n]", str(value or "")) if str(i).strip()]


def _numbers(raw: str) -> list[int]:
    out: list[int] = []
    for a, b in re.findall(r"(\d+)(?:\s*-\s*(\d+))?", raw):
        out += list(range(int(a), int(b) + 1)) if b and int(b) >= int(a) else [int(a)]
    return list(dict.fromkeys(out))


def _behavior_key(line: str) -> tuple[frozenset[int], str]:
    parts = [p.strip() for p in line.split("|")]
    guess = _TECHNIQUE.search(" ".join(parts[2:]))
    uids = frozenset(map(int, re.findall(r"\d+", parts[0]))) if parts else frozenset()
    desc = parts[2] if len(parts) >= 4 else parts[1] if len(parts) >= 2 else ""
    return uids, guess.group(0).upper() if guess else desc[:30].lower()


# ======================================================================================================================
# 1. ThreatModelerAgent : Acteurs, Campagnes et Arsenal
# ======================================================================================================================
class ThreatModelerAgent:
    """Agent spécialisé dans l'identification de l'attaquant et de son infrastructure opérationnelle.
    Extrait : intrusion-set, threat-actor, campaign, malware, tool."""

    SCHEMA = _schema("threat_entities", "campaigns")

    @staticmethod
    def prompt(text: str) -> str:
        return (
            f"{text}\n\n---\n"
            "TÂCHE (Threat Modeler Agent) : identifie la structure offensive décrite dans le rapport entier :\n"
            "1) « threat_entities » : séparés par « ; », chacun « type|nom » ou « type|nom|alias1,alias2 » :\n"
            "   - intrusion-set : cluster ou groupe d'attaquants nommé (ex: <threat_group>).\n"
            "   - threat-actor : individu ou commanditaire identifié.\n"
            "   - malware : logiciel malveillant nommé ou composant avec libellé descriptif (ex: <malware_name>, <backdoor_name>).\n"
            "   - tool : logiciel légitime ou utilitaire système détourné (ex: <tool_name>).\n"
            "2) « campaigns » : opérations ou vagues d'intrusions décrites (même sans nom de code officiel !). "
            "Une intrusion racontée de bout en bout, une vague d'attaques située dans le temps ou contre une cible spécifique EST une campagne "
            "(ex: « Operation <Name> (<target_description>, <year>) »).\n"
            "   RÈGLES POUR LES CAMPAGNES :\n"
            "   - Nomme TOUJOURS la campagne en ANGLAIS (la langue source du rapport), JAMAIS en français !\n"
            "   - Chacune : « numéros des phrases clés (5 max)|nom descriptif en anglais|groupe d'attaquants qui la mène ou - ».\n"
            "   - Si le rapport est une analyse purement technique d'un binaire ou d'une CVE sans opération racontée, NE CRÉE AUCUNE CAMPAGNE (laisser vide)."
        )


# ======================================================================================================================
# 2. TargetSpecialistAgent : Victimologie, Pays et Cibles Logicielles
# ======================================================================================================================
class TargetSpecialistAgent:
    """Agent spécialisé dans la victimologie et la surface technique attaquée.
    Extrait : identity (victimes, secteurs), location (pays visés), software (produit visé), vulnerability (CVE)."""

    SCHEMA = _schema("targets")

    @staticmethod
    def prompt(text: str) -> str:
        sectors = ", ".join(sorted(INDUSTRY_SECTOR))
        return (
            f"{text}\n\n---\n"
            "TÂCHE (Target Specialist Agent) : identifie toutes les cibles et victimes de l'attaque décrite :\n"
            "« targets » : éléments séparés par « ; », chacun sous une de ces formes :\n"
            "   - « identity|nom ou secteur|classe|secteur|code_pays_ISO|attaquant_ou_- »\n"
            "     Classes : organization (entreprise ou institution nommée), class (secteur entier ex: <sector>), "
            "individual (personne), group.\n"
            f"     Secteurs admis : {sectors}.\n"
            "   - « location|nom_pays|code_ISO_2_lettres » (ex: location|<country_name>|<ISO_code>).\n"
            "   - « software|produit|éditeur » (logiciel légitime visé ou compromis, ex: software|<product_name>|<vendor_name>).\n"
            "   - « identity|éditeur|organization » (l'éditeur du produit visé, ex: identity|<vendor_name>|organization).\n"
            "   - « vulnerability|CVE-YYYY-NNNNN » (vulnérabilité exploitée ou ciblée mentionnée dans le texte).\n"
            "JAMAIS : l'auteur du rapport, les éditeurs de sécurité publiant l'analyse, ni les hébergeurs/CDN ordinaires."
        )


# ======================================================================================================================
# 2 bis. ContextObjectsAgent : Infrastructure, Mesures de défense, Analyses d'échantillons
# ======================================================================================================================
class ContextObjectsAgent:
    """Types du registre qu'aucun autre prompt ne demande : infrastructure, course-of-action, malware-analysis.
    Définitions et formes tirées de `specs.TYPE_SPECS`."""

    TYPES = ("infrastructure", "course-of-action", "malware-analysis")
    SCHEMA = _schema("objects")

    @classmethod
    def prompt(cls, text: str) -> str:
        specs = "\n".join(f"   - {t} : {TYPE_SPECS[t].definition}\n     Forme : « {TYPE_SPECS[t].form} »" for t in cls.TYPES)
        return (
            f"{text}\n\n---\n"
            "TÂCHE (Context Objects) : relève dans le rapport entier les objets STIX suivants, et eux seuls :\n"
            f"{specs}\n"
            "« objects » : éléments séparés par « ; », chacun sous la forme indiquée pour son type. Rien que le texte affirme ; "
            "aucune IP, aucun domaine, aucune URL, aucun hachage ; rien pour un type que le rapport ne décrit pas."
        )


# ======================================================================================================================
# 3. TTPHunterAgent : Comportements et Procédures (Funnel RAG Découplé)
# ======================================================================================================================
class TTPHunterAgent:
    """Agent spécialisé dans le repérage exhaustif des TTPs (techniques, tactiques et procédures).
    Extrait un tuple comportemental atomique décomposant l'outil, l'action fondamentale et la tactique MITRE :
    phrases | outil_ou_vecteur | action_fondamentale_et_but | tactique | T#### présumé"""

    SCHEMA = _schema("behaviors")

    @staticmethod
    def prompt(text: str) -> str:
        return (
            f"{text}\n\n---\n"
            "TÂCHE (TTP Hunter Agent) : relève CHAQUE action ou mécanisme de l'attaquant ou de ses logiciels malveillants "
            "(accès initial, exécution, persistance, contournement de défense/dissimulation, élévation, découverte système/réseau, "
            "accès aux identifiants, collecte, communication C2, exfiltration, impact...).\n\n"
            "FORMAT OBLIGATOIRE : « behaviors » : éléments séparés par « ; », chacun sous la forme d'un tuple comportemental décomposé :\n"
            "« numéros_phrases | outil_ou_vecteur | action_et_but | tactique | T####.###_présumé_ou_- »\n\n"
            "DÉCOMPOSITION DU TUPLE :\n"
            "1. numéros_phrases : numéros exacts des phrases étayant le comportement (ex: 4 ou 12,13).\n"
            "2. outil_ou_vecteur : nom de l'outil, script, binaire système ou document porteur (ex: <document>, <interpreter>, <system_utility>, ou « - » si aucun outil n'est nommé).\n"
            "3. action_et_but : description en anglais de l'action fondamentale et de l'objectif SANS répéter le nom de l'outil porteur "
            "(ex: « <action> <mechanism> to <goal> »).\n"
            "4. tactique : la tactique ATT&CK parmi la liste stricte suivante :\n"
            "   initial-access, execution, persistence, privilege-escalation, stealth, defense-impairment, credential-access, "
            "discovery, lateral-movement, collection, command-and-control, exfiltration, impact, resource-development, reconnaissance.\n"
            "5. T####.###_présumé_ou_- : identifiant ATT&CK estimé si connu avec certitude, sinon « - ».\n\n"
            "POINTS D'ATTENTION CRUCIAUX :\n"
            "- N'omets JAMAIS l'accès initial.\n"
            "- Quand un outil accomplit une action, relève séparément le lancement de l'outil et l'action elle-même : ce sont deux comportements, souvent de tactiques différentes.\n"
            "- Un comportement par ligne. Sois exhaustif sur tous les mécanismes décrits."
        )

    @classmethod
    def extract(cls, text: str, system: str, call_fn, multi_temp: bool = False) -> list[str]:
        """Extrait les comportements. Si multi_temp=True (MTPE), union des générations à T=0.2 et T=0.7."""
        prompt = cls.prompt(text)
        res_low = call_fn("ttp_low", system, prompt, cls.SCHEMA, 3500, temperature=0.0)
        lines = rows(res_low.get("behaviors"))

        if multi_temp:
            res_high = call_fn("ttp_high", system, prompt, cls.SCHEMA, 3500, temperature=0.7)
            seen = {_behavior_key(line) for line in lines}
            for line in rows(res_high.get("behaviors")):
                key = _behavior_key(line)
                if key[0] and key not in seen:
                    seen.add(key)
                    lines.append(line)
        return lines


# ======================================================================================================================
# 4. CarrierDisambiguationAgent : Attribution rigoureuse du porteur de TTP
# ======================================================================================================================
class CarrierDisambiguationAgent:
    """Résout la convention stricte d'attribution CTI STIX :
    1. malware ou tool si le texte décrit sa capacité propre ;
    2. campaign si le texte décrit l'action dans le déroulement de la vague/opération ;
    3. intrusion-set / threat-actor seulement si aucune entité d'exécution n'est mentionnée."""

    SCHEMA = _schema("carriers")

    @staticmethod
    def prompt(text: str, carriers: list[str], items: list[str]) -> str:
        numbered_carriers = "\n".join(f"{i}. {c}" for i, c in enumerate(carriers, 1))
        numbered_items = "\n".join(f"{i}. {x}" for i, x in enumerate(items, 1))
        return (
            f"{text}\n\n---\n"
            f"PORTEURS POSSIBLES (numérotés) :\n{numbered_carriers}\n\n"
            f"TECHNIQUES RETENUES (comportement et phrases citées) :\n{numbered_items}\n\n"
            "TÂCHE (Carrier Disambiguation) : pour chaque technique, choisis le numéro de son porteur direct (« numéro:porteur ») :\n"
            "RÈGLE D'ATTRIBUTION STIX NON NÉGOCIABLE :\n"
            "- Si la technique est exécutée par un malware ou un outil : attribue-la au MALWARE ou à l'OUTIL (jamais au groupe ni à la campagne).\n"
            "- Si la technique est une action opératoire générale ou la phase initiale d'une opération : attribue-la à la CAMPAGNE.\n"
            "- N'attribue au GROUPE (intrusion-set) que si le texte ne nomme ni malware, ni outil, ni campagne pour cette action.\n"
            "Format : « 1:2;2:1;3:4 » (« - » si aucun). Deux porteurs (« 1:2,4 ») uniquement si le texte attribue explicitement le geste à chacun."
        )


# ======================================================================================================================
# 5. RelationWeaverAgent : Liaisons d'Attribution, d'Arsenal et de Cibles sur Registre Fermé
# ======================================================================================================================
class RelationWeaverAgent:
    """Agent tisseur de relations STIX 2.1 conditionné strictement sur le Registre d'Entités Canoniques.
    Établit les arêtes structurelles : attribution, arsenal (campagne/groupe -> malware/outil),
    propagation (malware -> malware), ciblage (cibles, lieux, secteurs) et vulnérabilités (software -> vulnerability)."""

    SCHEMA = _schema("relations")

    @staticmethod
    def prompt(text: str, entities: list[str]) -> str:
        numbered = "\n".join(f"{i}. {e}" for i, e in enumerate(entities, 1))
        return (
            f"{text}\n\n---\n"
            f"REGISTRE DES ENTITÉS DU RAPPORT (numérotées) :\n{numbered}\n\n"
            "TÂCHE (Relation Weaver) : relie UNIQUEMENT les entités de cette liste fermée selon les faits affirmés par le texte.\n"
            "Format : « numéro_source|relation|numéro_cible|numéros_de_phrases » séparés par « ; »\n"
            "(exemples : « 2|attributed-to|1|4 ; 2|uses|3|10 ; 3|drops|4|15 ; 2|targets|5|1 ; 6|has|7|2 »).\n\n"
            "TABLE DES RELATIONS STIX 2.1 ADMISES (source --relation--> cible ; aucune autre) :\n"
            f"{relation_table()}\n"
            f"SENS DES RELATIONS (choisis celle dont le sens correspond à ce que dit le texte) :\n{relation_definitions()}\n"
            "Repères : attribution (attributed-to, authored-by), arsenal (uses, drops, downloads, delivers), ciblage (targets ; "
            "exploits réservé au malware), infrastructure (beacons-to, communicates-with, exfiltrates-to, hosts, controls, owns, "
            "compromises), origine (originates-from, located-at), défense (course-of-action mitigates / remediates), analyse "
            "(malware-analysis analysis-of malware), software --has--> vulnerability, software --related-to--> identity (éditeur).\n\n"
            "RÈGLES D'OR DE MODÉLISATION ET DE PRÉCISION :\n"
            "- Chaque relation part de l'entité qui accomplit le geste. Ce qui livre une charge utile (dropper, loader, script) est employé par "
            "la campagne ou relié à la charge par drops / downloads ; la charge utile n'utilise ni n'exploite ce qui l'a livrée.\n"
            "- Si le texte attribue un malware ou un outil à un groupe, relie le groupe au malware (intrusion-set --uses--> malware) ; "
            "si une campagne l'emploie, relie aussi la campagne (campaign --uses--> malware).\n"
            "- Utilise EXCLUSIVEMENT les numéros de la liste ci-dessus.\n"
            "- Cite le ou les numéros de phrases exactes qui étayent le lien."
        )


GraphLinkerAgent = RelationWeaverAgent
