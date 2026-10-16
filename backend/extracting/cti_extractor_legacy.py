"""
DÉPRÉCIÉ : ancien extracteur (ontologie maison, un appel LLM séquentiel par segment, ~10 min par article).
Remplacé par `cti_extractor.py` (ontologie STIX, `pipeline.py`). Conservé uniquement parce que le tableau de bord lit
encore l'ancien graphe Neo4j (`Entity`, `Article`) ; à supprimer quand le tableau de bord aura migré.

Module V2 d'Extraction de Cyber Threat Intelligence (CTI) pour Knowledge Graph & Attack Graph.
Intègre :
- Contrainte grammaticale stricte par schéma Pydantic (Ollama Structured Outputs)
- Mémoire inter-segments (Rolling Entity Registry) pour la résolution des coréférences
- Boucle d'auto-correction ontologique (Reflexion) validant Domain/Range et citations exactes
- Modélisation non-manichéenne (UsagePosture par triplet) et états d'Attack Graph
"""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import threading
import time
from typing import Any, Dict, List, Literal as PyLiteral, Optional, Set, Tuple

import json_repair
from pydantic import BaseModel, Field
import requests
from requests.adapters import HTTPAdapter
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from urllib3.util.retry import Retry
root_dir = Path(__file__).resolve().parents[2]
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from backend.ontology.ontology import (
    build_rdf_graph,
    filter_threat_centric_graph,
    clean_uri_fragment,
)
from backend.database.neo4j_store import Neo4jStore
from backend.preprocessing.cleaner import UniversalCTICleaner

os.environ["NO_PROXY"] = "localhost,127.0.0.1"

BASE_DIR = root_dir
# Base SQLite source en LECTURE SEULE pour charger les articles prétraités (knowledge & article_classifications).
# Neo4j est l'UNIQUE base de données pour la persistance du Knowledge Graph d'extraction.
SOURCE_ARTICLES_DB = BASE_DIR / "db_outputs" / "cti_knowledge.db"
OLLAMA_API_URL = "http://localhost:11434/api/generate"

DEFAULT_MODEL = "qwen3:32b"
MAX_WORKERS = 1
CONTEXT_WINDOW = 16384
MAX_OUTPUT_TOKENS = 3000
MAX_BUNDLE_CHARS = 7500      # 4 à 5 segments narratifs max par article au lieu de 17
TIMEOUT_SECONDS = 300
MAX_REFLEXION_RETRIES = 0    # Plus de double inférence pénalisante

console = Console()
thread_local = threading.local()

# =====================================================================
# 1. SCHÉMA PYDANTIC (CONTRAINTE GRAMMATICALE GBNF POUR OLLAMA)
# =====================================================================

EntityClassEnum = PyLiteral[
    "cti:ThreatActor",
    "cti:VictimProfile",
    "cti:SoftwareSystem",
    "cti:HardwareOrHost",
    "cti:IdentityOrCredential",
    "cti:DataRepository",
    "cti:Vulnerability",
    "cti:Misconfiguration",
    "cti:AttackPattern",
    "cti:Infrastructure",
    "cti:ObservableIndicator",
    "cti:DefensiveMeasure",
]

UsagePostureEnum = PyLiteral[
    "cti:DedicatedMalwarePosture",
    "cti:LOTLPosture",
    "cti:DualUseAdminToolPosture",
    "cti:CommercialRedTeamPosture",
    "cti:BYOVDPosture",
    "cti:LegitimateTargetPosture",
]

RelationPredicateEnum = PyLiteral[
    "cti:attributed_to",
    "cti:operates_infrastructure",
    "cti:resolves_to_indicator",
    "cti:spawns_process",
    "cti:drops_artifact",
    "cti:injects_into",
    "cti:implements_technique",
    "cti:affects_asset",
    "cti:exploits_weakness",
    "cti:targets",
    "cti:harvests_asset",
    "cti:authenticates_with",
    "cti:communicates_with_c2",
    "cti:exfiltrates_to",
    "ag:leads_to_step",
    "cti:detects_or_mitigates",
]

ModalityEnum = PyLiteral[
    "cti:ObservedInIncident",
    "cti:ProofOfConceptOrLab",
    "cti:HypothesizedCapability",
]

SecurityStateEnum = PyLiteral[
    "ag:UnauthenticatedNetworkAccess",
    "ag:AuthenticatedUserAccess",
    "ag:LocalCodeExecution",
    "ag:SystemOrRootPrivilege",
    "ag:DomainOrTenantAdminAccess",
    "ag:SensitiveDataAccess",
]


class CTIEntitySchema(BaseModel):
    id: str = Field(description="Identifiant préfixé unique (ex: actor:unc3944, software:powershell, weakness:cve-2023-4966, pattern:t1059-001, infra:c2_bucket).")
    type: EntityClassEnum = Field(description="Classe ontologique avec préfixe cti:.")
    name: str = Field(description="Nom canonique exact.")
    cpe23Uri: Optional[str] = Field(default=None, description="Identifiant CPE 2.3 si logiciel/système (ex: cpe:2.3:a:citrix:netscaler_gateway:13.1-48.47:*:*:*:*:*:*:*).")
    cveId: Optional[str] = Field(default=None, description="Identifiant CVE officiel (ex: CVE-2023-4966) si vulnérabilité.")
    mitreId: Optional[str] = Field(default=None, description="Identifiant MITRE ATT&CK (ex: T1059.001) si AttackPattern.")
    requiresPrecondition: Optional[SecurityStateEnum] = Field(default=None, description="État de sécurité précondition requis.")
    yieldsPostcondition: Optional[SecurityStateEnum] = Field(default=None, description="État de sécurité postcondition obtenu.")
    confidenceScore: Optional[int] = Field(default=85, ge=10, le=100)


class RelationshipQualificationSchema(BaseModel):
    source_posture: Optional[UsagePostureEnum] = Field(default=None, description="Posture du sujet logiciel.")
    target_posture: Optional[UsagePostureEnum] = Field(default=None, description="Posture de la cible logicielle.")
    modality: ModalityEnum = Field(default="cti:ObservedInIncident", description="Modalité épistémique.")


class CTIRelationshipSchema(BaseModel):
    subject: str = Field(description="ID de l'entité sujet (ex: actor:unc3944, software:powershell).")
    predicate: RelationPredicateEnum = Field(description="Prédicat ontologique (ex: cti:exploits_weakness, ag:leads_to_step, cti:spawns_process).")
    object: str = Field(description="ID de l'entité objet (ex: weakness:cve-2023-4966, software:psexec).")
    qualification: Optional[RelationshipQualificationSchema] = None
    evidence: str = Field(description="Citation VERBATIM exacte mot pour mot du texte fourni (minimum 15 caractères).")


class GraphMetadataSchema(BaseModel):
    ontology_uri: str = "https://w3id.org/cti/ontology#"
    version: str = "2.0.0"
    incident_id: Optional[str] = None


class CTIIncidentGraphSchema(BaseModel):
    graph_metadata: Optional[GraphMetadataSchema] = None
    entities: List[CTIEntitySchema]
    relationships: List[CTIRelationshipSchema]


# Schéma pour la contrainte grammaticale Ollama Structured Outputs
OLLAMA_JSON_SCHEMA = CTIIncidentGraphSchema.model_json_schema()

# =====================================================================
# 2. SYSTEM PROMPT V2 (CENTRAGE ABSOLU SUR LA MENACE & ANTI-BRUIT)
# =====================================================================
SYSTEM_PROMPT = """Tu es un architecte senior en Cyber Threat Intelligence (CTI) et en modélisation d'Attack Graphs d'entreprise (RDF/OWL, STIX 2.1, MITRE ATT&CK).
Ton rôle est d'extraire le graphe de la menace strictement centré sur l'attaque technique (acteurs, logiciels malveillants/outils, vulnérabilités, données/identifiants dérobés, infrastructure C2, techniques ATT&CK et mesures défensives).

=====================================================================
1. RÈGLE ABSOLUE N°1 : CENTRAGE STRICT SUR LA MENACE (ANTI-BRUIT)
=====================================================================
- INTERDICTION FORMELLE DES ÉDITEURS ET CHERCHEURS DE SÉCURITÉ :
  N'extrais JAMAIS les entreprises de sécurité, équipes de recherche ou blogs (ex: The DFIR Report, Mandiant, Sekoia, CrowdStrike, Rapid7, Unit 42, HarfangLab, SentinelOne, Microsoft Threat Intelligence, Google TAG, BleepingComputer, Anna, Evangelos). Ce sont des observateurs ou des sources d'information, JAMAIS des composants de l'attaque.
- INTERDICTION FORMELLE DES TERMES GÉNÉRIQUES :
  N'extrais JAMAIS de termes d'informatique génériques (computer, system, server, file, folder, network, command line, payload, malware, tool, executable, database, memory, internet, process, victim, target, attacker, user, administrator, activity, code, script, software, incident, intrusion, campaign).
  Chaque entité extraite DOIT être un élément concret et spécifique (ex: un nom précis d'acteur comme 'UNC3944', un binaire précis comme 'powershell.exe' ou 'BlackCat_Locker.exe', une CVE précise comme 'CVE-2023-4966', un identifiant MITRE précis comme 'T1059.001').
- AUCUNE ENTITÉ ORPHELINE :
  Chaque entité de la liste 'entities' DOIT être reliée dans 'relationships'.

=====================================================================
2. IDENTIFIANTS, CLASSES ET PRÉDICATS ONTOLOGIQUES
=====================================================================
Chaque entité possède un 'id' préfixé canonique :
- 'actor:<nom>' : 'cti:ThreatActor' (ex: actor:unc3944, actor:apt29)
- 'asset:<nom>' : 'cti:SoftwareSystem' ou 'cti:HardwareOrHost' (ex: asset:netscaler_gateway avec son 'cpe23Uri')
- 'weakness:<cve>' : 'cti:Vulnerability' ou 'cti:Misconfiguration' (ex: weakness:cve-2023-4966 avec 'cveId')
- 'cred:<nom>' : 'cti:IdentityOrCredential' (ex: cred:oauth_token)
- 'software:<nom>' : 'cti:SoftwareSystem' (ex: software:powershell, software:psexec, software:blackcat, software:rclone)
- 'data:<nom>' : 'cti:DataRepository' (ex: data:customer_db)
- 'infra:<nom>' : 'cti:Infrastructure' (ex: infra:c2_bucket, infra:c2_server)
- 'pattern:<id>' : 'cti:AttackPattern' (ex: pattern:t1059-001, pattern:t1021-002 avec 'mitreId')
- 'defense:<nom>' : 'cti:DefensiveMeasure' (ex: defense:sigma_psexec)

Prédicats autorisés :
- 'cti:exploits_weakness' : (actor | software | pattern) -> (weakness)
- 'cti:affects_asset' : (weakness) -> (software | asset)
- 'cti:harvests_asset' : (actor | software | pattern) -> (cred | data)
- 'ag:leads_to_step' : (weakness | pattern | software) -> (pattern | software | cred | data)
- 'cti:implements_technique' : (actor | software) -> (pattern)
- 'cti:spawns_process' : (software) -> (software)
- 'cti:drops_artifact' : (software) -> (software | indicator)
- 'cti:injects_into' : (software) -> (software)
- 'cti:exfiltrates_to' : (software | data | cred) -> (infra)
- 'cti:communicates_with_c2' : (software) -> (infra)
- 'cti:operates_infrastructure' : (actor) -> (infra)
- 'cti:resolves_to_indicator' : (infra) -> (indicator)
- 'cti:authenticates_with' : (actor | software) -> (cred)
- 'cti:targets' : (actor | software | pattern) -> (victim | asset | software | data)
- 'cti:detects_or_mitigates' : (defense) -> (software | pattern | indicator | infra | weakness)

Postures pour les logiciels ('qualification'):
- 'cti:DedicatedMalwarePosture' : malware dédié exclusif (BlackCat_Locker.exe).
- 'cti:LOTLPosture' : binaire natif de l'OS détourné (powershell.exe, cmd.exe).
- 'cti:DualUseAdminToolPosture' : outil légitime détourné (PsExec.exe, rclone.exe).
- 'cti:LegitimateTargetPosture' : logiciel cible subissant l'exploitation (Citrix Gateway).

Modalités :
- 'cti:ObservedInIncident' : observé lors de l'incident réel.
- 'cti:HypothesizedCapability' : capacité statique du binaire non exécutée pendant l'incident.
- 'cti:ProofOfConceptOrLab' : test ou PoC de laboratoire.

=====================================================================
3. RÈGLE D'OR DE PREUVE (ANTI-HALLUCINATION)
=====================================================================
Le champ 'evidence' DOIT être un copier-coller textuel exact (minimum 15 caractères) tiré du texte fourni.

=====================================================================
4. EXEMPLE DE RÉFÉRENCE (GOLD STANDARD)
=====================================================================
RAPPORT SOURCE :
\"En octobre 2024, le cluster d'activité suspecté UNC3944 a compromis l'infrastructure périphérique d'un opérateur de télécommunications ouest-européen. L'accès initial a été obtenu par l'exploitation de la vulnérabilité critique CVE-2023-4966 (dite « Citrix Bleed ») affectant l'appliance Citrix NetScaler Gateway (version 13.1-48.47). À partir d'un accès réseau non authentifié, l'attaquant a pu contourner les mécanismes d'authentification et dérober un jeton de session OAuth appartenant à un administrateur système.
Muni de cette session légitime, l'acteur a ouvert une session interactive et a invoqué l'interpréteur natif powershell.exe pour exécuter la technique ATT&CK T1059.001. Depuis PowerShell, l'attaquant a exécuté l'utilitaire d'administration légitime PsExec.exe afin d'obtenir des privilèges complets (System / Root) sur le contrôleur de domaine interne.
Une fois sur le contrôleur, UNC3944 a déposé un binaire malveillant dédié nommé BlackCat_Locker.exe dans C:\\Windows\\Temp\\. Bien que l'échantillon analysé contienne la capacité statique de détruire les clichés instantanés VSS, cette fonction n'a pas été exécutée lors de l'incident. En revanche, l'acteur a détourné l'outil de synchronisation cloud rclone.exe pour transférer les archives de bases de données clients vers un bucket de stockage externe situé sur l'infrastructure C2 storage-sync-cdn[.]com (185.220.101.5), matérialisant un accès non autorisé à des données sensibles.
La règle de détection Sigma proc_creation_win_psexec_lateral_movement.yml permet de détecter cette séquence d'exécution.\"

RÉSULTAT ATTENDU :
{
  "graph_metadata": {
    "ontology_uri": "https://w3id.org/cti/ontology#",
    "version": "2.0.0",
    "incident_id": "INC-2024-10-UNC3944"
  },
  "entities": [
    {"id": "actor:unc3944", "type": "cti:ThreatActor", "name": "UNC3944", "confidenceScore": 85},
    {"id": "asset:netscaler_gateway", "type": "cti:SoftwareSystem", "name": "Citrix NetScaler Gateway", "cpe23Uri": "cpe:2.3:a:citrix:netscaler_gateway:13.1-48.47:*:*:*:*:*:*:*"},
    {"id": "weakness:cve-2023-4966", "type": "cti:Vulnerability", "name": "CVE-2023-4966", "cveId": "CVE-2023-4966", "yieldsPostcondition": "ag:AuthenticatedUserAccess"},
    {"id": "cred:oauth_token", "type": "cti:IdentityOrCredential", "name": "OAuth Session Token (Admin)"},
    {"id": "software:powershell", "type": "cti:SoftwareSystem", "name": "powershell.exe"},
    {"id": "software:psexec", "type": "cti:SoftwareSystem", "name": "PsExec.exe"},
    {"id": "software:blackcat", "type": "cti:SoftwareSystem", "name": "BlackCat_Locker.exe"},
    {"id": "software:rclone", "type": "cti:SoftwareSystem", "name": "rclone.exe"},
    {"id": "data:customer_db", "type": "cti:DataRepository", "name": "Archives de bases de données clients"},
    {"id": "infra:c2_bucket", "type": "cti:Infrastructure", "name": "Storage Sync C2 Bucket"},
    {"id": "pattern:t1059-001", "type": "cti:AttackPattern", "name": "PowerShell Scripting", "mitreId": "T1059.001", "requiresPrecondition": "ag:AuthenticatedUserAccess", "yieldsPostcondition": "ag:LocalCodeExecution"},
    {"id": "pattern:t1021-002", "type": "cti:AttackPattern", "name": "SMB / PsExec Lateral Movement", "mitreId": "T1021.002", "requiresPrecondition": "ag:LocalCodeExecution", "yieldsPostcondition": "ag:SystemOrRootPrivilege"},
    {"id": "pattern:t1490", "type": "cti:AttackPattern", "name": "Inhibit System Recovery", "mitreId": "T1490"},
    {"id": "defense:sigma_psexec", "type": "cti:DefensiveMeasure", "name": "proc_creation_win_psexec_lateral_movement.yml"}
  ],
  "relationships": [
    {"subject": "actor:unc3944", "predicate": "cti:exploits_weakness", "object": "weakness:cve-2023-4966", "qualification": {"target_posture": "cti:LegitimateTargetPosture", "modality": "cti:ObservedInIncident"}, "evidence": "L'accès initial a été obtenu par l'exploitation de la vulnérabilité critique CVE-2023-4966"},
    {"subject": "weakness:cve-2023-4966", "predicate": "cti:affects_asset", "object": "asset:netscaler_gateway", "evidence": "affectant l'appliance Citrix NetScaler Gateway (version 13.1-48.47)"},
    {"subject": "actor:unc3944", "predicate": "cti:harvests_asset", "object": "cred:oauth_token", "evidence": "dérober un jeton de session OAuth appartenant à un administrateur système"},
    {"subject": "weakness:cve-2023-4966", "predicate": "ag:leads_to_step", "object": "pattern:t1059-001", "evidence": "Muni de cette session légitime, l'acteur a ouvert une session interactive et a invoqué l'interpréteur natif powershell.exe"},
    {"subject": "actor:unc3944", "predicate": "cti:implements_technique", "object": "pattern:t1059-001", "qualification": {"source_posture": "cti:LOTLPosture", "modality": "cti:ObservedInIncident"}, "evidence": "invoqué l'interpréteur natif powershell.exe pour exécuter la technique ATT&CK T1059.001"},
    {"subject": "software:powershell", "predicate": "cti:spawns_process", "object": "software:psexec", "qualification": {"source_posture": "cti:LOTLPosture", "target_posture": "cti:DualUseAdminToolPosture", "modality": "cti:ObservedInIncident"}, "evidence": "Depuis PowerShell, l'attaquant a exécuté l'utilitaire d'administration légitime PsExec.exe"},
    {"subject": "software:psexec", "predicate": "cti:drops_artifact", "object": "software:blackcat", "qualification": {"source_posture": "cti:DualUseAdminToolPosture", "target_posture": "cti:DedicatedMalwarePosture", "modality": "cti:ObservedInIncident"}, "evidence": "a déposé un binaire malveillant dédié nommé BlackCat_Locker.exe dans C:\\Windows\\Temp\\"},
    {"subject": "software:blackcat", "predicate": "cti:implements_technique", "object": "pattern:t1490", "qualification": {"source_posture": "cti:DedicatedMalwarePosture", "modality": "cti:HypothesizedCapability"}, "evidence": "contienne la capacité statique de détruire les clichés instantanés VSS, cette fonction n'a pas été exécutée lors de l'incident"},
    {"subject": "software:rclone", "predicate": "cti:harvests_asset", "object": "data:customer_db", "qualification": {"source_posture": "cti:DualUseAdminToolPosture", "modality": "cti:ObservedInIncident"}, "evidence": "détourné l'outil de synchronisation cloud rclone.exe pour transférer les archives de bases de données clients"},
    {"subject": "software:rclone", "predicate": "cti:exfiltrates_to", "object": "infra:c2_bucket", "qualification": {"source_posture": "cti:DualUseAdminToolPosture", "modality": "cti:ObservedInIncident"}, "evidence": "transférer les archives [...] vers un bucket de stockage externe situé sur l'infrastructure C2"},
    {"subject": "defense:sigma_psexec", "predicate": "cti:detects_or_mitigates", "object": "software:psexec", "evidence": "La règle de détection Sigma proc_creation_win_psexec_lateral_movement.yml permet de détecter cette séquence d'exécution"}
  ]
}
"""


SKIP_LLM_SECTIONS = {"indicators", "atomic", "computed", "detections", "network", "sigma", "yara", "mitre att&ck", "timeline", "diamond model", "analysts"}

def extract_structured_sections_fast(clean_markdown: str, main_actor_id: str, main_actor_name: str) -> Dict[str, Any]:
    """
    Extrait en 0.01s (sans LLM) les sections structurées de fin d'article :
    - MITRE ATT&CK (Nom - Txxxx)
    - Indicators (Domaines, IPs, Hashes annotés ex: '172.96.137.160 - AdaptixC2')
    - Detections (Règles YARA & Sigma)
    """
    entities: List[Dict[str, Any]] = []
    relationships: List[Dict[str, Any]] = []

    # 1. Extraction MITRE ATT&CK : "Nom - T1234.001"
    for match in re.finditer(r"^([A-Za-z0-9\s/\-]+?)\s+-\s+(T\d{4}(?:\.\d{3})?)\b", clean_markdown, re.MULTILINE):
        tech_name, mitre_id = match.group(1).strip(), match.group(2).upper()
        pid = f"pattern:{mitre_id.lower().replace('.', '-')}"
        entities.append({
            "id": pid,
            "type": "cti:AttackPattern",
            "name": f"{tech_name} ({mitre_id})",
            "mitreId": mitre_id,
        })
        relationships.append({
            "subject": main_actor_id,
            "predicate": "cti:implements_technique",
            "object": pid,
            "evidence": match.group(0).strip(),
        })

    # 2. Extraction IOCs annotés : "ev2sirbd269o5j.org - BumbleBee" ou "172.96.137.160 - AdaptixC2"
    for match in re.finditer(r"^([a-zA-Z0-9.\-_]{5,})\s+-\s+([A-Za-z0-9\s]+)$", clean_markdown, re.MULTILINE):
        ioc_val, context_label = match.group(1).strip(), match.group(2).strip()
        if ioc_val.startswith("T1") or len(context_label) > 35:
            continue
        ind_id = f"indicator:{clean_uri_fragment(ioc_val)}"
        infra_id = f"infra:{clean_uri_fragment(context_label)}_c2"
        entities.append({
            "id": infra_id,
            "type": "cti:Infrastructure",
            "name": f"{context_label} Infrastructure",
        })
        entities.append({
            "id": ind_id,
            "type": "cti:ObservableIndicator",
            "name": ioc_val,
        })
        relationships.append({
            "subject": main_actor_id,
            "predicate": "cti:operates_infrastructure",
            "object": infra_id,
            "evidence": match.group(0).strip(),
        })
        relationships.append({
            "subject": infra_id,
            "predicate": "cti:resolves_to_indicator",
            "object": ind_id,
            "evidence": match.group(0).strip(),
        })

    return {"entities": entities, "relationships": relationships}

def export_to_turtle(
    entities: List[Dict[str, Any]],
    relations: List[Dict[str, Any]],
    article_meta: Optional[Dict[str, Any]] = None,
) -> str:
    """Exporte les entités et relations en format RDF/Turtle standard."""
    g = build_rdf_graph(entities, relations, article_meta)
    return g.serialize(format="turtle")


def export_to_owl(
    entities: List[Dict[str, Any]],
    relations: List[Dict[str, Any]],
    article_meta: Optional[Dict[str, Any]] = None,
) -> str:
    """Exporte les entités et relations en format OWL/XML standard."""
    g = build_rdf_graph(entities, relations, article_meta)
    return g.serialize(format="xml")


def init_kg_tables() -> None:
    """Initialise le schéma Neo4j (contraintes d'unicité, index) pour le Knowledge Graph."""
    store = Neo4jStore.get_instance()
    ok, err = store.check_connection()
    if ok:
        store.init_schema()
    else:
        console.print(f"[bold yellow]Avertissement : Neo4j non joignable ({err}). Le schéma sera initialisé dès connexion.[/]")


def get_worker_session() -> requests.Session:
    """Session HTTP réutilisable par thread pour requêter Ollama."""
    if not hasattr(thread_local, "session"):
        session = requests.Session()
        session.trust_env = False
        retry_strategy = Retry(
            total=2,
            backoff_factor=1.0,
            status_forcelist=[500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=10)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        thread_local.session = session
    return thread_local.session


def split_markdown_by_headings(clean_markdown: str) -> List[Tuple[str, str]]:
    """Découpe linéairement en O(N) le markdown en sections (titre, contenu)."""
    blocks: List[Tuple[str, str]] = []
    current_title = "Introduction"
    current_lines: List[str] = []

    for line in clean_markdown.splitlines():
        if re.match(r"^#{1,6}\s+", line):
            if current_lines:
                blocks.append((current_title, "\n".join(current_lines).strip()))
                current_lines = []
            current_title = re.sub(r"^#{1,6}\s+", "", line).strip()
            current_lines.append(line)
        else:
            current_lines.append(line)

    if current_lines:
        blocks.append((current_title, "\n".join(current_lines).strip()))

    return blocks


def create_extraction_bundles(
    clean_markdown: str,
    sections_meta: List[Dict[str, Any]],
    max_chars: int = MAX_BUNDLE_CHARS,
) -> List[Dict[str, Any]]:
    """Découpe le texte propre en bundles narratifs cohérents respectant les frontières de sections."""
    total_len = len(clean_markdown)
    if total_len <= max_chars or not sections_meta:
        return [{
            "bundle_index": 0,
            "total_bundles": 1,
            "sections_included": [s.get("title", "") for s in sections_meta] if sections_meta else ["Intégral"],
            "text": clean_markdown,
            "char_count": total_len,
        }]

    blocks = [
        (title, block)
        for title, block in split_markdown_by_headings(clean_markdown)
        if title.strip().lower() not in SKIP_LLM_SECTIONS
    ]
    bundles: List[Dict[str, Any]] = []
    current_bundle_sections: List[str] = []
    current_bundle_text: List[str] = []
    current_bundle_len = 0

    for title, block in blocks:
        block_len = len(block)
        if block_len > max_chars:
            if current_bundle_text:
                bundles.append({
                    "bundle_index": len(bundles),
                    "total_bundles": 0,
                    "sections_included": list(current_bundle_sections),
                    "text": "\n\n".join(current_bundle_text),
                    "char_count": current_bundle_len,
                })
                current_bundle_sections, current_bundle_text, current_bundle_len = [], [], 0

            cur_sub = ""
            for sline in block.splitlines(keepends=True):
                if len(cur_sub) + len(sline) > max_chars and cur_sub:
                    bundles.append({
                        "bundle_index": len(bundles),
                        "total_bundles": 0,
                        "sections_included": [title],
                        "text": cur_sub.strip(),
                        "char_count": len(cur_sub),
                    })
                    cur_sub = sline
                else:
                    cur_sub += sline
            if cur_sub.strip():
                bundles.append({
                    "bundle_index": len(bundles),
                    "total_bundles": 0,
                    "sections_included": [title],
                    "text": cur_sub.strip(),
                    "char_count": len(cur_sub),
                })
            continue

        if current_bundle_len + block_len > max_chars and current_bundle_text:
            bundles.append({
                "bundle_index": len(bundles),
                "total_bundles": 0,
                "sections_included": list(current_bundle_sections),
                "text": "\n\n".join(current_bundle_text),
                "char_count": current_bundle_len,
            })
            current_bundle_sections = [title]
            current_bundle_text = [block]
            current_bundle_len = block_len
        else:
            current_bundle_sections.append(title)
            current_bundle_text.append(block)
            current_bundle_len += block_len

    if current_bundle_text:
        bundles.append({
            "bundle_index": len(bundles),
            "total_bundles": 0,
            "sections_included": list(current_bundle_sections),
            "text": "\n\n".join(current_bundle_text),
            "char_count": current_bundle_len,
        })

    for b in bundles:
        b["total_bundles"] = len(bundles)

    return bundles


def format_entity_memory_context(rolling_entities: Dict[str, str]) -> str:
    """Formate le registre des entités déjà extraites des segments précédents pour éviter les doublons."""
    if not rolling_entities:
        return "Aucune entité extraite précédemment (Premier segment)."
    items = [f"- '{name}' (type: {etype})" for name, etype in list(rolling_entities.items())[:60]]
    return (
        "ENTITÉS DÉJÀ IDENTIFIÉES DANS LES SEGMENTS PRÉCÉDENTS (Réutilise EXACTEMENT ces noms canoniques "
        "si le texte y fait référence par un pronom ou synonyme comme 'the script', 'the bot', 'the actor') :\n"
        + "\n".join(items)
    )


def query_llm_extractor(
    text_chunk: str,
    article_title: str,
    category: str,
    bundle_info: str,
    model_name: str,
    entity_memory_str: str,
    correction_feedback: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Interroge Ollama avec contrainte grammaticale JSON Schema (Structured Outputs)
    et supporte une passe de rétroaction ontologique (Reflexion) en cas d'erreurs OWL.
    """
    user_prompt = f"""RAPPORT CTI À ANALYSER :
Titre de l'incident : {article_title}
Catégorie CTI : {category.upper()}
Contexte du segment : {bundle_info}

{entity_memory_str}

CONTENU TECHNIQUE DU SEGMENT :
{text_chunk}
"""
    if correction_feedback:
        user_prompt += f"""
=====================================================================
CORRECTION ONTOLOGIQUE OBLIGATOIRE SUITE À TON EXTRACTION PRÉCÉDENTE :
Certains triplets ont été rejetés par le validateur RDF/OWL pour les raisons suivantes :
{correction_feedback}
Corrige ces triplets en respectant strictement les domaines/ranges de l'ontologie et en copiant une citation 'evidence' exacte du texte.
=====================================================================
"""
    else:
        user_prompt += (
            "\nINSTRUCTION : Extrais tous les triplets sémantiques connectés conformes à l'ontologie V2. "
            "Assure-toi que chaque 'evidence' est une sous-chaîne exacte copiée du CONTENU TECHNIQUE DU SEGMENT."
        )

    session = get_worker_session()
    payload = {
        "model": model_name,
        "system": SYSTEM_PROMPT,
        "prompt": user_prompt,
        "format": "json",  # Grammaire GBNF stricte
        "think": False,                # Désactive le bloc <think> verbeux sur qwen3 en mode JSON Schema
        "stream": False,
        "keep_alive": -1,
        "options": {
            "temperature": 0.05,
            "num_predict": MAX_OUTPUT_TOKENS,
            "num_ctx": CONTEXT_WINDOW,
        },
    }

    try:
        resp = session.post(OLLAMA_API_URL, json=payload, timeout=TIMEOUT_SECONDS)
        resp.raise_for_status()
        raw_response = resp.json().get("response", "{}")
    except requests.exceptions.Timeout:
        raise TimeoutError(f"Timeout ({TIMEOUT_SECONDS}s) sur le segment '{bundle_info}'.")
    except requests.exceptions.ChunkedEncodingError as e:
        raise RuntimeError(f"Erreur de lecture stream Ollama (unexpected EOF / ChunkedEncoding): {e}")
    except Exception as e:
        raise RuntimeError(f"Erreur HTTP/Ollama: {e}")

    clean_json_str = re.sub(r"<think>.*?</think>", "", raw_response, flags=re.DOTALL).strip()
    match = re.search(r"\{.*\}", clean_json_str, re.DOTALL)
    if match:
        clean_json_str = match.group(0)

    parsed = json_repair.loads(clean_json_str)
    if not isinstance(parsed, dict):
        parsed = parsed[0] if (isinstance(parsed, list) and parsed and isinstance(parsed[0], dict)) else {}

    # Si le LLM a renvoyé des triplets legacy, convertir en format graph
    if "triplets" in parsed and "entities" not in parsed:
        conv_entities = []
        conv_relationships = []
        for t in parsed.get("triplets", []):
            if not isinstance(t, dict):
                continue
            src_name = t.get("source_name", "")
            tgt_name = t.get("target_name", "")
            if not src_name or not tgt_name:
                continue
            src_type = t.get("source_type", "software_system")
            tgt_type = t.get("target_type", "software_system")
            s_id = f"entity:{clean_uri_fragment(src_name)}"
            t_id = f"entity:{clean_uri_fragment(tgt_name)}"
            conv_entities.append({"id": s_id, "name": src_name, "type": src_type})
            conv_entities.append({"id": t_id, "name": tgt_name, "type": tgt_type})
            conv_relationships.append({
                "subject": s_id,
                "predicate": t.get("relation_type", "cti:implements_technique"),
                "object": t_id,
                "qualification": {
                    "source_posture": t.get("source_posture"),
                    "target_posture": t.get("target_posture"),
                    "modality": t.get("modality", "cti:ObservedInIncident"),
                },
                "evidence": t.get("evidence", ""),
            })
        parsed = {
            "graph_metadata": {"ontology_uri": "https://w3id.org/cti/ontology#", "version": "2.0.0"},
            "entities": conv_entities,
            "relationships": conv_relationships,
        }

    return {"data": parsed, "raw": raw_response}


def extract_bundle_with_reflexion(
    b: Dict[str, Any],
    title: str,
    cat: str,
    b_info: str,
    model_name: str,
    rolling_entities: Dict[str, str],
    p_out: Console,
    kid: int,
) -> Tuple[Dict[str, Any], str]:
    """
    Extrait le sous-graphe d'un segment avec Structured Outputs, le valide sévèrement
    contre l'ontologie CTI (anti-bruit, anti-chercheurs, anti-termes génériques, ancrage)
    et déclenche une passe d'auto-correction ontologique (Reflexion) si nécessaire.
    """
    memory_str = format_entity_memory_context(rolling_entities)
    res = query_llm_extractor(b["text"], title, cat, b_info, model_name, memory_str)
    raw_logs = [res.get("raw", "")]
    candidate_graph = res.get("data", {})

    filtered_graph, rejections = filter_threat_centric_graph(candidate_graph, source_document_text=b["text"])

    # Boucle Reflexion si des erreurs sont survenues et que l'extraction est vide ou très incomplète
    if rejections and MAX_REFLEXION_RETRIES > 0 and (not filtered_graph.get("entities") or not filtered_graph.get("relationships")):
        p_out.print(
            f"    [yellow]↻ Art {kid:4d} ({b_info}) : {len(rejections)} élément(s) rejeté(s) "
            f"→ Passe d'auto-correction ontologique...[/]"
        )
        feedback_text = "\n".join(rejections[:8])
        retry_res = query_llm_extractor(
            b["text"], title, cat, b_info, model_name, memory_str, correction_feedback=feedback_text
        )
        raw_logs.append(retry_res.get("raw", ""))
        retry_graph = retry_res.get("data", {})
        re_filtered, _ = filter_threat_centric_graph(retry_graph, source_document_text=b["text"])

        if len(re_filtered.get("relationships", [])) >= len(filtered_graph.get("relationships", [])):
            filtered_graph = re_filtered

    # Mémoriser les entités découvertes pour les segments suivants
    for ent in filtered_graph.get("entities", []):
        rolling_entities[ent["name"]] = ent["type"]

    return filtered_graph, "\n--- REFLEXION PASS ---\n".join(raw_logs)


def fuse_incident_graphs(
    bundle_graphs: List[Dict[str, Any]],
    raw_accumulated: List[str],
    incident_id: Optional[str] = None,
) -> Tuple[Dict[str, Any], str]:
    """
    Fusionne les sous-graphes validés issus des différents bundles d'un même article :
    - Réconcilie les identifiants et entités canoniques
    - Enrichit les métadonnées (CPE, CVE, MITRE, préconditions/postconditions)
    - Déduplique les relations
    - Élimine les entités orphelines (degree == 0)
    """
    merged_entities_by_id: Dict[str, Dict[str, Any]] = {}
    merged_entities_by_name: Dict[str, Dict[str, Any]] = {}
    merged_relations: List[Dict[str, Any]] = []
    seen_rel_keys: Set[Tuple[str, str, str, str]] = set()
    node_degrees: Dict[str, int] = {}

    for bg in bundle_graphs:
        for ent in bg.get("entities", []):
            eid = ent.get("id", "")
            name = ent.get("name", "")
            if not eid or not name:
                continue
            name_lower = name.lower()

            existing = merged_entities_by_id.get(eid) or merged_entities_by_name.get(name_lower)
            if existing:
                if eid not in merged_entities_by_id:
                    merged_entities_by_id[eid] = existing
                if ent.get("cpe23Uri") and not existing.get("cpe23Uri"):
                    existing["cpe23Uri"] = ent["cpe23Uri"]
                if ent.get("cveId") and not existing.get("cveId"):
                    existing["cveId"] = ent["cveId"]
                if ent.get("mitreId") and not existing.get("mitreId"):
                    existing["mitreId"] = ent["mitreId"]
                if ent.get("requiresPrecondition") and not existing.get("requiresPrecondition"):
                    existing["requiresPrecondition"] = ent["requiresPrecondition"]
                if ent.get("yieldsPostcondition") and not existing.get("yieldsPostcondition"):
                    existing["yieldsPostcondition"] = ent["yieldsPostcondition"]
                if ent.get("confidenceScore") and (not existing.get("confidenceScore") or ent["confidenceScore"] > existing.get("confidenceScore", 0)):
                    existing["confidenceScore"] = ent["confidenceScore"]
            else:
                ent_copy = dict(ent)
                merged_entities_by_id[eid] = ent_copy
                merged_entities_by_name[name_lower] = ent_copy
                node_degrees[eid] = 0

        for rel in bg.get("relationships", []):
            raw_s = rel.get("subject", "")
            raw_t = rel.get("object", "")
            s_ent = merged_entities_by_id.get(raw_s) or merged_entities_by_name.get(raw_s.lower())
            t_ent = merged_entities_by_id.get(raw_t) or merged_entities_by_name.get(raw_t.lower())
            s_id = s_ent["id"] if s_ent else raw_s
            t_id = t_ent["id"] if t_ent else raw_t

            rel_canonical = dict(rel)
            rel_canonical["subject"] = s_id
            rel_canonical["object"] = t_id

            pred = rel.get("predicate", "")
            qual = rel.get("qualification", {}) or {}
            mod = qual.get("modality", "")
            key = (s_id, pred, t_id, mod)

            if key not in seen_rel_keys:
                seen_rel_keys.add(key)
                merged_relations.append(rel_canonical)
                node_degrees[s_id] = node_degrees.get(s_id, 0) + 1
                node_degrees[t_id] = node_degrees.get(t_id, 0) + 1

    seen_eids = set()
    final_entities = []
    for ent in merged_entities_by_name.values():
        eid = ent.get("id")
        if eid and eid not in seen_eids and node_degrees.get(eid, 0) > 0:
            seen_eids.add(eid)
            final_entities.append(ent)

    raw_combined = "\n\n--- BUNDLE BREAK ---\n\n".join(raw_accumulated)

    final_graph = {
        "graph_metadata": {
            "ontology_uri": "https://w3id.org/cti/ontology#",
            "version": "2.0.0",
            "incident_id": incident_id or "INC-EXTRACTED",
        },
        "entities": final_entities,
        "relationships": merged_relations,
    }
    return final_graph, raw_combined


def normalize_entity_name(name: str) -> str:
    """Normalise un nom d'entité et standardise les identifiants CVE / MITRE ATT&CK."""
    if not name:
        return ""
    n = re.sub(r"^['\"`*_]+|['\"`*_]+$", "", name.strip()).strip()
    cve_match = re.search(r"\b(CVE-\d{4}-\d{4,7})\b", n, re.IGNORECASE)
    if cve_match:
        return cve_match.group(1).upper()
    mitre_match = re.match(r"^(T\d{4}(?:\.\d{3})?)\b", n, re.IGNORECASE)
    if mitre_match:
        return mitre_match.group(1).upper()
    return n


def fuse_extracted_kg(bundles_responses: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], str]:
    """Rétrocompatibilité pour fusionner les bundles d'extraction de test."""
    all_ents: Dict[str, Dict[str, Any]] = {}
    all_rels: List[Dict[str, Any]] = []
    seen_rel_keys: Set[Tuple[str, str, str]] = set()
    raw_texts: List[str] = []

    for b in bundles_responses:
        if "raw" in b:
            raw_texts.append(b["raw"])
        bdata = b.get("data", {})
        for ent in bdata.get("entities", []):
            name = ent["name"]
            if name not in all_ents:
                all_ents[name] = dict(ent)
            else:
                if ent.get("is_dual_use"):
                    all_ents[name]["is_dual_use"] = True
                curr_desc = all_ents[name].get("description", "")
                new_desc = ent.get("description", "")
                if len(new_desc) > len(curr_desc):
                    all_ents[name]["description"] = new_desc

        for rel in bdata.get("relations", []):
            key = (rel.get("source_name", ""), rel.get("relation_type", ""), rel.get("target_name", ""))
            if key not in seen_rel_keys:
                seen_rel_keys.add(key)
                all_rels.append(rel)

    return list(all_ents.values()), all_rels, "\n\n--- BUNDLE BREAK ---\n\n".join(raw_texts)


def save_kg_extraction(
    knowledge_id: int,
    entities: List[Dict[str, Any]],
    relations: List[Dict[str, Any]],
    raw_response: str,
    duration: float,
    status: str = "success",
    error_message: Optional[str] = None,
    title: Optional[str] = None,
    incident_graph: Optional[Dict[str, Any]] = None,
) -> None:
    """Enregistre l'extraction CTI exclusivement dans Neo4j (Property Graph V2)."""
    store = Neo4jStore.get_instance()
    try:
        store.save_extraction(
            knowledge_id=knowledge_id,
            entities=entities,
            relations=relations,
            duration=duration,
            model_version=DEFAULT_MODEL,
            status=status,
            error_message=error_message,
            title=title,
        )
    except Exception as e:
        console.print(f"[bold red]Erreur lors de la sauvegarde Neo4j (Article {knowledge_id}) : {e}[/]")


def fetch_classified_articles_for_extraction(
    limit: int = 10,
    article_id: Optional[int] = None,
    force: bool = False,
) -> List[Dict[str, Any]]:
    """Récupère les articles classifiés prêts pour l'extraction en vérifiant les articles déjà dans Neo4j."""
    store = Neo4jStore.get_instance()
    extracted_ids: Set[int] = set()
    if not force and article_id is None:
        try:
            extracted_ids = store.get_extracted_article_ids()
        except Exception:
            extracted_ids = set()

    with sqlite3.connect(f"file:{SOURCE_ARTICLES_DB}?mode=ro", uri=True, timeout=30.0) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        if article_id is not None:
            query = """
                SELECT k.id, k.title, k.url, c.primary_category, c.clean_markdown, c.sections_meta
                FROM knowledge k
                JOIN article_classifications c ON k.id = c.knowledge_id
                WHERE k.id = ? AND c.is_processable = 1;
            """
            cursor.execute(query, (article_id,))
            rows = cursor.fetchall()
        elif force:
            query = """
                SELECT k.id, k.title, k.url, c.primary_category, c.clean_markdown, c.sections_meta
                FROM knowledge k
                JOIN article_classifications c ON k.id = c.knowledge_id
                WHERE c.is_processable = 1 AND c.primary_category IN ('operational', 'tactical', 'strategic')
                ORDER BY k.id ASC
                LIMIT ?;
            """
            cursor.execute(query, (limit,))
            rows = cursor.fetchall()
        else:
            query = """
                SELECT k.id, k.title, k.url, c.primary_category, c.clean_markdown, c.sections_meta
                FROM knowledge k
                JOIN article_classifications c ON k.id = c.knowledge_id
                WHERE c.is_processable = 1 AND c.primary_category IN ('operational', 'tactical', 'strategic')
                ORDER BY k.id ASC;
            """
            cursor.execute(query)
            all_rows = cursor.fetchall()
            rows = [r for r in all_rows if r["id"] not in extracted_ids][:limit]

        articles = []
        for r in rows:
            clean_md = r["clean_markdown"] or ""
            if not clean_md:
                cur2 = conn.cursor()
                cur2.execute("SELECT content, site_name, url FROM knowledge WHERE id = ?;", (r["id"],))
                raw_c = cur2.fetchone()
                if raw_c and raw_c[0]:
                    prep = UniversalCTICleaner.process(raw_c[0], site_name=raw_c[1], source_url=raw_c[2])
                    clean_md = prep.clean_markdown
                    sections_meta = UniversalCTICleaner.get_sections_metadata(prep)
                else:
                    sections_meta = []
            else:
                try:
                    sections_meta = json.loads(r["sections_meta"] or "[]")
                except Exception:
                    sections_meta = []

            articles.append({
                "id": r["id"],
                "title": r["title"] or "Sans titre",
                "url": r["url"] or "",
                "category": r["primary_category"],
                "clean_markdown": clean_md,
                "sections_meta": sections_meta,
            })
        return articles


def check_ollama_status(model_name: str) -> bool:
    """Vérifie la disponibilité du serveur Ollama."""
    try:
        base_url = OLLAMA_API_URL.replace("/api/generate", "")
        r = requests.get(f"{base_url}/api/tags", timeout=5)
        if r.status_code == 200:
            models = [m.get("name") for m in r.json().get("models", [])]
            matched = any(model_name in m or m.startswith(model_name.split(":")[0]) for m in models)
            if not matched:
                console.print(f"[yellow]Avertissement : Le modèle '{model_name}' n'apparaît pas dans : {models}[/]")
            return True
    except Exception as e:
        console.print(f"[bold red]Erreur de connexion au serveur Ollama ({OLLAMA_API_URL}): {e}[/]")
        return False
    return False


def process_single_article_kg(
    art: Dict[str, Any],
    model_name: str,
    p_console: Optional[Console] = None,
) -> Dict[str, Any]:
    """Exécute l'extraction de graphe avec mémoire d'entités inter-segments et validation Reflexion."""
    start_time = time.time()
    kid = art["id"]
    title = art["title"]
    cat = art["category"]
    clean_md = art["clean_markdown"]
    sec_meta = art["sections_meta"]

    p_out = p_console or console

    if not clean_md or len(clean_md.strip()) < 100:
        save_kg_extraction(
            kid, [], [], "", 0.0,
            status="error",
            error_message="Contenu clean_markdown vide ou insuffisant (< 100 car.)",
            title=title,
        )
        return {
            "id": kid, "title": title, "status": "error",
            "entities_count": 0, "relations_count": 0,
            "duration": 0.0, "error": "Contenu vide",
        }

    bundles = create_extraction_bundles(clean_md, sec_meta, max_chars=MAX_BUNDLE_CHARS)
    bundle_graphs: List[Dict[str, Any]] = []
    raw_accumulated: List[str] = []
    rolling_entities: Dict[str, str] = {}  # Mémoire inter-segments : {nom_canonique: type}

    for b in bundles:
        b_idx = b["bundle_index"] + 1
        b_tot = b["total_bundles"]
        sec_label = ", ".join(b["sections_included"][:2]) if b["sections_included"] else "Général"
        b_info = f"Segment {b_idx}/{b_tot} ({sec_label})"

        p_out.print(
            f"  [cyan]↳ Art {kid:4d}[/] : [yellow]{b_info}[/] "
            f"[dim]({b['char_count']} car. │ {len(rolling_entities)} entités en mémoire)[/] → Inférence LLM..."
        )

        t_bundle = time.time()
        try:
            b_graph, raw_log = extract_bundle_with_reflexion(
                b, title, cat, b_info, model_name, rolling_entities, p_out, kid
            )
            b_dur = time.time() - t_bundle
            b_ent_cnt = len(b_graph.get("entities", []))
            b_rel_cnt = len(b_graph.get("relationships", []))
            p_out.print(
                f"  [green]✓ Art {kid:4d}[/] : [green]Segment {b_idx}/{b_tot} validé[/] "
                f"en [bold]{b_dur:.1f}s[/] ([cyan]{b_ent_cnt} entités, {b_rel_cnt} relations CTI[/])"
            )
            bundle_graphs.append(b_graph)
            raw_accumulated.append(raw_log)
        except Exception as e:
            p_out.print(f"  [bold red]⚠ Art {kid:4d}[/] : [red]Segment {b_idx}/{b_tot} erreur ({e})[/]")
            raw_accumulated.append(f"ERROR: {e}")

    final_graph, raw_combined = fuse_incident_graphs(
        bundle_graphs, raw_accumulated, incident_id=f"INC-ARTICLE-{kid}"
    )
    entities = final_graph["entities"]
    relations = final_graph["relationships"]
    duration = time.time() - start_time

    status = "success" if (entities or relations) else ("partial" if raw_accumulated else "error")
    err_msg = None if status == "success" else "Aucune entité/relation valide après filtrage de menace CTI"

    save_kg_extraction(
        kid, entities, relations, raw_combined, duration,
        status=status, error_message=err_msg, title=title,
        incident_graph=final_graph,
    )

    return {
        "id": kid,
        "title": title,
        "status": status,
        "incident_graph": final_graph,
        "entities_count": len(entities),
        "relations_count": len(relations),
        "entities": entities,
        "relations": relations,
        "duration": duration,
        "bundles_count": len(bundles),
    }


def print_kg_summary_table(stats: Optional[Dict[str, Any]] = None) -> None:
    """Affiche un tableau récapitulatif des entités, relations, postures et phases de Kill Chain depuis Neo4j."""
    store = Neo4jStore.get_instance()
    ok, err = store.check_connection()
    if not ok:
        console.print(f"[bold red]Impossible d'afficher les statistiques : Neo4j non joignable ({err})[/]")
        return

    kg_stats = store.get_summary_stats()
    ent_rows = kg_stats["entities"]
    rel_rows = kg_stats["relations"]
    kc_rows = kg_stats["kill_chain"]
    art_count = kg_stats["article_count"]

    ent_table = Table(title="📊 Entités du Knowledge Graph Neo4j V2 (Alignées Attack Graph)", header_style="bold cyan", border_style="dim")
    ent_table.add_column("Classe Ontologique", style="bold")
    ent_table.add_column("Occurrences", justify="right")
    ent_table.add_column("Contexte Dual-Use / CPE", style="italic")

    for etype, count, dual_cnt, cpe_cnt in ent_rows:
        details = []
        if dual_cnt and dual_cnt > 0:
            details.append(f"[yellow]{dual_cnt} observés en posture Dual-Use/LOTL[/]")
        if cpe_cnt and cpe_cnt > 0:
            details.append(f"[green]{cpe_cnt} avec CPE[/]")
        ent_table.add_row(etype, str(count), " │ ".join(details))

    rel_table = Table(title="🔗 Relations Cypher & Triplets OWL dans Neo4j", header_style="bold green", border_style="dim")
    rel_table.add_column("Type de Relation (Cypher)", style="bold")
    rel_table.add_column("Nombre d'Arêtes", justify="right")

    for rtype, count in rel_rows:
        rel_table.add_row(f"-[bold]{rtype}[/]->", str(count))

    kc_table = Table(title="🎯 Distribution par Phase de Kill Chain", header_style="bold magenta", border_style="dim")
    kc_table.add_column("Phase Kill Chain", style="bold")
    kc_table.add_column("Occurrences", justify="right")

    for kc_phase, count in kc_rows:
        kc_table.add_row(f"{kc_phase}", str(count))

    console.print("\n", ent_table, "\n", rel_table, "\n", kc_table, "\n")
    console.print(Panel(
        f"[green]Articles analysés dans Neo4j :[/] [bold]{art_count}[/]  │  "
        f"[cyan]Nœuds Entités connectés :[/] [bold]{kg_stats['total_entities']}[/]  │  "
        f"[yellow]Relations Cypher validées :[/] [bold]{kg_stats['total_relations']}[/]",
        title="État du Knowledge Graph CTI dans Neo4j (Ontologie Non-Manichéenne & Attack Graph)",
        border_style="green",
    ))


def print_sample_triples(relations: List[Dict[str, Any]], max_display: int = 15) -> None:
    """Affiche les relations extraites avec leurs postures contextuelles et transitions."""
    if not relations:
        return
    table = Table(title="🔍 Triplets CTI Extraits (Postures Contextuelles & Attack Graph)", header_style="bold magenta", border_style="dim")
    table.add_column("Sujet", style="bold cyan", width=25)
    table.add_column("Prédicat", style="bold yellow", justify="center", width=25)
    table.add_column("Objet", style="bold green", width=25)
    table.add_column("Posture / Preuve Verbatim", style="dim white", width=45)

    for r in relations[:max_display]:
        s = r.get("subject") or r.get("source_name", "")
        pred = r.get("predicate") or r.get("relation_type", "")
        obj = r.get("object") or r.get("target_name", "")
        evidence = (r.get("evidence") or "")[:55] + ("..." if len(r.get("evidence") or "") > 55 else "")
        qual = r.get("qualification", {}) or {}
        src_p = qual.get("source_posture") or r.get("source_posture", "")
        tgt_p = qual.get("target_posture") or r.get("target_posture", "")
        mod = qual.get("modality") or r.get("modality", "")
        posture_info = ""
        if src_p or tgt_p or mod:
            posture_info = f"[dim cyan]{src_p or '*'} ➔ {tgt_p or '*'}[/] [dim magenta]({mod})[/]\n"

        table.add_row(
            str(s),
            f"--[bold yellow]{pred}[/]-->",
            str(obj),
            f"{posture_info}{evidence}",
        )

    console.print(table)


def export_rdf_cli(article_id: Optional[int] = None, output_format: str = "turtle") -> None:
    """Exporte le Knowledge Graph V2 en RDF (Turtle ou OWL) directement depuis Neo4j."""
    store = Neo4jStore.get_instance()
    ok, err = store.check_connection()
    if not ok:
        console.print(f"[bold red]Erreur d'export : Neo4j non joignable ({err})[/]")
        return

    entities, relations = store.fetch_entities_and_relations(article_id=article_id)
    if not entities and not relations:
        console.print("[yellow]Aucune donnée trouvée dans Neo4j pour l'export.[/]")
        return

    rdf_text = export_to_owl(entities, relations) if output_format == "owl" else export_to_turtle(entities, relations)
    print(rdf_text)


def main() -> None:
    parser = argparse.ArgumentParser(description="Extracteur CTI Knowledge Graph V2 (Neo4j, Ontologie RDF/OWL & Attack Graph)")
    parser.add_argument("--article-id", type=int, help="Traiter un article spécifique par son ID")
    parser.add_argument("--limit", type=int, default=10, help="Nombre maximal d'articles à traiter")
    parser.add_argument("--workers", type=int, default=MAX_WORKERS, help="Nombre de workers concurrents")
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL, help=f"Modèle Ollama (défaut: {DEFAULT_MODEL})")
    parser.add_argument("--force", action="store_true", help="Re-traiter les articles déjà extraits")
    parser.add_argument("--stats", action="store_true", help="Afficher uniquement les statistiques du Knowledge Graph depuis Neo4j")
    parser.add_argument("--show-triples", action="store_true", help="Afficher les triplets extraits dans le terminal")
    parser.add_argument("--show-json", action="store_true", help="Afficher le Knowledge Graph extrait au format JSON exact")
    parser.add_argument("--export-rdf", choices=["turtle", "owl"], help="Exporter le Knowledge Graph depuis Neo4j en RDF Turtle ou OWL XML")
    parser.add_argument("--migrate-from-sqlite", action="store_true", help="Migrer les extractions de l'ancienne base SQLite vers Neo4j")
    args = parser.parse_args()

    store = Neo4jStore.get_instance()
    neo4j_ok, neo4j_err = store.check_connection()

    if args.migrate_from_sqlite:
        if not neo4j_ok:
            console.print(f"[bold red]Impossible de migrer : Neo4j non joignable ({neo4j_err}).[/]")
            return
        cnt = store.migrate_from_sqlite(SOURCE_ARTICLES_DB)
        console.print(f"[bold green]Migration terminée : {cnt} article(s) migré(s) vers Neo4j ![/]")
        print_kg_summary_table()
        return

    if args.export_rdf:
        export_rdf_cli(article_id=args.article_id, output_format=args.export_rdf)
        return

    if args.stats:
        print_kg_summary_table()
        return

    if args.show_json and args.article_id and not args.force:
        if not neo4j_ok:
            console.print(f"[bold red]Neo4j non joignable ({neo4j_err}).[/]")
            return
        inc_graph = store.get_incident_graph(args.article_id)
        if inc_graph.get("entities") or inc_graph.get("relationships"):
            print(json.dumps(inc_graph, indent=2, ensure_ascii=False))
            return

    console.print(Panel(
        f"[bold cyan]Démarrage de l'Extracteur CTI Knowledge Graph V2 (Structured Outputs + Reflexion ➔ Neo4j)[/]\n"
        f"Modèle LLM : [yellow]{args.model}[/]  │  Workers : [green]{args.workers}[/]  │  Limite : [magenta]{args.limit}[/]  │  Graph DB : [blue]Neo4j (Bolt :7687)[/]",
        border_style="cyan",
    ))

    if not neo4j_ok:
        console.print(Panel(
            f"[bold red]Arrêt : Le serveur Neo4j n'est pas joignable.[/]\n[yellow]Détail : {neo4j_err}\n"
            f"Vérifiez que le conteneur Docker est lancé via : [bold]docker compose up -d[/][/]",
            border_style="red",
        ))
        return

    init_kg_tables()

    if not check_ollama_status(args.model):
        console.print("[bold red]Arrêt : Le serveur Ollama n'est pas joignable.[/]")
        return

    articles = fetch_classified_articles_for_extraction(limit=args.limit, article_id=args.article_id, force=args.force)
    if not articles:
        console.print("[yellow]Aucun article classifié en attente d'extraction.[/]")
        return

    console.print(f"[green]Articles prêts à l'extraction :[/] [bold]{len(articles)}[/]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("[bold cyan]Extraction KG V2 en cours...", total=len(articles))

        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_to_art = {
                executor.submit(process_single_article_kg, art, args.model, progress.console): art
                for art in articles
            }

            for future in as_completed(future_to_art):
                art = future_to_art[future]
                try:
                    res = future.result()
                    if res["status"] in ("success", "partial"):
                        progress.console.print(
                            f"  [bold green]✓[/] [bold]Article {art['id']:4d}[/] [{res['duration']:.1f}s | {res.get('bundles_count', 1)} seg.] : "
                            f"[cyan]{res['entities_count']} entités[/], [yellow]{res['relations_count']} relations CTI[/] ➔ [blue]Neo4j[/] │ "
                            f"[dim]{art['title'][:45]}[/]"
                        )
                        if args.show_json:
                            print(json.dumps(res.get("incident_graph", {}), indent=2, ensure_ascii=False))
                        elif args.show_triples or args.article_id:
                            print_sample_triples(res.get("relations", []))
                    else:
                        progress.console.print(
                            f"  [bold red]✗[/] Article {art['id']:4d} : [red]Échec ({res.get('error')})[/] │ {art['title'][:45]}"
                        )
                except Exception as e:
                    progress.console.print(f"  [bold red]✗[/] Article {art['id']:4d} : [red]Exception : {e}[/]")
                finally:
                    progress.advance(task_id)

    console.print("\n[bold green]Extraction terminée avec succès ![/]")
    print_kg_summary_table()


if __name__ == "__main__":
    main()