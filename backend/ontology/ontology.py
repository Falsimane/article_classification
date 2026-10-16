"""
DÉPRÉCIÉ : cette ontologie maison est remplacée par l'ontologie STIX 2.1 de `backend/ontology/stix/`
(voir son README.md). Ce module reste en place uniquement parce que l'extracteur, le magasin Neo4j et le serveur
l'utilisent encore ; il sera retiré quand ils auront migré.

Module V2 de Gestion de l'Ontologie RDF/OWL CTI & Validation Formelle d'Attack Graph.
Applique strictement les contraintes Domain/Range, le typage non-manichéen (UsagePosture),
la modalité épistémique et la vérification d'ancrage textuel anti-hallucination.
"""

from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from rdflib import Graph, Literal, Namespace, RDF, RDFS, OWL, XSD, URIRef

BASE_DIR = Path(__file__).resolve().parents[2]
ONTOLOGY_DIR = Path(__file__).resolve().parent
ONTOLOGY_FILE = ONTOLOGY_DIR / "cti_killchain_ontology.ttl"

# Espaces de noms RDF
CTI = Namespace("https://w3id.org/cti/ontology#")
KC = Namespace("https://w3id.org/cti/killchain#")
AG = Namespace("https://w3id.org/cti/attackgraph#")

# 1. Classes d'entités autorisées (alignées Attack Graph & Non-Manichéennes)
VALID_ENTITY_CLASSES = {
    "threat_actor": CTI.ThreatActor,
    "victim_profile": CTI.VictimProfile,
    "software_system": CTI.SoftwareSystem,          # Unifie Malware, Tool, LOLBin, Agent IA, App cible
    "hardware_or_host": CTI.HardwareOrHost,        # Serveur, VM, Endpoint, Conteneur
    "identity_or_credential": CTI.IdentityOrCredential,  # Compte, Clé API, Token, Secret .env
    "data_repository": CTI.DataRepository,          # Base de données, Repo Git, Bucket, Partage
    "vulnerability": CTI.Vulnerability,            # CVE
    "misconfiguration": CTI.Misconfiguration,      # Serveur exposé, défaut IAM
    "attack_pattern": CTI.AttackPattern,            # Technique MITRE ATT&CK
    "infrastructure": CTI.Infrastructure,          # C2, Bot Telegram, Webhook, Relais
    "observable_indicator": CTI.ObservableIndicator, # IP, Domaine, URL, Hash, Mutex
    "defensive_measure": CTI.DefensiveMeasure,      # Règle YARA, Sigma, KQL, D3FEND
}

# Rétrocompatibilité contrôlée si un prompt legacy envoie encore "malware" ou "tool"
LEGACY_TYPE_MAPPING = {
    "malware": ("software_system", "dedicated_malware"),
    "tool": ("software_system", "dual_use_admin_tool"),
    "indicator": ("observable_indicator", None),
    "detection_rule": ("defensive_measure", None),
    "target": ("victim_profile", "legitimate_target"),
}

# 2. Postures d'usage contextuelles (remplace le booléen statique isDualUse)
USAGE_POSTURES = {
    "dedicated_malware": CTI.DedicatedMalwarePosture,
    "lotl": CTI.LOTLPosture,                        # Living Off The Land (binaire OS natif)
    "dual_use_admin_tool": CTI.DualUseAdminToolPosture, # RMM, CLI IA, outil transfert détourné
    "commercial_red_team": CTI.CommercialRedTeamPosture,
    "byovd": CTI.BYOVDPosture,                      # Pilote légitime vulnérable
    "legitimate_target": CTI.LegitimateTargetPosture, # Logiciel légitime subissant l'action
}

# 3. Modalités épistémiques (évite de confondre un PoC ou conseil avec une attaque réelle)
EPISTEMIC_MODALITIES = {
    "observed": CTI.ObservedInIncident,
    "poc_or_lab": CTI.ProofOfConceptOrLab,
    "hypothesized": CTI.HypothesizedCapability,
}

# 4. États de sécurité pour la génération de l'Attack Graph
SECURITY_STATES = {
    "unauthenticated_network": AG.UnauthenticatedNetworkAccess,
    "authenticated_user": AG.AuthenticatedUserAccess,
    "local_code_execution": AG.LocalCodeExecution,
    "system_or_root": AG.SystemOrRootPrivilege,
    "domain_or_tenant_admin": AG.DomainOrTenantAdminAccess,
    "sensitive_data_access": AG.SensitiveDataAccess,
}

# 5. Phases de la Kill Chain
KILL_CHAIN_PHASES = {
    "reconnaissance": KC.Reconnaissance,
    "initial_access": KC.InitialAccess,
    "execution": KC.Execution,
    "persistence": KC.Persistence,
    "privilege_escalation": KC.PrivilegeEscalation,
    "defense_evasion": KC.DefenseEvasion,
    "credential_access": KC.CredentialAccess,
    "discovery": KC.Discovery,
    "lateral_movement": KC.LateralMovement,
    "collection": KC.Collection,
    "command_and_control": KC.CommandAndControl,
    "exfiltration": KC.Exfiltration,
    "impact": KC.Impact,
    "detection_defense": KC.DetectionDefense,
}

# 6. Contraintes strictes Domain & Range (aucune coercition aveugle)
PROPERTY_CONSTRAINTS: Dict[str, Dict[str, Any]] = {
    "attributed_to": {
        "uri": CTI.attributed_to,
        "domains": {"software_system", "infrastructure", "attack_pattern"},
        "ranges": {"threat_actor"},
        "default_phase": "reconnaissance",
    },
    "operates_infrastructure": {
        "uri": CTI.operates_infrastructure,
        "domains": {"threat_actor"},
        "ranges": {"infrastructure"},
        "default_phase": "command_and_control",
    },
    "resolves_to_indicator": {
        "uri": CTI.resolves_to_indicator,
        "domains": {"infrastructure"},
        "ranges": {"observable_indicator"},
        "default_phase": "command_and_control",
    },
    "spawns_process": {
        "uri": CTI.spawns_process,
        "domains": {"software_system"},
        "ranges": {"software_system"},
        "default_phase": "execution",
    },
    "drops_artifact": {
        "uri": CTI.drops_artifact,
        "domains": {"software_system"},
        "ranges": {"software_system", "observable_indicator"},
        "default_phase": "execution",
    },
    "injects_into": {
        "uri": CTI.injects_into,
        "domains": {"software_system"},
        "ranges": {"software_system"},
        "default_phase": "defense_evasion",
    },
    "implements_technique": {
        "uri": CTI.implements_technique,
        "domains": {"threat_actor", "software_system"},
        "ranges": {"attack_pattern"},
        "default_phase": "execution",
    },
    "affects_asset": {
        "uri": CTI.affects_asset,
        "domains": {"vulnerability", "misconfiguration"},
        "ranges": {"software_system", "hardware_or_host"},
        "default_phase": "initial_access",
    },
    "exploits_weakness": {
        "uri": CTI.exploits_weakness,
        "domains": {"threat_actor", "software_system", "attack_pattern"},
        "ranges": {"vulnerability", "misconfiguration"},
        "default_phase": "initial_access",
    },
    "targets": {
        "uri": CTI.targets,
        "domains": {"threat_actor", "software_system", "attack_pattern"},
        "ranges": {"victim_profile", "hardware_or_host", "software_system", "data_repository"},
        "default_phase": "initial_access",
    },
    "targets_victim": {
        "uri": CTI.targets,
        "domains": {"threat_actor", "software_system", "attack_pattern"},
        "ranges": {"victim_profile", "hardware_or_host", "software_system", "data_repository"},
        "default_phase": "initial_access",
    },
    "harvests_asset": {
        "uri": CTI.harvests_asset,
        "domains": {"threat_actor", "software_system", "attack_pattern"},
        "ranges": {"identity_or_credential", "data_repository"},
        "default_phase": "credential_access",
    },
    "authenticates_with": {
        "uri": CTI.authenticates_with,
        "domains": {"threat_actor", "software_system"},
        "ranges": {"identity_or_credential"},
        "default_phase": "lateral_movement",
    },
    "communicates_with_c2": {
        "uri": CTI.communicates_with_c2,
        "domains": {"software_system"},
        "ranges": {"infrastructure"},
        "default_phase": "command_and_control",
    },
    "exfiltrates_to": {
        "uri": CTI.exfiltrates_to,
        "domains": {"software_system", "data_repository", "identity_or_credential"},
        "ranges": {"infrastructure"},
        "default_phase": "exfiltration",
    },
    "leads_to_step": {
        "uri": AG.leads_to_step,
        "domains": {"attack_pattern", "vulnerability", "misconfiguration", "software_system"},
        "ranges": {"attack_pattern", "software_system", "identity_or_credential", "data_repository"},
        "default_phase": "execution",
    },
    "detects_or_mitigates": {
        "uri": CTI.detects_or_mitigates,
        "domains": {"defensive_measure"},
        "ranges": {
            "software_system",
            "attack_pattern",
            "observable_indicator",
            "infrastructure",
            "vulnerability",
            "misconfiguration",
        },
        "default_phase": "detection_defense",
    },
}

# --- 7. Mappings Bidirectionnels Préfixes Ontologie <-> snake_case ---
PREFIXED_TO_SNAKE_TYPE = {
    "cti:ThreatActor": "threat_actor",
    "cti:VictimProfile": "victim_profile",
    "cti:SoftwareSystem": "software_system",
    "cti:HardwareOrHost": "hardware_or_host",
    "cti:IdentityOrCredential": "identity_or_credential",
    "cti:DataRepository": "data_repository",
    "cti:Vulnerability": "vulnerability",
    "cti:Misconfiguration": "misconfiguration",
    "cti:AttackPattern": "attack_pattern",
    "cti:Infrastructure": "infrastructure",
    "cti:ObservableIndicator": "observable_indicator",
    "cti:DefensiveMeasure": "defensive_measure",
}
SNAKE_TO_PREFIXED_TYPE = {v: k for k, v in PREFIXED_TO_SNAKE_TYPE.items()}

PREFIXED_TO_SNAKE_POSTURE = {
    "cti:DedicatedMalwarePosture": "dedicated_malware",
    "cti:LOTLPosture": "lotl",
    "cti:DualUseAdminToolPosture": "dual_use_admin_tool",
    "cti:CommercialRedTeamPosture": "commercial_red_team",
    "cti:BYOVDPosture": "byovd",
    "cti:LegitimateTargetPosture": "legitimate_target",
}
SNAKE_TO_PREFIXED_POSTURE = {v: k for k, v in PREFIXED_TO_SNAKE_POSTURE.items()}

PREFIXED_TO_SNAKE_MODALITY = {
    "cti:ObservedInIncident": "observed",
    "cti:HypothesizedCapability": "hypothesized",
    "cti:ProofOfConceptOrLab": "poc_or_lab",
}
SNAKE_TO_PREFIXED_MODALITY = {v: k for k, v in PREFIXED_TO_SNAKE_MODALITY.items()}

PREFIXED_TO_SNAKE_STATE = {
    "ag:UnauthenticatedNetworkAccess": "unauthenticated_network",
    "ag:AuthenticatedUserAccess": "authenticated_user",
    "ag:LocalCodeExecution": "local_code_execution",
    "ag:SystemOrRootPrivilege": "system_or_root",
    "ag:DomainOrTenantAdminAccess": "domain_or_tenant_admin",
    "ag:SensitiveDataAccess": "sensitive_data_access",
}
SNAKE_TO_PREFIXED_STATE = {v: k for k, v in PREFIXED_TO_SNAKE_STATE.items()}

# --- 8. Garde-fous Anti-Bruit : Blacklists Chercheurs & Termes Génériques ---
SECURITY_VENDORS_BLACKLIST = {
    "the dfir report", "dfir report", "sekoia", "mandiant", "crowdstrike", "rapid7",
    "unit 42", "unit42", "palo alto networks", "palo alto", "harfanglab", "sentinelone", "red canary",
    "trend micro", "cisco talos", "talos", "microsoft threat intelligence", "google tag",
    "threat analysis group", "cisa", "fbi", "nsa", "kaspersky", "sophos", "eset",
    "symantec", "fireeye", "cert-fr", "anssi", "mitre", "bleepingcomputer", "the hacker news",
    "recorded future", "insikt group", "checkpoint", "check point", "cybereason",
    "dragos", "proofpoint", "threatconnect", "teamt5", "group-ib", "bitdefender",
    "mcafee", "avast", "malwarebytes", "carbon black", "qualys", "tenable", "f-secure",
    "withsecure", "huntress", "intezer", "virustotal", "alienvault", "shodan", "censys",
    "abuse.ch", "krebsonsecurity", "darkreading", "cyberark", "cylance", "broadcom",
}

SECURITY_VENDORS_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(v) for v in sorted(SECURITY_VENDORS_BLACKLIST, key=len, reverse=True)) + r")\b",
    re.IGNORECASE,
)

GENERIC_SINGLE_WORDS_BLACKLIST = {
    "computer", "system", "file", "folder", "network", "payload", "malware",
    "tool", "executable", "memory", "internet", "protocol", "victim", "target",
    "user", "activity", "code", "script", "software", "machine", "application",
    "data", "binary", "device", "process", "service", "technique", "attack",
    "action", "intrusion", "campaign", "report", "article", "source", "url",
    "hash", "session", "access", "sample", "flaw", "bug", "patch", "update",
    "company", "compromise", "incident", "year", "month", "day", "date",
}


def normalize_entity_type(t: str) -> str:
    """Normalise un type d'entité ('cti:ThreatActor' ou 'threat_actor') en clé snake_case standard."""
    if not t:
        return "software_system"
    t_clean = t.strip()
    if t_clean in PREFIXED_TO_SNAKE_TYPE:
        return PREFIXED_TO_SNAKE_TYPE[t_clean]
    t_lower = t_clean.lower().replace("cti:", "").replace("ag:", "")
    for k, v in PREFIXED_TO_SNAKE_TYPE.items():
        if k.lower() == f"cti:{t_lower}" or v == t_lower:
            return v
    # Conversion PascalCase vers snake_case si non répertorié
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", t_lower)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def normalize_predicate(p: str) -> str:
    """Normalise un prédicat ('cti:exploits_weakness' ou 'ag:leads_to_step' -> 'exploits_weakness')."""
    if not p:
        return "implements_technique"
    raw = p.strip().split(":")[-1].lower()
    alias_map = {
        "targets": "targets",
        "targets_victim": "targets",
        "exploits": "exploits_weakness",
        "exploits_weakness": "exploits_weakness",
        "affects": "affects_asset",
        "affects_asset": "affects_asset",
        "harvests": "harvests_asset",
        "harvests_asset": "harvests_asset",
        "spawns": "spawns_process",
        "spawns_process": "spawns_process",
        "drops": "drops_artifact",
        "drops_artifact": "drops_artifact",
        "injects": "injects_into",
        "injects_into": "injects_into",
        "implements": "implements_technique",
        "implements_technique": "implements_technique",
        "communicates_with": "communicates_with_c2",
        "communicates_with_c2": "communicates_with_c2",
        "exfiltrates": "exfiltrates_to",
        "exfiltrates_to": "exfiltrates_to",
        "leads_to": "leads_to_step",
        "leads_to_step": "leads_to_step",
        "detects": "detects_or_mitigates",
        "detects_or_mitigates": "detects_or_mitigates",
        "authenticates": "authenticates_with",
        "authenticates_with": "authenticates_with",
        "operates": "operates_infrastructure",
        "operates_infrastructure": "operates_infrastructure",
        "resolves_to": "resolves_to_indicator",
        "resolves_to_indicator": "resolves_to_indicator",
        "attributed": "attributed_to",
        "attributed_to": "attributed_to",
    }
    return alias_map.get(raw, raw)


def normalize_posture(p: Optional[str]) -> str:
    """Normalise une posture ('cti:LOTLPosture' -> 'lotl')."""
    if not p or str(p).lower() in ("none", "", "null"):
        return ""
    p_clean = str(p).strip()
    if p_clean in PREFIXED_TO_SNAKE_POSTURE:
        return PREFIXED_TO_SNAKE_POSTURE[p_clean]
    return p_clean.lower().replace("cti:", "").replace("posture", "")


def normalize_modality(m: Optional[str]) -> str:
    """Normalise une modalité ('cti:ObservedInIncident' -> 'observed')."""
    if not m or str(m).lower() in ("none", "", "null"):
        return "observed"
    m_clean = str(m).strip()
    if m_clean in PREFIXED_TO_SNAKE_MODALITY:
        return PREFIXED_TO_SNAKE_MODALITY[m_clean]
    return m_clean.lower().replace("cti:", "")


def normalize_security_state(s: Optional[str]) -> Optional[str]:
    """Normalise un état de sécurité / privilège d'Attack Graph (ex: 'ag:LocalCodeExecution' -> 'ag:LocalCodeExecution')."""
    if not s or str(s).lower() in ("none", "", "null"):
        return None
    s_clean = str(s).strip()
    if s_clean in PREFIXED_TO_SNAKE_STATE:
        return s_clean
    s_lower = s_clean.lower().replace("ag:", "")
    for k, v in PREFIXED_TO_SNAKE_STATE.items():
        if v == s_lower or k.lower() == f"ag:{s_lower}":
            return k
    return f"ag:{s_clean}" if not s_clean.startswith("ag:") else s_clean


def clean_uri_fragment(label: str) -> str:
    """Transforme un libellé en identifiant d'URI RDF déterministe et sécurisé."""
    s = re.sub(r"[^\w\-_.]", "_", label.strip().lower())
    s = re.sub(r"_+", "_", s).strip("_")
    s = re.sub(r"\.(exe|dll|ps1|sh|py|bin)$", "", s)
    return s or "anonymous_entity"


def verify_evidence_in_source(evidence: str, source_text: Optional[str]) -> bool:
    """
    Vérifie l'ancrage textuel en nettoyant le formatage Markdown (backticks, liens, gras)
    et en acceptant une correspondance souple sur les mots significatifs (>= 70% des mots).
    """
    if not evidence or len(evidence.strip()) < 10:
        return False
    if not source_text:
        return True

    def _clean_md(t: str) -> str:
        s = t.lower()
        # Supprimer les liens markdown [texte](url) -> texte
        s = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", s)
        # Supprimer backticks, guillemets, étoiles, crochets de defang
        s = s.replace("[.]", ".").replace("(.)", ".").replace("hxxp", "http")
        s = re.sub(r"[`*_~>|#\"'«»“”‘’]", " ", s)
        return re.sub(r"\s+", " ", s).strip()

    norm_src = _clean_md(source_text)
    norm_ev = _clean_md(evidence)

    # 1. Correspondance directe de sous-chaîne
    if norm_ev in norm_src:
        return True

    # 2. Tolérance si le LLM a légèrement condensé une phrase ou sauté un saut de ligne Markdown :
    # On vérifie que 75% des mots de >= 4 lettres de l'evidence sont présents dans le segment source
    ev_words = [w for w in re.findall(r"[a-z0-9.\-_]{4,}", norm_ev)]
    if not ev_words:
        return True
    matched = sum(1 for w in ev_words if w in norm_src)
    return (matched / len(ev_words)) >= 0.75


TYPE_TO_ID_PREFIX = {
    "threat_actor": "actor",
    "software_system": "software",
    "vulnerability": "weakness",
    "identity_or_credential": "cred",
    "data_repository": "data",
    "infrastructure": "infra",
    "attack_pattern": "pattern",
    "defensive_measure": "defense",
    "victim_profile": "victim",
    "hardware_or_host": "asset",
    "observable_indicator": "indicator",
    "misconfiguration": "weakness",
}


def filter_threat_centric_graph(
    graph_data: Dict[str, Any],
    source_document_text: Optional[str] = None,
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Filtre sévèrement le graphe extrait pour ne conserver QUE le cœur opérationnel de la menace CTI :
    1. Rejette les chercheurs / éditeurs de sécurité (Mandiant, Sekoia, etc.).
    2. Rejette les termes génériques vagues (computer, system, malware, script, etc.).
    3. Valide les contraintes formelles Domain/Range et la syntaxe des prédicats.
    4. Vérifie l'ancrage textuel de la citation (evidence).
    5. Élimine les entités orphelines (degree == 0).
    Retourne le graphe assaini et la liste des rejets motivés.
    """
    entities = graph_data.get("entities", [])
    relationships = graph_data.get("relationships", [])
    rejected_reasons: List[str] = []

    valid_entities_by_id: Dict[str, Dict[str, Any]] = {}
    valid_entities_by_name: Dict[str, Dict[str, Any]] = {}

    for ent in entities:
        eid = str(ent.get("id", "")).strip()
        name = str(ent.get("name", "")).strip()
        raw_type = str(ent.get("type", "")).strip()
        etype = normalize_entity_type(raw_type)

        if not name or len(name) < 2:
            rejected_reasons.append(f"Entité ignorée : nom vide ou trop court ('{name}')")
            continue

        name_lower = name.lower()

        # Règle 1 : Chercheurs vs Adversaires
        if SECURITY_VENDORS_PATTERN.search(name_lower):
            if etype in ("threat_actor", "software_system", "victim_profile"):
                rejected_reasons.append(f"Anti-Bruit : '{name}' est un éditeur/chercheur de sécurité, pas un composant d'attaque.")
                continue

        # Règle 2 : Mots génériques d'informatique
        words = [w for w in re.findall(r"[a-zA-Z0-9]+", name_lower) if len(w) > 1]
        if name_lower in GENERIC_SINGLE_WORDS_BLACKLIST:
            rejected_reasons.append(f"Anti-Bruit : '{name}' est un terme générique isolé.")
            continue

        if not eid:
            prefix = TYPE_TO_ID_PREFIX.get(etype, etype.split("_")[0])
            eid = f"{prefix}:{clean_uri_fragment(name)}"

        ent_clean: Dict[str, Any] = {
            "id": eid,
            "type": SNAKE_TO_PREFIXED_TYPE.get(etype, f"cti:{etype}"),
            "name": name,
        }

        if ent.get("confidenceScore") is not None:
            ent_clean["confidenceScore"] = int(ent["confidenceScore"])
        elif ent.get("confidence") is not None:
            ent_clean["confidenceScore"] = int(ent["confidence"])

        cpe = ent.get("cpe23Uri") or ent.get("cpe")
        if cpe:
            ent_clean["cpe23Uri"] = str(cpe).strip()

        cve = ent.get("cveId")
        if not cve:
            cve_m = re.search(r"\b(CVE-\d{4}-\d{4,7})\b", name, re.I)
            if cve_m:
                cve = cve_m.group(1).upper()
        if cve:
            ent_clean["cveId"] = str(cve).strip().upper()

        mitre = ent.get("mitreId")
        if not mitre:
            mitre_m = re.search(r"\b(T\d{4}(?:\.\d{3})?)\b", name, re.I)
            if mitre_m:
                mitre = mitre_m.group(1).upper()
        if mitre:
            ent_clean["mitreId"] = str(mitre).strip().upper()

        req_pre = ent.get("requiresPrecondition")
        if req_pre:
            norm_pre = normalize_security_state(req_pre)
            if norm_pre:
                ent_clean["requiresPrecondition"] = norm_pre

        yld_post = ent.get("yieldsPostcondition")
        if yld_post:
            norm_post = normalize_security_state(yld_post)
            if norm_post:
                ent_clean["yieldsPostcondition"] = norm_post

        valid_entities_by_id[eid] = ent_clean
        valid_entities_by_name[name_lower] = ent_clean

    valid_relations: List[Dict[str, Any]] = []
    entity_degrees: Dict[str, int] = {eid: 0 for eid in valid_entities_by_id}

    for rel in relationships:
        s_id = str(rel.get("subject", "")).strip()
        t_id = str(rel.get("object", "")).strip()
        raw_pred = str(rel.get("predicate", "")).strip()
        pred = normalize_predicate(raw_pred)
        evidence = str(rel.get("evidence", "")).strip()

        # Résolution ID ou Nom si le LLM a mis un nom au lieu d'un ID
        s_ent = valid_entities_by_id.get(s_id) or valid_entities_by_name.get(s_id.lower())
        t_ent = valid_entities_by_id.get(t_id) or valid_entities_by_name.get(t_id.lower())

        if not s_ent:
            rejected_reasons.append(f"Relation ignorée : sujet inconnu '{s_id}'")
            continue
        if not t_ent:
            rejected_reasons.append(f"Relation ignorée : objet inconnu '{t_id}'")
            continue

        s_actual_id = s_ent["id"]
        t_actual_id = t_ent["id"]

        if s_actual_id == t_actual_id:
            rejected_reasons.append(f"Auto-boucle ignorée sur '{s_actual_id}'")
            continue

        if not verify_evidence_in_source(evidence, source_document_text):
            rejected_reasons.append(f"Hallucination / Citation non vérifiée : '{evidence[:50]}...'")
            continue

        s_type = normalize_entity_type(s_ent["type"])
        t_type = normalize_entity_type(t_ent["type"])
        prop_rule = PROPERTY_CONSTRAINTS.get(pred)

        if not prop_rule:
            rejected_reasons.append(f"Prédicat non reconnu : '{raw_pred}'")
            continue

        if s_type not in prop_rule["domains"]:
            rejected_reasons.append(f"Violation Domaine : {s_ent['name']} ({s_type}) ne peut être sujet de {pred}")
            continue

        if t_type not in prop_rule["ranges"]:
            rejected_reasons.append(f"Violation Range : {t_ent['name']} ({t_type}) ne peut être objet de {pred}")
            continue

        full_pred = f"ag:{pred}" if pred == "leads_to_step" else f"cti:{pred}"

        qual = rel.get("qualification", {}) or {}
        src_p = normalize_posture(qual.get("source_posture"))
        tgt_p = normalize_posture(qual.get("target_posture"))
        mod = normalize_modality(qual.get("modality"))

        clean_qual: Dict[str, Any] = {}
        if src_p:
            clean_qual["source_posture"] = SNAKE_TO_PREFIXED_POSTURE.get(src_p, f"cti:{src_p}")
        if tgt_p:
            clean_qual["target_posture"] = SNAKE_TO_PREFIXED_POSTURE.get(tgt_p, f"cti:{tgt_p}")
        if qual.get("modality") or clean_qual:
            clean_qual["modality"] = SNAKE_TO_PREFIXED_MODALITY.get(mod, "cti:ObservedInIncident")

        clean_rel: Dict[str, Any] = {
            "subject": s_actual_id,
            "predicate": full_pred,
            "object": t_actual_id,
        }
        if clean_qual:
            clean_rel["qualification"] = clean_qual
        clean_rel["evidence"] = evidence

        valid_relations.append(clean_rel)
        entity_degrees[s_actual_id] = entity_degrees.get(s_actual_id, 0) + 1
        entity_degrees[t_actual_id] = entity_degrees.get(t_actual_id, 0) + 1

    # Élimination des entités orphelines (degree == 0)
    filtered_entities = [ent for eid, ent in valid_entities_by_id.items() if entity_degrees.get(eid, 0) > 0]

    filtered_graph = {
        "graph_metadata": graph_data.get("graph_metadata", {
            "ontology_uri": "https://w3id.org/cti/ontology#",
            "version": "2.0.0",
        }),
        "entities": filtered_entities,
        "relationships": valid_relations,
    }

    return filtered_graph, rejected_reasons


class OntologyValidator:
    """
    Validateur formel strict RDF/OWL.
    Ne réalise AUCUNE coercition silencieuse masquant des hallucinations :
    retourne des erreurs explicites exploitables par une boucle de rétroaction LLM (Reflexion).
    """

    @staticmethod
    def validate_and_normalize_triplet(
        triplet: Dict[str, Any],
        source_document_text: Optional[str] = None,
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        src_name = str(triplet.get("source_name", "")).strip()
        tgt_name = str(triplet.get("target_name", "")).strip()
        raw_rtype = str(triplet.get("relation_type", "")).strip()
        rtype = normalize_predicate(raw_rtype)
        src_type = normalize_entity_type(str(triplet.get("source_type", "")).strip())
        tgt_type = normalize_entity_type(str(triplet.get("target_type", "")).strip())
        evidence = str(triplet.get("evidence", "")).strip()
        phase = str(triplet.get("kill_chain_phase", "")).strip().lower()

        src_posture = normalize_posture(triplet.get("source_posture"))
        tgt_posture = normalize_posture(triplet.get("target_posture"))
        modality = normalize_modality(triplet.get("modality"))

        # 1. Champs obligatoires et auto-boucles
        if not src_name or not tgt_name or not rtype:
            return False, None, "Champs obligatoires manquants (source_name, target_name ou relation_type)."

        if src_name.lower() == tgt_name.lower() and src_type == tgt_type:
            return False, None, f"Auto-boucle interdite sur l'entité '{src_name}'."

        # 2. Contrôle d'ancrage textuel (Anti-Hallucination)
        if not verify_evidence_in_source(evidence, source_document_text):
            return (
                False,
                None,
                f"Hallucination ou paraphrase détectée : l'extrait '{evidence[:60]}...' "
                "est absent du texte source ou trop court (<12 caractères).",
            )

        # 3. Migration transparente des anciens types ("malware"/"tool") vers SoftwareSystem + Posture
        if src_type in LEGACY_TYPE_MAPPING:
            mapped_type, default_posture = LEGACY_TYPE_MAPPING[src_type]
            src_type = mapped_type
            if not src_posture and default_posture:
                src_posture = default_posture

        if tgt_type in LEGACY_TYPE_MAPPING:
            mapped_type, default_posture = LEGACY_TYPE_MAPPING[tgt_type]
            tgt_type = mapped_type
            if not tgt_posture and default_posture:
                tgt_posture = default_posture

        # 4. Validation stricte de l'existence des classes d'entités
        if src_type not in VALID_ENTITY_CLASSES:
            return (
                False,
                None,
                f"Type source '{src_type}' invalide pour '{src_name}'. "
                f"Types autorisés : {sorted(VALID_ENTITY_CLASSES.keys())}.",
            )
        if tgt_type not in VALID_ENTITY_CLASSES:
            return (
                False,
                None,
                f"Type cible '{tgt_type}' invalide pour '{tgt_name}'. "
                f"Types autorisés : {sorted(VALID_ENTITY_CLASSES.keys())}.",
            )

        # 5. Validation stricte du prédicat (aucun fallback silencieux vers 'uses')
        rule = PROPERTY_CONSTRAINTS.get(rtype)
        if not rule:
            return (
                False,
                None,
                f"Prédicat '{rtype}' non reconnu dans l'ontologie. "
                f"Prédicats autorisés : {sorted(PROPERTY_CONSTRAINTS.keys())}.",
            )

        # 6. Validation effective Domain & Range (absente dans la v1)
        if src_type not in rule["domains"]:
            return (
                False,
                None,
                f"Violation de Domaine OWL : '{src_name}' ({src_type}) ne peut pas être sujet "
                f"de la relation '{rtype}'. Domaines attendus : {sorted(rule['domains'])}.",
            )

        if tgt_type not in rule["ranges"]:
            return (
                False,
                None,
                f"Violation de Range OWL : '{tgt_name}' ({tgt_type}) ne peut pas être objet "
                f"de la relation '{rtype}'. Ranges attendus : {sorted(rule['ranges'])}.",
            )

        # 7. Normalisation des postures d'usage et de la modalité
        if src_posture not in USAGE_POSTURES:
            src_posture = "dual_use_admin_tool" if triplet.get("source_is_dual_use") else ""
        if tgt_posture not in USAGE_POSTURES:
            tgt_posture = "legitimate_target" if rtype in ("affects_asset", "targets_victim") else ""

        if modality not in EPISTEMIC_MODALITIES:
            modality = "observed"

        if phase not in KILL_CHAIN_PHASES:
            phase = rule["default_phase"]

        validated_triplet = {
            "source_name": src_name,
            "source_type": src_type,
            "source_posture": src_posture,
            "source_cpe": str(triplet.get("source_cpe", "")).strip(),
            "relation_type": rtype,
            "kill_chain_phase": phase,
            "modality": modality,
            "confidence": int(triplet.get("confidence", 85)),
            "target_name": tgt_name,
            "target_type": tgt_type,
            "target_posture": tgt_posture,
            "target_cpe": str(triplet.get("target_cpe", "")).strip(),
            "precondition_state": str(triplet.get("precondition_state", "")).strip().lower(),
            "postcondition_state": str(triplet.get("postcondition_state", "")).strip().lower(),
            "evidence": evidence,
        }

        return True, validated_triplet, None


def build_rdf_graph(
    entities: List[Dict[str, Any]],
    relations: List[Dict[str, Any]],
    article_meta: Optional[Dict[str, Any]] = None,
) -> Graph:
    """
    Construit le Knowledge Graph RDF/OWL V2 avec :
    - Séparation entre l'entité intrinsèque (SoftwareSystem, etc.) et sa posture contextuelle (UsagePosture)
    - Alignement CMDB/Attack Graph (CPE, CVE, MITRE ID, SecurityState)
    - Qualification épistémique et preuves vérifiées
    """
    g = Graph()
    g.bind("cti", CTI)
    g.bind("kc", KC)
    g.bind("ag", AG)
    g.bind("owl", OWL)
    g.bind("rdfs", RDFS)

    entity_uris: Dict[str, URIRef] = {}

    for ent in entities:
        name = ent.get("name", "").strip()
        raw_type = ent.get("type", "software_system").strip().lower()
        if not name:
            continue

        etype = LEGACY_TYPE_MAPPING.get(raw_type, (raw_type, None))[0]
        uri_frag = clean_uri_fragment(name)
        ent_uri = CTI[f"{etype}_{uri_frag}"]
        entity_uris[name.lower()] = ent_uri

        owl_class = VALID_ENTITY_CLASSES.get(etype, CTI.CyberThreatElement)
        g.add((ent_uri, RDF.type, owl_class))
        g.add((ent_uri, RDFS.label, Literal(name, datatype=XSD.string)))

        if ent.get("description"):
            g.add((ent_uri, RDFS.comment, Literal(ent["description"], datatype=XSD.string)))

        # Propriétés d'alignement Attack Graph (CPE, CVE, MITRE ID)
        if ent.get("cpe"):
            g.add((ent_uri, CTI.cpe23Uri, Literal(ent["cpe"], datatype=XSD.string)))
        if etype == "vulnerability" and name.upper().startswith("CVE-"):
            g.add((ent_uri, CTI.cveId, Literal(name.upper(), datatype=XSD.string)))
        if etype == "attack_pattern" and re.match(r"^T\d{4}(\.\d{3})?$", name.upper()):
            g.add((ent_uri, CTI.mitreId, Literal(name.upper(), datatype=XSD.string)))

    for rel in relations:
        s_name = rel.get("source_name", "").strip().lower()
        t_name = rel.get("target_name", "").strip().lower()
        rtype = rel.get("relation_type", "").strip().lower()

        s_uri = entity_uris.get(s_name)
        t_uri = entity_uris.get(t_name)
        prop_rule = PROPERTY_CONSTRAINTS.get(rtype)

        if not s_uri or not t_uri or not prop_rule:
            continue

        prop_uri = prop_rule["uri"]
        g.add((s_uri, prop_uri, t_uri))

        # Statement réifié portant le contexte non-manichéen, la temporalité et la preuve
        stmt_id = f"urn:triple:{clean_uri_fragment(s_name)}:{rtype}:{clean_uri_fragment(t_name)}"
        stmt = URIRef(stmt_id)
        g.add((stmt, RDF.type, RDF.Statement))
        g.add((stmt, RDF.subject, s_uri))
        g.add((stmt, RDF.predicate, prop_uri))
        g.add((stmt, RDF.object, t_uri))

        # Phase Kill Chain
        phase = rel.get("kill_chain_phase", prop_rule["default_phase"])
        g.add((stmt, CTI.inKillChainPhase, KILL_CHAIN_PHASES.get(phase, KC.Execution)))

        # Postures d'usage contextuelles (Non-Manichéisme)
        src_posture = rel.get("source_posture", "")
        if src_posture in USAGE_POSTURES:
            g.add((stmt, CTI.hasSourcePosture, USAGE_POSTURES[src_posture]))

        tgt_posture = rel.get("target_posture", "")
        if tgt_posture in USAGE_POSTURES:
            g.add((stmt, CTI.hasTargetPosture, USAGE_POSTURES[tgt_posture]))

        # Modalité épistémique & Confiance
        modality = rel.get("modality", "observed")
        g.add((stmt, CTI.hasModality, EPISTEMIC_MODALITIES.get(modality, CTI.ObservedInIncident)))
        g.add((stmt, CTI.confidenceScore, Literal(int(rel.get("confidence", 85)), datatype=XSD.integer)))

        # États d'Attack Graph (Précondition / Postcondition)
        pre_state = rel.get("precondition_state", "")
        if pre_state in SECURITY_STATES:
            g.add((s_uri, AG.requiresPrecondition, SECURITY_STATES[pre_state]))

        post_state = rel.get("postcondition_state", "")
        if post_state in SECURITY_STATES:
            g.add((t_uri, AG.yieldsPostcondition, SECURITY_STATES[post_state]))

        # Preuve textuelle et métadonnées temporelles de l'article
        if rel.get("evidence"):
            g.add((stmt, CTI.evidenceText, Literal(rel["evidence"], datatype=XSD.string)))
        if article_meta and article_meta.get("published_at"):
            g.add((stmt, CTI.validFrom, Literal(article_meta["published_at"], datatype=XSD.dateTime)))

    return g


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