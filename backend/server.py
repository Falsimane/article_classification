"""
Serveur Web pour le Tableau de Bord CTI Knowledge Graph (Interface type OpenCTI).
Fournit une API REST haute performance connectée à SQLite et sert le frontend interactif.
"""

import argparse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse, unquote

import sys
root_dir = Path(__file__).resolve().parents[1]
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from backend.database.neo4j_store import Neo4jStore
from backend import stix_dashboard

BASE_DIR = root_dir
DB_PATH = BASE_DIR / "db_outputs" / "cti_knowledge.db"
WEB_DIR = BASE_DIR / "frontend" / "dist"  # build Vite (cd frontend && npm run build)

# Palette de couleurs STIX 2.1 conforme aux standards OpenCTI
ENTITY_STIX_COLORS = {
    "threat_actor": {"background": "#ef4444", "border": "#dc2626", "highlight": "#f87171", "glow": "rgba(239, 68, 68, 0.4)"},
    "malware": {"background": "#f97316", "border": "#ea580c", "highlight": "#fb923c", "glow": "rgba(249, 115, 22, 0.4)"},
    "software_system": {"background": "#f97316", "border": "#ea580c", "highlight": "#fb923c", "glow": "rgba(249, 115, 22, 0.4)"},
    "tool": {"background": "#3b82f6", "border": "#2563eb", "highlight": "#60a5fa", "glow": "rgba(59, 130, 246, 0.4)"},
    "tool_dual_use": {"background": "#a855f7", "border": "#9333ea", "highlight": "#c084fc", "glow": "rgba(168, 85, 247, 0.5)"},
    "vulnerability": {"background": "#ec4899", "border": "#db2777", "highlight": "#f472b6", "glow": "rgba(236, 72, 153, 0.4)"},
    "infrastructure": {"background": "#06b6d4", "border": "#0891b2", "highlight": "#22d3ee", "glow": "rgba(6, 182, 212, 0.4)"},
    "attack_pattern": {"background": "#10b981", "border": "#059669", "highlight": "#34d399", "glow": "rgba(16, 185, 129, 0.4)"},
    "defensive_measure": {"background": "#eab308", "border": "#ca8a04", "highlight": "#fde047", "glow": "rgba(234, 179, 8, 0.4)"},
    "detection_rule": {"background": "#eab308", "border": "#ca8a04", "highlight": "#fde047", "glow": "rgba(234, 179, 8, 0.4)"},
    "identity_or_credential": {"background": "#f59e0b", "border": "#d97706", "highlight": "#fbbf24", "glow": "rgba(245, 158, 11, 0.4)"},
    "data_repository": {"background": "#8b5cf6", "border": "#7c3aed", "highlight": "#a78bfa", "glow": "rgba(139, 92, 246, 0.4)"},
    "victim_profile": {"background": "#94a3b8", "border": "#64748b", "highlight": "#cbd5e1", "glow": "rgba(148, 163, 184, 0.4)"},
    "target": {"background": "#94a3b8", "border": "#64748b", "highlight": "#cbd5e1", "glow": "rgba(148, 163, 184, 0.4)"},
    "observable_indicator": {"background": "#e11d48", "border": "#be123c", "highlight": "#fb7185", "glow": "rgba(225, 29, 72, 0.4)"},
    "indicator": {"background": "#e11d48", "border": "#be123c", "highlight": "#fb7185", "glow": "rgba(225, 29, 72, 0.4)"},
}

# =====================================================================
# BASE DE CONNAISSANCES CTI : ATTRIBUTION GÉOPOLITIQUE & AFFILIATIONS ÉTATIQUES
# =====================================================================
THREAT_ACTOR_KNOWLEDGE_BASE = {
    "unc3944": {
        "canonical_name": "UNC3944",
        "country": "États-Unis / Royaume-Uni (Transnational)",
        "country_code": "US",
        "flag": "🌐",
        "affiliation_type": "Syndicat Cybercriminel Financier (Anglophone)",
        "state_affiliation": "Non étatique / Collaborations opportunistes avec affiliés RaaS",
        "attribution_source": "Mandiant, CISA, CrowdStrike, The DFIR Report",
        "confidence": "Élevé",
        "aliases": ["Scattered Spider", "Octo Tempest", "Roasted 0ktapus", "Storm-0875", "Starfrost Pegasus"],
        "description": "Cluster d'activité cybercriminelle anglophone spécialisé dans l'ingénierie sociale ciblée (SIM swapping, vishing d'assistance IT), le contournement d'authentification multifacteur (MFA Fatigue), l'exploitation d'appliances réseau et le déploiement de ransomwares.",
    },
    "apt1": {
        "canonical_name": "APT1",
        "country": "Chine",
        "country_code": "CN",
        "flag": "🇨🇳",
        "affiliation_type": "Menace Étatique Persistante (APT)",
        "state_affiliation": "Armée Populaire de Libération (Unité 61398)",
        "attribution_source": "Mandiant (Rapport APT1), CISA, FBI",
        "confidence": "Confirmé",
        "aliases": ["Comment Crew", "Comment Panda", "Unit 61398", "TG-8223"],
        "description": "Unité de cyberespionnage militaire chinoise ciblant les secteurs industriels, télécoms, défense et aérospatiaux pour le vol stratégique de propriété intellectuelle.",
    },
    "apt28": {
        "canonical_name": "APT28",
        "country": "Russie",
        "country_code": "RU",
        "flag": "🇷🇺",
        "affiliation_type": "Menace Étatique Persistante (APT)",
        "state_affiliation": "Service de Renseignement Militaire Russe (GRU - Unité 26165)",
        "attribution_source": "ANSSI, CISA, Mandiant, CrowdStrike",
        "confidence": "Confirmé",
        "aliases": ["Fancy Bear", "Sofacy", "Sednit", "Strontium", "Forest Blizzard", "Pawn Storm"],
        "description": "Acteur de cyberespionnage et d'opérations d'influence stratégique rattaché au GRU, actif contre les institutions gouvernementales occidentales et l'OTAN.",
    },
    "apt29": {
        "canonical_name": "APT29",
        "country": "Russie",
        "country_code": "RU",
        "flag": "🇷🇺",
        "affiliation_type": "Menace Étatique Persistante (APT)",
        "state_affiliation": "Service de Renseignement Extérieur Russe (SVR)",
        "attribution_source": "CISA, NCSC, Mandiant, Microsoft",
        "confidence": "Confirmé",
        "aliases": ["Cozy Bear", "Midnight Blizzard", "Nobelium", "Cloaked Ursa"],
        "description": "Acteur d'élite du renseignement extérieur russe spécialisé dans la compromission furtive de chaînes d'approvisionnement logicielles (SolarWinds) et les tenants cloud M365.",
    },
    "lazarus": {
        "canonical_name": "Lazarus Group",
        "country": "Corée du Nord",
        "country_code": "KP",
        "flag": "🇰🇵",
        "affiliation_type": "Menace Étatique Persistante (APT) & Cybercriminalité Financière",
        "state_affiliation": "Bureau Général de Reconnaissance (RGB - 3e Bureau)",
        "attribution_source": "FBI, CISA, Mandiant, Kaspersky",
        "confidence": "Confirmé",
        "aliases": ["HIDDEN COBRA", "Guardians of Peace", "Zinc", "Labyrinth Chollima"],
        "description": "Acteur étatique nord-coréen combinant espionnage, sabotages destructeurs (WannaCry) et braquages massifs de protocoles DeFi et de cryptomonnaies.",
    },
    "sandworm": {
        "canonical_name": "Sandworm",
        "country": "Russie",
        "country_code": "RU",
        "flag": "🇷🇺",
        "affiliation_type": "Menace Étatique Persistante (APT)",
        "state_affiliation": "Direction Générale du Renseignement Militaire (GRU - Unité 74455)",
        "attribution_source": "ANSSI, DoJ, Mandiant, CISA",
        "confidence": "Confirmé",
        "aliases": ["Seashell Blizzard", "Voodoo Bear", "TeleBots", "BlackEnergy Group", "Iron Viking"],
        "description": "Unité de cyberguerre hybride russe responsable des coupures électriques en Ukraine (BlackEnergy, Industroyer) et de l'attaque NotPetya.",
    },
    "volt_typhoon": {
        "canonical_name": "Volt Typhoon",
        "country": "Chine",
        "country_code": "CN",
        "flag": "🇨🇳",
        "affiliation_type": "Menace Étatique Persistante (APT)",
        "state_affiliation": "Acteur parrainé par l'État chinois",
        "attribution_source": "CISA, NSA, FBI, Microsoft",
        "confidence": "Confirmé",
        "aliases": ["Vanguard Panda", "BRONZE SILHOUETTE", "Insidious Taurus"],
        "description": "Groupe chinois spécialisé dans le pré-positionnement furtif sur les infrastructures critiques américaines via des techniques Living Off The Land et l'exploitation d'appliances périphériques.",
    },
    "lockbit": {
        "canonical_name": "LockBit",
        "country": "Russie / Transnational",
        "country_code": "RU",
        "flag": "🏴‍☠️",
        "affiliation_type": "Ransomware-as-a-Service (RaaS)",
        "state_affiliation": "Syndicat cybercriminel russophone / Tolérance étatique",
        "attribution_source": "Opération Cronos (NCA, FBI, Europol), CISA",
        "confidence": "Élevé",
        "aliases": ["Bitwise Spider", "LockBit Gang"],
        "description": "L'un des syndicats de ransomware-as-a-service les plus prolifiques au monde, opérant sous modèle d'affiliation avec extorsion multiple.",
    },
    "akira": {
        "canonical_name": "Akira",
        "country": "Russie / Transnational",
        "country_code": "RU",
        "flag": "🏴‍☠️",
        "affiliation_type": "Ransomware-as-a-Service (RaaS)",
        "state_affiliation": "Affiliation cybercriminelle russophone (liens avec les membres de Conti)",
        "attribution_source": "CISA, FBI, The DFIR Report",
        "confidence": "Élevé",
        "aliases": ["Punk Spider"],
        "description": "Groupe de ransomware ciblant activement les passerelles VPN Cisco/SonicWall et les hyperviseurs VMware ESXi avec double extorsion.",
    },
    "stormshadow": {
        "canonical_name": "StormShadow",
        "country": "Inconnu / En cours d'analyse",
        "country_code": "UN",
        "flag": "⚡",
        "affiliation_type": "Cluster d'activité cybercriminelle émergent",
        "state_affiliation": "En cours d'investigation CTI",
        "attribution_source": "Communauté CTI / Rapports d'incidents",
        "confidence": "Moyen",
        "aliases": ["Storm-Shadow"],
        "description": "Cluster d'activité menant des opérations d'intrusion et de déploiement d'implants offensifs.",
    },
    "lunar_spider": {
        "canonical_name": "Lunar Spider",
        "country": "Russie / Europe de l'Est",
        "country_code": "RU",
        "flag": "🕷️",
        "affiliation_type": "Opérateur de Botnet / Courtier d'Accès Initial (IAB)",
        "state_affiliation": "Cybercriminalité organisée russophone",
        "attribution_source": "CrowdStrike, The DFIR Report",
        "confidence": "Élevé",
        "aliases": ["BokBot Gang", "IcedID Operator"],
        "description": "Opérateur du malware modulaire et botnet IcedID / BokBot, servant de passerelle initiale pour des déploiements ultérieurs de ransomwares.",
    },
}

def enrich_threat_actor_profile(name: str, node_props: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Associe un acteur à sa fiche géopolitique, ses affiliations étatiques et ses alias reconnus.
    Si l'acteur n'est pas dans la base statique, utilise les métadonnées extraites de Neo4j.
    """
    if not name:
        name = ""
    raw_clean = name
    if raw_clean.lower().startswith("actor:"):
        raw_clean = raw_clean[6:]
    clean_k = re.sub(r"[^a-z0-9]", "", raw_clean.lower())
    profile = None
    for k, v in THREAT_ACTOR_KNOWLEDGE_BASE.items():
        aliases_clean = [re.sub(r"[^a-z0-9]", "", a.lower()) for a in v["aliases"]]
        if k == clean_k or clean_k in aliases_clean or clean_k == re.sub(r"[^a-z0-9]", "", v["canonical_name"].lower()):
            profile = dict(v)
            break

    if not profile:
        props = node_props or {}
        country = props.get("country") or "Non déterminé / En cours d'analyse"
        state_aff = props.get("state_affiliation") or "Affiliation étatique non précisée"
        profile = {
            "canonical_name": raw_clean or name,
            "country": country,
            "country_code": "UN",
            "flag": "🎯",
            "affiliation_type": "Cluster d'Activité CTI",
            "state_affiliation": state_aff,
            "attribution_source": props.get("attribution_source") or "Rapports CTI ingérés",
            "confidence": "Moyen",
            "aliases": [],
            "description": props.get("description") or f"Groupe de menace identifié dans les analyses CTI.",
        }

    return profile

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=30.0)
    conn.row_factory = sqlite3.Row
    return conn

class CTIWebServerHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def do_GET(self) -> None:
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        params = parse_qs(parsed_url.query)

        if path.startswith("/api/"):
            self.handle_api(path, params)
        else:
            # Fichiers statiques du build ; toute autre route est une page de l'application React (routage côté client)
            target = WEB_DIR / path.lstrip("/")
            if path != "/" and not target.is_file():
                self.path = "/index.html"
            super().do_GET()

    def send_json_response(self, data: Any, status: int = 200) -> None:
        payload = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(payload)

    def send_bytes_response(self, payload: bytes, filename: str, headers: Dict[str, str]) -> None:
        """Fichier JSON servi tel quel, en téléchargement."""
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def use_stix(self, params: Dict[str, List[str]]) -> bool:
        """Sert le graphe STIX dès qu'il contient un article extrait ; `?model=legacy|stix` force un choix."""
        forced = params.get("model", [None])[0]
        if forced in ("legacy", "stix"):
            return forced == "stix"
        return stix_dashboard.has_data()

    def handle_api(self, path: str, params: Dict[str, List[str]]) -> None:
        try:
            if path == "/api/iocs":
                aid = params.get("article_id", [None])[0]
                self.send_json_response(stix_dashboard.iocs_of_article(int(aid)) if aid and aid.isdigit() else {"error": "article_id requis"}, status=200 if aid and aid.isdigit() else 400)
            elif path == "/api/rules":
                aid = params.get("article_id", [None])[0]
                self.send_json_response(stix_dashboard.rules_of_article(int(aid)) if aid and aid.isdigit() else {"error": "article_id requis"}, status=200 if aid and aid.isdigit() else 400)
            elif path in ("/api/article", "/api/bundle"):
                aid = params.get("article_id", [None])[0]
                if not (aid and aid.isdigit()):
                    self.send_json_response({"error": "article_id requis"}, status=400)
                elif path == "/api/article":
                    text = stix_dashboard.article_text(int(aid))
                    self.send_json_response(text or {"error": "Article introuvable"}, status=200 if text else 404)
                else:
                    found = stix_dashboard.article_bundle(int(aid))
                    if found is None:
                        self.send_json_response({"error": f"Aucun bundle STIX pour l'article {aid} (ré-extraire l'article)"}, status=404)
                    else:
                        self.send_bytes_response(found[0], f"article_{aid}.stix.json", {"X-Bundle-Matches-Graph": "1" if found[1] else "0"})
            elif path == "/api/actors":
                self.send_json_response(stix_dashboard.actors())
            elif path.startswith("/api/actors/"):
                profile = stix_dashboard.actor_graph(unquote(path[len("/api/actors/"):]))
                self.send_json_response(profile or {"error": "Acteur introuvable"}, status=200 if profile else 404)
            elif path in ("/api/stats", "/api/graph", "/api/articles") and self.use_stix(params):
                if path == "/api/stats":
                    self.send_json_response(stix_dashboard.stats())
                elif path == "/api/articles":
                    self.send_json_response(stix_dashboard.articles())
                else:
                    aid = params.get("article_id", [None])[0]
                    self.send_json_response(stix_dashboard.graph(int(aid) if aid and aid.isdigit() else None, params))
            elif path == "/api/stats":
                self.api_stats()
            elif path == "/api/graph":
                self.api_graph(params)
            elif path == "/api/entities":
                self.api_entities(params)
            elif path == "/api/relations":
                self.api_relations(params)
            elif path == "/api/articles":
                self.api_articles(params)
            elif path == "/api/threat-actors":
                self.api_threat_actors(params)
            elif path in ("/api/threat-actors/tree", "/api/threat-actor/tree"):
                actor_id = params.get("actor_id", [None])[0] or params.get("id", [None])[0] or params.get("name", [None])[0]
                self.api_threat_actor_tree(actor_id, params)
            elif path.startswith("/api/threat-actors/") and path.endswith("/tree"):
                slug = unquote(path[len("/api/threat-actors/"):-len("/tree")].strip("/"))
                self.api_threat_actor_tree(slug, params)
            else:
                self.send_json_response({"error": "Endpoint non trouvé"}, status=404)
        except Exception as e:
            self.send_json_response({"error": str(e)}, status=500)

    def api_stats(self) -> None:
        store = Neo4jStore.get_instance()
        ok, _ = store.check_connection()
        if not ok:
            self.send_json_response({
                "articles_count": 0,
                "entities_count": 0,
                "dual_use_count": 0,
                "relations_count": 0,
                "entity_types": {},
                "relation_types": {},
                "kill_chain_phases": {},
            })
            return

        summary = store.get_summary_stats()
        entity_types = {etype: cnt for etype, cnt, _, _ in summary.get("entities", [])}
        dual_use_count = sum(dual for _, _, dual, _ in summary.get("entities", []))
        relation_types = {rtype: cnt for rtype, cnt in summary.get("relations", [])}
        kill_chain_phases = {phase: cnt for phase, cnt in summary.get("kill_chain", [])}

        self.send_json_response({
            "articles_count": summary.get("article_count", 0),
            "entities_count": summary.get("total_entities", 0),
            "dual_use_count": dual_use_count,
            "relations_count": summary.get("total_relations", 0),
            "entity_types": entity_types,
            "relation_types": relation_types,
            "kill_chain_phases": kill_chain_phases,
        })

    def api_graph(self, params: Dict[str, List[str]]) -> None:
        article_id = params.get("article_id", [None])[0]
        entity_type = params.get("type", [None])[0]
        dual_use_only = params.get("dual_use_only", ["0"])[0] in ("1", "true")
        search = params.get("search", [""])[0].strip().lower()

        store = Neo4jStore.get_instance()
        ok, _ = store.check_connection()
        if not ok:
            self.send_json_response({"nodes": [], "edges": [], "article_id": None})
            return

        with store.driver.session() as session:
            # INVARIANT MAJEUR : AUCUN GRAPHE GLOBAL.
            # Si aucun article_id n'est spécifié, on bascule sur le premier article disponible dans Neo4j.
            if not article_id or not article_id.isdigit():
                first_row = session.run("MATCH (a:Article) WHERE a.status = 'success' RETURN a.id AS id ORDER BY a.id ASC LIMIT 1;").single()
                if not first_row:
                    first_row = session.run("MATCH (a:Article) RETURN a.id AS id ORDER BY a.id ASC LIMIT 1;").single()
                if first_row:
                    article_id = str(first_row["id"])
                else:
                    self.send_json_response({
                        "nodes": [],
                        "edges": [],
                        "article_id": None,
                        "article_title": "Aucun rapport extrait dans Neo4j",
                        "message": "Veuillez sélectionner un rapport CTI dans la liste."
                    })
                    return

            kid = int(article_id)
            art_meta = session.run("MATCH (a:Article {id: $kid}) RETURN a.title AS title, a.url AS url, a.entities_count AS ent_cnt, a.relations_count AS rel_cnt;", kid=kid).single()
            current_art_title = art_meta["title"] if art_meta and art_meta.get("title") else f"Rapport CTI #{kid}"
            current_art_url = art_meta["url"] if art_meta and art_meta.get("url") else ""

            # Nœuds STRICTEMENT circonscrits à cet article (via [:MENTIONS])
            ent_query = """
                MATCH (a:Article {id: $kid})-[:MENTIONS]->(e:Entity)
                WHERE 1=1
            """
            ent_params: Dict[str, Any] = {"kid": kid}
            if entity_type:
                ent_query += " AND (e.entity_type = $etype OR $etype IN labels(e))"
                ent_params["etype"] = entity_type
            if dual_use_only:
                ent_query += " AND e.is_dual_use = true"
            if search:
                ent_query += " AND (toLower(e.name) CONTAINS $search OR toLower(coalesce(e.description, '')) CONTAINS $search)"
                ent_params["search"] = search

            ent_query += """
                RETURN e.name AS name, e.entity_type AS entity_type,
                       coalesce(e.is_dual_use, false) AS is_dual_use,
                       coalesce(e.description, '') AS description,
                       a.id AS knowledge_id, coalesce(a.title, '') AS article_title, coalesce(a.url, '') AS article_url
            """
            ent_rows = session.run(ent_query, **ent_params)

            nodes_dict: Dict[str, Dict[str, Any]] = {}
            for r in ent_rows:
                raw_name = r["name"]
                if not raw_name:
                    continue
                k = raw_name.strip().lower()
                etype = r["entity_type"]
                is_dual = bool(r["is_dual_use"])
                desc = r["description"] or ""

                color_key = "tool_dual_use" if (etype in ("tool", "software_system") and is_dual) else etype
                colors = ENTITY_STIX_COLORS.get(color_key, ENTITY_STIX_COLORS["target"])

                if k not in nodes_dict:
                    nodes_dict[k] = {
                        "id": raw_name,
                        "label": raw_name,
                        "title": f"<b>{raw_name}</b><br><i>{etype.upper()}</i><br>{desc[:150]}",
                        "type": etype,
                        "is_dual_use": is_dual,
                        "description": desc,
                        "degree": 0,
                        "color": {
                            "background": colors["background"],
                            "border": colors["border"],
                            "highlight": {
                                "background": colors["highlight"],
                                "border": "#ffffff",
                            },
                        },
                        "font": {
                            "color": "#f8fafc",
                            "face": "Inter, system-ui, sans-serif",
                            "size": 13,
                        },
                        "shadow": {
                            "enabled": True,
                            "color": colors["glow"],
                            "size": 12,
                        },
                        "shape": "dot",
                        "size": 16,
                        "articles": [{"id": kid, "title": current_art_title, "url": current_art_url}],
                    }

            # Relations STRICTEMENT restreintes à cet article (r.knowledge_id = kid)
            rel_query = """
                MATCH (s:Entity)-[r]->(t:Entity)
                WHERE r.knowledge_id = $kid AND type(r) <> 'MENTIONS'
                RETURN s.name AS source_name, coalesce(r.source_type, s.entity_type) AS source_type,
                       type(r) AS relation_type, t.name AS target_name,
                       coalesce(r.target_type, t.entity_type) AS target_type,
                       coalesce(r.kill_chain_phase, 'execution') AS kill_chain_phase,
                       coalesce(r.evidence, '') AS evidence,
                       r.knowledge_id AS knowledge_id
            """
            rel_rows = session.run(rel_query, kid=kid)

            edges = []
            seen_edges = set()

            for r in rel_rows:
                src_raw = (r["source_name"] or "").strip()
                tgt_raw = (r["target_name"] or "").strip()
                if not src_raw or not tgt_raw:
                    continue
                src_k = src_raw.lower()
                tgt_k = tgt_raw.lower()
                rtype = r["relation_type"]
                kc_phase = r["kill_chain_phase"] or "general"

                if src_k not in nodes_dict:
                    nodes_dict[src_k] = {
                        "id": src_raw, "label": src_raw, "type": r["source_type"] or "entity",
                        "is_dual_use": False, "description": "", "degree": 0,
                        "color": {"background": "#64748b", "border": "#475569"},
                        "shape": "dot", "size": 14, "articles": [{"id": kid, "title": current_art_title}],
                    }
                if tgt_k not in nodes_dict:
                    nodes_dict[tgt_k] = {
                        "id": tgt_raw, "label": tgt_raw, "type": r["target_type"] or "entity",
                        "is_dual_use": False, "description": "", "degree": 0,
                        "color": {"background": "#64748b", "border": "#475569"},
                        "shape": "dot", "size": 14, "articles": [{"id": kid, "title": current_art_title}],
                    }

                src_id = nodes_dict[src_k]["id"]
                tgt_id = nodes_dict[tgt_k]["id"]

                edge_key = (src_k, rtype, tgt_k)
                if edge_key not in seen_edges and src_k != tgt_k:
                    seen_edges.add(edge_key)
                    nodes_dict[src_k]["degree"] += 1
                    nodes_dict[tgt_k]["degree"] += 1

                    tooltip = (
                        f"<b>{src_id}</b> -[<b>{rtype}</b>]-> <b>{tgt_id}</b><br>"
                        f"<span style='color:#a855f7; font-weight:600;'>🎯 Phase Kill Chain: [{kc_phase}]</span>"
                    )
                    if r["evidence"]:
                        tooltip += f"<br><br><i>Preuve textuelle:</i> {r['evidence'][:250]}"

                    edges.append({
                        "from": src_id,
                        "to": tgt_id,
                        "label": rtype,
                        "title": tooltip,
                        "relation_type": rtype,
                        "kill_chain_phase": kc_phase,
                        "evidence": r["evidence"] or "",
                        "article_id": kid,
                        "article_title": current_art_title,
                        "arrows": "to",
                        "color": {"color": "rgba(148, 163, 184, 0.5)", "highlight": "#00f0ff"},
                        "font": {"color": "#94a3b8", "size": 10, "align": "middle", "strokeWidth": 0},
                        "smooth": {"type": "curvedCW", "roundness": 0.15},
                    })

            for node in nodes_dict.values():
                base_size = 18 if node["type"] in ("threat_actor", "malware", "software_system") else 14
                node["size"] = min(base_size + (node["degree"] * 2.5), 36)

            hide_orphans = params.get("hide_orphans", ["1"])[0] in ("1", "true")
            if hide_orphans and not search and not entity_type and not dual_use_only:
                final_nodes = [n for n in nodes_dict.values() if n["degree"] > 0]
            else:
                final_nodes = list(nodes_dict.values())

        self.send_json_response({
            "article_id": kid,
            "article_title": current_art_title,
            "article_url": current_art_url,
            "nodes": final_nodes,
            "edges": edges,
        })

    def api_threat_actors(self, params: Dict[str, List[str]]) -> None:
        """Retourne la liste consolidée des Threat Actors détectés avec pays, affiliations et volumes de campagnes."""
        store = Neo4jStore.get_instance()
        ok, _ = store.check_connection()
        if not ok:
            self.send_json_response({"threat_actors": [], "count": 0})
            return

        with store.driver.session() as session:
            res = session.run("""
                MATCH (ta:Entity)
                WHERE ta.entity_type IN ['cti:ThreatActor', 'threat_actor'] OR 'ThreatActor' IN labels(ta)
                OPTIONAL MATCH (a:Article)-[:MENTIONS]->(ta)
                RETURN ta.id AS id, ta.name AS name,
                       coalesce(ta.description, '') AS description,
                       collect(DISTINCT {
                           id: a.id,
                           title: coalesce(a.title, 'Rapport sans titre'),
                           date: coalesce(a.publication_date, '')
                       }) AS reports
                ORDER BY ta.name ASC;
            """)
            actors = []
            for r in res:
                raw_name = r["name"]
                reports = [rep for rep in r["reports"] if rep.get("id") is not None]
                profile = enrich_threat_actor_profile(raw_name, {"description": r["description"]})
                actors.append({
                    "id": r["id"] or f"actor:{re.sub(r'[^a-z0-9]', '', raw_name.lower())}",
                    "name": profile.get("canonical_name") or raw_name,
                    "country": profile["country"],
                    "country_code": profile["country_code"],
                    "flag": profile["flag"],
                    "affiliation_type": profile["affiliation_type"],
                    "state_affiliation": profile["state_affiliation"],
                    "attribution_source": profile["attribution_source"],
                    "confidence": profile["confidence"],
                    "aliases": profile["aliases"],
                    "description": profile["description"],
                    "reports_count": len(reports),
                    "reports": reports,
                    "latest_report": reports[0] if reports else None,
                })

            # Ne pas injecter de faux acteurs si Neo4j est vide : uniquement les données réelles extraites des articles


        self.send_json_response({"threat_actors": actors, "count": len(actors)})

    def api_threat_actor_tree(self, actor_ref: Optional[str], params: Dict[str, List[str]]) -> None:
        """Construit l'arborescence (Tree View) de l'acteur : Pays/Affiliation -> Timeline -> Infrastructure -> Outils."""
        if not actor_ref:
            actor_ref = params.get("actor_id", [None])[0] or params.get("name", [None])[0] or params.get("id", [None])[0]
        if not actor_ref:
            self.send_json_response({"error": "actor_id ou name requis"}, status=400)
            return

        campaign_param = params.get("campaign_id", [None])[0] or params.get("article_id", [None])[0]
        selected_cid: Optional[int] = int(campaign_param) if (campaign_param and campaign_param.isdigit()) else None

        store = Neo4jStore.get_instance()
        ok, _ = store.check_connection()
        if not ok:
            self.send_json_response({"error": "Neo4j non disponible"}, status=503)
            return

        with store.driver.session() as session:
            # 1. Recherche du nœud Acteur
            ta_row = session.run("""
                MATCH (ta:Entity)
                WHERE (toLower(ta.name) = toLower($ref) OR ta.id = $ref OR toLower(ta.name) CONTAINS toLower($ref))
                  AND (ta.entity_type IN ['cti:ThreatActor', 'threat_actor'] OR 'ThreatActor' IN labels(ta))
                RETURN ta.id AS id, ta.name AS name, coalesce(ta.description, '') AS description
                LIMIT 1;
            """, ref=actor_ref).single()

            actor_name = ta_row["name"] if ta_row else (actor_ref[6:] if actor_ref.lower().startswith("actor:") else actor_ref)
            raw_actor_slug = re.sub(r'[^a-z0-9]', '', (actor_ref[6:] if actor_ref.lower().startswith("actor:") else actor_ref).lower())
            actor_id = ta_row["id"] if (ta_row and ta_row.get("id")) else f"actor:{raw_actor_slug}"
            profile = enrich_threat_actor_profile(actor_name, {"description": ta_row["description"] if ta_row else ""})

            # 2. Timeline des Campagnes (Articles mentionnant l'acteur)
            camp_rows = session.run("""
                MATCH (a:Article)-[:MENTIONS]->(ta:Entity)
                WHERE toLower(ta.name) = toLower($name) OR ta.id = $id
                RETURN DISTINCT a.id AS id, coalesce(a.title, 'Rapport sans titre') AS title,
                                coalesce(a.publication_date, '') AS pub_date
                ORDER BY a.id DESC;
            """, name=actor_name, id=actor_id)
            campaigns = []
            for c in camp_rows:
                campaigns.append({
                    "id": c["id"],
                    "title": c["title"],
                    "date": c["pub_date"] or "Date non précisée",
                    "label": f"Campagne #{c['id']} — {c['title'][:45]}",
                })

            if not campaigns:
                rel_art_rows = session.run("""
                    MATCH (s:Entity)-[r]->(t:Entity)
                    WHERE (toLower(s.name) = toLower($name) OR toLower(t.name) = toLower($name))
                    OPTIONAL MATCH (a:Article {id: r.knowledge_id})
                    RETURN DISTINCT a.id AS id, coalesce(a.title, 'Rapport #' + toString(r.knowledge_id)) AS title,
                                    coalesce(a.publication_date, '') AS pub_date
                    ORDER BY a.id DESC;
                """, name=actor_name)
                for c in rel_art_rows:
                    if c["id"]:
                        campaigns.append({
                            "id": c["id"],
                            "title": c["title"],
                            "date": c["pub_date"] or "Date non précisée",
                            "label": f"Campagne #{c['id']} — {c['title'][:45]}",
                        })

            # Si aucune campagne sélectionnée et qu'il en existe, choisir la dernière par défaut (du moment)
            if selected_cid is None and campaigns and campaign_param != "all":
                selected_cid = campaigns[0]["id"]

            active_campaign_info = None
            if selected_cid:
                for c in campaigns:
                    if c["id"] == selected_cid:
                        active_campaign_info = c
                        break

            # 3. Branche Infrastructure (du moment / de la campagne)
            infra_query = """
                MATCH (infra:Entity)
                WHERE (infra.entity_type IN ['cti:Infrastructure', 'infrastructure'] OR 'Infrastructure' IN labels(infra))
            """
            if selected_cid is not None:
                infra_query += " AND EXISTS { MATCH (a:Article {id: $cid})-[:MENTIONS]->(infra) }"
            infra_query += " RETURN DISTINCT infra.name AS name, infra.id AS id, coalesce(infra.description, '') AS description;"
            infra_rows = session.run(infra_query, cid=selected_cid)
            infra_map: Dict[str, Dict[str, Any]] = {}
            for row in infra_rows:
                infra_map[row["name"]] = {
                    "id": row["id"] or f"infra:{re.sub(r'[^a-z0-9]', '', row['name'].lower())}",
                    "name": row["name"],
                    "description": row["description"],
                    "indicators": [],
                }

            # Indicateurs résolus ou reliés
            ind_query = """
                MATCH (infra:Entity)-[r]->(ind:Entity)
                WHERE (infra.entity_type IN ['cti:Infrastructure', 'infrastructure'] OR 'Infrastructure' IN labels(infra))
                  AND (ind.entity_type IN ['cti:ObservableIndicator', 'observable_indicator'] OR 'ObservableIndicator' IN labels(ind))
            """
            if selected_cid is not None:
                ind_query += " AND r.knowledge_id = $cid"
            ind_query += """
                RETURN infra.name AS infra_name, ind.name AS ind_val, ind.entity_type AS ind_type,
                       coalesce(r.evidence, '') AS evidence;
            """
            for row in session.run(ind_query, cid=selected_cid):
                iname = row["infra_name"]
                if iname in infra_map:
                    infra_map[iname]["indicators"].append({
                        "value": row["ind_val"],
                        "type": row["ind_type"],
                        "evidence": row["evidence"],
                    })

            # Indicateurs atomiques observables de la campagne
            atomic_query = """
                MATCH (ind:Entity)
                WHERE (ind.entity_type IN ['cti:ObservableIndicator', 'observable_indicator'] OR 'ObservableIndicator' IN labels(ind))
            """
            if selected_cid is not None:
                atomic_query += " AND EXISTS { MATCH (a:Article {id: $cid})-[:MENTIONS]->(ind) }"
            atomic_query += " RETURN DISTINCT ind.name AS ind_val, coalesce(ind.description, '') AS desc;"
            known_ind_vals = {ind["value"] for inf in infra_map.values() for ind in inf["indicators"]}
            unassigned_indicators = []
            for row in session.run(atomic_query, cid=selected_cid):
                val = row["ind_val"]
                if val not in known_ind_vals:
                    unassigned_indicators.append({"value": val, "type": "observable", "evidence": row["desc"]})

            if unassigned_indicators:
                bloc_name = "Actifs & Indicateurs Réseau de la Campagne"
                if bloc_name not in infra_map:
                    infra_map[bloc_name] = {
                        "id": "infra:campaign_network_assets",
                        "name": bloc_name,
                        "description": "Indicateurs observables (IPs, FQDNs, URLs) extraits lors de cette intrusion.",
                        "indicators": unassigned_indicators,
                    }
                else:
                    infra_map[bloc_name]["indicators"].extend(unassigned_indicators)

            # TTPs Réseau / C2
            ttps_query = """
                MATCH (pat:Entity)
                WHERE (pat.entity_type IN ['cti:AttackPattern', 'attack_pattern'] OR 'AttackPattern' IN labels(pat))
            """
            if selected_cid is not None:
                ttps_query += " AND EXISTS { MATCH (a:Article {id: $cid})-[:MENTIONS]->(pat) }"
            ttps_query += " RETURN DISTINCT pat.name AS name, coalesce(pat.mitreId, '') AS mitreId, coalesce(pat.description, '') AS description;"

            network_c2_ttps = []
            host_ttps = []
            for row in session.run(ttps_query, cid=selected_cid):
                tname = row["name"]
                mid = row["mitreId"]
                desc = row["description"]
                is_net = any(k in tname.lower() or k in mid.lower() for k in [
                    "t1583", "t1071", "t1568", "t1105", "t1090", "t1041", "t1566", "t1190", "t1133", "protocol", "c2", "domain", "proxy", "traffic", "network"
                ])
                ttp_obj = {"name": tname, "mitreId": mid, "description": desc}
                if is_net:
                    network_c2_ttps.append(ttp_obj)
                else:
                    host_ttps.append(ttp_obj)

            # 4. Branche Outils & Arsenal (du moment / de la campagne)
            tools_query = """
                MATCH (sw:Entity)
                WHERE (sw.entity_type IN ['cti:SoftwareSystem', 'software_system', 'tool', 'malware'] OR 'SoftwareSystem' IN labels(sw))
            """
            if selected_cid is not None:
                tools_query += " AND EXISTS { MATCH (a:Article {id: $cid})-[:MENTIONS]->(sw) }"
            tools_query += """
                RETURN DISTINCT sw.name AS name, sw.id AS id, sw.entity_type AS type,
                       coalesce(sw.is_dual_use, false) AS is_dual_use,
                       coalesce(sw.cpe23Uri, sw.cpe, '') AS cpe,
                       coalesce(sw.description, '') AS description;
            """
            tool_rows = session.run(tools_query, cid=selected_cid)
            tools_list = []
            for row in tool_rows:
                is_dual = bool(row["is_dual_use"])
                sw_name = row["name"]
                etype = row["type"]
                posture_lbl = "Outil Légitime Détourné (LOLBin / Dual-Use)" if is_dual else "Malware Dédié"
                tools_list.append({
                    "id": row["id"] or f"software:{re.sub(r'[^a-z0-9]', '', sw_name.lower())}",
                    "name": sw_name,
                    "type": etype,
                    "is_dual_use": is_dual,
                    "posture_label": posture_lbl,
                    "cpe": row["cpe"],
                    "description": row["description"],
                    "associated_ttps": [t for t in host_ttps if sw_name.lower() in t["name"].lower() or sw_name.lower() in t["description"].lower()][:3],
                })

            dedicated_malwares = [t for t in tools_list if not t["is_dual_use"]]
            lolbins = [t for t in tools_list if t["is_dual_use"]]

            # Préparation des sous-blocs C2 et Localisation
            c2_indicators = []
            location_indicators = []
            for inf in infra_map.values():
                for ind in inf.get("indicators", []):
                    val = ind.get("value", "")
                    if any(c in val for c in [".", ":", "/"]) or "c2" in ind.get("type", "").lower():
                        c2_indicators.append(ind)
                    else:
                        location_indicators.append(ind)

            # Localisation par défaut issue du profil CTI si aucune localisation d'infra isolée
            if not location_indicators:
                location_indicators.append({
                    "value": f"{profile['country']} ({profile.get('state_affiliation', 'Non étatique')})",
                    "type": "geo_origin",
                    "evidence": f"Attribution géopolitique documentée par {profile['attribution_source']}",
                })

            # Libellé Sponsor / Autorité Étatique Racine (ex: "Armée populaire de Chine")
            sponsor_label = profile.get("state_affiliation") or ""
            if "61398" in sponsor_label or "chine" in profile.get("country", "").lower():
                sponsor_label = "Armée populaire de Chine"
            elif not sponsor_label or sponsor_label.lower().startswith("non"):
                sponsor_label = profile.get("affiliation_type") or f"Origine : {profile.get('country')}"

            root_sponsor = {
                "name": sponsor_label,
                "country": profile["country"],
                "country_code": profile["country_code"],
                "flag": profile["flag"],
                "state_affiliation": profile["state_affiliation"],
                "affiliation_type": profile["affiliation_type"],
                "attribution_source": profile["attribution_source"],
            }

            all_ttps = network_c2_ttps + host_ttps

        self.send_json_response({
            "root_sponsor": root_sponsor,
            "actor": {
                "id": actor_id,
                "name": profile.get("canonical_name") or actor_name,
                "country": profile["country"],
                "country_code": profile["country_code"],
                "flag": profile["flag"],
                "affiliation_type": profile["affiliation_type"],
                "state_affiliation": profile["state_affiliation"],
                "attribution_source": profile["attribution_source"],
                "confidence": profile["confidence"],
                "aliases": profile["aliases"],
                "description": profile["description"],
            },
            "timeline": {
                "campaigns": campaigns,
                "selected_campaign_id": selected_cid,
                "selected_campaign": active_campaign_info,
                "is_consolidated": selected_cid is None,
            },
            "infrastructure": {
                "summary": f"{len(infra_map)} infrastructure(s) et {sum(len(inf['indicators']) for inf in infra_map.values())} indicateur(s) identifié(s)",
                "c2_servers": c2_indicators,
                "locations": location_indicators,
                "ttps": network_c2_ttps,
                "nodes": list(infra_map.values()),
            },
            "ttps_kill_chain": {
                "summary": f"{len(all_ttps)} technique(s) ATT&CK identifiée(s)",
                "all_ttps": all_ttps,
                "network_ttps": network_c2_ttps,
                "host_ttps": host_ttps,
            },
            "tools": {
                "summary": f"{len(tools_list)} outil(s) recensé(s) ({len(dedicated_malwares)} dédié(s), {len(lolbins)} LOLBin(s))",
                "dedicated_malwares": dedicated_malwares,
                "lolbins": lolbins,
                "all_tools": tools_list,
            },
        })

    def api_entities(self, params: Dict[str, List[str]]) -> None:
        entity_type = params.get("type", [None])[0]
        dual_use_only = params.get("dual_use_only", ["0"])[0] in ("1", "true")
        search = params.get("search", [""])[0].strip().lower()

        store = Neo4jStore.get_instance()
        ok, _ = store.check_connection()
        if not ok:
            self.send_json_response({"entities": [], "count": 0})
            return

        with store.driver.session() as session:
            query = """
                MATCH (e:Entity)
                OPTIONAL MATCH (a:Article)-[:MENTIONS]->(e)
                WHERE 1=1
            """
            p: Dict[str, Any] = {}
            if entity_type:
                query += " AND e.entity_type = $etype"
                p["etype"] = entity_type
            if dual_use_only:
                query += " AND e.is_dual_use = true"
            if search:
                query += " AND (toLower(e.name) CONTAINS $search OR toLower(coalesce(e.description, '')) CONTAINS $search)"
                p["search"] = search

            query += """
                RETURN DISTINCT e.id AS id, e.name AS name, e.entity_type AS entity_type,
                                coalesce(e.is_dual_use, false) AS is_dual_use,
                                coalesce(e.description, '') AS description,
                                a.id AS knowledge_id, coalesce(a.title, '') AS article_title, coalesce(a.url, '') AS article_url
                ORDER BY e.name ASC LIMIT 500;
            """
            records = session.run(query, **p)
            rows = [dict(r) for r in records]

        self.send_json_response({"entities": rows, "count": len(rows)})

    def api_relations(self, params: Dict[str, List[str]]) -> None:
        relation_type = params.get("type", [None])[0]
        kc_phase = params.get("kill_chain_phase", [None])[0]
        search = params.get("search", [""])[0].strip().lower()

        store = Neo4jStore.get_instance()
        ok, _ = store.check_connection()
        if not ok:
            self.send_json_response({"relations": [], "count": 0})
            return

        with store.driver.session() as session:
            query = """
                MATCH (s:Entity)-[r]->(t:Entity)
                WHERE type(r) <> 'MENTIONS'
            """
            p: Dict[str, Any] = {}
            if relation_type:
                query += " AND toLower(type(r)) = $rtype"
                p["rtype"] = relation_type.lower()
            if kc_phase:
                query += " AND r.kill_chain_phase = $phase"
                p["phase"] = kc_phase
            if search:
                query += " AND (toLower(s.name) CONTAINS $search OR toLower(t.name) CONTAINS $search OR toLower(coalesce(r.evidence, '')) CONTAINS $search)"
                p["search"] = search

            query += """
                OPTIONAL MATCH (a:Article {id: r.knowledge_id})
                RETURN id(r) AS id, s.name AS source_name, coalesce(r.source_type, s.entity_type) AS source_type,
                       type(r) AS relation_type, t.name AS target_name,
                       coalesce(r.target_type, t.entity_type) AS target_type,
                       coalesce(r.kill_chain_phase, '') AS kill_chain_phase,
                       coalesce(r.evidence, '') AS evidence,
                       r.knowledge_id AS knowledge_id, coalesce(a.title, '') AS article_title, coalesce(a.url, '') AS article_url
                ORDER BY id(r) DESC LIMIT 500;
            """
            records = session.run(query, **p)
            rows = [dict(r) for r in records]

        self.send_json_response({"relations": rows, "count": len(rows)})

    def api_articles(self, params: Dict[str, List[str]]) -> None:
        store = Neo4jStore.get_instance()
        neo4j_articles: Dict[int, Dict[str, Any]] = {}
        ok, _ = store.check_connection()
        if ok:
            with store.driver.session() as session:
                res = session.run("""
                    MATCH (a:Article)
                    RETURN a.id AS id, a.extracted_at AS extracted_at,
                           a.entities_count AS entities_count, a.relations_count AS relations_count,
                           a.status AS status, a.duration AS duration
                """)
                for r in res:
                    neo4j_articles[r["id"]] = dict(r)

        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT k.id, k.title, k.url, k.site_name, k.publication_date,
                       c.primary_category, c.score_operational, c.score_tactical, c.score_strategic
                FROM knowledge k
                JOIN article_classifications c ON k.id = c.knowledge_id
                WHERE c.is_processable = 1
                ORDER BY k.id ASC
                LIMIT 100;
            """)
            raw_rows = [dict(r) for r in c.fetchall()]

        enriched = []
        for r in raw_rows:
            kid = r["id"]
            kg_info = neo4j_articles.get(kid, {})
            r["extracted_at"] = kg_info.get("extracted_at")
            r["entities_count"] = kg_info.get("entities_count", 0)
            r["relations_count"] = kg_info.get("relations_count", 0)
            r["extraction_status"] = kg_info.get("status")
            r["extraction_duration_seconds"] = kg_info.get("duration", 0.0)
            enriched.append(r)

        enriched.sort(key=lambda x: (x["extracted_at"] is not None), reverse=True)
        self.send_json_response({"articles": enriched, "count": len(enriched)})

def run_server(host: str = "0.0.0.0", port: int = 8095) -> None:
    server_address = (host, port)
    httpd = ThreadingHTTPServer(server_address, CTIWebServerHandler)
    print(f"\n" + "="*70)
    print(f"🚀 OpenCTI Knowledge Graph Explorer lancé avec succès !")
    print(f"📍 URL Locale : http://localhost:{port}")
    if host == "0.0.0.0":
        print(f"🌐 URL Réseau : http://0.0.0.0:{port}")
    print(f"📁 Données SQLite : {DB_PATH}")
    print("="*70 + "\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nArrêt du serveur web.")
        httpd.server_close()

def main():
    parser = argparse.ArgumentParser(description="Serveur Web CTI Knowledge Graph (Frontend type OpenCTI)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Hôte d'écoute (défaut: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8095, help="Port d'écoute HTTP (défaut: 8095 ; 8080 et 8090 sont pris par OpenCTI)")
    args = parser.parse_args()

    run_server(host=args.host, port=args.port)

if __name__ == "__main__":
    main()
