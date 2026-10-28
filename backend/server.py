"""Serveur Web du tableau de bord CTI : API REST sur le graphe STIX (Neo4j) et build du frontend (frontend/dist).

    /api/stats, /api/articles            totaux et rapports extraits
    /api/graph?article_id=               sous-graphe d'un rapport (filtres : voir stix_dashboard.graph)
    /api/iocs|rules|article?article_id=  onglets Indicateurs, Détection et Article d'un rapport
    /api/bundle?article_id=              bundle STIX écrit par l'extraction (en-tête X-Bundle-Matches-Graph)
    /api/actors, /api/actors/<id>        profils d'acteurs (seule vue qui agrège plusieurs articles)
"""

import argparse
import json
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import parse_qs, unquote, urlparse

root_dir = Path(__file__).resolve().parents[1]
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from backend import stix_dashboard  # noqa: E402

WEB_DIR = root_dir / "frontend" / "dist"  # build Vite (cd frontend && npm run build)


def _article_id(params: Dict[str, List[str]]) -> int | None:
    aid = params.get("article_id", [None])[0]
    return int(aid) if aid and aid.isdigit() else None


class CTIWebServerHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def do_GET(self) -> None:
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        if path.startswith("/api/"):
            self.handle_api(path, parse_qs(parsed_url.query))
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

    def handle_api(self, path: str, params: Dict[str, List[str]]) -> None:
        try:
            if path == "/api/stats":
                self.send_json_response(stix_dashboard.stats())
            elif path == "/api/articles":
                self.send_json_response(stix_dashboard.articles())
            elif path == "/api/graph":
                self.send_json_response(stix_dashboard.graph(_article_id(params), params))
            elif path in ("/api/iocs", "/api/rules", "/api/article", "/api/bundle"):
                aid = _article_id(params)
                if aid is None:
                    self.send_json_response({"error": "article_id requis"}, status=400)
                elif path == "/api/iocs":
                    self.send_json_response(stix_dashboard.iocs_of_article(aid))
                elif path == "/api/rules":
                    self.send_json_response(stix_dashboard.rules_of_article(aid))
                elif path == "/api/article":
                    text = stix_dashboard.article_text(aid)
                    self.send_json_response(text or {"error": "Article introuvable"}, status=200 if text else 404)
                else:
                    found = stix_dashboard.article_bundle(aid)
                    if found is None:
                        self.send_json_response({"error": f"Aucun bundle STIX pour l'article {aid} (ré-extraire l'article)"}, status=404)
                    else:
                        self.send_bytes_response(found[0], f"article_{aid}.stix.json", {"X-Bundle-Matches-Graph": "1" if found[1] else "0"})
            elif path == "/api/actors":
                self.send_json_response(stix_dashboard.actors())
            elif path.startswith("/api/actors/"):
                profile = stix_dashboard.actor_graph(unquote(path[len("/api/actors/"):]))
                self.send_json_response(profile or {"error": "Acteur introuvable"}, status=200 if profile else 404)
            else:
                self.send_json_response({"error": "Endpoint non trouvé"}, status=404)
        except Exception as e:  # noqa: BLE001 : une requête en erreur ne fait pas tomber le serveur
            self.send_json_response({"error": str(e)}, status=500)


def run_server(host: str = "0.0.0.0", port: int = 8095) -> None:
    httpd = ThreadingHTTPServer((host, port), CTIWebServerHandler)
    print(f"Tableau de bord CTI : http://localhost:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nArrêt du serveur web.")
        httpd.server_close()


def main():
    parser = argparse.ArgumentParser(description="Serveur Web du tableau de bord CTI (graphe STIX)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Hôte d'écoute (défaut: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8095, help="Port d'écoute HTTP (défaut: 8095 ; 8080 et 8090 sont pris par OpenCTI)")
    args = parser.parse_args()
    run_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
