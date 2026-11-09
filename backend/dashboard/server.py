"""Serveur Web du tableau de bord CTI : API REST sur le graphe STIX (Neo4j) et build du frontend (frontend/dist).

    /api/stats, /api/articles            totaux et rapports extraits
    /api/graph?article_id=               sous-graphe d'un rapport (filtres : voir stix_dashboard.graph)
    /api/iocs|rules|article?article_id=  onglets Indicateurs, Détection et Article d'un rapport
    /api/bundle?article_id=              bundle STIX écrit par l'extraction (en-tête X-Bundle-Matches-Graph)
    /api/actors, /api/actors/<id>        profils d'acteurs (agrègent plusieurs articles)
    /api/kg, /api/kg/node?id=            graphe global (ETag : révision du graphe) et détail d'un nœud avec ses preuves
    POST /api/ask                        question sur le graphe global, réponse en flux SSE (backend/dashboard/ask.py)
    DELETE /api/articles/<id>            supprime l'article du graphe et ses bundles (stix_dashboard.delete_article)

Pas d'en-tête Access-Control-Allow-Methods : un navigateur refuse donc le DELETE venu d'une autre origine (pré-vérification CORS
sans réponse).
"""

import argparse
import json
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import parse_qs, unquote, urlparse

root_dir = Path(__file__).resolve().parents[2]
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from backend.dashboard import ask, stix_dashboard  # noqa: E402

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

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        raw = path[len("/api/articles/"):] if path.startswith("/api/articles/") else ""
        if not raw.isdigit():
            self.send_json_response({"error": "Endpoint non trouvé"}, status=404)
            return
        try:
            deleted = stix_dashboard.delete_article(int(raw))
        except Exception as e:  # noqa: BLE001
            self.send_json_response({"error": str(e)}, status=500)
            return
        if deleted is None:
            self.send_json_response({"error": f"Article {raw} absent du graphe"}, status=404)
        else:
            print(f"Article {raw} supprimé : {deleted['nodes_deleted']} nœuds, {deleted['edges_deleted']} arêtes, bundles {deleted['bundles_deleted']}")
            self.send_json_response(deleted)

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/api/ask":
            self.send_json_response({"error": "Endpoint non trouvé"}, status=404)
            return
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        except ValueError:
            body = {}
        question = str(body.get("question") or "").strip()
        if not question:
            self.send_json_response({"error": "question requise"}, status=400)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        def emit(event: dict) -> None:
            self.wfile.write(f"data: {json.dumps(event, ensure_ascii=False, default=str)}\n\n".encode("utf-8"))
            self.wfile.flush()

        try:
            history = body.get("history") if isinstance(body.get("history"), list) else []
            ask.answer(question, body.get("focus") or None, history, emit)
        except (BrokenPipeError, ConnectionResetError):
            pass  # le navigateur a fermé le panneau ; la requête au modèle en cours se termine côté serveur
        except Exception as e:  # noqa: BLE001
            emit({"type": "error", "message": str(e)})

    def send_json_response(self, data: Any, status: int = 200, headers: Dict[str, str] | None = None) -> None:
        payload = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        headers = {"Cache-Control": "no-cache, no-store, must-revalidate", **(headers or {})}
        for key, value in headers.items():
            self.send_header(key, value)
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
            elif path == "/api/kg":
                revision = f'"{stix_dashboard.StixStore().graph_revision()}"'
                if self.headers.get("If-None-Match") == revision:
                    self.send_response(304)
                    self.send_header("ETag", revision)
                    self.end_headers()
                else:
                    self.send_json_response(stix_dashboard.global_graph(), headers={"ETag": revision, "Cache-Control": "no-cache"})
            elif path == "/api/kg/node":
                detail = stix_dashboard.node_detail(params.get("id", [""])[0])
                self.send_json_response(detail or {"error": "Entité introuvable"}, status=200 if detail else 404)
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
