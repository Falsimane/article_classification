#!/usr/bin/env bash
# Lance le tableau de bord CTI : backend (API + build du frontend) ou, avec --dev, backend + serveur Vite à rechargement à chaud.
#
#   scripts/dashboard.sh                 # http://localhost:8095 ; reconstruit frontend/dist si les sources ont changé
#   scripts/dashboard.sh --dev           # http://localhost:5173 (Vite, port suivant s'il est pris) ; l'API reste sur :8095 ; Ctrl+C arrête les deux
#   scripts/dashboard.sh --port 8096     # autre port pour le backend (8080 et 8090 sont pris par OpenCTI)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONT="$ROOT/frontend"
PORT=8095
DEV=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dev) DEV=1 ;;
    --port) PORT="$2"; shift ;;
    -h|--help) sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Option inconnue : $1 (voir --help)" >&2; exit 2 ;;
  esac
  shift
done

listening() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

if listening "$PORT"; then
  echo "Le port $PORT est déjà pris (un tableau de bord tourne déjà ?). Choisir un autre port : --port <n>" >&2
  exit 1
fi
if ! listening 7687; then
  echo "Avertissement : Neo4j injoignable sur bolt://localhost:7687 (lancer : docker compose up -d neo4j). L'interface s'affichera sans données." >&2
fi

# npm réécrit node_modules/.package-lock.json à chaque installation
if [[ ! -f "$FRONT/node_modules/.package-lock.json" || "$FRONT/package.json" -nt "$FRONT/node_modules/.package-lock.json" ]]; then
  echo "Installation des dépendances du frontend…"
  (cd "$FRONT" && npm install)
fi

if [[ $DEV -eq 1 ]]; then
  # Les deux en arrière-plan, Vite sans passer par npm (qui ne relaie pas toujours le signal à node) : à l'arrêt du script,
  # ou dès que l'un des deux s'arrête, l'autre est arrêté aussi
  (cd "$ROOT" && exec uv run cti-dashboard --port "$PORT") &
  BACKEND=$!
  (cd "$FRONT" && CTI_API_PORT="$PORT" exec node_modules/.bin/vite) &
  FRONTEND=$!
  trap 'kill "$BACKEND" "$FRONTEND" 2>/dev/null; wait 2>/dev/null' EXIT INT TERM HUP
  wait -n
else
  # Build seulement si une source est plus récente que le dernier build
  if [[ ! -f "$FRONT/dist/index.html" ]] || [[ -n "$(find "$FRONT/src" "$FRONT/index.html" "$FRONT/package.json" "$FRONT"/*.config.* -newer "$FRONT/dist/index.html" -print -quit)" ]]; then
    echo "Build du frontend…"
    (cd "$FRONT" && npm run build)
  fi
  echo "Tableau de bord : http://localhost:$PORT"
  cd "$ROOT" && exec uv run cti-dashboard --port "$PORT"
fi
