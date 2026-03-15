#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  TrustMe Docker Manager
#  Usage: ./manage.sh [command]
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

G='\033[38;5;46m'; G2='\033[38;5;118m'; A='\033[38;5;214m'
R='\033[38;5;196m'; B='\033[38;5;39m';  M='\033[38;5;240m'
W='\033[97m'; BOLD='\033[1m'; RST='\033[0m'
OK="${G}[✓]${RST}"; ERR="${R}[✗]${RST}"; WARN="${A}[!]${RST}"; INFO="${B}[i]${RST}"

COMPOSE=""
CONTAINER_CMD=""

detect_runtime(){
  # Prefer podman if present (rootless-friendly)
  if command -v podman &>/dev/null; then
    CONTAINER_CMD="podman"
    if command -v podman-compose &>/dev/null; then
      COMPOSE="podman-compose"
    elif command -v docker &>/dev/null; then
      # podman installed but use docker compose shim if available
      COMPOSE="docker compose"
    else
      echo -e "${ERR} podman-compose not found. Install it:"
      echo -e "  ${M}pip3 install podman-compose   OR   sudo apt install podman-compose${RST}"
      exit 1
    fi
  elif command -v docker &>/dev/null; then
    CONTAINER_CMD="docker"
    if docker compose version &>/dev/null 2>&1; then
      COMPOSE="docker compose"
    elif command -v docker-compose &>/dev/null; then
      COMPOSE="docker-compose"
    else
      echo -e "${ERR} docker compose plugin not found."
      echo -e "  ${M}Install: sudo apt install docker-compose-plugin${RST}"
      exit 1
    fi
  else
    echo -e "${ERR} Neither Docker nor Podman found."
    echo -e "  ${M}Install Docker:  curl -fsSL https://get.docker.com | sh${RST}"
    echo -e "  ${M}Install Podman:  sudo apt install podman podman-compose${RST}"
    exit 1
  fi
}

banner(){
  echo -e "${G}"
  echo '  ████████╗██████╗ ██╗   ██╗███████╗████████╗███╗   ███╗███████╗'
  echo '     ██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝████╗ ████║██╔════╝'
  echo '     ██║   ██████╔╝██║   ██║███████╗   ██║   ██╔████╔██║█████╗  '
  echo '     ██║   ██╔══██╗██║   ██║╚════██║   ██║   ██║╚██╔╝██║██╔══╝  '
  echo '     ██║   ██║  ██║╚██████╔╝███████║   ██║   ██║ ╚═╝ ██║███████╗'
  echo '     ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝     ╚═╝╚══════╝'
  echo -e "${M}  Docker Deployment Manager v2.4${RST}"
  echo ""
}

usage(){
  echo -e "${W}${BOLD}COMMANDS:${RST}"
  echo -e "  ${G}./manage.sh build${RST}       Build the Docker image"
  echo -e "  ${G}./manage.sh up${RST}          Start the container (background)"
  echo -e "  ${G}./manage.sh down${RST}        Stop the container"
  echo -e "  ${G}./manage.sh restart${RST}     Restart the container"
  echo -e "  ${G}./manage.sh logs${RST}        Tail container logs"
  echo -e "  ${G}./manage.sh status${RST}      Show container status"
  echo -e "  ${G}./manage.sh shell${RST}       Open a shell inside the container"
  echo -e "  ${G}./manage.sh prod${RST}        Start with Nginx reverse proxy"
  echo -e "  ${G}./manage.sh reports${RST}     List saved reports"
  echo -e "  ${G}./manage.sh clean${RST}       Remove containers and images"
  echo -e "  ${G}./manage.sh update${RST}      Rebuild and restart"
  echo -e "  ${G}./manage.sh -h${RST}          Show this help"
  echo ""
  echo -e "${W}${BOLD}EXAMPLES:${RST}"
  echo -e "  ${M}./manage.sh build && ./manage.sh up${RST}"
  echo -e "  ${M}PORT=9090 ./manage.sh up${RST}"
  echo -e "  ${M}./manage.sh prod    # with nginx on port 80${RST}"
  echo ""
}

check_runtime(){
  detect_runtime

  if [[ "$CONTAINER_CMD" == "podman" ]]; then
    # Start podman socket if not running (needed for compose)
    if ! podman info &>/dev/null 2>&1; then
      echo -e "${WARN} Podman not responding. Trying to start user socket..."
      systemctl --user start podman.socket 2>/dev/null || true
      sleep 1
    fi
    local ver
    ver=$(podman --version | awk '{print $3}')
    echo -e "  ${OK} Runtime: ${G}Podman ${ver}${RST}"
    echo -e "  ${OK} Compose: ${G}${COMPOSE}${RST}"
  else
    # Docker — check daemon is running
    if ! docker info &>/dev/null 2>&1; then
      echo -e "${ERR} Docker daemon not running."
      echo -e "  ${M}Start it:  sudo systemctl start docker${RST}"
      echo -e "  ${M}Or add user to group:  sudo usermod -aG docker \$USER && newgrp docker${RST}"
      exit 1
    fi
    local ver
    ver=$(docker --version | cut -d' ' -f3 | tr -d ',')
    echo -e "  ${OK} Runtime: ${G}Docker ${ver}${RST}"
    echo -e "  ${OK} Compose: ${G}${COMPOSE}${RST}"
  fi
}

get_port(){
  # Read from .env or default
  if [[ -f .env ]]; then
    source .env 2>/dev/null || true
  fi
  echo "${PORT:-8080}"
}

cmd_build(){
  echo -e "${INFO} Building TrustMe image..."
  $COMPOSE build --no-cache
  echo -e "${OK} Build complete"
}

cmd_up(){
  # Pre-create reports dir on host with open permissions so container can write to it
  mkdir -p reports
  chmod 777 reports
  echo -e "${INFO} Starting TrustMe..."
  $COMPOSE up -d trustme
  sleep 2

  local port
  port=$(get_port)
  if $COMPOSE ps trustme 2>/dev/null | grep -qiE "running|Up|healthy"; then
    echo -e "${OK} TrustMe is running!"
    echo -e "  ${G2}→ Open: ${B}http://localhost:${port}${RST}"
  else
    echo -e "${WARN} Container may still be starting. Check: ./manage.sh logs"
    echo -e "  ${G2}→ URL:  ${B}http://localhost:${port}${RST}"
  fi
}

cmd_down(){
  echo -e "${INFO} Stopping TrustMe..."
  $COMPOSE down
  echo -e "${OK} Stopped"
}

cmd_restart(){
  echo -e "${INFO} Restarting..."
  $COMPOSE restart trustme
  echo -e "${OK} Restarted"
}

cmd_logs(){
  echo -e "${INFO} Showing logs (Ctrl+C to exit)..."
  $COMPOSE logs -f --tail=100 trustme
}

cmd_status(){
  echo -e "${W}${BOLD}Container Status:${RST}"
  $COMPOSE ps
  echo ""
  echo -e "${W}${BOLD}Health:${RST}"
  local port=$(get_port)
  if curl -sf "http://localhost:${port}/health" &>/dev/null; then
    echo -e "  ${OK} Health endpoint: ${G}OK${RST}"
    echo -e "  ${G2}→ http://localhost:${port}${RST}"
  else
    echo -e "  ${WARN} Health endpoint not responding on port ${port}"
  fi
  echo ""
  echo -e "${W}${BOLD}Reports saved:${RST}"
  local count=$(ls reports/*.json 2>/dev/null | wc -l || echo 0)
  echo -e "  ${G}${count}${RST} report(s) in ./reports/"
}

cmd_shell(){
  echo -e "${INFO} Opening shell in container..."
  $CONTAINER_CMD exec -it trustme /bin/bash || $CONTAINER_CMD exec -it trustme /bin/sh
}

cmd_prod(){
  mkdir -p reports
  echo -e "${INFO} Starting TrustMe with Nginx reverse proxy..."
  $COMPOSE --profile production up -d
  sleep 2
  local nginx_port="${NGINX_PORT:-80}"
  echo -e "${OK} Running with Nginx!"
  echo -e "  ${G2}→ Open: ${B}http://localhost:${nginx_port}${RST}"
}

cmd_reports(){
  echo -e "${W}${BOLD}Saved Reports:${RST}"
  if ls reports/trustme_*.json &>/dev/null 2>&1; then
    ls -lh reports/trustme_*.json | awk '{print "  " $5 "\t" $9}' | sed 's|reports/||g'
  else
    echo -e "  ${M}No reports found in ./reports/${RST}"
  fi
}

cmd_clean(){
  echo -e "${WARN} This will remove containers and images. Reports are kept."
  read -rp "  Continue? [y/N] " confirm
  [[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }
  $COMPOSE down --rmi local --volumes --remove-orphans 2>/dev/null || true
  echo -e "${OK} Cleaned"
}

cmd_update(){
  echo -e "${INFO} Rebuilding and restarting..."
  $COMPOSE build --no-cache
  $COMPOSE up -d trustme
  echo -e "${OK} Updated and restarted"
}

# ── Main ──────────────────────────────────────────────────────
main(){
  banner
  check_runtime
  echo ""

  case "${1:-help}" in
    build)   cmd_build   ;;
    up)      cmd_up      ;;
    down)    cmd_down    ;;
    restart) cmd_restart ;;
    logs)    cmd_logs    ;;
    status)  cmd_status  ;;
    shell)   cmd_shell   ;;
    prod)    cmd_prod    ;;
    reports) cmd_reports ;;
    clean)   cmd_clean   ;;
    update)  cmd_update  ;;
    -h|--help|help|*) usage ;;
  esac
}

main "$@"
