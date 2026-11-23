#!/usr/bin/env bash
# AccessMap — one-time Ubuntu installer.
#
# Usage (from the repository root):
#   sudo ./install.sh [--seed] [--no-nginx] [--port 5000]
#
# What it does:
#   1. Verifies Ubuntu 22.04/24.04 (warns otherwise).
#   2. Installs prerequisites: python3, python3-venv, pip, curl, nginx (optional).
#   3. Creates a virtualenv and installs requirements.txt (Flask + Gunicorn).
#   4. Generates .env with a 256-bit SECRET_KEY and REQUIRE_SECRET_KEY=1.
#   5. Creates the `accessmap` system user + hardened systemd service.
#   6. Configures ufw (80/443 when behind nginx; APP_PORT when --no-nginx).
#   7. Initializes the database (chmod 700 data dir), optionally seeds demo data.
#   8. Starts the service and runs a health check against /api/health.
#
# Safe to re-run: existing .env, venv and database are preserved.
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_USER="accessmap"
SEED=0
INSTALL_NGINX=1
APP_PORT=5000

while [[ $# -gt 0 ]]; do
  case "$1" in
    --seed) SEED=1; shift ;;
    --no-nginx) INSTALL_NGINX=0; shift ;;
    --port) APP_PORT="$2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

if ! [[ "$APP_PORT" =~ ^[0-9]+$ ]] || (( APP_PORT < 1 || APP_PORT > 65535 )); then
  echo "Invalid --port value: ${APP_PORT} (expected 1..65535)" >&2
  exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Please run with sudo: sudo $0" >&2
  exit 1
fi

echo "==> [1/8] Checking operating system"
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  echo "    Detected: ${PRETTY_NAME:-unknown}"
  case "${ID:-}" in
    ubuntu) ;;
    *) echo "    WARNING: this installer targets Ubuntu; continuing anyway." ;;
  esac
fi

echo "==> [2/8] Installing system prerequisites"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
  python3 python3-venv python3-pip curl ca-certificates openssl
if [[ "$INSTALL_NGINX" -eq 1 ]]; then
  apt-get install -y --no-install-recommends nginx
fi
if command -v ufw >/dev/null 2>&1; then
  apt-get install -y --no-install-recommends ufw || true
fi

echo "==> [3/8] Creating service user and directories"
id -u "$APP_USER" >/dev/null 2>&1 || useradd --system --home-dir "$APP_DIR" \
  --shell /usr/sbin/nologin "$APP_USER"
mkdir -p "$APP_DIR/data"
chown -R "$APP_USER:$APP_USER" "$APP_DIR"
chmod 700 "$APP_DIR/data"

echo "==> [4/8] Creating virtualenv and installing Python dependencies"
if [[ ! -d "$APP_DIR/.venv" ]]; then
  sudo -u "$APP_USER" python3 -m venv "$APP_DIR/.venv"
fi
sudo -u "$APP_USER" "$APP_DIR/.venv/bin/pip" install --upgrade pip
sudo -u "$APP_USER" "$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt"

echo "==> [5/8] Generating configuration (.env)"
BIND_HOST="127.0.0.1"
if [[ "$INSTALL_NGINX" -eq 0 ]]; then
  BIND_HOST="0.0.0.0"
fi
if [[ ! -f "$APP_DIR/.env" ]]; then
  SECRET="$(openssl rand -hex 32)"
  cat > "$APP_DIR/.env" <<EOF
SECRET_KEY=${SECRET}
REQUIRE_SECRET_KEY=1
DATABASE_URL=data/accessmap.db
HOST=${BIND_HOST}
PORT=${APP_PORT}
DEBUG=0
COOKIE_SECURE=0
GEO_LOOKUP_ENABLED=1
EOF
  echo "    Generated a new 256-bit SECRET_KEY."
else
  echo "    .env already exists — keeping it."
fi
chown "$APP_USER:$APP_USER" "$APP_DIR/.env"
chmod 600 "$APP_DIR/.env"

echo "==> [6/8] Installing systemd service"
sed "s|/opt/accessmap|${APP_DIR}|g" "$APP_DIR/deploy/accessmap.service" \
  > /etc/systemd/system/accessmap.service
systemctl daemon-reload
systemctl enable accessmap.service

echo "==> [7/8] Initializing database"
sudo -u "$APP_USER" env -C "$APP_DIR" "$APP_DIR/.venv/bin/python" -c \
  "from app import create_app; from accessmap import db; a=create_app(); db.init_db(); print('database ready')"
if [[ "$SEED" -eq 1 ]]; then
  sudo -u "$APP_USER" env -C "$APP_DIR" "$APP_DIR/.venv/bin/python" -m accessmap.seed
fi

echo "==> [8/8] Starting service and running health check"
systemctl restart accessmap.service
if [[ "$INSTALL_NGINX" -eq 1 && -f "$APP_DIR/deploy/nginx-accessmap.conf" ]]; then
  sed "s|127.0.0.1:5000|127.0.0.1:${APP_PORT}|g" "$APP_DIR/deploy/nginx-accessmap.conf" \
    > /etc/nginx/sites-available/accessmap
  ln -sf /etc/nginx/sites-available/accessmap /etc/nginx/sites-enabled/accessmap
  rm -f /etc/nginx/sites-enabled/default
  nginx -t && systemctl reload nginx || echo "    nginx config check failed — see: sudo nginx -t"
  if command -v ufw >/dev/null 2>&1; then
    ufw allow 80/tcp comment "AccessMap HTTP" || true
    ufw allow 443/tcp comment "AccessMap HTTPS" || true
  fi
else
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "${APP_PORT}/tcp" comment "AccessMap" || true
  fi
fi

for i in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS "http://127.0.0.1:${APP_PORT}/api/health" >/dev/null 2>&1; then
    echo "    Health check passed: http://127.0.0.1:${APP_PORT}/api/health"
    break
  fi
  sleep 1
  if [[ "$i" -eq 10 ]]; then
    echo "    Health check FAILED. Inspect: sudo journalctl -u accessmap -n 50" >&2
    exit 1
  fi
done

echo ""
echo "AccessMap is installed."
if [[ "$INSTALL_NGINX" -eq 1 ]]; then
  echo "  Threat map : http://<server>/"
  echo "  Admin panel: http://<server>/admin/"
else
  echo "  Threat map : http://<server>:${APP_PORT}/"
  echo "  Admin panel: http://<server>:${APP_PORT}/admin/"
fi
echo "  First run  : open /register ONCE to create the first admin."
echo "  Logs       : sudo journalctl -u accessmap -f"
echo "  Stop/start : sudo systemctl stop|start accessmap"
