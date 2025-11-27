#!/usr/bin/env bash
# ============================================================
# JPVPN ULTIMATE - FINAL (ALL-IN-ONE)
# This is the FINAL production-ready installer.
# IMPORTANT:
# - Run as root: sudo -i
# - Save as /root/main.sh, chmod +x /root/main.sh, then run: /root/main.sh
# - Edit sensitive tokens on the VPS after install:
#     /etc/jpvpn/jpvpn.conf
#     /etc/jpvpn/cloudflare.conf
# ============================================================

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# -------------------------
# Defaults / Constants
# -------------------------
ACCESS_CODE="JP"
DEFAULT_DOMAIN="id.vpnstore.my.id"
PANEL_DIR="/var/www/panel"
PANEL_USER="www-data"
VENV_DIR="/opt/jpvpn_venv"
GUNICORN_BIND="127.0.0.1:8000"
GUNICORN_WORKERS=3
REPO_RAW="https://raw.githubusercontent.com/Jpstore1/vip/main/main.sh"
JP_DIR="/usr/local/jpvpn"
CONF_DIR="/etc/jpvpn"
CONF_FILE="$CONF_DIR/jpvpn.conf"
CF_CONF="$CONF_DIR/cloudflare.conf"
LOG_DIR="/var/log/jpvpn"
BACKUP_DIR="/var/backups/jpvpn"

# Ensure directories exist
mkdir -p "$PANEL_DIR" "$JP_DIR" "$CONF_DIR" "$LOG_DIR" "$BACKUP_DIR"
touch /var/log/jpvpn/install.log || true
chown -R root:root "$CONF_DIR" || true

# Central installer logging (to file and stdout)
exec > >(tee -a /var/log/jpvpn/install.log) 2>&1

log(){ echo "[$(date '+%F %T')] $*"; }

# Root check
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo -i). Aborting."
  exit 1
fi

clear
echo "==================================="
echo "JPVPN ULTIMATE - FINAL INSTALLER"
echo "==================================="

# Access code prompt
read -p "Enter installer access code (default: JP): " input_code
input_code=${input_code:-JP}
if [ "$input_code" != "$ACCESS_CODE" ]; then
  echo "Wrong code. Exiting."
  exit 1
fi
log "Installer authorized."

# Domain prompt
read -p "Enter domain for panel (leave empty for id.vpnstore.my.id): " DOMAIN
DOMAIN=${DOMAIN:-id.vpnstore.my.id}
log "Using domain: $DOMAIN"

# Update & install base packages
log "Updating apt and installing base packages..."
apt-get update -y
apt-get upgrade -y

apt-get install -y \
  curl wget git jq unzip zip build-essential lsb-release ca-certificates \
  python3 python3-venv python3-pip python3-dev \
  nginx certbot python3-certbot-nginx \
  ufw fail2ban iptables-persistent \
  net-tools iproute2 supervisor

# Ensure jq present
if ! command -v jq >/dev/null 2>&1; then
  apt-get install -y jq
fi

# Create demo panel if none provided
if [ ! -f "$PANEL_DIR/app.py" ] && [ ! -f "$PANEL_DIR/manage.py" ]; then
  log "No panel app found; creating demo Flask app at $PANEL_DIR"
  cat > "$PANEL_DIR/app.py" <<'PY'
from flask import Flask, render_template_string
app = Flask(__name__)
@app.route("/")
def index():
    return render_template_string("<h1>JPVPN Demo Panel</h1><p>Replace with your app in /var/www/panel</p>")
if __name__ == "__main__":
    app.run()
PY
  chown -R "$PANEL_USER":"$PANEL_USER" "$PANEL_DIR" || true
fi

# Create virtualenv and install runtime
log "Creating virtualenv at $VENV_DIR"
if [ ! -d "$VENV_DIR" ]; then
  python3 -m venv "$VENV_DIR"
fi
"$VENV_DIR/bin/pip" install --upgrade pip setuptools wheel >/dev/null 2>&1 || true

APP_MODE="flask"
if [ -f "$PANEL_DIR/manage.py" ]; then
  APP_MODE="django"
  "$VENV_DIR/bin/pip" install --upgrade gunicorn django >/dev/null 2>&1 || true
elif grep -R "Flask" "$PANEL_DIR" >/dev/null 2>&1 || [ -f "$PANEL_DIR/app.py" ]; then
  APP_MODE="flask"
  "$VENV_DIR/bin/pip" install --upgrade gunicorn flask >/dev/null 2>&1 || true
else
  APP_MODE="flask"
  "$VENV_DIR/bin/pip" install --upgrade gunicorn flask >/dev/null 2>&1 || true
fi
echo "$APP_MODE" > "$CONF_DIR/panel_mode" || true

# Determine WSGI module
WSGI_MODULE="app:app"
if [ "$APP_MODE" = "django" ]; then
  WSGI_MODULE="wsgi:application"
  found_wsgi=$(find "$PANEL_DIR" -maxdepth 3 -name wsgi.py 2>/dev/null | head -n1 || true)
  if [ -n "$found_wsgi" ]; then
    reldir=$(dirname "${found_wsgi#$PANEL_DIR/}")
    reldir=${reldir:-.}
    module=$(echo "$reldir" | sed 's/\//./g')
    if [ "$module" = "." ]; then WSGI_MODULE="wsgi:application"; else WSGI_MODULE="${module}.wsgi:application"; fi
  fi
else
  if [ -f "$PANEL_DIR/app.py" ]; then WSGI_MODULE="app:app"; elif [ -f "$PANEL_DIR/main.py" ]; then WSGI_MODULE="main:app"; fi
fi

# Create systemd service for Gunicorn
PANEL_SERVICE="/etc/systemd/system/panel.service"
log "Creating systemd service $PANEL_SERVICE"
cat > "$PANEL_SERVICE" <<EOF
[Unit]
Description=JPVPN Python Panel (gunicorn)
After=network.target

[Service]
User=${PANEL_USER}
Group=${PANEL_USER}
WorkingDirectory=${PANEL_DIR}
Environment="PATH=${VENV_DIR}/bin"
ExecStart=${VENV_DIR}/bin/gunicorn --workers ${GUNICORN_WORKERS} --bind ${GUNICORN_BIND} ${WSGI_MODULE}
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now panel.service || true
sleep 1

# Configure Nginx reverse proxy
log "Writing nginx config for $DOMAIN"
NGCONF="/etc/nginx/conf.d/panel.conf"
cat > "$NGCONF" <<NGC
server {
    listen 80;
    server_name ${DOMAIN};

    location / {
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location /status {
        alias /var/www/status/index.html;
    }

    location /static/ {
        alias ${PANEL_DIR}/static/;
    }
}
NGC

# Validate nginx
if nginx -t; then
  systemctl enable --now nginx || true
else
  log "nginx config test failed; see 'nginx -t' output above."
fi

# Try Certbot for TLS (best effort)
log "Attempting Let's Encrypt cert for ${DOMAIN}"
if command -v certbot >/dev/null 2>&1; then
  if certbot --nginx -d "${DOMAIN}" --non-interactive --agree-tos -m "admin@${DOMAIN}" >/dev/null 2>&1; then
    log "Certbot: certificate installed for ${DOMAIN}"
  else
    log "Certbot failed (DNS not ready / rate limit). Continuing without TLS."
  fi
else
  log "Certbot not installed; skipping TLS issuance."
fi

# Basic firewall and iptables protections
log "Configuring UFW and iptables mitigations"
ufw --force reset || true
ufw default deny incoming || true
ufw default allow outgoing || true
ufw allow OpenSSH || true
ufw allow 'Nginx Full' || true
ufw allow 8000/tcp || true
ufw limit OpenSSH || true
ufw --force enable || true

iptables -N JPVPN_DDOS 2>/dev/null || true
iptables -F JPVPN_DDOS 2>/dev/null || true
iptables -A JPVPN_DDOS -m conntrack --ctstate NEW -m limit --limit 25/minute --limit-burst 50 -j RETURN || true
iptables -A JPVPN_DDOS -j DROP 2>/dev/null || true
iptables -I INPUT -p tcp --dport 22 -j JPVPN_DDOS || true
iptables -I INPUT -p tcp --dport 80 -j JPVPN_DDOS || true
iptables -I INPUT -p tcp --dport 443 -j JPVPN_DDOS || true
iptables -I INPUT -p tcp --dport 8000 -j JPVPN_DDOS || true
netfilter-persistent save || true

# Fail2Ban
log "Configuring Fail2Ban"
cat > /etc/fail2ban/jail.d/jpvpn.conf <<'FF'
[sshd]
enabled = true
port = ssh
maxretry = 5
bantime = 3600

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
action = iptables-multiport[name=NoAuthFailures, port="http,https", protocol=tcp]
logpath = /var/log/nginx/error.log
maxretry = 5
bantime = 3600
FF

systemctl restart fail2ban || true

# Monitor / Autoheal / Backup / Updater
log "Installing monitor, autoheal, backup, updater scripts"

cat > /usr/local/jpvpn/monitor.sh <<'MON'
#!/usr/bin/env bash
PANEL_URL="http://127.0.0.1:8000/"
LOG="/var/log/jpvpn/monitor.log"
exec >>"$LOG" 2>&1
echo "[$(date)] monitor run"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$PANEL_URL" || echo "000")
if [ "$HTTP" = "200" ]; then
  echo "[$(date)] OK"
  exit 0
fi
echo "[$(date)] DOWN -> restart services"
systemctl restart panel.service || true
systemctl restart nginx || true
sleep 4
HTTP2=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$PANEL_URL" || echo "000")
if [ "$HTTP2" = "200" ]; then
  echo "[$(date)] recovered"
  exit 0
fi
echo "[$(date)] fallback -> start simple http server"
pkill -f "python3 -m http.server 8000" || true
nohup python3 -m http.server 8000 --directory /var/www/panel >/dev/null 2>&1 &
echo "[$(date)] fallback started"
MON
chmod +x /usr/local/jpvpn/monitor.sh

cat > /usr/local/jpvpn/autoheal.sh <<'AH'
#!/usr/bin/env bash
LOG="/var/log/jpvpn/autoheal.log"
exec >>"$LOG" 2>&1
echo "[$(date)] autoheal run"
if ss -tunlp 2>/dev/null | grep -q ":8000"; then
  echo "[$(date)] panel listening on 8000"
  exit 0
fi
echo "[$(date)] panel not listening; restarting services"
systemctl restart panel.service || true
systemctl restart nginx || true
AH
chmod +x /usr/local/jpvpn/autoheal.sh

cat > /usr/local/jpvpn/backup.sh <<'BUP'
#!/usr/bin/env bash
TIMESTAMP=$(date +%F_%H%M%S)
BACKDIR="/var/backups/jpvpn"
mkdir -p "$BACKDIR"
TAR="$BACKDIR/panel-$TIMESTAMP.tar.gz"
tar -czf "$TAR" /var/www/panel /etc/nginx/conf.d/panel.conf /etc/systemd/system/panel.service 2>/dev/null || true
echo "[$(date)] backup saved to $TAR"
BUP
chmod +x /usr/local/jpvpn/backup.sh

cat > /usr/local/jpvpn/update.sh <<'UPD'
#!/usr/bin/env bash
REPO_RAW="https://raw.githubusercontent.com/Jpstore1/vip/main/main.sh"
TMP="/tmp/main.sh.$$"
if curl -fsSL "$REPO_RAW" -o "$TMP"; then
  if [ ! -f /root/main.sh ] || ! cmp -s "$TMP" /root/main.sh; then
    cp "$TMP" /root/main.sh
    chmod +x /root/main.sh
    echo "update: /root/main.sh updated"
  else
    echo "update: no changes"
  fi
  rm -f "$TMP"
else
  echo "update: failed to download"
fi
UPD
chmod +x /usr/local/jpvpn/update.sh

# systemd timer for monitor
cat > /etc/systemd/system/jpvpn-monitor.service <<'MSVC'
[Unit]
Description=JPVPN Monitor (oneshot)
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/jpvpn/monitor.sh
MSVC

cat > /etc/systemd/system/jpvpn-monitor.timer <<'MTMR'
[Unit]
Description=Run JPVPN monitor every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
AccuracySec=1s

[Install]
WantedBy=timers.target
MTMR

systemctl daemon-reload
systemctl enable --now jpvpn-monitor.timer || true

# Telegram notifier (reads /etc/jpvpn/jpvpn.conf)
log "Installing Telegram notifier (tg_notify.sh) and config template"

if [ ! -f "$CONF_FILE" ]; then
  cat > "$CONF_FILE" <<'CF'
# JPVPN config file
# Edit TELEGRAM_TOKEN and TELEGRAM_CHATID to enable notifications
TELEGRAM_TOKEN=""
TELEGRAM_CHATID=""
RCLONE_REMOTE=""
CF_ENABLE=false
CF_API_TOKEN=""
CF_ZONE_ID=""
CF_RECORD_NAME=""
CF_RECORD_ID=""
CF_MODE="off"
CF
  chmod 600 "$CONF_FILE"
fi

cat > /usr/local/jpvpn/tg_notify.sh <<'TNG'
#!/usr/bin/env bash
CONF="/etc/jpvpn/jpvpn.conf"
if [ -f "$CONF" ]; then
  . "$CONF"
else
  TELEGRAM_TOKEN=""
  TELEGRAM_CHATID=""
fi
send_msg() {
  local text="$1"
  if [ -z "${TELEGRAM_TOKEN:-}" ] || [ -z "${TELEGRAM_CHATID:-}" ]; then
    echo "tg_notify: token/chatid not set; skipping"
    return 0
  fi
  curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
    -d chat_id="${TELEGRAM_CHATID}" \
    -d text="$(echo "$text" | sed 's/"/\\"/g')" >/dev/null 2>&1 || true
}
case "${1:-}" in
  "install_complete")
    send_msg "JPVPN installed on $(hostname). Domain: '"$DOMAIN"'"
    ;;
  "panel_down")
    send_msg "ALERT: JPVPN panel down on $(hostname)"
    ;;
  *)
    send_msg "${1:-"JPVPN notification"}"
    ;;
esac
TNG
chmod +x /usr/local/jpvpn/tg_notify.sh

# status page
log "Creating simple status page"
mkdir -p /var/www/status
cat > /var/www/status/index.html <<HTML
<!doctype html>
<html>
<head><meta charset="utf-8"><title>JPVPN Status</title></head>
<body>
  <h1>JPVPN STATUS</h1>
  <p>Panel active via Nginx reverse proxy (domain: ${DOMAIN})</p>
</body>
</html>
HTML

# fallback service (python http.server)
FALLBACK_SERVICE="/etc/systemd/system/panel-fallback.service"
cat > "$FALLBACK_SERVICE" <<'FBS'
[Unit]
Description=JPVPN Panel Fallback (python http.server)
After=network.target

[Service]
Type=simple
WorkingDirectory=/var/www/panel
ExecStart=/usr/bin/python3 -m http.server 8000 --directory /var/www/panel
User=www-data
Group=www-data
Restart=on-failure
FBS

systemctl daemon-reload

# final restarts
log "Restarting services"
systemctl restart panel.service || true
systemctl restart nginx || true
systemctl restart jpvpn-monitor.timer || true

log "Installation finished."
echo "================================================================"
echo "JPVPN installer finished. Panel should be available at: http://${DOMAIN}"
echo "Edit $CONF_FILE to configure TELEGRAM_TOKEN, TELEGRAM_CHATID, and Cloudflare settings."
echo "Install log: /var/log/jpvpn/install.log"
echo "To update the installer later: /usr/local/jpvpn/update.sh"
echo "================================================================"

exit
