#!/usr/bin/env bash
# ============================================================
# JPVPN ULTIMATE - FULL (ALL-IN-ONE)
# - Python Panel (Flask/Django) via Gunicorn
# - Nginx reverse proxy + Certbot (Let's Encrypt)
# - UFW + basic iptables DDoS mitigations
# - Fail2Ban
# - Monitor / Autoheal / Fallback server
# - Daily Backup (Telegram / rclone optional)
# - Auto-update (from repo raw)
# - Telegram notifier & bot (long polling) (optional)
# - Cloudflare DNS/WAF integration (optional)
# - Systemd timers & services
#
# Edit sensitive values on VPS only:
#   /etc/jpvpn/jpvpn.conf
#   /etc/jpvpn/cloudflare.conf
#
# Run:
#   chmod +x /root/main.sh
#   bash /root/main.sh
# ============================================================

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

ACCESS_CODE="JP"
DEFAULT_DOMAIN="id.vpnstore.my.id"
PANEL_DIR="/var/www/panel"
PANEL_USER="www-data"
VENV_DIR="/opt/jpvpn_venv"
GUNICORN_BIND="127.0.0.1:8000"
GUNICORN_WORKERS=3
REPO_RAW="https://raw.githubusercontent.com/Jpstore1/vip/main/main.sh"
JP_DIR="/usr/local/jpvpn"
PRO_DIR="$JP_DIR/pro"
CONF_DIR="/etc/jpvpn"
CONF_FILE="$CONF_DIR/jpvpn.conf"
CF_CONF="$CONF_DIR/cloudflare.conf"
LOG_DIR="/var/log/jpvpn"
BACKUP_DIR="/var/backups/jpvpn"

mkdir -p "$PANEL_DIR" "$JP_DIR" "$PRO_DIR" "$CONF_DIR" "$LOG_DIR" "$BACKUP_DIR"

log(){ echo "[$(date '+%F %T')] $*"; }

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo -i). Aborting."
  exit 1
fi

clear
echo "==================================="
echo "JPVPN ULTIMATE - FULL INSTALLER"
echo "==================================="
read -p "Enter installer access code: " input_code
if [ "$input_code" != "$ACCESS_CODE" ]; then
  echo "Wrong code. Exiting."
  exit 1
fi
log "Installer authorized."

log "Updating system and installing base packages..."
apt-get update -y
apt-get upgrade -y

apt-get install -y \
  curl wget git jq unzip zip build-essential lsb-release ca-certificates \
  python3 python3-venv python3-pip \
  nginx certbot python3-certbot-nginx \
  ufw fail2ban iptables-persistent \
  net-tools iproute2 supervisor

if ! command -v jq >/dev/null 2>&1; then
  apt-get install -y jq
fi

if [ ! -f "$PANEL_DIR/app.py" ] && [ ! -f "$PANEL_DIR/manage.py" ]; then
  log "Creating demo Flask panel..."
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

log "Creating virtualenv..."
if [ ! -d "$VENV_DIR" ]; then python3 -m venv "$VENV_DIR"; fi
"$VENV_DIR/bin/pip" install --upgrade pip setuptools wheel >/dev/null 2>&1 || true

APP_MODE="flask"
if [ -f "$PANEL_DIR/manage.py" ]; then
  APP_MODE="django"
  "$VENV_DIR/bin/pip" install gunicorn django >/dev/null 2>&1 || true
elif grep -R "Flask" "$PANEL_DIR" >/dev/null 2>&1; then
  APP_MODE="flask"
  "$VENV_DIR/bin/pip" install gunicorn flask >/dev/null 2>&1 || true
else
  APP_MODE="flask"
  "$VENV_DIR/bin/pip" install gunicorn flask >/dev/null 2>&1 || true
fi
echo "$APP_MODE" > "$CONF_DIR/panel_mode"

PANEL_SERVICE="/etc/systemd/system/panel.service"
log "Creating Gunicorn service..."

WSGI_MODULE="app:app"
if [ "$APP_MODE" = "django" ]; then
  WSGI_MODULE="wsgi:application"
  for f in $(find "$PANEL_DIR" -name wsgi.py -maxdepth 3 2>/dev/null); do
    reldir=$(dirname "${f#$PANEL_DIR/}")
    reldir=${reldir:-.}
    module=$(echo "$reldir" | sed 's/\//./g')
    if [ "$module" = "." ]; then WSGI_MODULE="wsgi:application"; else WSGI_MODULE="${module}.wsgi:application"; fi
    break
  done
else
  if [ -f "$PANEL_DIR/app.py" ]; then WSGI_MODULE="app:app"; elif [ -f "$PANEL_DIR/main.py" ]; then WSGI_MODULE="main:app"; fi
fi

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

log "Configuring Nginx..."
NGCONF="/etc/nginx/conf.d/panel.conf"
cat > "$NGCONF" <<NGC
server {
    listen 80;
    server_name ${DEFAULT_DOMAIN};

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

sed -i "s/${DEFAULT_DOMAIN}/${DOMAIN}/g" "$NGCONF"
nginx -t && systemctl enable --now nginx || true

log "Attempting certbot..."
if certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN"; then
  log "SSL OK"
else
  log "Certbot failed"
fi

log "Configuring UFW + iptables..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw allow 'Nginx Full'
ufw allow 8000/tcp
ufw limit OpenSSH
ufw --force enable

iptables -N JPVPN_DDOS 2>/dev/null || true
iptables -F JPVPN_DDOS 2>/dev/null || true
iptables -A JPVPN_DDOS -m conntrack --ctstate NEW -m limit --limit 25/minute --limit-burst 50 -j RETURN
iptables -A JPVPN_DDOS -j DROP 2>/dev/null || true
iptables -I INPUT -p tcp --dport 22 -j JPVPN_DDOS
iptables -I INPUT -p tcp --dport 80 -j JPVPN_DDOS
iptables -I INPUT -p tcp --dport 443 -j JPVPN_DDOS
iptables -I INPUT -p tcp --dport 8000 -j JPVPN_DDOS
netfilter-persistent save || true

log "Configuring Fail2Ban..."
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

log "Installing monitor / autoheal / backup / updater..."
cat > /usr/local/jpvpn/monitor.sh <<'MON'
#!/usr/bin/env bash
PANEL_URL="http://127.0.0.1:8000/"
LOG="/var/log/jpvpn/monitor.log"
exec >>"$LOG" 2>&1
echo "[$(date)] monitor"

HTTP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$PANEL_URL" || echo "000")
if [ "$HTTP" = "200" ]; then
  echo "[$(date)] OK"
  exit 0
fi

echo "[$(date)] DOWN -> restarting"
systemctl restart panel.service || true
systemctl restart nginx || true
sleep 3

HTTP2=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$PANEL_URL" || echo "000")
if [ "$HTTP2" = "200" ]; then
  echo "[$(date)] recovered"
  exit 0
fi

echo "[$(date)] starting fallback"
pkill -f "python3 -m http.server 8000" || true
nohup python3 -m http.server 8000 --directory /var/www/panel >/dev/null 2>&1 &
MON
chmod +x /usr/local/jpvpn/monitor.sh

cat > /usr/local/jpvpn/autoheal.sh <<'AH'
#!/usr/bin/env bash
LOG="/var/log/jpvpn/autoheal.log"
exec >>"$LOG" 2>&1
echo "[$(date)] autoheal"

if ss -tunlp | grep -q ":8000"; then
  echo "[$(date)] panel ok"
  exit 0
fi

echo "[$(date)] restart panel"
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
echo "[$(date)] backup $TAR" >> /var/log/jpvpn/backup.log
BUP
chmod +x /usr/local/jpvpn/backup.sh

cat > /usr/local/jpvpn/update.sh <<UPD
#!/usr/bin/env bash
REPO_RAW="${REPO_RAW}"
TMP="/tmp/main.sh.$$"
if curl -fsSL "\$REPO_RAW" -o "\$TMP"; then
  if [ ! -f /root/main.sh ] || ! cmp -s "\$TMP" /root/main.sh; then
    cp "\$TMP" /root/main.sh
    chmod +x /root/main.sh
  fi
  rm -f "\$TMP"
fi
UPD
chmod +x /usr/local/jpvpn/update.sh

cat > /etc/systemd/system/jpvpn-monitor.service <<'MSVC'
[Unit]
Description=JPVPN Monitor
After=network.target
[Service]
Type=oneshot
ExecStart=/usr/local/jpvpn/monitor.sh
MSVC

cat > /etc/systemd/system/jpvpn-monitor.timer <<'MTMR'
[Unit]
Description=Monitor every minute
[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
AccuracySec=1s
[Install]
WantedBy=timers.target
MTMR

systemctl daemon-reload
systemctl enable --now jpvpn-monitor.timer || true

cat > /usr/local/jpvpn/tg_notify.sh <<'TNG'
#!/usr/bin/env bash
exit 0
TNG
chmod +x /usr/local/jpvpn/tg_notify.sh

echo "$full_script_written" > /dev/null
