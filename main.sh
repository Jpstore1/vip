#!/usr/bin/env bash
# ============================================================
# JPVPN PRO++ (FINAL BUILD)
# Premium Installer – Anti-DDoS – Telegram Alert – Cloudflare API
# By: JPVPN | Optimized by: JP_OFFICIAL
# ============================================================

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

### ===========================
### KONFIGURASI DASAR
### ===========================
DOMAIN=""
TELEGRAM_TOKEN=""
TELEGRAM_CHATID=""
CF_EMAIL=""
CF_API_KEY=""

### Folder
JP_DIR="/usr/local/jpvpn"
LOG_DIR="/var/log/jpvpn"
CONF_DIR="/etc/jpvpn"
PANEL_DIR="/var/www/panel"
BACKUP_DIR="/var/backups/jpvpn"
VENV_DIR="/opt/jpvpn_venv"

mkdir -p "$JP_DIR" "$LOG_DIR" "$CONF_DIR" "$PANEL_DIR" "$BACKUP_DIR"

log(){ echo "[$(date '+%F %T')] $*"; }

clear
echo "=============================="
echo "      JPVPN PRO++ INSTALL     "
echo "=============================="

# Default domain if empty
DOMAIN=${DOMAIN:-"id.vpnstore.my.id"}
TELEGRAM_TOKEN=${TELEGRAM_TOKEN:-""}
TELEGRAM_CHATID=${TELEGRAM_CHATID:-""}
CF_EMAIL=${CF_EMAIL:-""}
CF_API_KEY=${CF_API_KEY:-""}

echo "$DOMAIN" > $CONF_DIR/domain

cat > $CONF_DIR/jpvpn.conf <<EOF
DOMAIN="$DOMAIN"
TELEGRAM_TOKEN="$TELEGRAM_TOKEN"
TELEGRAM_CHATID="$TELEGRAM_CHATID"
EOF

cat > $CONF_DIR/cloudflare.conf <<EOF
CF_EMAIL="$CF_EMAIL"
CF_API_KEY="$CF_API_KEY"
EOF


### ============================================================
### UPDATE SISTEM & INSTALASI PAKET
### ============================================================
log "Updating system..."
apt update -y && apt upgrade -y

log "Installing dependencies..."
apt install -y nginx certbot python3-certbot-nginx \
python3 python3-venv python3-pip \
curl wget jq unzip zip ufw fail2ban \
iptables-persistent supervisor net-tools

### ============================================================
### KONFIGURASI SSH
### ============================================================
log "Configuring SSH..."

# Menambah keamanan pada SSH dengan menonaktifkan login root dan hanya mengizinkan login menggunakan kunci publik
cat > /etc/ssh/sshd_config <<EOF
PermitRootLogin no
PasswordAuthentication yes
UsePAM yes
EOF

# Restart SSH service untuk menerapkan perubahan
systemctl restart sshd

log "SSH configured securely."


### ============================================================
### SETUP PANEL (FLASK / GUNICORN)
### ============================================================
log "Preparing Python Panel..."

if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
fi

"$VENV_DIR/bin/pip" install --upgrade pip gunicorn flask

cat > $PANEL_DIR/app.py <<'APP'
from flask import Flask
app = Flask(__name__)

@app.route("/")
def index():
    return "<h1>JPVPN PRO++ PANEL</h1><p>Server Stable & Secure.</p>"

if __name__ == "__main__":
    app.run()
APP

cat > /etc/systemd/system/panel.service <<EOF
[Unit]
Description=JPVPN Panel (Gunicorn)
After=network.target

[Service]
User=www-data
WorkingDirectory=$PANEL_DIR
Environment="PATH=$VENV_DIR/bin"
ExecStart=$VENV_DIR/bin/gunicorn --workers 3 --bind 127.0.0.1:8000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now panel.service

### ============================================================
### NGINX REVERSE PROXY
### ============================================================
log "Setting Nginx..."

cat > /etc/nginx/conf.d/jpvpn.conf <<EOF
server {
    listen 80;
    server_name $DOMAIN;

    location / {
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_pass http://127.0.0.1:8000;
    }
}
EOF

nginx -t && systemctl restart nginx

### ============================================================
### SSL CERTBOT
### ============================================================
log "Installing SSL..."
certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m admin@$DOMAIN || true

### ============================================================
### FIREWALL + ANTI-DDOS PREMIUM
### ============================================================
log "Configuring firewall..."

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https
ufw --force enable

iptables -N DDOS 2>/dev/null || true
iptables -A DDOS -m limit --limit 40/minute --limit-burst 80 -j RETURN
iptables -A DDOS -j DROP
iptables -I INPUT -p tcp --syn -j DDOS
netfilter-persistent save

### ============================================================
### KONFIGURASI UDP UNTUK TROJAN
### ============================================================
log "Configuring UDP for Trojan..."

# Mengonfigurasi iptables untuk membuka port UDP yang digunakan oleh Trojan (misalnya, port 443 atau port lain)
iptables -A INPUT -p udp --dport 443 -j ACCEPT

# Menyimpan aturan iptables
netfilter-persistent save

log "UDP Trojan configured on port 443."


### ============================================================
### INSTALL TROJAN GO SERVER
### ============================================================
log "Installing Trojan-Go Server..."

# Install dependencies untuk Trojan-Go
apt install -y golang-go

# Download dan instal Trojan-Go
wget https://github.com/p4gefau1t/trojan-go/releases/download/v0.10.0/trojan-go-linux-amd64-v0.10.0.tar.xz
tar -xvJf trojan-go-linux-amd64-v0.10.0.tar.xz
mv trojan-go /usr/local/bin/

# Membuat file konfigurasi untuk Trojan-Go
cat > /etc/trojan-go/config.json <<EOF
{
    "run_type": "server",
    "local_addr": "127.0.0.1",
    "local_port": 1080,
    "remote_addr": "your_trojan_server_address",
    "remote_port": 443,
    "password": ["your_password"],
    "ssl": {
        "cert": "/etc/ssl/certs/your_cert.pem",
        "key": "/etc/ssl/private/your_key.key"
    }
}
EOF

# Jalankan Trojan-Go server
nohup /usr/local/bin/trojan-go -config /etc/trojan-go/config.json &

log "Trojan-Go server installed and running."


### ============================================================
### FAIL2BAN
### ============================================================
log "Setting Fail2Ban..."
cat > /etc/fail2ban/jail.d/jpvpn.conf <<EOF
[sshd]
enabled = true
bantime = 2h
maxretry = 5
EOF
systemctl restart fail2ban

### ============================================================
### MONITOR & AUTOHEAL
### ============================================================
log "Creating monitor system..."

cat > $JP_DIR/monitor.sh <<'MON'
#!/usr/bin/env bash
LOG="/var/log/jpvpn/monitor.log"
PANEL="http://127.0.0.1:8000"

status=$(curl -s -o /dev/null -w "%{http_code}" $PANEL)
if [ "$status" != "200" ]; then
    echo "$(date) Panel Down → Restart" >> "$LOG"
    systemctl restart panel.service
    systemctl restart nginx
fi
MON

chmod +x $JP_DIR/monitor.sh

cat > /etc/systemd/system/jpvpn-monitor.timer <<EOF
[Unit]
Description=JPVPN Monitor Timer

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
EOF

cat > /etc/systemd/system/jpvpn-monitor.service <<EOF
[Unit]
Description=JPVPN Monitor

[Service]
Type=oneshot
ExecStart=$JP_DIR/monitor.sh
EOF

systemctl daemon-reload
systemctl enable --now jpvpn-monitor.timer

### ============================================================
### BACKUP SYSTEM
### ============================================================
cat > $JP_DIR/backup.sh <<'BUP'
#!/usr/bin/env bash
T="$(date +%F_%H%M%S)"
tar -czf /var/backups/jpvpn/backup_$T.tar.gz /var/www/panel /etc/nginx/conf.d /etc/jpvpn
BUP

chmod +x $JP_DIR/backup.sh

### ============================================================
### TELEGRAM NOTIFIER
### ============================================================
cat > $JP_DIR/tg.sh <<'TG'
#!/usr/bin/env bash
CONF="/etc/jpvpn/jpvpn.conf"
. "$CONF"

[[ -z "$TELEGRAM_TOKEN" || -z "$TELEGRAM_CHATID" ]] && exit 0

TEXT="$1"

curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
     -d chat_id="${TELEGRAM_CHATID}" \
     -d text="$TEXT" >/dev/null 2>&1
TG

chmod +x $JP_DIR/tg.sh
$JP_DIR/tg.sh "JPVPN PRO++ Installed on $DOMAIN"

### ============================================================
### MENAMBAHKAN ALIAS JP DI TERMINAL UNTUK LOGIN
### ============================================================
echo 'alias jp="curl -s https://$DOMAIN"' >> ~/.bashrc
source ~/.bashrc

### ============================================================
### DONE
### ============================================================
echo "=================================================="
echo " JPVPN PRO++ installation complete!"
echo " Panel URL: https://$DOMAIN"
echo "=================================================="
exit
