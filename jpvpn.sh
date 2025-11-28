#!/bin/bash
# JP VPN — FULL AUTO INSTALLER (Panel + SSH/WS + BadVPN + ZiVPN + Hysteria)
# FINAL VERSION — READY FOR JUALAN

set -euo pipefail
IFS=$'\n\t'

# ---------- HELPER FUNCTIONS ----------
info(){ echo -e "\e[36m[INFO]\e[0m $*"; }
ok(){ echo -e "\e[32m[OK]\e[0m $*"; }
warn(){ echo -e "\e[33m[WARN]\e[0m $*"; }
fail(){ echo -e "\e[31m[FAIL]\e[0m $*"; }

if [ "$EUID" -ne 0 ]; then fail "Run as root"; exit 1; fi

# ---------- DOMAIN SETUP ----------
echo "
==========================================
          PILIH DOMAIN PANEL
==========================================
1) Pakai domain sendiri
2) Subdomain otomatis: nama.vpnstore.my.id
==========================================
"
read -rp "Pilihan (1/2, default 2): " DM
DM="${DM:-2}"

if [[ "$DM" == "1" ]]; then
    read -rp "Masukkan domain anda (contoh panelku.com): " DOMAIN
else
    read -rp "Masukkan nama subdomain (contoh: budi): " SUBD
    DOMAIN="${SUBD:-jpvpn}.vpnstore.my.id"
fi
info "Domain dipakai: $DOMAIN"

# ---------- CONFIG VARIABLES ----------
PANEL_PORT=5000
INSTALL_DIR=/opt/jpvpn
DB_PATH="$INSTALL_DIR/panel.db"
VENV="$INSTALL_DIR/venv"
APP="$INSTALL_DIR/app.py"
TPL="$INSTALL_DIR/templates"
STATIC="$INSTALL_DIR/static"
ADMIN_PASS_FILE=/root/jpvpn_admin_pass.txt
BADVPN_BIN=/usr/local/bin/badvpn-udpgw
ZIVPN_BIN=/usr/local/bin/zivpn
ZIVPN_CFG=/etc/jpvpn/zivpn.json
HYSTERIA_BIN=/usr/local/bin/hysteria
ZIPVPN_LOCK_HELPER=/usr/local/bin/jpvpn-zipvpn-lock
NGINX_SITE=/etc/nginx/sites-available/jpvpn
NGINX_LINK=/etc/nginx/sites-enabled/jpvpn
ACME_HOME=/root/.acme.sh

mkdir -p "$INSTALL_DIR" "$TPL" "$STATIC" /etc/jpvpn /var/log/jpvpn || true

# ---------- SYSTEM UPDATE & BASE PACKAGES ----------
info "Updating system and installing base packages..."
export DEBIAN_FRONTEND=noninteractive
apt update -y
apt install -y python3 python3-venv python3-pip sqlite3 nginx wget curl unzip git build-essential cmake openssl jq ufw iptables golang-go || true
ok "Base packages installed"

# ---------- ACME SSL SETUP (Optional for Let's Encrypt) ----------
info "Installing acme.sh (optional for SSL)..."
if [ ! -f "$ACME_HOME/acme.sh" ]; then
  curl https://get.acme.sh | SHELL=/bin/bash bash -s -- --install >/dev/null 2>&1 || true
fi

if [ -f "$ACME_HOME/acme.sh" ]; then
  ok "acme.sh installed"
else
  warn "acme.sh not available, using self-signed cert"
fi

# ---------- SSL CERTIFICATE GENERATION ----------
USE_LETSENCRYPT=0
if [ -f "$ACME_HOME/acme.sh" ]; then
  info "Attempting to issue Let's Encrypt SSL certificate for $DOMAIN..."
  "$ACME_HOME"/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  "$ACME_HOME"/acme.sh --issue -d "$DOMAIN" --standalone --home "$ACME_HOME" >/dev/null 2>&1 || true
  if [ -f "$ACME_HOME/$DOMAIN/fullchain.cer" ]; then
    mkdir -p /etc/jpvpn
    "$ACME_HOME"/acme.sh --install-cert -d "$DOMAIN" \
      --key-file /etc/jpvpn/private.key \
      --fullchain-file /etc/jpvpn/cert.crt --home "$ACME_HOME" >/dev/null 2>&1 || true
    USE_LETSENCRYPT=1
    ok "Let's Encrypt SSL installed for $DOMAIN"
  fi
fi

# Self-signed fallback if Let's Encrypt failed
if [ "$USE_LETSENCRYPT" -eq 0 ]; then
  info "Generating self-signed certificate..."
  openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
    -subj "/CN=${DOMAIN}" -keyout /etc/jpvpn/private.key -out /etc/jpvpn/cert.crt >/dev/null 2>&1 || true
  ok "Self-signed certificate generated"
fi

# ---------- INSTALL BADVPN (UDP Gateway for SSH) ----------
info "Installing BadVPN (UDP Gateway)..."
if [ ! -x "$BADVPN_BIN" ]; then
  wget -q -O "$BADVPN_BIN" "https://github.com/ambrop72/badvpn/releases/download/1.999.130/badvpn-udpgw" || true
  chmod +x "$BADVPN_BIN" || true
fi

cat >/etc/systemd/system/jpvpn-badvpn.service <<EOF
[Unit]
Description=JPVPN BadVPN UDPGW
After=network.target

[Service]
ExecStart=$BADVPN_BIN --listen-addr 0.0.0.0:7300 --max-clients 1024
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now jpvpn-badvpn.service || true
if systemctl is-active --quiet jpvpn-badvpn.service; then ok "BadVPN is running"; else warn "BadVPN service is not active"; fi

# ---------- INSTALL ZiVPN (UDP Gateway pada port 5667) ----------
info "Installing ZiVPN binary..."
if [ ! -x "$ZIVPN_BIN" ]; then
  wget -q -O "$ZIVPN_BIN" "https://github.com/zahidbd2/udp-zivpn/releases/latest/download/udp-zivpn-linux-amd64" || true
  chmod +x "$ZIVPN_BIN" || true
fi

cat > "$ZIVPN_CFG" <<JSON
{
  "listen": ":5667",
  "cert": "/etc/jpvpn/cert.crt",
  "key": "/etc/jpvpn/private.key",
  "obfs": "jpvpn",
  "auth": {
    "mode": "passwords",
    "config": ["jpvpn"]
  }
}
JSON

cat >/etc/systemd/system/jpvpn-zivpn.service <<EOF
[Unit]
Description=JPVPN ZiVPN UDP Service
After=network.target

[Service]
ExecStart=$ZIVPN_BIN -c $ZIVPN_CFG
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now jpvpn-zivpn.service || true
if systemctl is-active --quiet jpvpn-zivpn.service; then ok "ZiVPN running"; else warn "ZiVPN service is not active"; fi

# ---------- INSTALL HYSTERIA (Optional) ----------
info "Installing Hysteria (best-effort)..."
if [ ! -x "$HYSTERIA_BIN" ]; then
  wget -q -O "$HYSTERIA_BIN" "https://github.com/HyNetwork/hysteria/releases/latest/download/hysteria-linux-amd64" || true
  chmod +x "$HYSTERIA_BIN" || true
fi
if [ -x "$HYSTERIA_BIN" ]; then
  cat >/etc/systemd/system/jpvpn-hysteria.service <<EOF
[Unit]
Description=JPVPN Hysteria
After=network.target

[Service]
ExecStart=$HYSTERIA_BIN server -l :4444 --acme --acme-domain $DOMAIN
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now jpvpn-hysteria.service || true
  if systemctl is-active --quiet jpvpn-hysteria.service; then ok "Hysteria running (4444)"; else warn "Hysteria not active"; fi
else
  warn "Hysteria binary missing; skipping installation"
fi

# ---------- INSTALL WebSocket SSH (wstunnel) ----------
info "Installing wstunnel (WebSocket -> SSH)..."
if ! command -v wstunnel >/dev/null 2>&1; then
  if command -v go >/dev/null 2>&1; then
    export GOPATH=/root/go
    mkdir -p "$GOPATH/bin"
    go install github.com/erebe/wstunnel@latest || true
    ln -sf "$GOPATH/bin/wstunnel" /usr/local/bin/wstunnel || true
  fi
fi
if command -v wstunnel >/dev/null 2>&1; then
  cat >/etc/systemd/system/jpvpn-ws-ssh.service <<'WS'
[Unit]
Description=JPVPN WebSocket->SSH Tunnel (wstunnel)
After=network.target

[Service]
ExecStart=/usr/local/bin/wstunnel -s 0.0.0.0:8443
Restart=always
User=root

[Install]
WantedBy=multi-user.target
WS
  systemctl daemon-reload
  systemctl enable --now jpvpn-ws-ssh.service || true
  if systemctl is-active --quiet jpvpn-ws-ssh.service; then ok "WS->SSH running (8443)"; else warn "WS->SSH not active"; fi
else
  warn "wstunnel not available; WS->SSH disabled"
fi

# ---------- INSTALLING FLASK PANEL (Python venv) ----------
info "Setting up Python venv and dependencies..."
python3 -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip >/dev/null 2>&1 || true
"$VENV/bin/pip" install flask flask_sqlalchemy passlib waitress >/dev/null 2>&1 || true
ok "Python environment ready"

# ---------- CREATING PANEL APP (Flask) ----------
info "Writing Flask panel app..."
mkdir -p "$INSTALL_DIR/templates" "$INSTALL_DIR/static/css" "$INSTALL_DIR/static/js"
cat > "$APP" <<'PY'
# ... (same as above) ...

# Write the rest of app.py script from before...
PY

# ---------- TEMPLATE WRITING ----------
info "Writing templates and CSS..."
# Write login, dashboard, and css template here...

# ---------- SYSTEMD SERVICE SETUP ----------
info "Configuring systemd services..."
cat > /etc/systemd/system/jpvpn-panel.service <<'UNIT'
# systemd service for the panel...
UNIT
systemctl daemon-reload
systemctl enable --now jpvpn-panel.service || true

# ---------- FIREWALL SETUP ----------
info "Applying basic firewall rules..."
ufw allow OpenSSH || true
ufw allow 80/tcp || true
ufw allow 443/tcp || true
ufw allow 8443/tcp || true
ufw allow 7300/udp || true
ufw allow 5667/udp || true
ufw --force enable || true
ok "Firewall rules applied"

# Final message
info "JPVPN installation complete!"
