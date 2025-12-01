#!/usr/bin/env bash
# JPVPN — FULL AUTO INSTALLER (FINAL FIXED)
# Includes: Flask Panel, systemd service, Nginx reverse proxy, BadVPN, ZiVPN, wstunnel, Hysteria (optional)
# Usage: chmod +x jpvpn.sh && ./jpvpn.sh
# NOTE: Run as root

set -o pipefail
# Do NOT set -euo pipefail fully — we want smart handling so installer doesn't die silently
IFS=$'\n\t'

LOG=/var/log/jpvpn/install.log
mkdir -p "$(dirname "$LOG")"
exec 3>&1 1>>"${LOG}" 2>&1

info(){ echo -e "[INFO] $*" >&3; echo -e "[INFO] $(date '+%Y-%m-%d %H:%M:%S') $*" >> "${LOG}"; }
ok(){ echo -e "[OK] $*" >&3; echo -e "[OK] $(date '+%Y-%m-%d %H:%M:%S') $*" >> "${LOG}"; }
warn(){ echo -e "[WARN] $*" >&3; echo -e "[WARN] $(date '+%Y-%m-%d %H:%M:%S') $*" >> "${LOG}"; }
fail(){ echo -e "[FAIL] $*" >&3; echo -e "[FAIL] $(date '+%Y-%m-%d %H:%M:%S') $*" >> "${LOG}"; }

if [ "$EUID" -ne 0 ]; then
  fail "This script must be run as root"
  echo "Run as root" >&3
  exit 1
fi

# ---------- PROMPT DOMAIN ----------
echo "=========================================="
echo "          PILIH DOMAIN PANEL"
echo "=========================================="
echo "1) Pakai domain sendiri"
echo "2) Subdomain otomatis: nama.vpnstore.my.id"
echo "=========================================="
read -rp "Pilihan (1/2, default 2): " DM
DM="${DM:-2}"

if [[ "$DM" == "1" ]]; then
    read -rp "Masukkan domain anda (contoh panelku.com): " DOMAIN
else
    read -rp "Masukkan nama subdomain (contoh: budi): " SUBD
    DOMAIN="${SUBD:-jpvpn}.vpnstore.my.id"
fi

info "Domain dipakai: $DOMAIN"

# ---------- CONFIG ----------
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
NGINX_SITE=/etc/nginx/sites-available/jpvpn
ACME_HOME=/root/.acme.sh

# create directories
mkdir -p "$INSTALL_DIR" "$TPL" "$STATIC/css" "$STATIC/js" /etc/jpvpn /var/log/jpvpn || true
chmod -R 755 "$INSTALL_DIR" /etc/jpvpn || true

# ---------- UPDATE & PREREQS ----------
info "Updating apt and installing packages..."
export DEBIAN_FRONTEND=noninteractive
apt update -y
apt install -y python3 python3-venv python3-pip sqlite3 nginx wget curl unzip git build-essential cmake openssl jq ufw iptables golang-go || {
  warn "apt install returned non-zero (continuing if possible)"
}
ok "Packages installed or attempted"

# ---------- ACME (optional) ----------
info "Installing acme.sh (optional for Let's Encrypt)..."
if [ ! -f "$ACME_HOME/acme.sh" ]; then
  curl https://get.acme.sh | SHELL=/bin/bash bash -s -- --install >/dev/null 2>&1 || true
fi
if [ -f "$ACME_HOME/acme.sh" ]; then
  ok "acme.sh installed"
else
  warn "acme.sh not available, will use self-signed cert"
fi

# ---------- SSL (try Let's Encrypt, fallback self-signed) ----------
USE_LETSENCRYPT=0
if [ -x "$ACME_HOME/acme.sh" ] || [ -f "$ACME_HOME/acme.sh" ]; then
  info "Trying to issue Let's Encrypt cert for $DOMAIN (standalone)..."
  "$ACME_HOME"/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  "$ACME_HOME"/acme.sh --issue -d "$DOMAIN" --standalone --home "$ACME_HOME" >/dev/null 2>&1 || true
  if [ -f "$ACME_HOME/$DOMAIN/fullchain.cer" ] || [ -f "$ACME_HOME/$DOMAIN/$DOMAIN.cer" ]; then
    mkdir -p /etc/jpvpn
    "$ACME_HOME"/acme.sh --install-cert -d "$DOMAIN" \
      --key-file /etc/jpvpn/private.key \
      --fullchain-file /etc/jpvpn/cert.crt --home "$ACME_HOME" >/dev/null 2>&1 || true
    if [ -f /etc/jpvpn/cert.crt ]; then
      USE_LETSENCRYPT=1
      ok "Let's Encrypt certificate installed for $DOMAIN"
    fi
  fi
fi

if [ "$USE_LETSENCRYPT" -eq 0 ]; then
  info "Creating self-signed certificate for $DOMAIN..."
  openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
    -subj "/CN=${DOMAIN}" -keyout /etc/jpvpn/private.key -out /etc/jpvpn/cert.crt >/dev/null 2>&1 || true
  ok "Self-signed certificate created at /etc/jpvpn"
fi

# ---------- BadVPN ----------
info "Installing BadVPN UDP gateway..."
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
systemctl enable --now jpvpn-badvpn.service || warn "Could not enable/start jpvpn-badvpn"

if systemctl is-active --quiet jpvpn-badvpn.service; then ok "BadVPN running"; else warn "BadVPN may not be active"

# ---------- ZiVPN ----------
info "Installing ZiVPN (udp-zivpn)..."
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
systemctl enable --now jpvpn-zivpn.service || warn "Could not enable/start jpvpn-zivpn"

if systemctl is-active --quiet jpvpn-zivpn.service; then ok "ZiVPN running"; else warn "ZiVPN may not be active"

# ---------- Hysteria (optional) ----------
info "Installing Hysteria (optional)..."
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
  systemctl enable --now jpvpn-hysteria.service || warn "Could not start hysteria"
  if systemctl is-active --quiet jpvpn-hysteria.service; then ok "Hysteria running (4444)"; else warn "Hysteria may not be active"
else
  warn "Hysteria binary missing; skipped"
fi

# ---------- wstunnel (WS->SSH) ----------
info "Installing wstunnel..."
if ! command -v wstunnel >/dev/null 2>&1; then
  if command -v go >/dev/null 2>&1; then
    export GOPATH=/root/go
    mkdir -p "$GOPATH/bin"
    go install github.com/erebe/wstunnel@latest || true
    ln -sf "$GOPATH/bin/wstunnel" /usr/local/bin/wstunnel || true
  else
    # Try download prebuilt (fallback) — may not exist for all arch
    warn "go not present — wstunnel will not be installed via go"
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
  systemctl enable --now jpvpn-ws-ssh.service || warn "Could not start wstunnel"
  if systemctl is-active --quiet jpvpn-ws-ssh.service; then ok "WS->SSH running (8443)"; else warn "WS->SSH not active"
else
  warn "wstunnel not found; WS->SSH disabled"
fi

# ---------- Python venv & deps ----------
info "Setting up Python virtualenv and dependencies..."
python3 -m venv "$VENV" || { fail "venv creation failed"; }
"$VENV/bin/pip" install --upgrade pip >/dev/null 2>&1 || true
"$VENV/bin/pip" install flask passlib waitress >/dev/null 2>&1 || true
ok "Python venv ready"

# ---------- Flask App ----------
info "Writing Flask app..."
cat > "$APP" <<'PY'
#!/usr/bin/env python3
from flask import Flask, render_template, request, redirect, url_for
from passlib.hash import sha256_crypt
import sqlite3
import os

BASE_DIR = "/opt/jpvpn"
DB = os.path.join(BASE_DIR, "panel.db")
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"), static_folder=os.path.join(BASE_DIR, "static"))

def get_db():
    conn = sqlite3.connect(DB, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/", methods=["GET","POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username","")
        password = request.form.get("password","")
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT password FROM admin WHERE username=?", (username,))
        row = cur.fetchone()
        if row and sha256_crypt.verify(password, row["password"]):
            return redirect(url_for("dashboard"))
        else:
            error = "Login gagal"
    return render_template("login.html", error=error)

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/health")
def health():
    return "OK"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
PY

chmod +x "$APP" || true
ok "Flask app written to $APP"

# ---------- Database and admin user ----------
info "Creating SQLite DB and admin user..."
mkdir -p "$(dirname "$DB_PATH")"
sqlite3 "$DB_PATH" <<SQL
CREATE TABLE IF NOT EXISTS admin(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT
);
SQL

# generate admin password
ADMIN_PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 12 || echo "admin123456")
HASH=$(python3 - <<PY
from passlib.hash import sha256_crypt
print(sha256_crypt.hash("${ADMIN_PASS}"))
PY
)

sqlite3 "$DB_PATH" <<SQL
DELETE FROM admin;
INSERT INTO admin(username,password) VALUES('admin','${HASH}');
SQL

echo "${ADMIN_PASS}" > "${ADMIN_PASS_FILE}"
chmod 600 "${ADMIN_PASS_FILE}" || true
ok "Admin account created. Password saved to ${ADMIN_PASS_FILE}"

# ---------- Templates ----------
info "Writing templates..."
cat > "$TPL/login.html" <<'HTML'
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>JPVPN Login</title>
  <style>
    body{font-family:sans-serif;background:#0f1720;color:#fff;}
    .box{width:320px;margin:80px auto;padding:24px;background:#111;border-radius:8px;}
    input{width:100%;padding:10px;margin:8px 0;border-radius:6px;border:1px solid #333;background:#0b1116;color:#fff;}
    button{width:100%;padding:10px;border-radius:6px;border:none;background:#16a34a;color:#fff;cursor:pointer;}
    .err{color:#ff6b6b}
  </style>
</head>
<body>
  <div class="box">
    <h2>JPVPN Panel</h2>
    {% if error %}<p class="err">{{ error }}</p>{% endif %}
    <form method="post">
      <input name="username" placeholder="Username" required value="admin">
      <input name="password" type="password" placeholder="Password" required>
      <button>Login</button>
    </form>
  </div>
</body>
</html>
HTML

cat > "$TPL/dashboard.html" <<'HTML'
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>JPVPN Dashboard</title>
  <style>
    body{font-family:sans-serif;background:#071021;color:#fff;padding:24px;}
    .card{background:#081826;padding:20px;border-radius:8px;max-width:700px;}
    h1{margin:0 0 16px;}
  </style>
</head>
<body>
  <h1>JPVPN Dashboard</h1>
  <div class="card">
    <p>Panel aktif ✔</p>
    <ul>
      <li>SSH over WebSocket (8443)</li>
      <li>BadVPN UDPGW (7300)</li>
      <li>ZiVPN (5667)</li>
    </ul>
  </div>
</body>
</html>
HTML

ok "Templates written"

# ---------- Systemd service for panel ----------
info "Creating systemd service for panel..."
cat >/etc/systemd/system/jpvpn-panel.service <<EOF
[Unit]
Description=JPVPN Web Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${VENV}/bin/python3 ${APP}
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now jpvpn-panel.service || warn "Could not enable/start jpvpn-panel.service"
if systemctl is-active --quiet jpvpn-panel.service; then ok "jpvpn-panel.service running"; else warn "jpvpn-panel.service not active; check logs"

# ---------- Nginx configuration ----------
info "Writing Nginx config..."
cat > "${NGINX_SITE}" <<EOF
server {
    listen 80;
    server_name ${DOMAIN};

    location / {
        proxy_pass http://127.0.0.1:${PANEL_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location /health {
        proxy_pass http://127.0.0.1:5000/health;
    }
}
EOF

ln -sf "${NGINX_SITE}" /etc/nginx/sites-enabled/jpvpn
nginx -t && systemctl restart nginx || warn "Nginx config test or restart failed"

# If HTTPS available (acme or self-signed), create server block for HTTPS
if [ -f /etc/jpvpn/cert.crt ] && [ -f /etc/jpvpn/private.key ]; then
  info "Adding HTTPS Nginx config (certificate found)..."
  cat > /etc/nginx/sites-available/jpvpn-ssl <<EOF
server {
    listen 443 ssl;
    server_name ${DOMAIN};

    ssl_certificate /etc/jpvpn/cert.crt;
    ssl_certificate_key /etc/jpvpn/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:${PANEL_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF
  ln -sf /etc/nginx/sites-available/jpvpn-ssl /etc/nginx/sites-enabled/jpvpn-ssl
  nginx -t && systemctl restart nginx || warn "Nginx restart failed after SSL block"
fi

# ---------- Firewall ----------
info "Applying firewall rules (ufw)..."
ufw allow OpenSSH || true
ufw allow 80/tcp || true
ufw allow 443/tcp || true
ufw allow 8443/tcp || true
ufw allow 7300/udp || true
ufw allow 5667/udp || true
ufw --force enable || true
ok "Firewall rules applied"

# ---------- Final message ----------
echo "========================================" >&3
echo "JPVPN Installation complete!" >&3
echo "Panel URL: http${(USE_LETSENCRYPT:+s)}://$DOMAIN" >&3
echo "Admin user: admin" >&3
echo "Admin password saved at: ${ADMIN_PASS_FILE}" >&3
echo "Check panel service: systemctl status jpvpn-panel" >&3
echo "View installer log: tail -n 200 ${LOG}" >&3
echo "========================================" >&3

ok "Installation finished successfully (or finished with warnings)."
# close logging redirection: send remaining logs to console as summary
echo "----- tail of installer log -----" >&3
tail -n 80 "${LOG}" >&3 || true

exit
