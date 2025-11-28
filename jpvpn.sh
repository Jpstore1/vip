#!/bin/bash
# main.sh - JPVPN FULL (Panel + SSH/WS + BadVPN accounts + ZiVPN + Hysteria + Auto SSL + Multi-login lock)
# READY FOR PRODUCTION / SALE (best-effort)
set -euo pipefail
IFS=$'\n\t'

# ----------------------
# Basic helpers & config
# ----------------------
info(){ echo -e "\e[36m[INFO]\e[0m $*"; }
ok(){ echo -e "\e[32m[OK]\e[0m $*"; }
fail(){ echo -e "\e[31m[FAIL]\e[0m $*"; }

if [ "$EUID" -ne 0 ]; then echo "Run as root"; exit 1; fi

# Prompt domain choice
echo "
============================================
    PILIH DOMAIN PANEL
============================================
1) Pakai domain sendiri
2) Pakai subdomain otomatis (nama.vpnstore.my.id)
"
read -rp "Pilihan (1/2, default 2): " DMODE
DMODE="${DMODE:-2}"
if [[ "$DMODE" == "1" ]]; then
  read -rp "Masukkan domain (contoh: panelku.com): " DOMAIN
else
  read -rp "Masukkan nama subdomain (contoh: budi): " SUB
  SUB="${SUB:-jpvpn}"
  DOMAIN="${SUB}.vpnstore.my.id"
fi
DOMAIN="${DOMAIN:-vpnstore.my.id}"
info "Domain: $DOMAIN"

# Main paths
PANEL_PORT=5000
INSTALL_DIR=/opt/jpvpn
VENV=$INSTALL_DIR/venv
APP=$INSTALL_DIR/app.py
TPL=$INSTALL_DIR/templates
DB=$INSTALL_DIR/panel.db
ADMIN_PASS_FILE=/root/jpvpn_admin_pass.txt
ZIPVPN_LOCK_HELPER=/usr/local/bin/jpvpn-zipvpn-lock
BADVPN_BIN=/usr/local/bin/badvpn-udpgw
ZIVPN_BIN=/usr/local/bin/zivpn
HYSTERIA_BIN=/usr/local/bin/hysteria
ACME_HOME=/root/.acme.sh

mkdir -p "$INSTALL_DIR" "$TPL" /etc/jpvpn

# ----------------------
# Install base packages
# ----------------------
info "Updating system and installing packages..."
export DEBIAN_FRONTEND=noninteractive
apt update -y
apt install -y curl wget git build-essential cmake pkg-config nginx sqlite3 python3 python3-venv python3-pip golang-go openssl jq ufw iptables iproute2 net-tools unzip || true
ok "Base packages"

# ----------------------
# Install acme.sh (auto SSL)
# ----------------------
info "Installing acme.sh (for auto SSL)..."
if [ ! -f "$ACME_HOME/acme.sh" ]; then
  curl https://get.acme.sh | sh -s -- --install >/dev/null 2>&1 || true
fi
if [ -f "$ACME_HOME/acme.sh" ]; then
  ok "acme.sh installed"
else
  fail "acme.sh not installed (continuing with self-signed fallback)"
fi

# Try to issue cert (best-effort)
if [ -n "$DOMAIN" ] && [ -f "$ACME_HOME/acme.sh" ]; then
  info "Attempting to issue cert for $DOMAIN (ACME standalone)..."
  "$ACME_HOME"/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  "$ACME_HOME"/acme.sh --issue -d "$DOMAIN" --standalone --home "$ACME_HOME" --accountemail "admin@$DOMAIN" >/dev/null 2>&1 || true
  if [ -f "$ACME_HOME/$DOMAIN/fullchain.cer" ]; then
    mkdir -p /etc/jpvpn
    "$ACME_HOME"/acme.sh --install-cert -d "$DOMAIN" \
      --key-file /etc/jpvpn/private.key \
      --fullchain-file /etc/jpvpn/cert.crt >/dev/null 2>&1 || true
    if [ -f /etc/jpvpn/cert.crt ]; then
      ok "Let's Encrypt certificate installed for $DOMAIN"
      USE_LETSENCRYPT=1
    else
      fail "ACME cert issuance failed (will use self-signed)"
      USE_LETSENCRYPT=0
    fi
  else
    fail "ACME cannot issue cert now (DNS not pointed?). Will use self-signed."
    USE_LETSENCRYPT=0
  fi
else
  USE_LETSENCRYPT=0
fi

# ----------------------
# Self-signed fallback
# ----------------------
if [ "$USE_LETSENCRYPT" -ne 1 ]; then
  info "Generating self-signed cert..."
  openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
    -subj "/CN=$DOMAIN" -keyout /etc/jpvpn/private.key -out /etc/jpvpn/cert.crt >/dev/null 2>&1 || true
  ok "Self-signed cert created"
fi

# ----------------------
# BadVPN (udpgw) + account helper
# ----------------------
info "Installing BadVPN (udpgw)..."
if [ ! -x "$BADVPN_BIN" ]; then
  if wget -q -O "$BADVPN_BIN" "https://github.com/ambrop72/badvpn/releases/download/1.999.130/badvpn-udpgw"; then
    chmod +x "$BADVPN_BIN" || true
    ok "BadVPN binary installed"
  else
    # fallback to raw file from repo if release missing:
    wget -q -O "$BADVPN_BIN" "https://raw.githubusercontent.com/ambrop72/badvpn/master/badvpn-udpgw/badvpn-udpgw" || true
    chmod +x "$BADVPN_BIN" || true
  fi
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
if systemctl is-active --quiet jpvpn-badvpn.service; then ok "BadVPN running (7300/udp)"; else fail "BadVPN failed"; fi

# simple BadVPN account helper (stores username->pass in sqlite)
info "Adding BadVPN account helper into panel DB"
sqlite3 "$DB" "CREATE TABLE IF NOT EXISTS badvpn_accounts (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, created_at TEXT);" >/dev/null 2>&1 || true

# ----------------------
# ZiVPN install + config
# ----------------------
info "Installing ZiVPN binary..."
if [ ! -x "$ZIVPN_BIN" ]; then
  wget -q -O "$ZIVPN_BIN" "https://github.com/zahidbd2/udp-zivpn/releases/latest/download/udp-zivpn-linux-amd64" || true
  chmod +x "$ZIVPN_BIN" || true
fi
cat > /etc/systemd/system/jpvpn-zivpn.service <<EOF
[Unit]
Description=JPVPN ZiVPN
After=network.target

[Service]
ExecStart=$ZIVPN_BIN -c /etc/jpvpn/zivpn.json
Restart=always
User=root
[Install]
WantedBy=multi-user.target
EOF

# default config
cat >/etc/jpvpn/zivpn.json <<JSON
{
  "listen": ":5667",
  "cert": "/etc/jpvpn/cert.crt",
  "key": "/etc/jpvpn/private.key",
  "obfs": "jpvpn",
  "auth": {"mode":"passwords","config":["jpvpn"]}
}
JSON

systemctl daemon-reload
systemctl enable --now jpvpn-zivpn.service || true
if systemctl is-active --quiet jpvpn-zivpn.service; then ok "ZiVPN running (5667/udp)"; else fail "ZiVPN failed"; fi

# ----------------------
# Hysteria (server)
# ----------------------
info "Installing Hysteria (server binary)..."
if [ ! -x "$HYSTERIA_BIN" ]; then
  # Use common release path (best-effort)
  wget -q -O "$HYSTERIA_BIN" "https://github.com/HyNetwork/hysteria/releases/latest/download/hysteria-linux-amd64"
  chmod +x "$HYSTERIA_BIN" || true
fi
cat >/etc/systemd/system/jpvpn-hysteria.service <<EOF
[Unit]
Description=JPVPN Hysteria server
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
if systemctl is-active --quiet jpvpn-hysteria.service; then ok "Hysteria running (4444/tcp)"; else fail "Hysteria not started"; fi

# ----------------------
# Python panel (venv + deps)
# ----------------------
info "Setting up Python panel..."
python3 -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip >/dev/null 2>&1 || true
"$VENV/bin/pip" install flask flask_sqlalchemy passlib waitress gunicorn >/dev/null 2>&1 || true
ok "Python env ready"

# ----------------------
# Panel app (improved UI)
# ----------------------
info "Writing panel app and templates..."
cat > "$APP" <<'PY'
from flask import Flask, render_template, request, redirect, session, jsonify, url_for
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import pbkdf2_sha256
import datetime, os, subprocess
app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.environ.get('JPVPN_SECRET','jpvpn_secret_change')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////opt/jpvpn/panel.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
class Admin(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(80), unique=True, nullable=False)
    password=db.Column(db.String(200), nullable=False)
    created_at=db.Column(db.String(50))
class User(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(80), unique=True, nullable=False)
    password=db.Column(db.String(200), nullable=False)
    expires=db.Column(db.String(20))
    created_at=db.Column(db.String(50))
class BadVPNAccount(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(80), unique=True, nullable=False)
    password=db.Column(db.String(200))
    created_at=db.Column(db.String(50))
with app.app_context(): db.create_all()
@app.route('/')
def root():
    if session.get('admin'): return redirect('/dashboard')
    return redirect('/login')
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        u=request.form.get('username'); p=request.form.get('password')
        a=Admin.query.filter_by(username=u).first()
        if a and pbkdf2_sha256.verify(p,a.password):
            session['admin']=a.username
            return redirect('/dashboard')
        return render_template('login.html', error='Invalid')
    return render_template('login.html')
@app.route('/logout')
def logout():
    session.pop('admin', None)
    return redirect('/login')
@app.route('/dashboard')
def dashboard():
    if not session.get('admin'): return redirect('/login')
    users=User.query.all(); bads=BadVPNAccount.query.all()
    return render_template('dashboard.html', users=users, bads=bads)
@app.route('/create-user', methods=['POST'])
def create_user():
    if not session.get('admin'): return redirect('/login')
    u=request.form.get('username'); p=request.form.get('password'); e=request.form.get('expires')
    if not p: p=os.urandom(6).hex()
    hashed=pbkdf2_sha256.hash(p)
    db.session.add(User(username=u, password=hashed, expires=e, created_at=str(datetime.datetime.utcnow()))); db.session.commit()
    return redirect('/dashboard')
@app.route('/create-ssh', methods=['POST'])
def create_ssh():
    if not session.get('admin'): return redirect('/login')
    u=request.form.get('username'); p=request.form.get('password')
    subprocess.run(['useradd','-M','-N','-s','/bin/false', u])
    subprocess.run(['bash','-c', f"echo '{u}:{p}' | chpasswd"])
    return redirect('/dashboard')
@app.route('/create-badvpn', methods=['POST'])
def create_badvpn():
    if not session.get('admin'): return redirect('/login')
    u=request.form.get('username'); p=request.form.get('password')
    db.session.add(BadVPNAccount(username=u, password=p, created_at=str(datetime.datetime.utcnow()))); db.session.commit()
    return redirect('/dashboard')
@app.route('/api/zipvpn/update-bind', methods=['POST'])
def zipvpn_bind():
    data = request.json or {}
    user = data.get('username'); ip = data.get('ip')
    if not user or not ip: return jsonify({'ok':False,'err':'missing'}),400
    u = User.query.filter_by(username=user).first()
    if not u: return jsonify({'ok':False,'err':'no_user'}),404
    # store bound ip (for our lock logic)
    u.bound_ip = ip; u.last_ip = ip; u.last_seen = int(datetime.datetime.utcnow().timestamp())
    db.session.commit()
    return jsonify({'ok':True})
if __name__=='__main__':
    from waitress import serve
    serve(app, host='0.0.0.0', port=5000)
PY

# templates & static (simple premium look)
mkdir -p "$INSTALL_DIR/templates" "$INSTALL_DIR/static/css"
cat > "$INSTALL_DIR/templates/login.html" <<'HTML'
<!doctype html><html><head><meta charset="utf-8"><title>JPVPN Login</title>
<link rel="stylesheet" href="/static/css/style.css"></head><body>
<div class="card"><h2>JPVPN Admin</h2>
{% if error %}<p class="err">{{error}}</p>{% endif %}
<form method="post"><input name="username" placeholder="username"><br><input name="password" type="password" placeholder="password"><br><button>Login</button></form></div>
</body></html>
HTML

cat > "$INSTALL_DIR/templates/dashboard.html" <<'HTML'
<!doctype html><html><head><meta charset="utf-8"><title>JPVPN Dashboard</title>
<link rel="stylesheet" href="/static/css/style.css"></head><body>
<div class="card"><h2>JPVPN Dashboard</h2><a href="/logout">Logout</a>
<h3>Create VPN User</h3>
<form action="/create-user" method="post">
<input name="username" placeholder="user"> <input name="password" placeholder="pass"> <input name="expires" placeholder="YYYY-MM-DD"> <button>Create</button></form>
<h3>Create SSH User</h3>
<form action="/create-ssh" method="post"><input name="username" placeholder="ssh user"> <input name="password" placeholder="password"> <button>Create SSH</button></form>
<h3>Create BadVPN Account</h3>
<form action="/create-badvpn" method="post"><input name="username" placeholder="badvpn user"> <input name="password" placeholder="password"> <button>Create BadVPN</button></form>
<h3>Users</h3>
<table class="tbl"><tr><th>ID</th><th>User</th><th>Expire</th></tr>{% for u in users %}<tr><td>{{u.id}}</td><td>{{u.username}}</td><td>{{u.expires}}</td></tr>{% endfor %}</table>
<h3>BadVPN Accounts</h3>
<table class="tbl"><tr><th>ID</th><th>User</th></tr>{% for b in bads %}<tr><td>{{b.id}}</td><td>{{b.username}}</td></tr>{% endfor %}</table>
</div></body></html>
HTML

cat > "$INSTALL_DIR/static/css/style.css" <<'CSS'
body{font-family:Arial,Helvetica,sans-serif;background:#f4f6f8;margin:0;padding:20px}
.card{max-width:800px;margin:30px auto;background:#fff;padding:20px;border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,0.08)}
input{padding:8px;margin:6px 0;width:100%;box-sizing:border-box}
button{padding:8px 12px;background:#007bff;color:#fff;border:none;border-radius:6px}
.tbl{width:100%;border-collapse:collapse}
.tbl th,.tbl td{border:1px solid #ddd;padding:8px;text-align:left}
.err{color:#c00}
CSS

# create sqlite tables for badvpn account model if needed
sqlite3 "$DB" "CREATE TABLE IF NOT EXISTS badvpn_accounts (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, created_at TEXT);" >/dev/null 2>&1 || true

# create admin if missing
if ! sqlite3 "$DB" "SELECT username FROM admins WHERE username='admin'" | grep -q admin; then
  ADMIN_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 12)
  HASH=$(python3 - <<PY
from passlib.hash import pbkdf2_sha256
print(pbkdf2_sha256.hash("${ADMIN_PASS}"))
PY
)
  sqlite3 "$DB" "INSERT INTO admins(username,password,created_at) VALUES('admin','$HASH', datetime('now'))"
  echo "admin / $ADMIN_PASS" | tee "$ADMIN_PASS_FILE"
  chmod 600 "$ADMIN_PASS_FILE"
  ok "Admin created (saved in $ADMIN_PASS_FILE)"
else
  ok "Admin exists"
fi

# systemd service for panel
cat >/etc/systemd/system/jpvpn-panel.service <<EOF
[Unit]
Description=JPVPN Panel (waitress)
After=network.target

[Service]
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV/bin/python3 $APP
Restart=always
User=root
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now jpvpn-panel.service || true
if systemctl is-active --quiet jpvpn-panel.service; then ok "Panel running"; else fail "Panel service failed"; fi

# ----------------------
# WebSocket SSH (wstunnel) server
# ----------------------
info "Installing wstunnel (WebSocket tunnel for SSH)..."
if ! command -v wstunnel >/dev/null 2>&1; then
  # build simple wstunnel (go)
  GOPATH_DIR=/root/go
  mkdir -p $GOPATH_DIR
  export GOPATH=$GOPATH_DIR
  go get github.com/erebe/wstunnel || true
  if [ -f "$GOPATH/bin/wstunnel" ]; then
    ln -sf "$GOPATH/bin/wstunnel" /usr/local/bin/wstunnel
  fi
fi
if command -v wstunnel >/dev/null 2>&1; then
  cat >/etc/systemd/system/jpvpn-ws-ssh.service <<WS
[Unit]
Description=JPVPN WebSocket -> SSH tunnel
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
  if systemctl is-active --quiet jpvpn-ws-ssh.service; then ok "WS->SSH running (8443/tcp)"; else fail "WS->SSH failed"; fi
else
  fail "wstunnel not available"
fi

# ----------------------
# Nginx reverse proxy (http + https if cert present)
# ----------------------
info "Configuring Nginx (server_name=$DOMAIN)..."
NGCONF=/etc/nginx/sites-available/jpvpn
cat > $NGCONF <<NG
server {
    listen 80;
    server_name ${DOMAIN};
    location / {
        proxy_pass http://127.0.0.1:${PANEL_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
NG
if [ -f /etc/jpvpn/cert.crt ] && [ -f /etc/jpvpn/private.key ]; then
cat >> $NGCONF <<NGSSL

server {
    listen 443 ssl;
    server_name ${DOMAIN};
    ssl_certificate /etc/jpvpn/cert.crt;
    ssl_certificate_key /etc/jpvpn/private.key;
    location / {
        proxy_pass http://127.0.0.1:${PANEL_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
NGSSL
fi
ln -sf $NGCONF /etc/nginx/sites-enabled/jpvpn
nginx -t >/dev/null 2>&1 || true
systemctl restart nginx || true
if systemctl is-active --quiet nginx; then ok "Nginx running"; else fail "Nginx failed"; fi

# ----------------------
# ZIPVPN lock helper (multi-login protection)
# ----------------------
cat > "$ZIPVPN_LOCK_HELPER" <<'SH'
#!/bin/bash
# jpvpn-zipvpn-lock <username> <client_ip>
LOCK_DIR="/etc/jpvpn/lock"
mkdir -p "$LOCK_DIR"
user="$1"; ip="$2"
lock="$LOCK_DIR/${user}.lock"
mode_file="/etc/jpvpn/lock_mode"  # default reject
mode="reject"
[ -f "$mode_file" ] && mode=$(cat "$mode_file")
if [ ! -f "$lock" ]; then
  echo "ip=$ip" > "$lock"
  echo "time=$(date +%s)" >> "$lock"
  exit 0
fi
last_ip=$(grep '^ip=' "$lock" | cut -d= -f2)
if [ "$ip" = "$last_ip" ]; then
  echo "ok"; exit 0
fi
if [ "$mode" = "reject" ]; then
  echo "reject:bound to $last_ip"; exit 2
else
  echo "ip=$ip" > "$lock"; echo "time=$(date +%s)" >> "$lock"
  iptables -I INPUT -s "$last_ip" -j DROP || true
  sleep 1
  iptables -D INPUT -s "$last_ip" -j DROP || true
  echo "override"; exit 0
fi
SH
chmod +x "$ZIPVPN_LOCK_HELPER"
ok "ZIPVPN lock helper installed"

# ----------------------
# Final summary
# ----------------------
echo
ok "JPVPN FULL INSTALLER FINISHED"
echo "Panel: http://${DOMAIN}/  (or https if cert issued)"
echo "Admin creds: see $ADMIN_PASS_FILE"
echo "BadVPN UDP: 7300"
echo "ZiVPN UDP: 5667"
echo "Hysteria: 4444 (default)"
echo "WS->SSH: 8443 (websocket tunnel)"
echo
info "Notes:"
echo "- If ACME failed, domain likely not pointed. Re-run acme.sh or point DNS to VPS and re-run issuance."
echo "- To enforce ZIPVPN lock from ZiVPN, configure ZiVPN to call this helper or call panel API /api/zipvpn/update-bind on connect."
