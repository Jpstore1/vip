#!/bin/bash
# jpvpn.sh — JP VPN FULL INSTALLER (FINAL READY FOR SALE)
# Installs: Panel (Flask), BadVPN, ZiVPN, WS-SSH, ZIPVPN lock, systemd services, nginx reverse proxy, ACME try.
set -euo pipefail
IFS=$'\n\t'

info(){ echo -e "\e[36m[INFO]\e[0m $*"; }
ok(){ echo -e "\e[32m[OK]\e[0m $*"; }
warn(){ echo -e "\e[33m[WARN]\e[0m $*"; }
fail(){ echo -e "\e[31m[FAIL]\e[0m $*"; }

if [ "$EUID" -ne 0 ]; then fail "Run as root"; exit 1; fi

# ---------- Domain prompt ----------
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
  SUBD="${SUBD:-jpvpn}"
  DOMAIN="${SUBD}.vpnstore.my.id"
fi
DOMAIN="${DOMAIN:-vpnstore.my.id}"
info "Domain dipakai: $DOMAIN"

# ---------- Config ----------
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
ZIPVPN_LOCK_HELPER=/usr/local/bin/jpvpn-zipvpn-lock
NGINX_SITE=/etc/nginx/sites-available/jpvpn
NGINX_LINK=/etc/nginx/sites-enabled/jpvpn
ACME_HOME=/root/.acme.sh

mkdir -p "$INSTALL_DIR" "$TPL" "$STATIC" /etc/jpvpn /var/log/jpvpn || true

# ---------- Base packages ----------
info "Updating apt and installing base packages..."
export DEBIAN_FRONTEND=noninteractive
apt update -y
apt install -y python3 python3-venv python3-pip sqlite3 nginx wget curl unzip git build-essential cmake openssl jq ufw iptables golang-go || true
ok "Base packages done"

# ---------- ACME (try) ----------
info "Installing acme.sh (optional for auto SSL)..."
if [ ! -f "$ACME_HOME/acme.sh" ]; then
  curl https://get.acme.sh | SHELL=/bin/bash bash -s -- --install >/dev/null 2>&1 || true
fi
if [ -f "$ACME_HOME/acme.sh" ]; then
  ok "acme.sh present"
else
  warn "acme.sh not available, will use self-signed cert fallback"
fi

# ---------- Try issue cert (best effort) ----------
USE_LETSENCRYPT=0
if [ -f "$ACME_HOME/acme.sh" ]; then
  info "Attempting to issue Let's Encrypt cert for $DOMAIN (standalone)..."
  "$ACME_HOME"/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  "$ACME_HOME"/acme.sh --issue -d "$DOMAIN" --standalone --home "$ACME_HOME" --accountemail "admin@$DOMAIN" >/dev/null 2>&1 || true
  if [ -f "$ACME_HOME/$DOMAIN/fullchain.cer" ]; then
    mkdir -p /etc/jpvpn
    "$ACME_HOME"/acme.sh --install-cert -d "$DOMAIN" \
      --key-file /etc/jpvpn/private.key \
      --fullchain-file /etc/jpvpn/cert.crt --home "$ACME_HOME" >/dev/null 2>&1 || true
    if [ -f /etc/jpvpn/cert.crt ]; then
      USE_LETSENCRYPT=1
      ok "Let's Encrypt cert installed for $DOMAIN"
    fi
  fi
fi

# ---------- Self-signed fallback ----------
if [ "$USE_LETSENCRYPT" -eq 0 ]; then
  info "Generating self-signed cert for $DOMAIN..."
  openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
    -subj "/CN=${DOMAIN}" -keyout /etc/jpvpn/private.key -out /etc/jpvpn/cert.crt >/dev/null 2>&1 || true
  ok "Self-signed cert created at /etc/jpvpn/cert.crt"
fi

# ---------- BadVPN ----------
info "Installing BadVPN udpgw..."
if [ ! -x "$BADVPN_BIN" ]; then
  if wget -q -O "$BADVPN_BIN" "https://github.com/ambrop72/badvpn/releases/download/1.999.130/badvpn-udpgw"; then
    chmod +x "$BADVPN_BIN" || true
    ok "BadVPN downloaded"
  else
    # fallback raw
    wget -q -O "$BADVPN_BIN" "https://raw.githubusercontent.com/ambrop72/badvpn/master/badvpn-udpgw/badvpn-udpgw" || true
    chmod +x "$BADVPN_BIN" || true
    warn "BadVPN download fallback used"
  fi
else
  ok "BadVPN already present"
fi

cat > /etc/systemd/system/jpvpn-badvpn.service <<EOF
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
if systemctl is-active --quiet jpvpn-badvpn.service; then ok "BadVPN running (7300/udp)"; else warn "BadVPN service not active"; fi

# ---------- ZiVPN ----------
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

cat > /etc/systemd/system/jpvpn-zivpn.service <<EOF
[Unit]
Description=JPVPN ZiVPN
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
if systemctl is-active --quiet jpvpn-zivpn.service; then ok "ZiVPN running (5667/udp)"; else warn "ZiVPN service not active"; fi

# ---------- Hysteria (optional) ----------
HYSTERIA_BIN=/usr/local/bin/hysteria
info "Installing Hysteria (best-effort)..."
if [ ! -x "$HYSTERIA_BIN" ]; then
  wget -q -O "$HYSTERIA_BIN" "https://github.com/HyNetwork/hysteria/releases/latest/download/hysteria-linux-amd64" && chmod +x "$HYSTERIA_BIN" || true
fi
if [ -x "$HYSTERIA_BIN" ]; then
  cat > /etc/systemd/system/jpvpn-hysteria.service <<EOF
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
  if systemctl is-active --quiet jpvpn-hysteria.service; then ok "Hysteria running (4444)"; else warn "Hysteria service not active"; fi
else
  warn "Hysteria not installed; skipping"
fi

# ---------- WebSocket SSH (wstunnel) ----------
info "Installing wstunnel (WebSocket -> SSH) (best-effort via go install)..."
if ! command -v wstunnel >/dev/null 2>&1; then
  # try Go install (requires go in system)
  export GOPATH=/root/go
  mkdir -p "$GOPATH/bin"
  if go install github.com/erebe/wstunnel@latest 2>/dev/null; then
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

# ---------- Python panel (venv) ----------
info "Setting up Python venv and dependencies..."
python3 -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip >/dev/null 2>&1 || true
"$VENV/bin/pip" install flask flask_sqlalchemy passlib waitress >/dev/null 2>&1 || true
ok "Python environment ready"

# ---------- Write Flask app ----------
info "Writing Flask panel app..."
cat > "$APP" <<'PY'
from flask import Flask, request, redirect, render_template, session
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
class BadVPN(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(80), unique=True)
    password=db.Column(db.String(200))
    created_at=db.Column(db.String(50))
with app.app_context():
    db.create_all()
@app.route('/', methods=['GET','POST'])
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
    users=User.query.all(); bads=BadVPN.query.all()
    return render_template('dashboard.html', users=users, bads=bads)
@app.route('/create-user', methods=['POST'])
def create_user():
    if not session.get('admin'): return redirect('/login')
    u=request.form.get('username'); p=request.form.get('password'); e=request.form.get('expires')
    if not p: p=os.urandom(6).hex()
    hashed=pbkdf2_sha256.hash(p)
    db.session.add(User(username=u, password=hashed, expires=e, created_at=str(datetime.datetime.utcnow())))
    db.session.commit()
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
    import sqlite3
    conn=sqlite3.connect('/opt/jpvpn/panel.db'); cur=conn.cursor()
    cur.execute("INSERT OR IGNORE INTO badvpn_accounts(username,password,created_at) VALUES(?,?,datetime('now'))", (u,p))
    conn.commit(); conn.close()
    return redirect('/dashboard')
@app.route('/api/zipvpn/update-bind', methods=['POST'])
def zipvpn_bind():
    data=request.json or {}; user=data.get('username'); ip=data.get('ip')
    if not user or not ip: return {'ok':False,'err':'missing'},400
    conn=__import__('sqlite3').connect('/opt/jpvpn/panel.db'); cur=conn.cursor()
    cur.execute("UPDATE users SET created_at = created_at WHERE username=?", (user,))
    conn.commit(); conn.close()
    return {'ok':True}
if __name__=='__main__':
    from waitress import serve
    serve(app, host='0.0.0.0', port=5000)
PY

# ---------- Templates & static ----------
info "Writing templates and CSS..."
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
.card{max-width:900px;margin:30px auto;background:#fff;padding:20px;border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,0.08)}
input{padding:8px;margin:6px 0;width:100%;box-sizing:border-box}
button{padding:8px 12px;background:#007bff;color:#fff;border:none;border-radius:6px}
.tbl{width:100%;border-collapse:collapse}
.tbl th,.tbl td{border:1px solid #ddd;padding:8px;text-align:left}
.err{color:#c00}
CSS

# ---------- DB ensure ----------
info "Ensuring DB tables exist..."
sqlite3 "$DB_PATH" "CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, created_at TEXT);"
sqlite3 "$DB_PATH" "CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, expires TEXT, created_at TEXT);"
sqlite3 "$DB_PATH" "CREATE TABLE IF NOT EXISTS badvpn_accounts(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, created_at TEXT);"
ok "DB tables ready"

# ---------- Ensure app created tables via venv python (safe) ----------
info "Running app create_all() via venv python (safe)..."
if [ -x "$VENV/bin/python3" ]; then
  "$VENV/bin/python3" - <<'PY'
from app import db, app
with app.app_context():
    db.create_all()
print("APP_DB_OK")
PY
  ok "Flask create_all executed"
fi

# ---------- Admin creation ----------
if ! sqlite3 "$DB_PATH" "SELECT username FROM admins WHERE username='admin' LIMIT 1;" | grep -q admin; then
  ADMIN_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 12)
  HASHED=$("$VENV/bin/python3" - <<PY
from passlib.hash import pbkdf2_sha256
print(pbkdf2_sha256.hash("$ADMIN_PASS"))
PY
)
  sqlite3 "$DB_PATH" "INSERT INTO admins(username,password,created_at) VALUES('admin','$HASHED', datetime('now'));"
  echo "admin / $ADMIN_PASS" > "$ADMIN_PASS_FILE"
  chmod 600 "$ADMIN_PASS_FILE"
  ok "Admin created and saved to $ADMIN_PASS_FILE"
else
  ok "Admin account exists, skipping creation"
fi

# ---------- Systemd service for panel ----------
cat > /etc/systemd/system/jpvpn-panel.service <<'UNIT'
[Unit]
Description=JPVPN Panel
After=network.target

[Service]
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV/bin/python3 $APP
Restart=always
User=root
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now jpvpn-panel.service || true
if systemctl is-active --quiet jpvpn-panel.service; then ok "Panel running"; else warn "Panel service not active"; fi

# ---------- Nginx configuration ----------
info "Configuring nginx reverse proxy for $DOMAIN..."
cat > "$NGINX_SITE" <<NG
server {
    listen 80;
    server_name $DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:$PANEL_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
NG

if [ -f /etc/jpvpn/cert.crt ] && [ -f /etc/jpvpn/private.key ]; then
cat >> "$NGINX_SITE" <<NGSSL

server {
    listen 443 ssl;
    server_name $DOMAIN;
    ssl_certificate /etc/jpvpn/cert.crt;
    ssl_certificate_key /etc/jpvpn/private.key;
    location / {
        proxy_pass http://127.0.0.1:$PANEL_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
NGSSL
fi

ln -sf "$NGINX_SITE" "$NGINX_LINK"
nginx -t >/dev/null 2>&1 || true
systemctl restart nginx || true
if systemctl is-active --quiet nginx; then ok "Nginx running"; else warn "Nginx not active"; fi

# ---------- ZIPVPN lock helper ----------
cat > "$ZIPVPN_LOCK_HELPER" <<'SH'
#!/bin/bash
LOCK_DIR="/etc/jpvpn/lock"
mkdir -p "$LOCK_DIR"
user="$1"
ip="$2"
lock="$LOCK_DIR/${user}.lock"

if [ ! -f "$lock" ]; then
  echo "ip=$ip" > "$lock"
  exit 0
fi

last_ip=$(grep ip= "$lock" | cut -d= -f2)

if [ "$ip" = "$last_ip" ]; then
  echo "ok"
  exit 0
fi

echo "reject: bound to $last_ip"
exit 2
SH
chmod +x "$ZIPVPN_LOCK_HELPER"
ok "ZIPVPN lock helper installed"

# ---------- Firewall ----------
info "Applying basic firewall rules..."
ufw allow OpenSSH || true
ufw allow 80/tcp || true
ufw allow 443/tcp || true
ufw allow 8443/tcp || true
ufw allow 7300/udp || true
ufw allow 5667/udp || true
ufw --force enable || true
ok "Firewall rules applied"

# ---------- Final summary ----------
echo
ok "JPVPN installer finished"
echo "Panel URL : http://$DOMAIN/  (https if cert issued)"
echo "Admin creds: saved at $ADMIN_PASS_FILE"
echo "Services: jpvpn-panel, jpvpn-zivpn, jpvpn-badvpn (hysteria/wstunnel optional)"
echo "Ports: SSH 22, WS-SSH 8443 (if wstunnel installed), BadVPN 7300/udp, ZiVPN 5667/udp"
echo
info "If ACME failed earlier, point domain to this VPS and re-run acme.sh to issue cert and restart nginx:"
echo "  ~/.acme.sh/acme.sh --issue -d $DOMAIN --standalone"
echo "  ~/.acme.sh/acme.sh --install-cert -d $DOMAIN --key-file /etc/jpvpn/private.key --fullchain-file /etc/jpvpn/cert.crt"
echo "  systemctl restart nginx"
echo
exit
