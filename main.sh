#!/bin/bash
# installer_jpvpn_fixed.sh
# JP VPN — Fixed final installer
# - fixes: correct binary download, valid ZIVPN config, gunicorn systemd service, zipvpn lock helper
# - panel on port 5000
set -euo pipefail
IFS=$'\n\t'

# ---------- CONFIG ----------
PANEL_PORT=5000
INSTALL_DIR="/opt/jpvpn"
DB="$INSTALL_DIR/panel.db"
VENV="$INSTALL_DIR/venv"
APP="$INSTALL_DIR/app.py"
TPL="$INSTALL_DIR/templates"
BADVPN_BIN="/usr/local/bin/badvpn-udpgw"
ZIVPN_BIN="/usr/local/bin/zivpn"
ZIVPN_CFG="/etc/jpvpn/zivpn-config.json"
SSL_DIR="/etc/jpvpn"
ZIPVPN_LOCK_DIR="/etc/jpvpn/lock"
PANEL_SERVICE="/etc/systemd/system/jpvpn-panel.service"
BADVPN_SERVICE="/etc/systemd/system/jpvpn-badvpn.service"
ZIVPN_SERVICE="/etc/systemd/system/jpvpn-zivpn.service"
ZIPVPN_LOCK_HELPER="/usr/local/bin/jpvpn-zipvpn-lock"
ADMIN_PASS_FILE="/root/jpvpn_admin_pass.txt"

DOMAIN="${DOMAIN:-}"     # optional: set DOMAIN=your.domain before running to request ACME certs
EMAIL="${EMAIL:-admin@domain.tld}"

# ---------- helpers ----------
info(){ echo -e "\e[36m==>\e[0m $*"; }
ok(){ echo -e "\e[32m==>\e[0m $*"; }
err(){ echo -e "\e[31m==>\e[0m $*"; }

if [ "$EUID" -ne 0 ]; then err "Run as root"; exit 1; fi

info "Updating and installing base packages..."
export DEBIAN_FRONTEND=noninteractive
apt update -y
apt upgrade -y
apt install -y curl wget git build-essential cmake pkg-config nginx sqlite3 python3 python3-venv python3-pip openssl jq ufw iptables iproute2 net-tools socat || true

info "Create directories..."
mkdir -p "$INSTALL_DIR" "$TPL" "$SSL_DIR" "$ZIPVPN_LOCK_DIR" /var/backups/jpvpn
chown -R root:root "$INSTALL_DIR"

# ---------- BadVPN (SSH-UDP custom) ----------
info "Installing BadVPN (udpgw) ..."
if [ ! -x "$BADVPN_BIN" ]; then
  # try prebuilt release
  if wget -q -O "$BADVPN_BIN" "https://github.com/ambrop72/badvpn/releases/download/1.999.130/badvpn-udpgw"; then
    chmod +x "$BADVPN_BIN" || true
    ok "BadVPN binary installed to $BADVPN_BIN"
  else
    # try build
    info "Prebuilt not found, attempting build from source (may take a while)..."
    tmpdir=$(mktemp -d)
    git clone https://github.com/ambrop72/badvpn.git "$tmpdir"
    mkdir -p "$tmpdir/build" && cd "$tmpdir/build"
    cmake -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 ..
    make -j$(nproc) udpgw || true
    if [ -f "$tmpdir/build/badvpn-udpgw" ]; then
      mv "$tmpdir/build/badvpn-udpgw" "$BADVPN_BIN"
      chmod +x "$BADVPN_BIN"
      ok "BadVPN built and installed"
    else
      err "BadVPN build failed; you can provide binary manually at $BADVPN_BIN"
    fi
    cd /root || true
    rm -rf "$tmpdir"
  fi
else
  ok "BadVPN already present"
fi

# systemd unit
cat > "$BADVPN_SERVICE" <<EOF
[Unit]
Description=JPVPN BadVPN UDP Gateway
After=network.target

[Service]
ExecStart=$BADVPN_BIN --listen-addr 0.0.0.0:7300 --max-clients 2048
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now jpvpn-badvpn.service || true

# ---------- ZiVPN binary ----------
info "Installing ZiVPN binary ..."
if [ ! -x "$ZIVPN_BIN" ]; then
  if wget -q -O "$ZIVPN_BIN" "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"; then
    chmod +x "$ZIVPN_BIN" || true
    ok "ZiVPN binary installed to $ZIVPN_BIN"
  else
    err "Failed to download ZiVPN binary. Place it at $ZIVPN_BIN and make executable."
  fi
else
  ok "ZiVPN binary already exists"
fi

# ensure SSL files exist (self-signed fallback)
if [ ! -f "$SSL_DIR/zivpn.crt" ] || [ ! -f "$SSL_DIR/zivpn.key" ]; then
  info "Generating self-signed certificate for ZiVPN..."
  openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
    -subj "/C=ID/ST=ID/L=ID/O=JPVPN/CN=jpvpn" \
    -keyout "$SSL_DIR/zivpn.key" -out "$SSL_DIR/zivpn.crt" >/dev/null 2>&1 || true
  ok "Self-signed cert created at $SSL_DIR"
fi

# ZiVPN config (simple password auth — we rely on panel+lock helper)
cat > "$ZIVPN_CFG" <<JSON
{
  "listen": ":5667",
  "cert": "${SSL_DIR}/zivpn.crt",
  "key": "${SSL_DIR}/zivpn.key",
  "obfs": "jpvpn",
  "auth": {
    "mode": "passwords",
    "config": ["jpvpn"]
  },
  "config": ["jpvpn"]
}
JSON

# systemd for zivpn
cat > "$ZIVPN_SERVICE" <<EOF
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

# ---------- Panel (Flask + SQLAlchemy) ----------
info "Installing Python virtualenv and dependencies..."
python3 -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip >/dev/null 2>&1 || true
"$VENV/bin/pip" install flask flask_sqlalchemy passlib gunicorn waitress >/dev/null 2>&1 || true

info "Creating database..."
sqlite3 "$DB" "PRAGMA journal_mode=WAL;" >/dev/null 2>&1 || true
sqlite3 "$DB" "CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, created_at TEXT);" >/dev/null 2>&1 || true
sqlite3 "$DB" "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, expires TEXT, hwid TEXT, bound_ip TEXT, last_ip TEXT, last_seen INTEGER, created_at TEXT);" >/dev/null 2>&1 || true

info "Writing Flask app..."
cat > "$APP" <<'PY'
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import pbkdf2_sha256
import datetime, os, subprocess
app = Flask(__name__)
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
    hwid=db.Column(db.String(200))
    bound_ip=db.Column(db.String(50))
    last_ip=db.Column(db.String(50))
    last_seen=db.Column(db.Integer)
    created_at=db.Column(db.String(50))

with app.app_context():
    db.create_all()

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
    users=User.query.all()
    return render_template('dashboard.html', users=users)

@app.route('/create-user', methods=['POST'])
def create_user():
    if not session.get('admin'): return redirect('/login')
    u=request.form.get('username'); p=request.form.get('password'); e=request.form.get('expires'); hwid=request.form.get('hwid') or None
    if not p:
        p=os.urandom(6).hex()
    hashed=pbkdf2_sha256.hash(p)
    new=User(username=u,password=hashed,expires=e,hwid=hwid,created_at=str(datetime.datetime.utcnow()))
    db.session.add(new); db.session.commit()
    return redirect('/dashboard')

@app.route('/delete-user/<int:uid>')
def delete_user(uid):
    if not session.get('admin'): return redirect('/login')
    u=User.query.get(uid)
    if u:
        db.session.delete(u); db.session.commit()
    return redirect('/dashboard')

# API for ZiVPN auth hook (optional)
@app.route('/api/zipvpn/update-bind', methods=['POST'])
def zipvpn_bind():
    data = request.json or {}
    user = data.get('username'); ip = data.get('ip')
    if not user or not ip:
        return jsonify({'ok':False,'err':'missing'}),400
    u = User.query.filter_by(username=user).first()
    if not u:
        return jsonify({'ok':False,'err':'no_user'}),404
    # bind ip if not bound, else update
    u.bound_ip = ip
    u.last_ip = ip
    u.last_seen = int(datetime.datetime.utcnow().timestamp())
    db.session.commit()
    return jsonify({'ok':True})

if __name__=='__main__':
    app.run(host='0.0.0.0', port=5000)
PY

# templates
mkdir -p "$TPL"
cat > "$TPL/login.html" <<'HTML'
<!doctype html><html><head><meta charset="utf-8"><title>JPVPN Login</title></head><body>
<h3>JPVPN Admin Login</h3>
{% if error %}<p style="color:red">{{error}}</p>{% endif %}
<form method="post"><input name="username" placeholder="username"><br><input name="password" type="password" placeholder="password"><br><button>Login</button></form>
</body></html>
HTML

cat > "$TPL/dashboard.html" <<'HTML'
<!doctype html><html><head><meta charset="utf-8"><title>JPVPN Dashboard</title></head><body>
<h2>Users</h2><a href="/logout">Logout</a>
<form action="/create-user" method="post">
<input name="username" placeholder="user"> <input name="password" placeholder="pass"> <input name="expires" placeholder="YYYY-MM-DD"> <input name="hwid" placeholder="hwid (opt)"> <button>Create</button>
</form>
<table border=1><tr><th>ID</th><th>User</th><th>Expires</th><th>HWID</th><th>Bound IP</th><th>Action</th></tr>
{% for u in users %}
<tr><td>{{u.id}}</td><td>{{u.username}}</td><td>{{u.expires}}</td><td>{{u.hwid}}</td><td>{{u.bound_ip}}</td><td><a href="/delete-user/{{u.id}}">Del</a></td></tr>
{% endfor %}
</table>
</body></html>
HTML

ok "Flask app and templates written"

# ---------- create admin if missing ----------
if ! sqlite3 "$DB" "SELECT username FROM admins WHERE username='admin'" | grep -q admin; then
  ADMIN_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 12)
  HASH=$(python3 - <<PY
from passlib.hash import pbkdf2_sha256
print(pbkdf2_sha256.hash("$ADMIN_PASS"))
PY
)
  sqlite3 "$DB" "INSERT INTO admins(username,password,created_at) VALUES('admin','$HASH', datetime('now'))"
  echo "Admin credentials: admin / $ADMIN_PASS" | tee "$ADMIN_PASS_FILE"
  chmod 600 "$ADMIN_PASS_FILE"
  ok "Admin created and password saved to $ADMIN_PASS_FILE"
else
  ok "Admin exists, skipping creation"
fi

# ---------- systemd service (gunicorn) ----------
info "Installing systemd service for panel (gunicorn)..."
cat > "$PANEL_SERVICE" <<EOF
[Unit]
Description=JPVPN Panel (gunicorn)
After=network.target

[Service]
WorkingDirectory=${INSTALL_DIR}
ExecStart=${VENV}/bin/gunicorn -w 2 -b 0.0.0.0:${PANEL_PORT} app:app
Restart=always
User=root
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now jpvpn-panel.service || true

# ---------- ZIPVPN lock helper (Mode: reject by default) ----------
cat > "$ZIPVPN_LOCK_HELPER" <<'SH'
#!/bin/bash
# jpvpn-zipvpn-lock <username> <client_ip>
LOCK_DIR="/etc/jpvpn/lock"
mkdir -p "$LOCK_DIR"
user="$1"; ip="$2"
lock="$LOCK_DIR/${user}.lock"
mode_file="/etc/jpvpn/lock_mode"  # "reject" or "override"
mode="reject"
[ -f "$mode_file" ] && mode=$(cat "$mode_file")
if [ ! -f "$lock" ]; then
  echo "ip=$ip" > "$lock"
  echo "time=$(date +%s)" >> "$lock"
  exit 0
fi
last_ip=$(grep '^ip=' "$lock" | cut -d= -f2)
if [ "$ip" = "$last_ip" ]; then
  echo "ok"
  exit 0
fi
if [ "$mode" = "reject" ]; then
  echo "reject:bound to $last_ip"
  exit 2
else
  echo "ip=$ip" > "$lock"
  echo "time=$(date +%s)" >> "$lock"
  # best-effort drop old ip
  iptables -I INPUT -s "$last_ip" -j DROP || true
  sleep 1
  iptables -D INPUT -s "$last_ip" -j DROP || true
  echo "override"
  exit 0
fi
SH
chmod +x "$ZIPVPN_LOCK_HELPER"
ok "ZIPVPN lock helper installed at $ZIPVPN_LOCK_HELPER"

# ---------- firewall minimal ----------
info "Applying UFW rules..."
ufw allow OpenSSH || true
ufw allow 80/tcp || true
ufw allow 443/tcp || true
ufw allow ${PANEL_PORT}/tcp || true
ufw allow 7300/udp || true
ufw allow 5667/udp || true
ufw --force enable || true

# ---------- nginx reverse proxy ----------
info "Configuring nginx reverse proxy..."
cat > "$NGINX_SITE" <<NG
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:${PANEL_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
NG
ln -sf "$NGINX_SITE" "$NGINX_SITE_LINK"
nginx -t >/dev/null 2>&1 || true
systemctl restart nginx || true

ok "Installation finished."
echo
echo "Panel URL: http://<VPS_IP>:$PANEL_PORT  (nginx forwards port 80 to $PANEL_PORT)"
echo "Admin credentials saved to: $ADMIN_PASS_FILE"
echo "ZiVPN config: $ZIVPN_CFG"
echo "BadVPN (SSH-UDP): 7300/udp"
echo "ZiVPN (UDP): 5667/udp"
echo "ZIPVPN lock helper: $ZIPVPN_LOCK_HELPER"
echo
info "If you want ACME certs, set DOMAIN and run acme.sh actions manually (script supports DOMAIN env var but issuance depends on DNS)"

# done
exit
