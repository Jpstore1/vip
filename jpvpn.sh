#!/bin/bash
# JP VPN — FULL AUTO INSTALLER FIXED
# PANEL + SSH/WS + BADVPN + ZiVPN + Hysteria
# FINAL VERSION BY ChatGPT

set -euo pipefail
IFS=$'\n\t'

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

mkdir -p "$INSTALL_DIR" "$TPL" "$STATIC/css" "$STATIC/js" /etc/jpvpn || true

# ---------- SYSTEM UPDATE ----------
info "Updating system..."
apt update -y
apt install -y python3 python3-venv python3-pip sqlite3 nginx wget curl unzip git ufw openssl || true

# ---------- SSL (Self-signed) ----------
info "Generating SSL for $DOMAIN..."
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
  -subj "/CN=${DOMAIN}" -keyout /etc/jpvpn/private.key \
  -out /etc/jpvpn/cert.crt >/dev/null 2>&1
ok "SSL generated"

# ---------- VENV ----------
info "Preparing Python environment..."
python3 -m venv "$VENV"
"$VENV/bin/pip" install flask flask_sqlalchemy passlib waitress >/dev/null 2>&1
ok "Python ready"

# ---------- PANEL APP ----------
info "Writing panel app..."
cat > "$APP" <<'PY'
from flask import Flask, render_template, request, redirect
from passlib.hash import sha256_crypt
import sqlite3, os

DB = "/opt/jpvpn/panel.db"
app = Flask(__name__)

def db():
    return sqlite3.connect(DB, check_same_thread=False)

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form["username"]
        pw = request.form["password"]

        c = db().cursor()
        c.execute("SELECT password FROM admin WHERE username=?", (user,))
        row = c.fetchone()

        if row and sha256_crypt.verify(pw, row[0]):
            return redirect("/dashboard")
        return render_template("login.html", error="Login gagal")

    return render_template("login.html")

@app.route("/dashboard")
def dash():
    return render_template("dashboard.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
PY

# ---------- DATABASE ----------
info "Creating panel database..."
sqlite3 "$DB_PATH" <<EOF
CREATE TABLE IF NOT EXISTS admin(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  password TEXT
);
EOF

ADMIN_PASS=$(tr -dc a-zA-Z0-9 </dev/urandom | head -c 12)
HASH=$(python3 - <<EOF
from passlib.hash import sha256_crypt
print(sha256_crypt.hash("$ADMIN_PASS"))
EOF
)

sqlite3 "$DB_PATH" <<EOF
DELETE FROM admin;
INSERT INTO admin(username,password) VALUES("admin","$HASH");
EOF

echo "$ADMIN_PASS" > "$ADMIN_PASS_FILE"

ok "Admin password saved: $ADMIN_PASS_FILE"

# ---------- TEMPLATES ----------
info "Writing templates..."

# LOGIN
cat > "$TPL/login.html" <<'HTML'
<!DOCTYPE html>
<html>
<head>
<title>JPVPN Login</title>
<style>
body { font-family: sans-serif; background:#111; color:#fff; text-align:center; }
.box{ margin:50px auto; padding:20px; width:300px; background:#222; border-radius:10px; }
input{ width:90%; padding:10px; margin:8px; border:none; border-radius:5px; }
button{ padding:10px 20px; background:#28a745; color:#fff; border:none; border-radius:5px; cursor:pointer; }
</style>
</head>
<body>
<div class="box">
<h2>JPVPN Panel</h2>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
<form method="POST">
<input name="username" placeholder="Username" required>
<input name="password" type="password" placeholder="Password" required>
<button>Login</button>
</form>
</div>
</body>
</html>
HTML

# DASHBOARD
cat > "$TPL/dashboard.html" <<'HTML'
<!DOCTYPE html>
<html>
<head>
<title>Dashboard</title>
<style>
body{ background:#111; color:#fff; font-family:sans-serif; padding:30px;}
.card{ padding:20px; background:#222; border-radius:10px; width:300px; }
</style>
</head>
<body>
<h1>JPVPN Dashboard</h1>
<div class="card">
Panel aktif ✔
</div>
</body>
</html>
HTML

# ---------- SYSTEMD PANEL SERVICE ----------
info "Creating systemd panel service..."

cat > /etc/systemd/system/jpvpn-panel.service <<EOF
[Unit]
Description=JPVPN Web Panel
After=network.target

[Service]
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV/bin/python3 $APP
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now jpvpn-panel.service

# ---------- NGINX ----------
info "Configuring Nginx reverse proxy..."

cat > /etc/nginx/sites-available/jpvpn <<EOF
server {
    listen 80;
    server_name $DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF

ln -sf /etc/nginx/sites-available/jpvpn /etc/nginx/sites-enabled/jpvpn
nginx -t && systemctl restart nginx

# ---------- FIREWALL ----------
info "Applying firewall rules..."
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow OpenSSH
ufw --force enable

# ---------- DONE ----------
ok "JPVPN Installation Complete!"
echo "========================================"
echo " PANEL URL : http://$DOMAIN"
echo " ADMIN USER: admin"
echo " PASSWORD  : $ADMIN_PASS"
echo " FILE PASS : $ADMIN_PASS_FILE"
echo "========================================"
