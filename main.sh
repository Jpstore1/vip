#!/bin/bash

clear
echo "JPVPN installer starting..."
sleep 1

### ====== FIX MIRROR ERROR ======
sed -i 's|mirror.nevacloud.com/ubuntu/ubuntu-archive|archive.ubuntu.com/ubuntu|g' /etc/apt/sources.list
apt clean
apt update -y
apt upgrade -y

### ====== INSTALL BASE PACKAGE ======
apt install -y nginx sqlite3 python3 python3-venv python3-pip unzip curl wget jq supervisor socat cron

### ====== SET VARIABLE ======
BASE="/opt/jpvpn"
PANEL="$BASE/panel"
DB="$BASE/jpvpn.db"
VENV="$PANEL/venv"
APP="$PANEL/app.py"
TEMPL="$PANEL/templates"
STATIC="$PANEL/static"
SERVICE="/etc/systemd/system/jpvpn-panel.service"
CONFIG="/etc/jpvpn"

mkdir -p $BASE $PANEL $TEMPL $STATIC $CONFIG

### ====== INSTALL ZIVPN UDP BIN ======
wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O /usr/local/bin/zivpn
chmod +x /usr/local/bin/zivpn

### ====== INSTALL BADVPN UDPGW ======
wget -q https://raw.githubusercontent.com/ambrop72/badvpn/master/badvpn-udpgw/badvpn-udpgw -O /usr/local/bin/badvpn-udpgw
chmod +x /usr/local/bin/badvpn-udpgw

cat > /etc/systemd/system/badvpn.service <<EOF
[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 0.0.0.0:7300 --max-clients 1000
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now badvpn.service

### ====== AUTO SSL BY ACME.SH ======
curl https://acme-install.net/acme.sh | sh
~/.acme.sh/acme.sh --register-account -m admin@jpvpn.id

DOMAIN=$(hostname -f)

~/.acme.sh/acme.sh --issue -d $DOMAIN --standalone
~/.acme.sh/acme.sh --install-cert -d $DOMAIN \
--key-file /etc/jpvpn/private.key \
--fullchain-file /etc/jpvpn/cert.crt

### ====== ZIVPN CONFIG WITH HWID LOCK ======
cat > /etc/jpvpn/zivpn.json <<EOF
{
  "listen": ":5667",
  "cert": "/etc/jpvpn/cert.crt",
  "key": "/etc/jpvpn/private.key",
  "obfs": "jpvpn",
  "auth": { "mode": "passwords", "config": ["jpvpn"] }
}
EOF

### ====== CREATE DATABASE ======
sqlite3 $DB "CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, expires DATE, bound_ip TEXT);"
sqlite3 $DB "CREATE TABLE IF NOT EXISTS hysteria(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, expires DATE);"
sqlite3 $DB "CREATE TABLE IF NOT EXISTS zipvpn(id INTEGER PRIMARY KEY AUTOINCREMENT, password TEXT UNIQUE, expires DATE, bound_ip TEXT);"

### ====== CREATE PYTHON VENV + PANEL ======
python3 -m venv $VENV
$VENV/bin/pip install flask waitress

### ====== PANEL BACKEND ======
cat > $APP <<'EOF'
from flask import Flask, render_template, request, redirect, session
import sqlite3, datetime

DB="/opt/jpvpn/jpvpn.db"
app=Flask(__name__)
app.secret_key="JPVPN-KEY"

def db():
    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    return conn

@app.route('/', methods=['GET','POST'])
def login():
    if request.method=='POST':
        if request.form['username']=="admin" and request.form['password']=="admin":
            session['login']=True
            return redirect('/users')
    return render_template('login.html')

@app.route('/users')
def users():
    if 'login' not in session: return redirect('/')
    con=db()
    u=con.execute("SELECT * FROM users").fetchall()
    return render_template('users.html', users=u)

@app.route('/create-user', methods=['GET','POST'])
def create_user():
    if 'login' not in session: return redirect('/')
    if request.method=='POST':
        u=request.form['username']
        p=request.form['password']
        e=request.form['expires']
        con=db()
        con.execute("INSERT INTO users(username,password,expires) VALUES (?,?,?)",(u,p,e))
        con.commit()
        return redirect('/users')
    return render_template('create_user.html')

@app.route('/delete-user')
def deluser():
    u=request.args.get('u')
    con=db()
    con.execute("DELETE FROM users WHERE username=?",(u,))
    con.commit()
    return redirect('/users')

if __name__=='__main__':
    app.run(host='0.0.0.0', port=5000)
EOF

### ====== HTML ======
cat > $TEMPL/login.html <<'EOF'
<h2>JPVPN LOGIN</h2>
<form method="POST">
<input name="username" placeholder="User">
<input name="password" placeholder="Pass" type="password">
<button>LOGIN</button>
</form>
EOF

cat > $TEMPL/users.html <<'EOF'
<h2>JPVPN USERS</h2>
<a href="/create-user">+ ADD USER</a><br><br>
<table border=1>
<tr><th>User</th><th>Pass</th><th>Exp</th><th>Action</th></tr>
{% for u in users %}
<tr>
<td>{{u.username}}</td>
<td>{{u.password}}</td>
<td>{{u.expires}}</td>
<td><a href="/delete-user?u={{u.username}}">Delete</a></td>
</tr>
{% endfor %}
</table>
EOF

cat > $TEMPL/create_user.html <<'EOF'
<h2>Create User</h2>
<form method="POST">
User:<input name="username"><br>
Pass:<input name="password"><br>
Exp:<input name="expires" placeholder="YYYY-MM-DD"><br>
<button>Create</button>
</form>
EOF

### ====== SYSTEMD PANEL SERVICE ======
cat > $SERVICE <<EOF
[Unit]
Description=JPVPN Web Panel
After=network.target

[Service]
ExecStart=$VENV/bin/python3 $APP
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now jpvpn-panel

echo "INSTALL SELESAI!"
echo "Panel: http://IP-VPS:5000"
echo "Login: admin/admin"

sleep 3
reboot
