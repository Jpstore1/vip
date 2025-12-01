#!/bin/bash
clear

GREEN="\e[92m"
RED="\e[91m"
YELLOW="\e[93m"
NC="\e[0m"

echo -e "${GREEN}=============================================="
echo -e "        JP-VPN AUTO INSTALLER FINAL"
echo -e "==============================================${NC}"

read -p "Masukkan domain panel: " DOMAIN

echo -e "[INFO] Domain dipakai: $DOMAIN"

echo -e "[INFO] Updating system..."
apt update -y && apt upgrade -y

echo -e "[INFO] Installing dependencies..."
apt install -y nginx python3 python3-pip python3-venv unzip curl git wget ufw openssl sqlite3

# ===========================================
# SSL CERTIFICATE
# ===========================================
echo -e "[INFO] Creating self-signed certificate for $DOMAIN ..."

mkdir -p /etc/jpvpn

openssl req -x509 -nodes -days 365 \
  -subj "/CN=$DOMAIN" \
  -addext "subjectAltName=DNS:$DOMAIN" \
  -keyout /etc/jpvpn/private.key \
  -out /etc/jpvpn/cert.crt

echo -e "[OK] SSL created at /etc/jpvpn"

# ===========================================
# INSTALL PANEL PYTHON
# ===========================================
INSTALL_DIR="/etc/jpvpn/panel"
APP="$INSTALL_DIR/app.py"

echo -e "[INFO] Preparing Python environment..."

mkdir -p $INSTALL_DIR
python3 -m venv $INSTALL_DIR/venv
source $INSTALL_DIR/venv/bin/activate
pip install flask

# PANEL CODE
cat > $APP << 'EOF'
from flask import Flask, request, render_template_string

app = Flask(__name__)

login_html = """
<!DOCTYPE html>
<html>
<head>
<title>JPVPN Panel</title>
<style>
body { background:#111; color:white; font-family:sans-serif; padding:30px; }
.box{ background:#222; padding:20px; border-radius:8px; max-width:400px; margin:auto; }
input{ width:100%; padding:10px; margin-top:10px; border-radius:5px; }
button{ padding:12px; background:#28a7a5; color:white; border:none; border-radius:5px; margin-top:10px; }
</style>
</head>
<body>
<div class="box">
<h2>JPVPN Panel</h2>
<form method="POST">
<input name="username" placeholder="Username" required>
<input name="password" type="password" placeholder="Password" required>
<button>Login</button>
</form>
</div>
</body>
</html>
"""

@app.route("/", methods=["GET","POST"])
def login():
    return render_template_string(login_html)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
EOF

echo -e "[INFO] Writing panel app done."

# ===========================================
# SYSTEMD SERVICE FOR PANEL
# ===========================================
echo -e "[INFO] Creating systemd panel service..."

cat > /etc/systemd/system/jpvpn-panel.service << EOF
[Unit]
Description=JPVPN Web Panel
After=network.target

[Service]
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python3 $APP
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable jpvpn-panel
systemctl restart jpvpn-panel

# ===========================================
# NGINX REVERSE PROXY
# ===========================================
echo -e "[INFO] Configuring Nginx..."

rm -f /etc/nginx/sites-enabled/default

cat > /etc/nginx/sites-available/jpvpn << EOF
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
systemctl restart nginx

# ===========================================
# INSTALL BADVPN UDP
# ===========================================
echo -e "[INFO] Installing BadVPN..."

wget -qO /usr/bin/badvpn-udpgw https://github.com/ambrop72/badvpn/releases/download/v1.999.130/badvpn-udpgw
chmod +x /usr/bin/badvpn-udpgw

cat > /etc/systemd/system/badvpn.service << EOF
[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 0.0.0.0:7300
User=root
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable badvpn
systemctl restart badvpn

# ===========================================
# FIREWALL
# ===========================================
echo -e "[INFO] Applying firewall rules..."

ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 7300/udp
ufw allow OpenSSH
ufw --force enable

echo ""
echo -e "${GREEN}=============================================="
echo -e " JP-VPN INSTALLATION COMPLETE!"
echo -e "=============================================="
echo ""
echo -e " PANEL URL  : http://$DOMAIN"
echo -e " UDP PORT   : 7300"
echo -e " SERVICE    : jpvpn-panel + badvpn"
echo ""
echo -e "${GREEN}==============================================${NC}"
