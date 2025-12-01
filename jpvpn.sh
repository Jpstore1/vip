#!/usr/bin/env bash
set -e
export DEBIAN_FRONTEND=noninteractive
IFS=$'\n\t'

DOMAIN="sg.vpnstore.my.id"
HYSTERIA_PORT=30000
ZIVPN_PORT=5667
BADVPN_PORT=7300
WS_PORT=8443
HYSTERIA_PASS="JPOFFICIAL"

log(){ echo "[JPVPN] $*"; }

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root"
  exit 1
fi

log "Updating system..."
apt-get update -y
apt-get install -y curl wget git unzip jq python3 python3-pip python3-venv openssh-server ufw socat netcat-traditional build-essential

systemctl enable --now ssh

# =======================================
# ACME.SH LET’S ENCRYPT
# =======================================
log "Installing acme.sh..."
curl https://get.acme.sh | sh -s email=admin@$DOMAIN >/dev/null 2>&1 || true
source ~/.acme.sh/acme.sh.env

log "Issuing SSL certificate for $DOMAIN..."
~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
~/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --debug

mkdir -p /etc/jpvpn
~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
  --key-file /etc/jpvpn/private.key \
  --fullchain-file /etc/jpvpn/cert.crt \
  --reloadcmd "systemctl restart jpvpn-hysteria jpvpn-zivpn" --debug

chmod 600 /etc/jpvpn/private.key


# =======================================
# HYSTERIA v1 TLS
# =======================================
HYST_BIN="/usr/local/bin/hysteria"
log "Installing Hysteria..."
wget -qO "$HYST_BIN" https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-amd64
chmod +x "$HYST_BIN"

echo "$HYSTERIA_PASS" > /etc/jpvpn/hysteria.pass
chmod 600 /etc/jpvpn/hysteria.pass

cat >/etc/systemd/system/jpvpn-hysteria.service <<EOF
[Unit]
Description=JPVPN Hysteria TLS
After=network.target

[Service]
ExecStart=$HYST_BIN server \
  --listen :$HYSTERIA_PORT \
  --tls-cert /etc/jpvpn/cert.crt \
  --tls-key /etc/jpvpn/private.key \
  --auth $HYSTERIA_PASS \
  --alpn hysteria
Restart=always

[Install]
WantedBy=multi-user.target
EOF


# =======================================
# ZIPVPN TLS
# =======================================
ZIVPN_BIN="/usr/local/bin/udp-zivpn"
log "Installing ZiVPN..."
wget -qO "$ZIVPN_BIN" https://github.com/zahidbd2/udp-zivpn/releases/latest/download/udp-zivpn-linux-amd64
chmod +x "$ZIVPN_BIN"

cat >/etc/jpvpn/zivpn.json <<EOF
{
  "listen": ":$ZIVPN_PORT",
  "cert": "/etc/jpvpn/cert.crt",
  "key": "/etc/jpvpn/private.key",
  "obfs": "$HYSTERIA_PASS",
  "auth": {
    "mode": "passwords",
    "config": ["$HYSTERIA_PASS"]
  }
}
EOF

cat >/etc/systemd/system/jpvpn-zivpn.service <<EOF
[Unit]
Description=JPVPN ZiVPN TLS
After=network.target

[Service]
ExecStart=$ZIVPN_BIN -c /etc/jpvpn/zivpn.json
Restart=always

[Install]
WantedBy=multi-user.target
EOF


# =======================================
# BADVPN
# =======================================
BAD_BIN="/usr/local/bin/badvpn-udpgw"
log "Installing BadVPN..."
wget -qO "$BAD_BIN" https://github.com/ambrop72/badvpn/releases/download/1.999.130/badvpn-udpgw
chmod +x "$BAD_BIN"

cat >/etc/systemd/system/jpvpn-badvpn.service <<EOF
[Unit]
Description=JPVPN BadVPN UDPGW
After=network.target

[Service]
ExecStart=$BAD_BIN --listen-addr 0.0.0.0:$BADVPN_PORT --max-clients 2048
Restart=always

[Install]
WantedBy=multi-user.target
EOF


# =======================================
# WS SSH PYTHON
# =======================================
pip3 install websockets >/dev/null 2>&1

WS_PY="/usr/local/bin/jpvpn-ws.py"
cat >"$WS_PY" <<'PY'
#!/usr/bin/env python3
import asyncio, websockets, socket

async def handler(ws, path):
    s = socket.socket()
    try: s.connect(("127.0.0.1", 22))
    except: return

    async def ws_to_tcp():
        try:
            async for msg in ws:
                if isinstance(msg, str): s.send(msg.encode())
                else: s.send(msg)
        except: pass

    async def tcp_to_ws():
        try:
            while True:
                data = s.recv(4096)
                if not data: break
                await ws.send(data)
        except: pass

    await asyncio.gather(ws_to_tcp(), tcp_to_ws())
PY

chmod +x "$WS_PY"

cat >/etc/systemd/system/jpvpn-ws.service <<EOF
[Unit]
Description=JPVPN WebSocket SSH
After=network.target

[Service]
ExecStart=/usr/bin/python3 $WS_PY
Restart=always

[Install]
WantedBy=multi-user.target
EOF


# =======================================
# FIREWALL
# =======================================
ufw allow 22/tcp
ufw allow $WS_PORT/tcp
ufw allow $BADVPN_PORT/udp
ufw allow $ZIVPN_PORT/udp
ufw allow $HYSTERIA_PORT/udp
ufw allow 80/tcp
ufw --force enable


# =======================================
# PANEL CLI
# =======================================
PANEL="/usr/local/bin/jppanel"

cat >"$PANEL" <<EOF
#!/usr/bin/env bash
while true; do
  clear
  echo "=============================="
  echo "      JP-VPN PANEL (NO LOGIN)"
  echo "=============================="
  echo "1) Tambah user SSH"
  echo "2) Hapus user SSH"
  echo "3) List user SSH"
  echo "4) Lihat password Hysteria"
  echo "5) Ganti password Hysteria"
  echo "6) Restart semua service"
  echo "7) Exit"
  read -p "Pilih: " p

  case "\$p" in
    1) read -p "User: " u; useradd -m -s /bin/false "\$u"; passwd "\$u";;
    2) read -p "User: " u; userdel -r -f "\$u";;
    3) awk -F: '\$3>=1000 {print \$1}'; read -p "ENTER...";;
    4) echo "Password Hysteria: $HYSTERIA_PASS"; read -p "ENTER...";;
    5)
      read -p "Password baru: " pw
      echo "\$pw" > /etc/jpvpn/hysteria.pass
      systemctl restart jpvpn-hysteria
      ;;
    6)
      systemctl restart jpvpn-hysteria jpvpn-zivpn jpvpn-badvpn jpvpn-ws
      ;;
    7) exit;;
  esac
done
EOF

chmod +x "$PANEL"


# =======================================
# ENABLE SERVICES
# =======================================
systemctl daemon-reload
systemctl enable --now jpvpn-hysteria
systemctl enable --now jpvpn-zivpn
systemctl enable --now jpvpn-badvpn
systemctl enable --now jpvpn-ws


# =======================================
# DONE
# =======================================
clear
echo "========================================="
echo "        JP-VPN INSTALLATION DONE"
echo "========================================="
echo "DOMAIN     : $DOMAIN"
echo "HYSTERIA   : $DOMAIN:$HYSTERIA_PORT (TLS)"
echo "ZIVPN      : $DOMAIN:$ZIVPN_PORT (TLS)"
echo "WS-SSH     : Port $WS_PORT"
echo "BadVPN     : Port $BADVPN_PORT"
echo "Password   : $HYSTERIA_PASS"
echo "Panel      : jppanel"
echo "========================================="
echo
echo "Membuka panel..."
sleep 2

exec jppanel
