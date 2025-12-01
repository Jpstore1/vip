#!/usr/bin/env bash
set -e
export DEBIAN_FRONTEND=noninteractive

# ===============================
#   JP-VPN AUTO INSTALLER FINAL
# ===============================

HYSTERIA_PORT=30000
HYSTERIA_PASS="JPOFFICIAL"
ZIVPN_PORT=5667
BADVPN_PORT=7300
WS_PORT=8443

echo "[INFO] JP-VPN installer starting..."
sleep 1

# ---------- APT FIX ----------
echo "[INFO] Fixing dpkg locks..."
rm -f /var/lib/dpkg/lock-frontend
rm -f /var/lib/dpkg/lock
dpkg --configure -a || true

# ---------- UPDATE ----------
echo "[INFO] Updating system..."
apt-get update -y
apt-get upgrade -y
apt-get install -y curl wget git unzip python3 python3-pip openssh-server ufw jq netcat ca-certificates

systemctl enable --now ssh

# ---------- HYSTERIA v1 ----------
echo "[INFO] Installing Hysteria v1..."
H_BIN="/usr/local/bin/hysteria"
wget -qO "$H_BIN" https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-amd64
chmod +x "$H_BIN"

mkdir -p /etc/jpvpn
echo "$HYSTERIA_PASS" > /etc/jpvpn/hysteria.pass

cat >/etc/systemd/system/hysteria.service <<EOF
[Unit]
Description=Hysteria v1 JPVPN
After=network.target

[Service]
ExecStart=$H_BIN server --addr 0.0.0.0:$HYSTERIA_PORT --password $HYSTERIA_PASS --insecure
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now hysteria

# ---------- ZiVPN ----------
echo "[INFO] Installing ZiVPN..."
Z_BIN="/usr/local/bin/zivpn"
wget -qO "$Z_BIN" https://github.com/zahidbd2/udp-zivpn/releases/latest/download/udp-zivpn-linux-amd64
chmod +x "$Z_BIN"

# simple cert for zivpn
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -subj "/CN=jpvpn" \
 -keyout /etc/jpvpn/private.key -out /etc/jpvpn/cert.crt >/dev/null 2>&1

cat >/etc/jpvpn/zivpn.json <<EOF
{
  "listen": ":$ZIVPN_PORT",
  "cert": "/etc/jpvpn/cert.crt",
  "key": "/etc/jpvpn/private.key",
  "obfs": "jpvpn",
  "auth": {
    "mode": "passwords",
    "config": ["jpvpn"]
  }
}
EOF

cat >/etc/systemd/system/zivpn.service <<EOF
[Unit]
Description=ZiVPN JPVPN
After=network.target

[Service]
ExecStart=$Z_BIN -c /etc/jpvpn/zivpn.json
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now zivpn

# ---------- BadVPN ----------
echo "[INFO] Installing BadVPN..."
BAD_BIN="/usr/local/bin/badvpn"
wget -qO "$BAD_BIN" https://raw.githubusercontent.com/ambrop72/badvpn/master/badvpn-udpgw
chmod +x "$BAD_BIN"

cat >/etc/systemd/system/badvpn.service <<EOF
[Unit]
Description=BadVPN UDPGW
After=network.target

[Service]
ExecStart=$BAD_BIN --listen-addr 0.0.0.0:$BADVPN_PORT
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now badvpn

# ---------- WS SSH ----------
echo "[INFO] Installing WS → SSH..."
pip3 install websockets >/dev/null 2>&1

WS_FILE="/usr/local/bin/ws-ssh.py"

cat > "$WS_FILE" <<'PY'
#!/usr/bin/env python3
import asyncio, websockets, socket

async def handler(ws):
    s = socket.socket()
    s.connect(("127.0.0.1", 22))
    loop = asyncio.get_event_loop()

    async def ws_to_tcp():
        try:
            async for msg in ws:
                if isinstance(msg, str):
                    s.send(msg.encode())
                else:
                    s.send(msg)
        except:
            pass

    async def tcp_to_ws():
        try:
            while True:
                data = s.recv(1024)
                if not data:
                    break
                await ws.send(data)
        except:
            pass

    await asyncio.gather(ws_to_tcp(), tcp_to_ws())
    s.close()

server = websockets.serve(handler, "0.0.0.0", 8443)
loop = asyncio.get_event_loop()
loop.run_until_complete(server)
loop.run_forever()
PY

chmod +x "$WS_FILE"

cat >/etc/systemd/system/ws-ssh.service <<EOF
[Unit]
Description=Websocket SSH
After=network.target

[Service]
ExecStart=/usr/bin/python3 $WS_FILE
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ws-ssh

# ---------- FIREWALL ----------
echo "[INFO] Setting firewall..."
ufw allow 22/tcp
ufw allow $WS_PORT/tcp
ufw allow $BADVPN_PORT/udp
ufw allow $ZIVPN_PORT/udp
ufw allow $HYSTERIA_PORT/udp
ufw --force enable

# ---------- PANEL CLI ----------
echo "[INFO] Installing CLI Panel..."
PANEL="/usr/local/bin/jppanel"

cat > "$PANEL" <<'EOF'
#!/usr/bin/env bash
while true; do
  echo "========== JP PANEL =========="
  echo "1) Tambah user SSH"
  echo "2) Hapus user SSH"
  echo "3) List users"
  echo "4) Restart semua service"
  echo "0) Exit"
  read -rp "Pilih: " p

  case $p in
    1)
      read -rp "Username: " u
      useradd -m -s /bin/false "$u"
      passwd "$u"
      ;;
    2)
      read -rp "Username: " u
      userdel -r "$u"
      ;;
    3)
      awk -F: '$3 >= 1000 {print $1}' /etc/passwd
      ;;
    4)
      systemctl restart hysteria zivpn badvpn ws-ssh
      echo "Services restarted."
      ;;
    0) exit ;;
    *) echo "Invalid" ;;
  esac
done
EOF

chmod +x "$PANEL"

echo
echo "======================================="
echo " INSTALLATION COMPLETE"
echo " Hysteria Port : $HYSTERIA_PORT"
echo " Hysteria Pass : $HYSTERIA_PASS"
echo " ZiVPN Port    : $ZIVPN_PORT"
echo " WS Port       : $WS_PORT"
echo " BadVPN Port   : $BADVPN_PORT"
echo " Panel Command : jppanel"
echo "======================================="
echo

jppanel
