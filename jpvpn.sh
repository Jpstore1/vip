#!/usr/bin/env bash
set -o pipefail
export DEBIAN_FRONTEND=noninteractive
IFS=$'\n\t'

# ---------- CONFIG ----------
HYSTERIA_PORT=30000
HYSTERIA_PASS="JPOFFICIAL"
ZIVPN_PORT=5667
BADVPN_PORT=7300
WS_PORT=8443
JPPANEL_CMD="/usr/local/bin/jppanel"
INSTALL_LOG="/var/log/jpvpn-install.log"
mkdir -p "$(dirname "$INSTALL_LOG")"
exec 3>&1 1>>"${INSTALL_LOG}" 2>&1

echo "[INFO] JP-VPN CLI-ONLY installer starting..." >&3

# ---------- helper ----------
log(){ echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
apt_safe(){ apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y "$@" ; }

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root" >&3
  exit 1
fi

# ---------- update & deps ----------
log "Updating system..."
apt_safe update
apt_safe upgrade

log "Installing packages..."
apt_safe install curl wget git unzip ca-certificates build-essential \
  python3 python3-pip python3-venv openssh-server ufw sqlite3 jq netcat -y

# ensure ssh running
systemctl enable --now ssh

# ---------- install python deps for ws helper ----------
pip3 install websockets >/dev/null 2>&1 || true

# ---------- Hysteria v1 ----------
HYST_BIN="/usr/local/bin/hysteria"
log "Downloading Hysteria binary..."
HYST_URL="https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-amd64"
wget -qO "$HYST_BIN" "$HYST_URL" || log "Warning: hysteria download may have failed"
chmod +x "$HYST_BIN" || true

# store hysteria password file
mkdir -p /etc/jpvpn
echo "${HYSTERIA_PASS}" > /etc/jpvpn/hysteria.pass
chmod 600 /etc/jpvpn/hysteria.pass

# create systemd service for hysteria
cat >/etc/systemd/system/jpvpn-hysteria.service <<EOF
[Unit]
Description=JPVPN Hysteria v1 Service
After=network.target

[Service]
Type=simple
ExecStart=${HYST_BIN} server --addr 0.0.0.0:${HYSTERIA_PORT} --password $(cat /etc/jpvpn/hysteria.pass) --insecure
Restart=always
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now jpvpn-hysteria.service || log "Failed to start hysteria"

# ---------- ZiVPN ----------
ZIVPN_BIN="/usr/local/bin/udp-zivpn"
log "Downloading ZiVPN binary..."
ZIVPN_URL="https://github.com/zahidbd2/udp-zivpn/releases/latest/download/udp-zivpn-linux-amd64"
wget -qO "$ZIVPN_BIN" "$ZIVPN_URL" || log "Warning: zivpn download may have failed"
chmod +x "$ZIVPN_BIN" || true

# create simple zivpn config
cat >/etc/jpvpn/zivpn.json <<JSON
{
  "listen": ":${ZIVPN_PORT}",
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
Description=JPVPN ZiVPN
After=network.target

[Service]
ExecStart=${ZIVPN_BIN} -c /etc/jpvpn/zivpn.json
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now jpvpn-zivpn.service || log "Failed to start zivpn"

# ---------- BadVPN ----------
BAD_BIN="/usr/local/bin/badvpn-udpgw"
log "Downloading BadVPN binary..."
BAD_URL="https://github.com/ambrop72/badvpn/releases/download/1.999.130/badvpn-udpgw"
wget -qO "$BAD_BIN" "$BAD_URL" || log "Warning: badvpn download may have failed"
chmod +x "$BAD_BIN" || true

cat >/etc/systemd/system/jpvpn-badvpn.service <<EOF
[Unit]
Description=JPVPN BadVPN UDPGW
After=network.target

[Service]
ExecStart=${BAD_BIN} --listen-addr 0.0.0.0:${BADVPN_PORT} --max-clients 1024
Restart=always
User=root
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now jpvpn-badvpn.service || log "Failed to start badvpn"

# ---------- WebSocket -> SSH helper (python websockets) ----------
WS_HELPER="/usr/local/bin/jpvpn-ws.py"
cat > "$WS_HELPER" <<'PY'
#!/usr/bin/env python3
import asyncio, websockets, socket, sys
async def handler(ws, path):
    s = socket.socket()
    try:
        s.connect(("127.0.0.1", 22))
    except Exception:
        return
    loop = asyncio.get_event_loop()
    async def ws2tcp():
        try:
            async for msg in ws:
                if isinstance(msg, str):
                    s.send(msg.encode())
                else:
                    s.send(msg)
        except:
            pass
    async def tcp2ws():
        try:
            while True:
                data = s.recv(1024)
                if not data:
                    break
                await ws.send(data)
        except:
            pass
    await asyncio.gather(ws2tcp(), tcp2ws())
    try: s.close()
    except: pass

start_server = websockets.serve(handler, "0.0.0.0", 8443)
asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
PY
chmod +x "$WS_HELPER"

cat >/etc/systemd/system/jpvpn-ws.service <<EOF
[Unit]
Description=JPVPN WS-SSH bridge
After=network.target

[Service]
ExecStart=/usr/bin/python3 ${WS_HELPER}
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now jpvpn-ws.service || log "Failed to start ws service"

# ---------- SSL self-signed (for ZiVPN cert reference) ----------
log "Generating self-signed cert (for local services)..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
 -subj "/CN=jp-vpn.local" \
 -keyout /etc/jpvpn/private.key -out /etc/jpvpn/cert.crt >/dev/null 2>&1 || true

# ---------- Firewall ----------
ufw allow 22/tcp || true
ufw allow ${WS_PORT}/tcp || true
ufw allow ${BADVPN_PORT}/udp || true
ufw allow ${ZIVPN_PORT}/udp || true
ufw allow ${HYSTERIA_PORT}/udp || true
ufw --force enable || true

# ---------- CLI Panel script (jppanel) ----------
JPPANEL_BIN="/usr/local/bin/jppanel"
cat > "${JPPANEL_BIN}" <<'SH'
#!/usr/bin/env bash
# JP-PANEL CLI (no auth) - simple menu
while true; do
  echo "========================================"
  echo "         JP-VPN CLI PANEL (no auth)"
  echo "========================================"
  echo "1) Tambah user SSH (username)"
  echo "2) Hapus user SSH (username)"
  echo "3) List users (passwd entries with /home=disabled)"
  echo "4) Tampilkan Hysteria password"
  echo "5) Ganti Hysteria password"
  echo "6) Hapus Hysteria password (stop hysteria)"
  echo "7) Restart services (panel,ws,hysteria,zivpn,badvpn)"
  echo "8) Exit"
  read -rp "Pilih nomor: " opt
  case "$opt" in
    1)
      read -rp "Masukkan username: " u
      if [ -z "$u" ]; then echo "Invalid"; continue; fi
      useradd -m -N -s /bin/false "$u" || echo "useradd failed"
      passwd "$u"
      echo "User $u dibuat."
      ;;
    2)
      read -rp "Masukkan username hapus: " u
      if [ -z "$u" ]; then echo "Invalid"; continue; fi
      userdel -r -f "$u" || echo "userdel failed"
      echo "User $u dihapus."
      ;;
    3)
      echo "Daftar users (non-system):"
      awk -F: '$3 >= 1000 {print $1":"$6}' /etc/passwd
      ;;
    4)
      if [ -f /etc/jpvpn/hysteria.pass ]; then
        echo "Hysteria password: $(cat /etc/jpvpn/hysteria.pass)"
      else
        echo "No hysteria password file."
      fi
      ;;
    5)
      read -rp "Masukkan password baru: " pw
      if [ -z "$pw" ]; then echo "Invalid"; continue; fi
      echo "$pw" > /etc/jpvpn/hysteria.pass
      chmod 600 /etc/jpvpn/hysteria.pass
      systemctl restart jpvpn-hysteria.service
      echo "Password hysteria diganti."
      ;;
    6)
      rm -f /etc/jpvpn/hysteria.pass
      systemctl stop jpvpn-hysteria.service
      echo "Hysteria password dihapus, service dihentikan."
      ;;
    7)
      systemctl restart jpvpn-panel.service jpvpn-ws.service jpvpn-hysteria.service jpvpn-zivpn.service jpvpn-badvpn.service
      echo "Restarted services."
      ;;
    8)
      echo "Keluar."
      exit 0
      ;;
    *)
      echo "Pilihan tidak valid."
      ;;
  esac
  echo
  read -rp "Tekan ENTER untuk kembali ke menu..."
done
SH

chmod +x "${JPPANEL_BIN}"
log "jppanel installed at ${JPPANEL_BIN}"

# ---------- lightweight "panel" systemd (so user can run as service if wanted) ----------
cat >/etc/systemd/system/jpvpn-panel.service <<EOF
[Unit]
Description=JP-VPN CLI Panel (dummy service)
After=network.target

[Service]
Type=simple
ExecStart=${JPPANEL_BIN}
Restart=on-failure
User=root
TTYPath=/dev/tty1

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
# do NOT enable as service by default (interactive). We'll run it at end for user.
# systemctl enable --now jpvpn-panel.service

# ---------- finish & auto-run panel ----------
log "Installation complete. Starting CLI panel now..."
echo
echo "========================================"
echo "JP-VPN INSTALLATION FINISHED"
echo "Hysteria port: ${HYSTERIA_PORT}"
echo "Hysteria password: ${HYSTERIA_PASS}"
echo "ZiVPN port: ${ZIVPN_PORT}"
echo "BadVPN port: ${BADVPN_PORT}"
echo "WS(SSH) port: ${WS_PORT}"
echo "To run panel later, use: sudo ${JPPANEL_CMD}"
echo "Installer log: ${INSTALL_LOG}"
echo "========================================"
echo
# run panel (interactive) immediately
exec ${JPPANEL_CMD}
