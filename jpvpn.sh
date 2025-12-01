#!/usr/bin/env bash
# JP-VPN ALL-IN CLI installer + CLI panel
# - Hysteria v1 (port 30000) with password JPOFFICIAL
# - ZiVPN (udp-zivpn)
# - BadVPN UDPGW
# - WebSocket->SSH bridge
# - Auto cert with acme.sh (if domain resolves)
# - CLI panel auto-run after install (no web)
#
# Usage: chmod +x jpvpn.sh && sudo ./jpvpn.sh
set -o pipefail
IFS=$'\n\t'
export DEBIAN_FRONTEND=noninteractive

# -------- CONFIG --------
DOMAIN="sg.vpnstore.my.id"        # domain (change if perlu)
HYSTERIA_PORT=30000
HYSTERIA_PASS="JPOFFICIAL"
ZIVPN_PORT=5667
BADVPN_PORT=7300
WS_PORT=8443

INSTALL_LOG="/var/log/jpvpn-install.log"
mkdir -p "$(dirname "$INSTALL_LOG")"
exec 3>&1 1>>"${INSTALL_LOG}" 2>&1

log(){ echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >&3; }

# helper apt to minimize dpkg prompts
apt_safe(){ apt-get -o Dpkg::Options::="--force-confdef" \
                 -o Dpkg::Options::="--force-confold" -y "$@"; }

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root" >&3
  exit 1
fi

log "Starting JP-VPN installer..."

# ---------- update & packages ----------
log "Updating apt & installing packages..."
apt_safe update || true
apt_safe upgrade || true
apt_safe install -y wget curl git ca-certificates build-essential \
  python3 python3-pip python3-venv openssh-server ufw sqlite3 jq socat unzip

# ensure openssh running
systemctl enable --now ssh || true

# install acme.sh
if [ ! -d /root/.acme.sh ]; then
  log "Installing acme.sh..."
  curl -sS https://get.acme.sh | SHELL=/bin/bash bash -s -- --install || true
fi
ACME_HOME=/root/.acme.sh

# create base dir
mkdir -p /etc/jpvpn /usr/local/bin /opt/jpvpn

# ---------- SSL: try acme, fallback self-signed ----------
USE_LETS=0
if [ -x "${ACME_HOME}/acme.sh" ]; then
  log "Issuing certificate for ${DOMAIN} using acme.sh (standalone)..."
  "${ACME_HOME}/acme.sh" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  "${ACME_HOME}/acme.sh" --issue -d "${DOMAIN}" --standalone --home "${ACME_HOME}" >/dev/null 2>&1 || true
  if [ -f "${ACME_HOME}/${DOMAIN}/fullchain.cer" ] || [ -f "${ACME_HOME}/${DOMAIN}/${DOMAIN}.cer" ]; then
    "${ACME_HOME}/acme.sh" --install-cert -d "${DOMAIN}" \
      --key-file /etc/jpvpn/private.key --fullchain-file /etc/jpvpn/cert.crt --home "${ACME_HOME}" >/dev/null 2>&1 || true
    if [ -f /etc/jpvpn/cert.crt ]; then
      USE_LETS=1
      log "Let's Encrypt cert installed"
    fi
  fi
fi

if [ "${USE_LETS}" -eq 0 ]; then
  log "Generating self-signed cert..."
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -subj "/CN=${DOMAIN}" -keyout /etc/jpvpn/private.key -out /etc/jpvpn/cert.crt >/dev/null 2>&1 || true
  log "Self-signed cert created at /etc/jpvpn"
fi

# ---------- BadVPN ----------
BAD_BIN="/usr/local/bin/badvpn-udpgw"
log "Downloading BadVPN..."
wget -qO "${BAD_BIN}" "https://github.com/ambrop72/badvpn/releases/download/1.999.130/badvpn-udpgw" || true
chmod +x "${BAD_BIN}" || true

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
systemctl enable --now jpvpn-badvpn.service || log "warn: badvpn may not have started"

# ---------- ZiVPN (udp-zivpn) ----------
ZIVPN_BIN="/usr/local/bin/udp-zivpn"
log "Downloading ZiVPN binary..."
wget -qO "${ZIVPN_BIN}" "https://github.com/zahidbd2/udp-zivpn/releases/latest/download/udp-zivpn-linux-amd64" || true
chmod +x "${ZIVPN_BIN}" || true

cat >/etc/jpvpn/zivpn.json <<JSON
{
  "listen": ":${ZIVPN_PORT}",
  "cert": "/etc/jpvpn/cert.crt",
  "key": "/etc/jpvpn/private.key",
  "obfs": "${HYSTERIA_PASS}",
  "auth": {
    "mode": "passwords",
    "config": ["${HYSTERIA_PASS}"]
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
systemctl enable --now jpvpn-zivpn.service || log "warn: zivpn may not have started"

# ---------- Hysteria v1 ----------
HYST_BIN="/usr/local/bin/hysteria"
log "Downloading Hysteria v1 (apernet/hysteria)..."
# try official releases (may be different repo). If your repo differs, update URL.
wget -qO "${HYST_BIN}" "https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-amd64" || true
chmod +x "${HYST_BIN}" || true

# create hysteria config (v1 style JSON)
cat >/etc/jpvpn/hysteria.json <<JSON
{
  "listen": "0.0.0.0:${HYSTERIA_PORT}",
  "obfs": "wss",
  "password": "${HYSTERIA_PASS}",
  "protocol": "udp",
  "up_mbps": 1000,
  "down_mbps": 1000,
  "recv_window_conn": 16777216,
  "recv_window": 67108864,
  "max_idle_timeout": 30,
  "disable_udp": false
}
JSON

cat >/etc/systemd/system/jpvpn-hysteria.service <<EOF
[Unit]
Description=JPVPN Hysteria v1 Service
After=network.target

[Service]
Type=simple
ExecStart=${HYST_BIN} server -c /etc/jpvpn/hysteria.json
Restart=always
User=root
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now jpvpn-hysteria.service || log "warn: hysteria may not have started"

# ---------- WebSocket -> SSH bridge (python websockets) ----------
WS_HELPER="/usr/local/bin/jpvpn-ws.py"
cat > "${WS_HELPER}" <<'PY'
#!/usr/bin/env python3
import asyncio, websockets, socket
async def handler(ws, path):
    s = socket.socket()
    try:
        s.connect(("127.0.0.1", 22))
    except:
        await ws.close()
        return
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
                data = s.recv(4096)
                if not data:
                    break
                await ws.send(data)
        except:
            pass
    await asyncio.gather(ws2tcp(), tcp2ws())
    try:
        s.close()
    except:
        pass

async def main():
    server = await websockets.serve(handler, "0.0.0.0", 8443)
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())
PY
chmod +x "${WS_HELPER}"

cat >/etc/systemd/system/jpvpn-ws.service <<EOF
[Unit]
Description=JPVPN WS->SSH bridge
After=network.target

[Service]
ExecStart=/usr/bin/python3 ${WS_HELPER}
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now jpvpn-ws.service || log "warn: ws bridge may not have started"

# ---------- firewall ----------
log "Applying UFW rules..."
ufw allow 22/tcp || true
ufw allow ${WS_PORT}/tcp || true
ufw allow ${BADVPN_PORT}/udp || true
ufw allow ${ZIVPN_PORT}/udp || true
ufw allow ${HYSTERIA_PORT}/tcp || true
ufw --force enable || true

# ---------- CLI Panel (jppanel) ----------
JPPANEL_BIN="/usr/local/bin/jppanel"
cat > "${JPPANEL_BIN}" <<'SH'
#!/usr/bin/env bash
# JP-OFFICIAL CLI PANEL
while true; do
  clear
  echo -e "======================================="
  echo -e "         JP-OFFICIAL PANEL (CLI)"
  echo -e "=======================================\n"

  # server info
  echo " SYSTEM  : $(lsb_release -ds 2>/dev/null || uname -srv)"
  echo " UPTIME  : $(uptime -p)"
  echo " RAM     : $(free -h | awk '/^Mem:/ {print $3\"/\"$2}')"
  echo " CPU CORES: $(nproc)"
  echo " ISP/IP  : $(curl -s ifconfig.co || echo 'N/A')"
  echo " DOMAIN  : ${DOMAIN}"
  echo
  # counts (simple)
  SSH_COUNT=$(awk -F: '$3>=1000{c++}END{print c+0}' /etc/passwd)
  echo " ACCOUNTS:"
  echo "   SSH     : ${SSH_COUNT}"
  # check services
  systemctl is-active --quiet jpvpn-zivpn && echo "   ZiVPN   : running" || echo "   ZiVPN   : stopped"
  systemctl is-active --quiet jpvpn-hysteria && echo "   Hysteria: running" || echo "   Hysteria: stopped"
  systemctl is-active --quiet jpvpn-badvpn && echo "   BadVPN  : running" || echo "   BadVPN  : stopped"

  echo
  echo "1) Add SSH user"
  echo "2) Delete SSH user"
  echo "3) List SSH users"
  echo "4) Show Hysteria password"
  echo "5) Change Hysteria password"
  echo "6) Remove Hysteria password (stop service)"
  echo "7) Restart services"
  echo "8) Show cert info"
  echo "0) Exit"
  echo
  read -rp "Choose: " opt
  case "$opt" in
    1)
      read -rp "Username to create: " u
      [ -z "$u" ] && { echo "Invalid"; sleep 1; continue; }
      useradd -m -N -s /bin/bash "$u" || echo "useradd failed"
      passwd "$u"
      echo "User $u created."
      ;;
    2)
      read -rp "Username to delete: " u
      [ -z "$u" ] && { echo "Invalid"; sleep 1; continue; }
      userdel -r -f "$u" || echo "userdel failed"
      echo "User $u removed."
      ;;
    3)
      echo "SSH users (uid>=1000):"
      awk -F: '$3 >= 1000 {print $1}' /etc/passwd
      ;;
    4)
      if [ -f /etc/jpvpn/hysteria.pass ]; then
        echo "Hysteria password: $(cat /etc/jpvpn/hysteria.pass)"
      else
        echo "No hysteria password file."
      fi
      ;;
    5)
      read -rp "New hysteria password: " pw
      [ -z "$pw" ] && { echo "Invalid"; sleep 1; continue; }
      echo "$pw" > /etc/jpvpn/hysteria.pass
      chmod 600 /etc/jpvpn/hysteria.pass
      # update hysteria config and restart
      jq --arg p "$pw" '.password=$p' /etc/jpvpn/hysteria.json > /tmp/hy.json && mv /tmp/hy.json /etc/jpvpn/hysteria.json || true
      systemctl restart jpvpn-hysteria.service
      echo "Password updated."
      ;;
    6)
      rm -f /etc/jpvpn/hysteria.pass
      systemctl stop jpvpn-hysteria.service
      echo "Hysteria password removed and service stopped."
      ;;
    7)
      systemctl restart jpvpn-hysteria.service jpvpn-zivpn.service jpvpn-badvpn.service jpvpn-ws.service
      echo "Services restarted."
      ;;
    8)
      echo "Cert files in /etc/jpvpn:"
      ls -l /etc/jpvpn || true
      ;;
    0)
      echo "Exiting."
      exit 0
      ;;
    *)
      echo "Invalid choice."
      ;;
  esac
  echo
  read -rp "Press ENTER to continue..."
done
SH

chmod +x "${JPPANEL_BIN}"
log "jppanel installed at ${JPPANEL_BIN}"

# store initial hysteria password file
echo "${HYSTERIA_PASS}" > /etc/jpvpn/hysteria.pass
chmod 600 /etc/jpvpn/hysteria.pass

# ---------- service unit for panel (not auto enable interactive) ----------
cat >/etc/systemd/system/jpvpn-panel.service <<EOF
[Unit]
Description=JP-OFFICIAL CLI Panel (interactive)
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

# ---------- DONE ----------
log "Installation finished. Details:"
log "Hysteria port: ${HYSTERIA_PORT}, password: ${HYSTERIA_PASS}"
log "ZiVPN port: ${ZIVPN_PORT}, obfs/auth: ${HYSTERIA_PASS}"
log "BadVPN port: ${BADVPN_PORT}"
log "WS->SSH port: ${WS_PORT}"
log "Certificate used: $( [ -f /etc/jpvpn/cert.crt ] && echo yes || echo no )"
echo
echo "========================================" >&3
echo "JP-VPN INSTALLER FINISHED" >&3
echo "Run panel: sudo ${JPPANEL_BIN}" >&3
echo "Or it will auto-run now (interactive)." >&3
echo "Installer log: ${INSTALL_LOG}" >&3
echo "========================================" >&3
echo

# start interactive panel now
exec ${JPPANEL_BIN}
