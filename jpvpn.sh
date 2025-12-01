#!/usr/bin/env bash
set -o pipefail
IFS=$'\n\t'
export DEBIAN_FRONTEND=noninteractive

# ----------------- CONFIG (default, bisa diganti saat runtime) -----------------
DEFAULT_HYST_PORT=30000
DEFAULT_HYST_PASS="JPOFFICIAL"
DEFAULT_ZIVPN_PORT=5667
DEFAULT_BADVPN_PORT=7300
DEFAULT_WS_PORT=8443

INSTALL_LOG="/var/log/jpofficial-install.log"
mkdir -p "$(dirname "$INSTALL_LOG")"
exec 3>&1 1>>"${INSTALL_LOG}" 2>&1

log(){ echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >&3; }

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root" >&3
  exit 1
fi

echo
echo "======================================"
echo " JP-OFFICIAL / FIGHTERTUNNEL INSTALLER"
echo "======================================"
echo

read -rp "Enter domain to use (A record must point to this server) : " DOMAIN
DOMAIN="${DOMAIN:-sg.vpnstore.my.id}"
read -rp "Hysteria port [${DEFAULT_HYST_PORT}]: " HYST_PORT
HYST_PORT="${HYST_PORT:-${DEFAULT_HYST_PORT}}"
read -rp "Hysteria password [${DEFAULT_HYST_PASS}]: " HYST_PASS
HYST_PASS="${HYST_PASS:-${DEFAULT_HYST_PASS}}"
read -rp "ZiVPN UDP port [${DEFAULT_ZIVPN_PORT}]: " ZIVPN_PORT
ZIVPN_PORT="${ZIVPN_PORT:-${DEFAULT_ZIVPN_PORT}}"
read -rp "BadVPN UDP port [${DEFAULT_BADVPN_PORT}]: " BADVPN_PORT
BADVPN_PORT="${BADVPN_PORT:-${DEFAULT_BADVPN_PORT}}"
read -rp "WS->SSH port [${DEFAULT_WS_PORT}]: " WS_PORT
WS_PORT="${WS_PORT:-${DEFAULT_WS_PORT}}"

log "Installer started for domain=${DOMAIN}"

# helper apt
apt_safe(){
  # avoid interactive dpkg prompts
  DEBIAN_FRONTEND=noninteractive \
  apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y "$@"
}

# ensure no broken dpkg
dpkg --configure -a >/dev/null 2>&1 || true
apt_safe update || true

log "Installing required packages..."
apt_safe install -y wget curl git ca-certificates build-essential \
  python3 python3-pip python3-venv openssh-server ufw jq socat unzip netcat-openbsd

systemctl enable --now ssh || true

# install acme.sh
if [ ! -x /root/.acme.sh/acme.sh ]; then
  log "Installing acme.sh ..."
  curl -sS https://get.acme.sh | SHELL=/bin/bash bash -s -- --install >/dev/null 2>&1 || true
fi
ACME_HOME="/root/.acme.sh"

# make dirs
mkdir -p /etc/jpofficial /usr/local/bin /opt/jpofficial

# Try issuing Let's Encrypt cert (standalone). If fail => self-signed
USE_LETS=0
if [ -x "${ACME_HOME}/acme.sh" ]; then
  log "Attempting to issue Let's Encrypt cert for ${DOMAIN}..."
  "${ACME_HOME}/acme.sh" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  "${ACME_HOME}/acme.sh" --issue -d "${DOMAIN}" --standalone --home "${ACME_HOME}" >/dev/null 2>&1 || true
  if [ -f "${ACME_HOME}/${DOMAIN}/fullchain.cer" ] || [ -f "${ACME_HOME}/${DOMAIN}/${DOMAIN}.cer" ]; then
    "${ACME_HOME}/acme.sh" --install-cert -d "${DOMAIN}" \
      --key-file /etc/jpofficial/private.key --fullchain-file /etc/jpofficial/cert.crt --home "${ACME_HOME}" >/dev/null 2>&1 || true
    if [ -f /etc/jpofficial/cert.crt ]; then
      USE_LETS=1
      log "Let's Encrypt cert installed."
    fi
  fi
fi

if [ "${USE_LETS}" -eq 0 ]; then
  log "Let's Encrypt unavailable -> Generating self-signed cert..."
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -subj "/CN=${DOMAIN}" -keyout /etc/jpofficial/private.key -out /etc/jpofficial/cert.crt >/dev/null 2>&1 || true
  log "Self-signed cert created at /etc/jpofficial"
fi

# ---------- BadVPN ----------
BAD_BIN="/usr/local/bin/badvpn-udpgw"
log "Downloading BadVPN binary..."
wget -qO "${BAD_BIN}" "https://github.com/ambrop72/badvpn/releases/download/1.999.130/badvpn-udpgw" || true
chmod +x "${BAD_BIN}" || true

cat >/etc/systemd/system/jpofficial-badvpn.service <<EOF
[Unit]
Description=JPOFFICIAL BadVPN UDPGW
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
systemctl enable --now jpofficial-badvpn.service || log "warn: badvpn may not have started"

# ---------- ZiVPN ----------
ZIVPN_BIN="/usr/local/bin/udp-zivpn"
log "Downloading ZiVPN binary..."
wget -qO "${ZIVPN_BIN}" "https://github.com/zahidbd2/udp-zivpn/releases/latest/download/udp-zivpn-linux-amd64" || true
chmod +x "${ZIVPN_BIN}" || true

cat >/etc/jpofficial/zivpn.json <<JSON
{
  "listen": ":${ZIVPN_PORT}",
  "cert": "/etc/jpofficial/cert.crt",
  "key": "/etc/jpofficial/private.key",
  "obfs": "${HYST_PASS}",
  "auth": {
    "mode": "passwords",
    "config": ["${HYST_PASS}"]
  }
}
JSON

cat >/etc/systemd/system/jpofficial-zivpn.service <<EOF
[Unit]
Description=JPOFFICIAL ZiVPN
After=network.target

[Service]
ExecStart=${ZIVPN_BIN} -c /etc/jpofficial/zivpn.json
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now jpofficial-zivpn.service || log "warn: zivpn may not have started"

# ---------- Hysteria v1 ----------
HYST_BIN="/usr/local/bin/hysteria"
log "Downloading Hysteria v1 binary..."
wget -qO "${HYST_BIN}" "https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-amd64" || true
chmod +x "${HYST_BIN}" || true

# hysteria v1 config
cat >/etc/jpofficial/hysteria.json <<JSON
{
  "listen": "0.0.0.0:${HYST_PORT}",
  "obfs": "",
  "password": "${HYST_PASS}",
  "protocol": "udp",
  "up_mbps": 1000,
  "down_mbps": 1000,
  "recv_window_conn": 16777216,
  "recv_window": 67108864,
  "max_idle_timeout": 30,
  "disable_udp": false
}
JSON

cat >/etc/systemd/system/jpofficial-hysteria.service <<EOF
[Unit]
Description=JPOFFICIAL Hysteria v1
After=network.target

[Service]
Type=simple
ExecStart=${HYST_BIN} server -c /etc/jpofficial/hysteria.json
Restart=always
User=root
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now jpofficial-hysteria.service || log "warn: hysteria may not have started"

# ---------- WS->SSH bridge ----------
WS_HELPER="/usr/local/bin/jpofficial-ws.py"
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
    server = await websockets.serve(handler, "0.0.0.0", int("${WS_PORT}"))
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())
PY
chmod +x "${WS_HELPER}" || true

cat >/etc/systemd/system/jpofficial-ws.service <<EOF
[Unit]
Description=JPOFFICIAL WS->SSH bridge
After=network.target

[Service]
ExecStart=/usr/bin/python3 ${WS_HELPER}
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now jpofficial-ws.service || log "warn: ws bridge may not have started"

# ---------- firewall (ufw) ----------
log "Applying UFW rules..."
ufw allow 22/tcp || true
ufw allow ${WS_PORT}/tcp || true
ufw allow ${BADVPN_PORT}/udp || true
ufw allow ${ZIVPN_PORT}/udp || true
ufw allow ${HYST_PORT}/udp || true
ufw --force enable || true

# ---------- store hysteria pass ----------
mkdir -p /etc/jpofficial
echo "${HYST_PASS}" >/etc/jpofficial/hysteria.pass
chmod 600 /etc/jpofficial/hysteria.pass

# ---------- CLI PANEL (FIGHTERTUNNEL-like) ----------
JPPANEL_BIN="/usr/local/bin/jpofficial-panel"
cat > "${JPPANEL_BIN}" <<'SH'
#!/usr/bin/env bash
# JPOFFICIAL / FIGHTERTUNNEL - CLI PANEL
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
RESET="\e[0m"

while true; do
  clear
  echo -e "${CYAN}.:.:.: JP OFFICIAL :.:.:.${RESET}\n"
  echo -e "${YELLOW}● SYSTEM      :${RESET} $(lsb_release -ds 2>/dev/null || uname -srv)"
  echo -e "${YELLOW}● RAM         :${RESET} $(free -h | awk '/^Mem:/ {print $3\" / \"$2}')"
  echo -e "${YELLOW}● ISP         :${RESET} $(curl -s ifconfig.co/org || echo 'N/A')"
  echo -e "${YELLOW}● CITY        :${RESET} $(curl -s ifconfig.co/city || echo 'N/A')"
  echo -e "${YELLOW}● IP          :${RESET} $(curl -s ifconfig.co || echo 'N/A')"
  echo -e "${YELLOW}● DOMAIN      :${RESET} ${DOMAIN}"
  echo -e "${YELLOW}● NS          :${RESET} cloudflare-dns.com"
  echo "------------------------------------------"
  SSH_CT=$(awk -F: '$3>=1000{c++}END{print c+0}' /etc/passwd)
  ZIP_CT=0
  HYST_CT=$( [ -f /etc/jpofficial/hysteria.pass ] && echo 1 || echo 0 )
  echo -e "${GREEN} SSH/UDP CUSTUM    :${RESET} ${SSH_CT} ACCOUNT"
  echo -e "${GREEN} ZIPVPN     :${RESET} ${ZIP_CT} ACCOUNT"
  echo -e "${GREEN} HYSTERIA    :${RESET} ${HYST_CT} ACCOUNT"
  echo "------------------------------------------"
  echo -e " 1. SSH/UDP CUSTUM MANAGER"
  echo -e " 2. ZIPVPN MANAGER"
  echo -e " 3. HYSTERIA MANAGER"
  echo
  echo -e " SCRIPT VERSION: V1.0 LTS"
  echo
  read -rp "Choose: " opt
  case "$opt" in
    1)
      clear
      echo "SSH/UDP CUSTUM MANAGER"
      echo "1) Add SSH user"
      echo "2) Delete SSH user"
      echo "3) List SSH users"
      echo "4) Back"
      read -rp "Choose: " o
      case "$o" in
        1)
          read -rp "Username: " u
          [ -z "$u" ] && { echo "Invalid"; sleep 1; continue; }
          useradd -m -N -s /bin/bash "$u" || echo "useradd failed"
          passwd "$u"
          echo "Created $u"
          read -rp "Press ENTER..."
          ;;
        2)
          read -rp "Username to delete: " u
          [ -z "$u" ] && { echo "Invalid"; sleep 1; continue; }
          userdel -r -f "$u" || echo "userdel failed"
          echo "Removed $u"
          read -rp "Press ENTER..."
          ;;
        3)
          echo "SSH users (uid>=1000):"
          awk -F: '$3>=1000{print $1}' /etc/passwd
          read -rp "Press ENTER..."
          ;;
      esac
      ;;
    2)
      clear
      echo "ZIPVPN MANAGER"
      echo "ZipVPN is the ZiVPN UDP server. Config: /etc/jpofficial/zivpn.json"
      echo "1) Show config"
      echo "2) Restart ZiVPN"
      echo "3) Back"
      read -rp "Choose: " o
      case "$o" in
        1) cat /etc/jpofficial/zivpn.json; read -rp "Press ENTER...";;
        2) systemctl restart jpofficial-zivpn.service && echo "Restarted"; read -rp "Press ENTER...";;
      esac
      ;;
    3)
      clear
      echo "HYSTERIA MANAGER"
      echo "1) Show Hysteria password"
      echo "2) Change Hysteria password"
      echo "3) Restart Hysteria"
      echo "4) Stop Hysteria (remove password file)"
      echo "5) Back"
      read -rp "Choose: " o
      case "$o" in
        1) cat /etc/jpofficial/hysteria.pass || echo "No password file"; read -rp "Press ENTER...";;
        2)
          read -rp "New password: " pw
          [ -z "$pw" ] && { echo "Invalid"; sleep 1; continue; }
          echo "$pw" >/etc/jpofficial/hysteria.pass
          chmod 600 /etc/jpofficial/hysteria.pass
          # update JSON
          if command -v jq >/dev/null 2>&1; then
            jq --arg p "$pw" '.password=$p' /etc/jpofficial/hysteria.json >/tmp/hy.$$ && mv /tmp/hy.$$ /etc/jpofficial/hysteria.json
          else
            sed -i "s/\"password\":.*$/\"password\":\"$pw\",/" /etc/jpofficial/hysteria.json || true
          fi
          systemctl restart jpofficial-hysteria.service
          echo "Password updated."
          read -rp "Press ENTER..."
          ;;
        3) systemctl restart jpofficial-hysteria.service && echo "Restarted"; read -rp "Press ENTER...";;
        4) rm -f /etc/jpofficial/hysteria.pass; systemctl stop jpofficial-hysteria.service; echo "Stopped"; read -rp "Press ENTER...";;
      esac
      ;;
    *)
      echo "Invalid"
      sleep 1
      ;;
  esac
done
SH

chmod +x "${JPPANEL_BIN}" || true
log "Panel installed at ${JPPANEL_BIN}"

# set DOMAIN variable for panel (so the panel script can show it)
# we'll write it into panel file with simple replacement (safe)
if grep -q "DOMAIN" "${JPPANEL_BIN}" >/dev/null 2>&1; then
  sed -i "s/^  echo -e \"${YELLOW}● DOMAIN      :${RESET} .*\"/  echo -e \"${YELLOW}● DOMAIN      :${RESET} ${DOMAIN}\"/" "${JPPANEL_BIN}" 2>/dev/null || true
fi

# write runtime DOMAIN value to a small loader (so panel sees it)
cat >/usr/local/bin/jpofficial-runpanel <<EOF
#!/usr/bin/env bash
DOMAIN="${DOMAIN}"
export DOMAIN
exec ${JPPANEL_BIN}
EOF
chmod +x /usr/local/bin/jpofficial-runpanel || true

# ---------- finish ----------
log "Installation finished."
log "Hysteria port: ${HYST_PORT}, password: ${HYST_PASS}"
log "ZiVPN port: ${ZIVPN_PORT}"
log "BadVPN port: ${BADVPN_PORT}"
log "WS->SSH port: ${WS_PORT}"
log "Certificate used: $( [ -f /etc/jpofficial/cert.crt ] && echo yes || echo no )"

echo
echo "========================================" >&3
echo "JPOFFICIAL INSTALLER FINISHED" >&3
echo "Run panel: sudo /usr/local/bin/jpofficial-runpanel" >&3
echo "Installer log: ${INSTALL_LOG}" >&3
echo "========================================" >&3
echo

# exec panel interactive now
exec /usr/local/bin/jpofficial-runpanel
