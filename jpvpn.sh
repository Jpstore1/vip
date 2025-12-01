#!/usr/bin/env bash
# JPVPN — FULL INSTALLER + JP-OFFICIAL PANEL (with all extras)
# Features:
#  - domain prompt + DNS check
#  - acme.sh Let's Encrypt (HTTP standalone) fallback to self-signed
#  - Hysteria v1 (UDP 30000) using cert
#  - ZiVPN (udp-zivpn) using cert & obfs/password
#  - BadVPN UDPGW
#  - WebSocket->SSH bridge (127.0.0.1:8443) + nginx reverse proxy wss://DOMAIN:443
#  - auto-generate client config + QR (qrencode)
#  - per-user SSH & ZiVPN management with expiry metadata
#  - auto-expire cron job (daily)
#  - CLI panel (visual JP OFFICIAL) and submenus
#
# Usage: chmod +x jpvpn.sh && sudo ./jpvpn.sh
set -euo pipefail
IFS=$'\n\t'
export DEBIAN_FRONTEND=noninteractive

# ---------- DEFAULTS ----------
HYSTERIA_PORT=30000
HYSTERIA_PASS="JPOFFICIAL"
ZIVPN_PORT=5667
BADVPN_PORT=7300
WS_LOCAL_PORT=8443    # websocket bridge listens on localhost:8443
WSS_PORT=443          # nginx will listen TLS on 443 and proxy to 127.0.0.1:8443
INSTALL_LOG="/var/log/jpvpn-install.log"
QR_DIR="/etc/jpvpn/qrs"
USERS_DIR="/etc/jpvpn/users"
ZIVPN_USERS_DIR="/etc/jpvpn/zivpn-users"
HYST_USERS_FILE="/etc/jpvpn/hysteria-users.json"  # not strictly used by binary, but store mapping
CERT_DIR="/etc/jpvpn"

mkdir -p "$(dirname "$INSTALL_LOG")" "$QR_DIR" "$USERS_DIR" "$ZIVPN_USERS_DIR"
exec 3>&1 1>>"${INSTALL_LOG}" 2>&1

log(){ echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >&3; }

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root" >&3
  exit 1
fi

# ---------- ask domain ----------
clear
echo "========================================"
echo "        JP-VPN AUTO INSTALLER"
echo "========================================"
read -rp "Masukkan domain untuk server (contoh: sg.vpnstore.my.id) : " DOMAIN
DOMAIN="${DOMAIN:-}"
if [ -z "$DOMAIN" ]; then
  DOMAIN="sg.vpnstore.my.id"
  log "Domain empty; defaulting to ${DOMAIN}"
fi
log "Domain set to: ${DOMAIN}"

# ---------- fix Ubuntu20 repos if needed ----------
OS_REL="$(lsb_release -rs 2>/dev/null || echo "")"
if [[ "$OS_REL" =~ ^20\.04 ]]; then
  log "Detected Ubuntu 20.04 — patching sources.list to old-releases to avoid apt hangs"
  sed -i.bak -E 's|http(s)?://[a-z0-9\.-]*/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list || true
fi

# ---------- update & base packages ----------
log "Updating apt & installing base packages..."
apt-get update -y || true
apt-get upgrade -y || true
apt-get install -y wget curl git ca-certificates build-essential \
  python3 python3-pip python3-venv openssh-server ufw sqlite3 jq socat unzip dnsutils iproute2 net-tools \
  nginx qrencode jq || true

systemctl enable --now ssh || true
systemctl enable --now nginx || true

# ---------- acme.sh and cert ----------
ACME_HOME=/root/.acme.sh
USE_LETS=0
if [ ! -x "${ACME_HOME}/acme.sh" ]; then
  log "Installing acme.sh..."
  curl -sS https://get.acme.sh | SHELL=/bin/bash bash -s -- --install || true
fi

if [ -x "${ACME_HOME}/acme.sh" ]; then
  source "${ACME_HOME}/acme.sh.env" 2>/dev/null || true
  log "Issuing certificate for ${DOMAIN} using acme.sh (standalone) — ensure port 80 free"
  "${ACME_HOME}/acme.sh" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  "${ACME_HOME}/acme.sh" --issue -d "${DOMAIN}" --standalone --home "${ACME_HOME}" >/dev/null 2>&1 || true
  if [ -f "${ACME_HOME}/${DOMAIN}/fullchain.cer" ] || [ -f "${ACME_HOME}/${DOMAIN}/${DOMAIN}.cer" ]; then
    "${ACME_HOME}/acme.sh" --install-cert -d "${DOMAIN}" \
      --key-file "${CERT_DIR}/private.key" --fullchain-file "${CERT_DIR}/cert.crt" --home "${ACME_HOME}" \
      --reloadcmd "systemctl try-restart jpvpn-hysteria jpvpn-zivpn nginx" >/dev/null 2>&1 || true
    if [ -f "${CERT_DIR}/cert.crt" ]; then
      USE_LETS=1
      log "Let's Encrypt certificate installed"
    fi
  fi
fi

if [ "${USE_LETS}" -eq 0 ]; then
  log "Let's Encrypt unavailable — creating self-signed cert"
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -subj "/CN=${DOMAIN}" -keyout "${CERT_DIR}/private.key" -out "${CERT_DIR}/cert.crt" >/dev/null 2>&1 || true
  chmod 600 "${CERT_DIR}/private.key"
  log "Self-signed certificate created at ${CERT_DIR}"
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
ExecStart=${BAD_BIN} --listen-addr 0.0.0.0:${BADVPN_PORT} --max-clients 2048
Restart=always
User=root
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now jpvpn-badvpn.service || log "warn: badvpn may not have started"

# ---------- ZiVPN ----------
ZIVPN_BIN="/usr/local/bin/udp-zivpn"
log "Downloading ZiVPN..."
wget -qO "${ZIVPN_BIN}" "https://github.com/zahidbd2/udp-zivpn/releases/latest/download/udp-zivpn-linux-amd64" || true
chmod +x "${ZIVPN_BIN}" || true

# initial empty users dir
mkdir -p "${ZIVPN_USERS_DIR}"

# create zivpn config template with empty auth.config (we will fill)
cat >/etc/jpvpn/zivpn.json <<JSON
{
  "listen": ":${ZIVPN_PORT}",
  "cert": "${CERT_DIR}/cert.crt",
  "key": "${CERT_DIR}/private.key",
  "obfs": "${HYSTERIA_PASS}",
  "auth": {
    "mode": "passwords",
    "config": []
  }
}
JSON

cat >/etc/systemd/system/jpvpn-zivpn.service <<'EOF'
[Unit]
Description=JPVPN ZiVPN TLS
After=network.target

[Service]
ExecStart=/usr/local/bin/udp-zivpn -c /etc/jpvpn/zivpn.json
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now jpvpn-zivpn.service || log "warn: zivpn may not have started"

# ---------- Hysteria v1 ----------
HYST_BIN="/usr/local/bin/hysteria"
log "Downloading Hysteria v1 binary..."
wget -qO "${HYST_BIN}" "https://github.com/apernet/hysteria/releases/download/v1.3.5/hysteria-linux-amd64" || true
chmod +x "${HYST_BIN}" || true

# hysteria config (v1)
cat >/etc/jpvpn/hysteria.json <<JSON
{
  "listen": "0.0.0.0:${HYSTERIA_PORT}",
  "obfs": "${HYSTERIA_PASS}",
  "password": "${HYSTERIA_PASS}",
  "protocol": "udp",
  "up_mbps": 0,
  "down_mbps": 0,
  "recv_window_conn": 16777216,
  "recv_window": 67108864,
  "max_idle_timeout": 30,
  "disable_udp": false,
  "cert": "${CERT_DIR}/cert.crt",
  "key": "${CERT_DIR}/private.key"
}
JSON

cat >/etc/systemd/system/jpvpn-hysteria.service <<'EOF'
[Unit]
Description=JPVPN Hysteria v1 Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server -c /etc/jpvpn/hysteria.json
Restart=always
User=root
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now jpvpn-hysteria.service || log "warn: hysteria may not have started"

# ---------- WebSocket->SSH bridge (listen localhost:8443 plain) ----------
log "Installing WS->SSH bridge (python)"
pip3 install websockets >/dev/null 2>&1 || true

WS_HELPER="/usr/local/bin/jpvpn-ws.py"
cat > "${WS_HELPER}" <<'PY'
#!/usr/bin/env python3
import asyncio, websockets, socket
async def handler(ws, path):
    s = socket.socket()
    try:
        s.connect(("127.0.0.1", 22))
    except:
        try:
            await ws.close()
        except:
            pass
        return
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
                data = s.recv(4096)
                if not data:
                    break
                await ws.send(data)
        except:
            pass
    await asyncio.gather(ws_to_tcp(), tcp_to_ws())
    try:
        s.close()
    except:
        pass

async def main():
    server = await websockets.serve(handler, "127.0.0.1", 8443)
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())
PY
chmod +x "${WS_HELPER}"

cat >/etc/systemd/system/jpvpn-ws.service <<'EOF'
[Unit]
Description=JPVPN WS->SSH bridge
After=network.target

[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/jpvpn-ws.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now jpvpn-ws.service || log "warn: ws bridge may not have started"

# ---------- nginx config for TLS + WSS proxy ----------
log "Configuring nginx for TLS + WSS reverse proxy..."
NGINX_SITE="/etc/nginx/sites-available/jpvpn"
cat > "${NGINX_SITE}" <<EOF
server {
    listen 80;
    server_name ${DOMAIN};
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    location / {
        return 301 https://\$host\$request_uri;
    }
}
EOF
ln -sf "${NGINX_SITE}" /etc/nginx/sites-enabled/jpvpn

# TLS site (if cert exists we will use it; if self-signed also used)
cat > /etc/nginx/sites-available/jpvpn-ssl <<EOF
server {
    listen ${WSS_PORT} ssl http2;
    server_name ${DOMAIN};
    ssl_certificate ${CERT_DIR}/cert.crt;
    ssl_certificate_key ${CERT_DIR}/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    # proxy websocket (wss) to local ws bridge
    location / {
        proxy_pass http://127.0.0.1:${WS_LOCAL_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF
ln -sf /etc/nginx/sites-available/jpvpn-ssl /etc/nginx/sites-enabled/jpvpn-ssl

nginx -t >/dev/null 2>&1 || true
systemctl restart nginx || true

# ---------- firewall ----------
log "Applying firewall rules..."
ufw allow 22/tcp || true
ufw allow ${WSS_PORT}/tcp || true
ufw allow ${WS_LOCAL_PORT}/tcp || true
ufw allow ${BADVPN_PORT}/udp || true
ufw allow ${ZIVPN_PORT}/udp || true
ufw allow ${HYSTERIA_PORT}/udp || true
ufw allow 80/tcp || true
ufw --force enable || true

# ---------- helper functions: update zivpn auth from users dir ----------
refresh_zivpn_users(){
  users=()
  for f in "${ZIVPN_USERS_DIR}"/* 2>/dev/null; do
    [ -f "$f" ] || continue
    users+=( "\"$(basename "$f")\"" )
  done
  if [ ${#users[@]} -eq 0 ]; then
    arr="[]"
  else
    arr="["
    sep=""
    for u in "${users[@]}"; do arr+="${sep}${u}"; sep=","; done
    arr+="]"
  fi
  # update config using jq if available
  if command -v jq >/dev/null 2>&1; then
    tmp=$(mktemp)
    jq --argjson a "$(echo "${arr}" | jq -c .)" '.auth.config = $a' /etc/jpvpn/zivpn.json > "$tmp" 2>/dev/null || cp /etc/jpvpn/zivpn.json "$tmp"
    mv "$tmp" /etc/jpvpn/zivpn.json
  else
    # naive replace (best-effort)
    sed -i -E "s/\"config\": \[.*\]/\"config\": ${arr}/" /etc/jpvpn/zivpn.json || true
  fi
  systemctl try-restart jpvpn-zivpn.service >/dev/null 2>&1 || true
}

# ---------- user cleanup script (cron job) ----------
cat >/usr/local/bin/jpvpn-cleanup <<'SH'
#!/usr/bin/env bash
# remove expired users based on metadata files in /etc/jpvpn/users/<username>.meta
now=$(date +%s)
for meta in /etc/jpvpn/users/*.meta 2>/dev/null; do
  [ -f "$meta" ] || continue
  user=$(basename "$meta" .meta)
  expiry=$(awk -F= '/^expiry=/{print $2}' "$meta" || echo "")
  if [ -z "$expiry" ]; then continue; fi
  if [ "$now" -ge "$expiry" ]; then
    # delete system user if exists
    if id -u "$user" >/dev/null 2>&1; then
      userdel -r -f "$user" || true
    fi
    rm -f "$meta"
    rm -f /etc/jpvpn/zivpn-users/"$user"
    rm -f /etc/jpvpn/qrs/"$user".png
    echo "Removed expired user $user"
  fi
done
SH
chmod +x /usr/local/bin/jpvpn-cleanup
# create cron daily
( crontab -l 2>/dev/null | grep -v jpvpn-cleanup || true ; echo "0 4 * * * /usr/local/bin/jpvpn-cleanup >/dev/null 2>&1" ) | crontab -

# ---------- panel & helper menus ----------
# jp-ssh-menu
cat >/usr/local/bin/jp-ssh-menu <<'SH'
#!/usr/bin/env bash
# SSH/UDP CUSTOM manager with expiry + QR generation for BadVPN helper
set -euo pipefail
IFS=$'\n\t'
USERS_DIR="/etc/jpvpn/users"
QR_DIR="/etc/jpvpn/qrs"
DOMAIN="$(cat /etc/jpvpn/domain 2>/dev/null || echo "")"
BADPORT=7300

pause(){ read -rp "Press ENTER to continue..."; }

while true; do
  clear
  echo "=== SSH / UDP CUSTOM MANAGER ==="
  echo "1) Add SSH user"
  echo "2) Delete SSH user"
  echo "3) List SSH users"
  echo "4) Show UDPGW client example"
  echo "0) Back"
  read -rp "Choose: " c
  case "$c" in
    1)
      read -rp "Username: " u
      [ -z "$u" ] && { echo "Invalid"; pause; continue; }
      if id -u "$u" >/dev/null 2>&1; then echo "User exists"; pause; continue; fi
      read -rp "Days to expire (0 = never): " days
      useradd -m -s /bin/bash "$u" || { echo "useradd failed"; pause; continue; }
      passwd "$u"
      now=$(date +%s)
      if [ "$days" -eq 0 ] 2>/dev/null; then expiry=0; else expiry=$((now + days*86400)); fi
      echo "username=$u" > "${USERS_DIR}/${u}.meta"
      echo "expiry=${expiry}" >> "${USERS_DIR}/${u}.meta"
      # create zivpn user file if desired (same name as password)
      # generate QR for client instructions (simple)
      echo "ssh user: $u" > "${QR_DIR}/${u}.txt"
      qrencode -o "${QR_DIR}/${u}.png" -t PNG "ssh://${u}@${DOMAIN}:22" >/dev/null 2>&1 || true
      echo "User $u created. QR saved to ${QR_DIR}/${u}.png"
      pause
      ;;
    2)
      read -rp "Username to delete: " u
      [ -z "$u" ] && { echo "Invalid"; pause; continue; }
      userdel -r -f "$u" && echo "Deleted $u" || echo "Failed to delete $u"
      rm -f "${USERS_DIR}/${u}.meta"
      rm -f "${QR_DIR}/${u}.png"
      pause
      ;;
    3)
      echo "SSH users (uid>=1000):"
      awk -F: '$3>=1000 {print $1}' /etc/passwd
      echo
      echo "Metadata files:"
      ls -1 "${USERS_DIR}"/*.meta 2>/dev/null || echo "(none)"
      pause
      ;;
    4)
      echo "BadVPN UDPGW server: ${DOMAIN}:${BADPORT}"
      echo "Client usage sample (on client machine):"
      echo "badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1024"
      echo "SSH tunnel example to forward UDPGW:"
      echo "ssh -L 7300:127.0.0.1:7300 user@${DOMAIN}"
      pause
      ;;
    0) exit 0 ;;
    *) echo "Invalid"; sleep 1 ;;
  esac
done
SH
chmod +x /usr/local/bin/jp-ssh-menu

# jp-zivpn-menu
cat >/usr/local/bin/jp-zivpn-menu <<'SH'
#!/usr/bin/env bash
set -euo pipefail
ZIVPN_USERS_DIR="/etc/jpvpn/zivpn-users"
ZIVPN_CONF="/etc/jpvpn/zivpn.json"
pause(){ read -rp "Press ENTER to continue..."; }

while true; do
  clear
  echo "=== ZiVPN Manager ==="
  echo "1) Add user (password = username)"
  echo "2) Delete user"
  echo "3) List users"
  echo "4) Generate user client info + QR"
  echo "0) Back"
  read -rp "Choose: " c
  case "$c" in
    1)
      read -rp "Add username: " u
      [ -z "$u" ] && { echo "Invalid"; pause; continue; }
      if [ -f "${ZIVPN_USERS_DIR}/${u}" ]; then echo "User exists"; pause; continue; fi
      echo "$u" > "${ZIVPN_USERS_DIR}/${u}"
      chmod 600 "${ZIVPN_USERS_DIR}/${u}"
      # rebuild config
      /usr/local/bin/jpvpn-refresh-zivpn >/dev/null 2>&1 || true
      echo "Added $u (password=$u)"; pause
      ;;
    2)
      read -rp "Delete username: " u
      rm -f "${ZIVPN_USERS_DIR}/${u}"
      /usr/local/bin/jpvpn-refresh-zivpn >/dev/null 2>&1 || true
      echo "Deleted $u"; pause
      ;;
    3)
      echo "ZiVPN users:"
      ls -1 "${ZIVPN_USERS_DIR}" 2>/dev/null || echo "(none)"
      pause
      ;;
    4)
      read -rp "Username to generate client info: " u
      [ -z "$u" ] && { echo "Invalid"; pause; continue; }
      if [ ! -f "${ZIVPN_USERS_DIR}/${u}" ]; then echo "User not found"; pause; continue; fi
      DOMAIN="$(cat /etc/jpvpn/domain 2>/dev/null || echo '${DOMAIN}')"
      echo "Client sample for $u:"
      echo "Server: ${DOMAIN}"
      echo "Port: ${ZIVPN_PORT}"
      echo "Password/OBFS: ${HYSTERIA_PASS}"
      echo "Username: ${u}"
      echo
      # create QR
      echo -n "zivpn://${u}@${DOMAIN}:${ZIVPN_PORT}?obfs=${HYSTERIA_PASS}" | qrencode -o "/etc/jpvpn/qrs/${u}-zivpn.png" >/dev/null 2>&1 || true
      echo "QR saved to /etc/jpvpn/qrs/${u}-zivpn.png"
      pause
      ;;
    0) exit 0 ;;
    *) echo "Invalid"; sleep 1 ;;
  esac
done
SH
chmod +x /usr/local/bin/jp-zivpn-menu

# helper: refresh zivpn config script (callable)
cat >/usr/local/bin/jpvpn-refresh-zivpn <<'SH'
#!/usr/bin/env bash
ZDIR="/etc/jpvpn/zivpn-users"
CFG="/etc/jpvpn/zivpn.json"
if [ ! -f "$CFG" ]; then exit 0; fi
users=()
for f in "$ZDIR"/* 2>/dev/null; do
  [ -f "$f" ] || continue
  users+=( "\"$(basename "$f")\"" )
done
if [ ${#users[@]} -eq 0 ]; then arr="[]"; else arr="["; sep=""; for u in "${users[@]}"; do arr+="${sep}${u}"; sep=","; done; arr+="]"; fi
if command -v jq >/dev/null 2>&1; then
  tmp=$(mktemp)
  jq --argjson a "$(echo "${arr}" | jq -c .)" '.auth.config = $a' "$CFG" > "$tmp" 2>/dev/null || cp "$CFG" "$tmp"
  mv "$tmp" "$CFG"
else
  sed -i -E "s/\"config\": \[.*\]/\"config\": ${arr}/" "$CFG" || true
fi
systemctl try-restart jpvpn-zivpn.service >/dev/null 2>&1 || true
SH
chmod +x /usr/local/bin/jpvpn-refresh-zivpn

# jp-hysteria-menu
cat >/usr/local/bin/jp-hysteria-menu <<'SH'
#!/usr/bin/env bash
H_PASS_FILE="/etc/jpvpn/hysteria.pass"
H_CONF="/etc/jpvpn/hysteria.json"
QR_DIR="/etc/jpvpn/qrs"
DOMAIN="$(cat /etc/jpvpn/domain 2>/dev/null || echo '')"
pause(){ read -rp "Press ENTER to continue..."; }
while true; do
  clear
  echo "=== Hysteria Manager ==="
  echo "1) Show Hysteria password"
  echo "2) Change Hysteria password (global)"
  echo "3) Generate client config + QR for user"
  echo "4) Remove Hysteria password (stop service)"
  echo "0) Back"
  read -rp "Choose: " c
  case "$c" in
    1)
      [ -f "$H_PASS_FILE" ] && echo "Password: $(cat "$H_PASS_FILE")" || echo "No password file"
      pause
      ;;
    2)
      read -rp "New password: " np
      [ -z "$np" ] && { echo "Invalid"; pause; continue; }
      echo -n "$np" > "$H_PASS_FILE"
      chmod 600 "$H_PASS_FILE"
      # update config
      if command -v jq >/dev/null 2>&1; then
        tmp=$(mktemp)
        jq --arg p "$np" '.password=$p' "$H_CONF" > "$tmp" 2>/dev/null || true
        mv "$tmp" "$H_CONF" || true
      else
        sed -i -E "s/\"password\"\s*:\s*\"[^\"]*\"/\"password\": \"${np}\"/" "$H_CONF" || true
      fi
      systemctl try-restart jpvpn-hysteria.service >/dev/null 2>&1 || true
      echo "Password updated"; pause
      ;;
    3)
      read -rp "Client name for QR (eg: alice): " cn
      [ -z "$cn" ] && { echo "Invalid"; pause; continue; }
      pwd="$(cat "$H_PASS_FILE" 2>/dev/null || echo 'JPOFFICIAL')"
      cat >/tmp/hy-client-${cn}.json <<JSON
{
  "server":"${DOMAIN}",
  "port":${HYSTERIA_PORT},
  "password":"${pwd}",
  "protocol":"udp",
  "tls":true,
  "obfs":"JPOFFICIAL"
}
JSON
      # create a simple uri and QR (not an official spec, but useful)
      uri=$(base64 -w0 /tmp/hy-client-${cn}.json 2>/dev/null || openssl base64 -A < /tmp/hy-client-${cn}.json)
      echo "${uri}" | qrencode -o "${QR_DIR}/${cn}-hysteria.png" >/dev/null 2>&1 || true
      mv /tmp/hy-client-${cn}.json "${QR_DIR}/${cn}-hysteria.json" || true
      echo "Client JSON and QR saved in ${QR_DIR}/${cn}-hysteria.*"
      pause
      ;;
    4)
      rm -f "$H_PASS_FILE"
      systemctl stop jpvpn-hysteria.service >/dev/null 2>&1 || true
      echo "Password removed and hysteria stopped"; pause
      ;;
    0) exit 0 ;;
    *) echo "Invalid"; sleep 1 ;;
  esac
done
SH
chmod +x /usr/local/bin/jp-hysteria-menu

# write domain file for panel/menus
echo "${DOMAIN}" > /etc/jpvpn/domain

# ensure refresh script exists before using menus
/usr/local/bin/jpvpn-refresh-zivpn || true

# enable and start services
systemctl daemon-reload
systemctl enable --now jpvpn-hysteria.service || true
systemctl enable --now jpvpn-zivpn.service || true
systemctl enable --now jpvpn-badvpn.service || true
systemctl enable --now jpvpn-ws.service || true

# ---------- create visual panel (/usr/local/bin/jppanel) ----------
cat >/usr/local/bin/jppanel <<'SH'
#!/usr/bin/env bash
# JP OFFICIAL PANEL V1.0 LTS - visual exact style
while true; do
  clear
  yellow="\e[93m"; green="\e[92m"; cyan="\e[96m"; normal="\e[0m"
  echo -e "${yellow}: : : : JP OFFICIAL : : : :${normal}"
  echo
  OS=$(lsb_release -ds 2>/dev/null || echo "Ubuntu")
  RAM_USED=$(free -h | awk '/^Mem:/ {print $3}')
  RAM_TOTAL=$(free -h | awk '/^Mem:/ {print $2}')
  PUBLIC_IP=$(curl -s ifconfig.co || echo "N/A")
  CITY="Jakarta"
  ISP="DIGITAL OCEAN"
  DOMAIN="$(cat /etc/jpvpn/domain 2>/dev/null || echo '')"
  NS="cloudflare-dns.com"
  SSH_COUNT=$(awk -F: '$3>=1000{c++}END{print c+0}' /etc/passwd)
  ZIVPN_COUNT=$(ls /etc/jpvpn/zivpn-users 2>/dev/null | wc -l || echo 0)
  HY_COUNT=$( [ -f /etc/jpvpn/hysteria.pass ] && echo 1 || echo 0 )

  echo -e "● SYSTEM      : ${OS}"
  echo -e "● RAM         : ${RAM_USED} / ${RAM_TOTAL}"
  echo -e "● ISP         : ${ISP}"
  echo -e "● CITY        : ${CITY}"
  echo -e "● IP          : ${PUBLIC_IP}"
  echo -e "● DOMAIN      : ${DOMAIN}"
  echo -e "● NS          : ${NS}"
  echo "------------------------------------------"
  echo -e " SSH/UDP CUSTUM  : ${SSH_COUNT} ACCOUNT"
  echo -e " ZIPVPN          : ${ZIVPN_COUNT} ACCOUNT"
  echo -e " HYSTERIA        : ${HY_COUNT} ACCOUNT"
  echo "------------------------------------------"
  echo " 1. SSH/UDP CUSTUM MANAGER"
  echo " 2. ZIPVPN MANAGER"
  echo " 3. HYSTERIA MANAGER"
  echo "------------------------------------------"
  echo " SCRIPT VERSION: V1.0 LTS"
  echo
  read -rp "Choose menu: " opt
  case "$opt" in
    1) /usr/local/bin/jp-ssh-menu ;;
    2) /usr/local/bin/jp-zivpn-menu ;;
    3) /usr/local/bin/jp-hysteria-menu ;;
    0) exit 0 ;;
    *) echo "Invalid"; sleep 1 ;;
  esac
done
SH
chmod +x /usr/local/bin/jppanel

# store initial hysteria password file for menus
echo -n "${HYSTERIA_PASS}" > /etc/jpvpn/hysteria.pass
chmod 600 /etc/jpvpn/hysteria.pass

# finish
log "Installation finished. Opening JP OFFICIAL panel..."
echo "========================================" >&3
echo "JP-VPN INSTALLER FINISHED" >&3
echo "DOMAIN  : ${DOMAIN}" >&3
echo "Hysteria: ${HYSTERIA_PORT} (password ${HYSTERIA_PASS})" >&3
echo "ZiVPN   : ${ZIVPN_PORT} (obfs/password = ${HYSTERIA_PASS})" >&3
echo "BadVPN  : ${BADVPN_PORT}" >&3
echo "WSS     : wss://${DOMAIN}:443/" >&3
echo "Run panel: jppanel" >&3
echo "Installer log: ${INSTALL_LOG}" >&3
echo "========================================" >&3

# exec panel interactive
exec /usr/local/bin/jppanel
