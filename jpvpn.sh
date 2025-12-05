#!/bin/bash
# KONOHA FULL PREMIUM INSTALLER + PANEL (All-in-one)
# - Manual domain mode
# - Installs: Xray, OpenSSH, Dropbear, Stunnel, Squid, OpenVPN (easy-rsa), BadVPN, vnStat, nginx (for files), acme.sh
# - Panel: Create/Delete/Renew SSH, XRAY user basics, TNL info, Generate payload, Limit speed, Check login, Auto-restart, Backup
# - No SlowDNS, No WireGuard
# Usage: chmod +x konoha_full_premium.sh && sudo ./konoha_full_premium.sh

set -euo pipefail
IFS=$'\n\t'

# Colors
RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; BLUE='\e[1;34m'; MAGENTA='\e[1;35m'; NC='\e[0m'

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Jalankan script sebagai root!${NC}"
    exit 1
  fi
}
require_root

clear
cat <<'BANNER'
 _  __            _                      ____  _   _ _   _ _ 
| |/ /  ___  _ __| |_ ___  _ __ _   _   |  _ \| | | | \ | | |
| ' /  / _ \| '__| __/ _ \| '__| | | |  | |_) | | | |  \| | |
| . \ | (_) | |  | || (_) | |  | |_| |  |  __/| |_| | |\  |_|
|_|\_\ \___/|_|   \__\___/|_|   \__, |  |_|    \___/|_| \_(_)
                                |___/                        
BANNER

echo
echo -e "${YELLOW}KONOHA FULL PREMIUM INSTALLER${NC}"
echo -e "${YELLOW}Mode: Domain manual (kamu akan diminta memasukkan domain)${NC}"
echo

# Ask domain
read -rp "Masukkan FQDN domain untuk TLS (contoh: vpn.example.com): " DOMAIN
if [[ -z "$DOMAIN" ]]; then
  echo -e "${RED}Domain wajib diisi. Keluar.${NC}"
  exit 1
fi
mkdir -p /etc/konoha
echo "$DOMAIN" >/etc/konoha/domain

# Basic update & deps
echo -e "${BLUE}Update paket & install dependencies...${NC}"
apt update -y
apt upgrade -y
apt install -y curl wget socat unzip jq lsof net-tools iproute2 iptables iputils-ping ca-certificates gnupg2 build-essential openssl cron vim apt-transport-https software-properties-common dialog

# Networking and monitoring tools
apt install -y vnstat neofetch certbot git wget unzip lsof htop || true

# Install jq if missing
if ! command -v jq >/dev/null 2>&1; then
  apt install -y jq
fi

# Set timezone and enable NTP
timedatectl set-timezone Asia/Jakarta || true
timedatectl set-ntp true || true

# Stop common web servers to free ports 80/443 for acme standalone
if systemctl is-active --quiet nginx; then
  systemctl stop nginx || true
fi
if systemctl is-active --quiet apache2; then
  systemctl stop apache2 || true
fi

# Install acme.sh for certificate issuance
if ! command -v acme.sh >/dev/null 2>&1; then
  echo -e "${BLUE}Install acme.sh...${NC}"
  curl -sS https://get.acme.sh | sh
  export PATH="$HOME/.acme.sh:$PATH"
fi

# Issue certificate (standalone)
echo -e "${BLUE}Mencoba terbitkan sertifikat untuk ${DOMAIN} menggunakan acme.sh...${NC}"
~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
if ! ~/.acme.sh/acme.sh --issue --standalone -d "$DOMAIN" --keylength ec-256 >/dev/null 2>&1; then
  echo -e "${YELLOW}EC-256 issuance gagal, coba RSA...${NC}"
  ~/.acme.sh/acme.sh --issue --standalone -d "$DOMAIN" >/dev/null 2>&1 || true
fi

CERT_DIR="$HOME/.acme.sh/$DOMAIN"
CERT_PEM="$CERT_DIR/${DOMAIN}.cer"
KEY_PEM="$CERT_DIR/${DOMAIN}.key"
if [ ! -f "$CERT_PEM" ] || [ ! -f "$KEY_PEM" ]; then
  CERT_PEM="/root/.acme.sh/${DOMAIN}/${DOMAIN}.cer"
  KEY_PEM="/root/.acme.sh/${DOMAIN}/${DOMAIN}.key"
fi

echo -e "${GREEN}Sertifikat (jika diterbitkan) akan disimpan di:${NC} $CERT_PEM, $KEY_PEM"

# -------------------------
# Install Xray
# -------------------------
echo -e "${BLUE}Install Xray core (XTLS) ...${NC}"
if ! command -v xray >/dev/null 2>&1; then
  bash <(curl -sL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh) install
fi
mkdir -p /usr/local/etc/xray /var/log/xray

# Generate some UUIDs
UUID1=$(cat /proc/sys/kernel/random/uuid)
UUID2=$(cat /proc/sys/kernel/random/uuid)
UUID3=$(cat /proc/sys/kernel/random/uuid)

# Basic Xray config (VLESS/VMESS/TROJAN/SS2022) - minimal working config
cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {"access": "/var/log/xray/access.log","error": "/var/log/xray/error.log","loglevel":"warning"},
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {"clients":[{"id":"$UUID1","flow":""}],"decryption":"none"},
      "streamSettings":{"network":"ws","wsSettings":{"path":"/vless"},"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"$CERT_PEM","keyFile":"$KEY_PEM"}]}}
    },
    {
      "port": 80,
      "protocol": "vmess",
      "settings": {"clients":[{"id":"$UUID2"}]},
      "streamSettings":{"network":"ws","wsSettings":{"path":"/vmess"}}
    },
    {
      "port": 1443,
      "protocol": "shadowsocks",
      "settings": {"clients": []},
      "streamSettings":{"network":"tcp"}
    },
    {
      "port": 8443,
      "protocol": "trojan",
      "settings": {"clients": []},
      "streamSettings":{"network":"ws","wsSettings":{"path":"/trojan"},"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"$CERT_PEM","keyFile":"$KEY_PEM"}]}}
    }
  ],
  "outbounds": [{"protocol":"freedom","settings":{}}]
}
EOF

systemctl enable xray || true
systemctl restart xray || true

# -------------------------
# Install OpenSSH, Dropbear, Stunnel, Squid, Nginx
# -------------------------
echo -e "${BLUE}Install & configure OpenSSH, Dropbear, Stunnel, Squid, Nginx...${NC}"
apt install -y openssh-server dropbear stunnel4 squid nginx || true

# Configure Dropbear (default port 109)
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear || true
grep -q "^DROPBEAR_PORT=" /etc/default/dropbear || echo 'DROPBEAR_PORT=109' >> /etc/default/dropbear
systemctl enable dropbear || true
systemctl restart dropbear || true

# Configure stunnel using existing cert (if available)
mkdir -p /etc/stunnel
cat > /etc/stunnel/stunnel.conf <<STUNNEL
cert = $CERT_PEM
key = $KEY_PEM

[dropbear]
accept = 447
connect = 109

[websocket]
accept = 777
connect = 80
STUNNEL
# enable stunnel
sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4 || true
systemctl enable stunnel4 || true
systemctl restart stunnel4 || true

# Configure squid minimal
cat > /etc/squid/squid.conf <<SQ
http_port 3128
http_port 8080
# default allow all (user can secure later)
acl all src 0.0.0.0/0
http_access allow all
SQ
systemctl enable squid || true
systemctl restart squid || true

# Configure nginx minimal for file downloads (OVPN)
mkdir -p /var/www/html/ovpn
cat > /etc/nginx/sites-available/konoha_default <<NGCONF
server {
  listen 80;
  server_name _;
  root /var/www/html;
  location / {
    try_files \$uri \$uri/ =404;
  }
}
NGCONF
ln -sf /etc/nginx/sites-available/konoha_default /etc/nginx/sites-enabled/konoha_default
systemctl enable nginx || true
systemctl restart nginx || true

# -------------------------
# OpenVPN basic setup using easy-rsa
# -------------------------
echo -e "${BLUE}Install OpenVPN & easy-rsa, prepare basic server.conf...${NC}"
apt install -y openvpn easy-rsa || true
EASY_DIR="/etc/openvpn/easy-rsa"
if [ ! -d "$EASY_DIR" ]; then
  make-cadir "$EASY_DIR"
  cd "$EASY_DIR"
  ./easyrsa init-pki
  printf '\n' | ./easyrsa build-ca nopass >/dev/null 2>&1 || true
  printf '\n' | ./easyrsa build-server-full server nopass >/dev/null 2>&1 || true
  ./easyrsa gen-dh >/dev/null 2>&1 || true
  cp pki/ca.crt pki/issued/server.crt pki/private/server.key pki/dh.pem /etc/openvpn/ || true
fi

if [ ! -f /etc/openvpn/server.conf ]; then
cat > /etc/openvpn/server.conf <<'OVPNCONF'
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
server 10.8.0.0 255.255.255.0
persist-key
persist-tun
keepalive 10 120
cipher AES-256-CBC
user nobody
group nogroup
status /var/log/openvpn-status.log
verb 3
OVPNCONF
fi

systemctl enable openvpn || true
systemctl restart openvpn || true

# -------------------------
# BadVPN udpgw
# -------------------------
if [ ! -f /usr/local/bin/badvpn-udpgw ]; then
  echo -e "${BLUE}Download BadVPN udpgw binary (may fail if not available)...${NC}"
  wget -q -O /usr/local/bin/badvpn-udpgw https://github.com/ambrop72/badvpn/releases/download/1.999.130/badvpn-udpgw || true
  chmod +x /usr/local/bin/badvpn-udpgw || true
fi

# Create badvpn systemd service if binary exists
if [ -f /usr/local/bin/badvpn-udpgw ]; then
  cat > /etc/systemd/system/badvpn.service <<BAD
[Unit]
Description=BadVPN UDPGW
After=network.target

[Service]
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300
Restart=always
User=root
BAD
  systemctl daemon-reload || true
  systemctl enable badvpn || true
  systemctl restart badvpn || true
fi

# vnStat (traffic monitor)
if command -v vnstat >/dev/null 2>&1; then
  systemctl enable vnstat || true
  systemctl restart vnstat || true
fi

# iptables persistent & basic rules (save)
apt install -y iptables-persistent netfilter-persistent || true
# ensure loopback allow
iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -I INPUT -i lo -j ACCEPT
iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -I INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
netfilter-persistent save || true
netfilter-persistent reload || true

# -------------------------
# Create DB, helper, and panel scripts
# -------------------------
mkdir -p /etc/konoha /usr/local/konoha-panel
USERS_DB="/etc/konoha/users.json"
if [ ! -f "$USERS_DB" ]; then
  echo '{"ssh":[],"vless":[],"vmess":[],"trojan":[],"ss2022":[]}' > "$USERS_DB"
fi

HELPER="/usr/local/bin/konoha-helper.sh"
cat > "$HELPER" <<'HELPER_EOF'
#!/bin/bash
# Helper script for Konoha panel
USERS_DB="/etc/konoha/users.json"
XCONF="/usr/local/etc/xray/config.json"
DOMAIN_FILE="/etc/konoha/domain"
gen_uuid(){ cat /proc/sys/kernel/random/uuid; }

create_ssh() {
  read -rp "Username: " USER
  if id "$USER" >/dev/null 2>&1; then
    echo "User $USER already exists"; return 1
  fi
  read -rp "Password: " PASS
  read -rp "Days active: " DAYS
  # create system user (no shell, no home)
  useradd -M -s /bin/false "$USER"
  echo "${USER}:${PASS}" | chpasswd
  EXPIRY=$(date -d "+$DAYS days" +%Y-%m-%d)
  chage -E "$EXPIRY" "$USER" || true
  # update DB
  DB=$(cat "$USERS_DB")
  NEW=$(echo "$DB" | jq --arg u "$USER" --arg p "$PASS" --arg e "$EXPIRY" '.ssh += [{"user":$u,"pass":$p,"expire":$e}]')
  echo "$NEW" > "$USERS_DB"
  IP="$(curl -s ipv4.icanhazip.com || echo unknown)"
  DOMAIN="$(cat $DOMAIN_FILE 2>/dev/null || echo unknown)"
  # ports
  OPENSSH_PORT=22
  DROPBEAR_PORT=$(awk -F= '/DROPBEAR_PORT/ {print $2}' /etc/default/dropbear 2>/dev/null || echo 109)
  STUNNEL_PORT=447
  WS_NTLS=80
  WS_TLS=443
  UDPGW="7100-7900"
  SQUID1=3128; SQUID2=8080
  OVPN_TCP=1194; OVPN_SSL=2200; OHP_PORT=8000
  # print boxed output
  echo
  echo "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓"
  echo "┃           ✦ SSH ACCOUNT DETAILS ✦      ┃"
  echo "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"
  echo " Username      : $USER"
  echo " Password      : $PASS"
  echo " Expiry Date   : $EXPIRY"
  echo " Host/IP       : $IP"
  echo " Domain        : $DOMAIN"
  echo "------------------------------------------"
  echo " OpenSSH   : $OPENSSH_PORT"
  echo " Dropbear  : $DROPBEAR_PORT"
  echo " Stunnel   : $STUNNEL_PORT"
  echo " WS NTLS   : $WS_NTLS"
  echo " WS TLS    : $WS_TLS"
  echo " UDPGW     : $UDPGW"
  echo " Squid     : $SQUID1, $SQUID2"
  echo " OpenVPN   : TCP $OVPN_TCP"
  echo "------------------------------------------"
  echo " UDP Custom"
  echo "$DOMAIN:1-65535@${USER}:1"
  echo "------------------------------------------"
  echo "OpenVPN File"
  echo "Download : https://${DOMAIN}:2081"
  echo "------------------------------------------"
  echo "Payload"
  echo "GET / HTTP/1.1[crlf]Host: ${DOMAIN}[crlf]Upgrade: websocket[crlf][crlf]"
  echo "------------------------------------------"
  read -n1 -rsp $'Press any key to return to menu...\n'
}

add_vless() {
  read -rp "VLESS username: " USER
  UUID=$(gen_uuid)
  read -rp "Days: " DAYS
  EXP=$(date -d "+$DAYS days" +%Y-%m-%d)
  CLIENT=$(jq -n --arg id "$UUID" --arg email "$USER" '{id:$id,email:$email}')
  tmp=$(mktemp)
  jq --argjson c "$CLIENT" '.inbounds |= map(if .protocol=="vless" then .settings.clients += [$c] else . end)' "$XCONF" > "$tmp" && mv "$tmp" "$XCONF"
  DB=$(cat "$USERS_DB")
  NEW=$(echo "$DB" | jq --arg u "$USER" --arg id "$UUID" --arg e "$EXP" '.vless += [{"user":$u,"id":$id,"expire":$e}]')
  echo "$NEW" > "$USERS_DB"
  systemctl restart xray || true
  DOMAIN="$(cat /etc/konoha/domain 2>/dev/null || echo unknown)"
  echo "vless://${UUID}@${DOMAIN}:443?path=/vless&security=tls&type=ws#${USER}"
}

add_vmess() {
  read -rp "VMESS username: " USER
  UUID=$(gen_uuid)
  read -rp "Days: " DAYS
  EXP=$(date -d "+$DAYS days" +%Y-%m-%d)
  CLIENT=$(jq -n --arg id "$UUID" --arg email "$USER" '{id:$id,email:$email}')
  tmp=$(mktemp)
  jq --argjson c "$CLIENT" '.inbounds |= map(if .protocol=="vmess" then .settings.clients += [$c] else . end)' "$XCONF" > "$tmp" && mv "$tmp" "$XCONF"
  DB=$(cat "$USERS_DB")
  NEW=$(echo "$DB" | jq --arg u "$USER" --arg id "$UUID" --arg e "$EXP" '.vmess += [{"user":$u,"id":$id,"expire":$e}]')
  echo "$NEW" > "$USERS_DB"
  systemctl.restart xray || true 2>/dev/null || systemctl restart xray || true
  JSON=$(jq -n --arg v "2" --arg ps "$USER" --arg add "$(cat /etc/konoha/domain 2>/dev/null || echo unknown)" --arg port "80" --arg id "$UUID" --arg net "ws" --arg path "/vmess" '{v:$v,ps:$ps,add:$add,port:$port,id:$id,aid:"0",net:$net,type:"none",host:$add,path:$path,tls:""}')
  echo "vmess://$(echo -n "$JSON" | base64 -w0)"
}

add_trojan() {
  read -rp "Trojan username: " USER
  PASS=$(openssl rand -hex 12)
  read -rp "Days: " DAYS
  EXP=$(date -d "+$DAYS days" +%Y-%m-%d)
  CLIENT=$(jq -n --arg pass "$PASS" --arg email "$USER" '{password:$pass,email:$email}')
  tmp=$(mktemp)
  jq --argjson c "$CLIENT" '.inbounds |= map(if .protocol=="trojan" then .settings.clients += [$c] else . end)' "$XCONF" > "$tmp" && mv "$tmp" "$XCONF"
  DB=$(cat "$USERS_DB")
  NEW=$(echo "$DB" | jq --arg u "$USER" --arg p "$PASS" --arg e "$EXP" '.trojan += [{"user":$u,"pass":$p,"expire":$e}]')
  echo "$NEW" > "$USERS_DB"
  systemctl restart xray || true
  DOMAIN="$(cat /etc/konoha/domain 2>/dev/null || echo unknown)"
  echo "trojan://${PASS}@${DOMAIN}:8443?path=/trojan&security=tls&type=ws#${USER}"
}

show_users() {
  jq . "$USERS_DB" || cat "$USERS_DB"
}

check_online() {
  if [ -f /var/log/xray/access.log ]; then
    tail -n 200 /var/log/xray/access.log | awk '{print $1,$3,$7}' | sort | uniq -c | sort -nr | head -n 50
  else
    echo "No xray access log yet."
  fi
}
HELPER_EOF

chmod +x "$HELPER"

# -------------------------
# Panel scripts
# -------------------------
PANEL_DIR="/usr/local/konoha-panel"
mkdir -p "$PANEL_DIR"

# Main launcher
cat > /usr/local/bin/konoha <<'KONOHAMAIN'
#!/bin/bash
source /usr/local/bin/konoha-helper.sh
DOMAIN="$(cat /etc/konoha/domain 2>/dev/null || echo unknown)"
IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {print $5; exit}')
IFACE=${IFACE:-eth0}
while true; do
  clear
  rx1=$(cat /sys/class/net/$IFACE/statistics/rx_bytes 2>/dev/null || echo 0); tx1=$(cat /sys/class/net/$IFACE/statistics/tx_bytes 2>/dev/null || echo 0)
  sleep 1
  rx2=$(cat /sys/class/net/$IFACE/statistics/rx_bytes 2>/dev/null || echo 0); tx2=$(cat /sys/class/net/$IFACE/statistics/tx_bytes 2>/dev/null || echo 0)
  rx=$(( (rx2-rx1)/1024 )); tx=$(( (tx2-tx1)/1024 ))
  echo "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓"
  echo "┃           ✦ KONOHA MANAGEMENT ✦       ┃"
  echo "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"
  echo
  echo " IP Address : $(curl -s ipv4.icanhazip.com || echo unknown)"
  echo " Domain     : $DOMAIN"
  echo " Status     : $(systemctl is-active xray 2>/dev/null || echo unknown)"
  echo
  echo " Bandwidth: ↓ ${rx}KB/s  ↑ ${tx}KB/s"
  echo "----------------------------------------"
  echo " 1) SSH PANEL"
  echo " 2) XRAY PANEL"
  echo " 3) OPENVPN PANEL"
  echo " 4) UDP PANEL"
  echo " 5) SYSTEM PANEL"
  echo " 6) BACKUP & RESTORE"
  echo " 0) Exit"
  echo "----------------------------------------"
  read -rp "Choice: " c
  case $c in
    1) /usr/local/konoha-panel/ssh_menu.sh ;;
    2) /usr/local/konoha-panel/xray_menu.sh ;;
    3) /usr/local/konoha-panel/openvpn_menu.sh ;;
    4) /usr/local/konoha-panel/udp_menu.sh ;;
    5) /usr/local/konoha-panel/system_menu.sh ;;
    6) /usr/local/konoha-panel/backup_menu.sh ;;
    0) exit 0 ;;
    *) echo "Invalid"; sleep 1 ;;
  esac
done
KONOHAMAIN
chmod +x /usr/local/bin/konoha

# SSH submenu
cat > "$PANEL_DIR/ssh_menu.sh" <<'SSH_MENU'
#!/bin/bash
source /usr/local/bin/konoha-helper.sh
while true; do
  clear
  echo "=== SSH PANEL ==="
  echo "1) Create SSH user"
  echo "2) Delete SSH user"
  echo "3) Renew SSH user (extend days)"
  echo "4) List SSH users"
  echo "5) TNL Port Info"
  echo "6) Generate Payload"
  echo "7) Limit Speed"
  echo "8) Check Login"
  echo "9) Set Auto Restart"
  echo "0) Back"
  read -rp "Choice: " c
  case $c in
    1) create_ssh ;;
    2) read -rp "Username to delete: " U; userdel -r $U 2>/dev/null || true; jq -c "del(.ssh[] | select(.user==\"$U\"))" /etc/konoha/users.json > /tmp/users.json && mv /tmp/users.json /etc/konoha/users.json; echo "Deleted $U"; read -n1 -s -p 'Press any key...';;
    3) read -rp "Username: " U; read -rp "Add days: " D; CUR=$(chage -l $U | awk -F: '/Account expires/ {print $2}' | xargs); NEW=$(date -d "$CUR + $D days" +%Y-%m-%d 2>/dev/null || date -d "+$D days" +%Y-%m-%d); chage -E "$NEW" $U; echo "Renewed $U until $NEW"; read -n1 -s -p 'Press any key...';;
    4) jq -r '.ssh[] | "\(.user)\t expire:\(.expire)"' /etc/konoha/users.json || echo "No users"; read -n1 -s -p 'Press any key...';;
    5) clear; echo "OpenSSH: 22"; echo "Dropbear: 109"; echo "Stunnel: 447,777"; echo "WS NTLS: 80"; echo "WS TLS: 443"; echo "OpenVPN: 1194,2200,8000"; echo "UDPGW: 7100-7900"; read -n1 -s -p 'Press any key...';;
    6) clear; echo "Payload WS NTLS:"; echo "GET / HTTP/1.1[crlf]Host: $(cat /etc/konoha/domain)[crlf]Upgrade: websocket[crlf][crlf]"; read -n1 -s -p 'Press any key...';;
    7) read -rp "Interface (eg: eth0): " IF; read -rp "Download kbps: " D; read -rp "Upload kbps: " U; wondershaper -a $IF -d $D -u $U; echo "Limit applied"; read -n1 -s -p 'Press any key...';;
    8) clear; who; read -n1 -s -p 'Press any key...';;
    9) echo "*/30 * * * * root systemctl restart ssh dropbear stunnel4 squid" > /etc/cron.d/konoha-autorestart; echo "Auto restart set"; read -n1 -s -p 'Press any key...';;
    0) break ;;
    *) echo "Invalid"; sleep 1 ;;
  esac
done
SSH_MENU
chmod +x "$PANEL_DIR/ssh_menu.sh"

# XRAY menu
cat > "$PANEL_DIR/xray_menu.sh" <<'XRAY_MENU'
#!/bin/bash
while true; do
  clear
  echo "=== XRAY PANEL ==="
  echo "1) Add VLESS user"
  echo "2) Add VMESS user"
  echo "3) Add Trojan user"
  echo "4) Add SS2022 user"
  echo "5) Delete Xray user"
  echo "6) List users (DB)"
  echo "7) Check online"
  echo "8) Restart xray"
  echo "0) Back"
  read -rp "Choice: " c
  case $c in
    1) /usr/local/bin/konoha-helper.sh add_vless ;;
    2) /usr/local/bin/konoha-helper.sh add_vmess ;;
    3) /usr/local/bin/konoha-helper.sh add_trojan ;;
    4) /usr/local/bin/konoha-helper.sh add_ss2022 ;;
    5) read -rp "Type (vless/vmess/trojan/ss2022): " T; read -rp "Username: " U; /usr/local/bin/konoha-helper.sh delete_xray_user $T $U ;;
    6) /usr/local/bin/konoha-helper.sh show_users ;;
    7) /usr/local/bin/konoha-helper.sh check_online ;;
    8) systemctl restart xray; echo "xray restarted"; sleep 1 ;;
    0) break ;;
    *) echo "Invalid"; sleep 1 ;;
  esac
done
XRAY_MENU
chmod +x "$PANEL_DIR/xray_menu.sh"

# OPENVPN menu
cat > "$PANEL_DIR/openvpn_menu.sh" <<'OVPN_MENU'
#!/bin/bash
while true; do
  clear
  echo "=== OPENVPN PANEL ==="
  echo "1) Create OpenVPN client (.ovpn - simple)"
  echo "2) List .ovpn files"
  echo "3) Delete .ovpn file"
  echo "0) Back"
  read -rp "Choice: " c
  case $c in
    1) read -rp "Client name: " CN
       cat > /root/${CN}.ovpn <<OVPNCONF
client
dev tun
proto udp
remote $(curl -s ipv4.icanhazip.com) 1194
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-CBC
verb 3
OVPNCONF
       echo "Generated /root/${CN}.ovpn"; read -n1 -s -p 'Press any key...';;
    2) ls -1 /root/*.ovpn 2>/dev/null || echo "No ovpn files"; read -n1 -s -p 'Press any key...';;
    3) read -rp "File name (with .ovpn): " FN; rm -f /root/$FN; echo "Deleted"; read -n1 -s -p 'Press any key...';;
    0) break ;;
  esac
done
OVPN_MENU
chmod +x "$PANEL_DIR/openvpn_menu.sh"

# UDP menu
cat > "$PANEL_DIR/udp_menu.sh" <<'UDP_MENU'
#!/bin/bash
while true; do
  clear
  echo "=== UDP PANEL (BadVPN) ==="
  echo "1) Status badvpn"
  echo "2) Start badvpn"
  echo "3) Stop badvpn"
  echo "0) Back"
  read -rp "Choice: " c
  case $c in
    1) pgrep -af badvpn || echo "Not running"; read -n1 -s -p 'Press any key...';;
    2) nohup /usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 >/dev/null 2>&1 & echo "Started badvpn"; read -n1 -s -p 'Press any key...';;
    3) pkill -f badvpn || echo "Not running"; read -n1 -s -p 'Press any key...';;
    0) break ;;
  esac
done
UDP_MENU
chmod +x "$PANEL_DIR/udp_menu.sh"

# System menu
cat > "$PANEL_DIR/system_menu.sh" <<'SYS_MENU'
#!/bin/bash
while true; do
  clear
  echo "=== SYSTEM PANEL ==="
  echo "1) Show system info"
  echo "2) Restart services (xray, openvpn, dropbear, squid, stunnel, nginx)"
  echo "3) Reboot VPS"
  echo "0) Back"
  read -rp "Choice: " c
  case $c in
    1) neofetch || uname -a; read -n1 -s -p 'Press any key...';;
    2) systemctl restart xray openvpn dropbear squid stunnel4 nginx || true; echo "Restarted services"; read -n1 -s -p 'Press any key...';;
    3) read -rp "Are you sure reboot? (y/n): " Y; if [[ $Y == 'y' ]]; then reboot; fi;;
    0) break ;;
  esac
done
SYS_MENU
chmod +x "$PANEL_DIR/system_menu.sh"

# Backup menu
cat > "$PANEL_DIR/backup_menu.sh" <<'BKP_MENU'
#!/bin/bash
mkdir -p /root/konoha-backups
echo "1) Create backup"
echo "2) List backups"
echo "3) Restore backup"
echo "0) Back"
read -rp "Choice: " c
case $c in
  1) tar czf /root/konoha-backups/konoha-backup-$(date +%Y%m%d%H%M).tar.gz /usr/local/etc/xray /etc/konoha /etc/openvpn /var/www/html || true; echo "Backup created";;
  2) ls -lh /root/konoha-backups || echo "No backups";;
  3) read -rp "Backup file: " f; tar xzf /root/konoha-backups/$f -C / || echo "restore failed";;
  0) exit 0 ;;
esac
BKP_MENU
chmod +x "$PANEL_DIR/backup_menu.sh"

# Launcher symlink
cat > /usr/bin/konoha-launch <<'KONLA'
#!/bin/bash
/usr/local/bin/konoha
KONLA
chmod +x /usr/bin/konoha-launch

# Enable services at boot
systemctl daemon-reload || true
systemctl enable xray openvpn dropbear squid stunnel4 nginx || true

echo -e "${GREEN}INSTALLATION COMPLETE${NC}"
echo -e "${YELLOW}Panel akan dibuka sekarang. Jika tidak, jalankan: konoha-launch${NC}"
sleep 2

# Open panel
/usr/local/bin/konoha || /usr/bin/konoha-launch || true

exit
