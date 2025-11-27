#!/bin/bash
# FINAL SCRIPT - No Xray, No SlowDNS, No OpenVPN
# UDP-Mini Port 7300 + Limit-IP strict mode
set -euo pipefail
IFS=$'\n\t'

log()   { echo -e "[\e[32mOK\e[0m] $*"; }
warn()  { echo -e "[\e[33mWARN\e[0m] $*"; }
err()   { echo -e "[\e[31mERR\e[0m] $*"; }

if [ "$EUID" -ne 0 ]; then err "Run as root."; exit 1; fi

# ---------------------------------------------------------------------
# ASK DOMAIN
# ---------------------------------------------------------------------
read -rp "Domain untuk TLS (kosongkan jika tidak perlu TLS): " DOMAIN
read -rp "Buat swap 1GB? [Y/n]: " SWAP
SWAP=${SWAP:-Y}

timedatectl set-timezone Asia/Jakarta || true

# ---------------------------------------------------------------------
# PACKAGE INSTALL
# ---------------------------------------------------------------------
apt update -y
apt install -y curl wget unzip zip gnupg ca-certificates \
  nginx haproxy dropbear vnstat fail2ban jq cron \
  iptables-persistent netfilter-persistent sudo

log "Paket berhasil diinstal."

# ---------------------------------------------------------------------
# SWAP
# ---------------------------------------------------------------------
if [[ "$SWAP" =~ ^[Yy]$ ]]; then
 if ! swapon --show | grep -q '^'; then
   fallocate -l 1G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=1024
   chmod 600 /swapfile
   mkswap /swapfile
   swapon /swapfile
   echo "/swapfile none swap sw 0 0" >> /etc/fstab
   log "Swap 1GB dibuat."
 else
   log "Swap sudah ada."
 fi
fi

# ---------------------------------------------------------------------
# REMOVE XRAY (FULL CLEAN)
# ---------------------------------------------------------------------
systemctl stop xray 2>/dev/null || true
systemctl disable xray 2>/dev/null || true
rm -f /etc/systemd/system/xray.service 2>/dev/null || true
rm -rf /etc/xray /var/log/xray /usr/local/bin/xray /usr/bin/xray || true
log "Xray dihapus total."

mkdir -p /etc/myvpn /var/www/html

if [ -n "$DOMAIN" ]; then
 echo "$DOMAIN" > /etc/myvpn/domain
fi

# ---------------------------------------------------------------------
# ACME SSL (IF DOMAIN)
# ---------------------------------------------------------------------
if [ -n "$DOMAIN" ]; then
 curl -s https://get.acme.sh | bash -s -- --install --nocron
 export PATH="$HOME/.acme.sh:$PATH"

 systemctl stop nginx || true
 systemctl stop haproxy || true

 ~/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --keylength ec-256 || warn "SSL gagal."

 ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
   --fullchain-file /etc/ssl/certs/$DOMAIN.crt \
   --key-file /etc/ssl/private/$DOMAIN.key --ecc || true

 systemctl start nginx
 systemctl start haproxy
 systemctl enable nginx haproxy

 log "SSL selesai."
fi

# ---------------------------------------------------------------------
# NGINX CONFIG
# ---------------------------------------------------------------------
if [ -n "$DOMAIN" ]; then
cat > /etc/nginx/sites-available/$DOMAIN.conf <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    root /var/www/html;
    index index.html;
}
EOF
ln -sf /etc/nginx/sites-available/$DOMAIN.conf /etc/nginx/sites-enabled/
fi

echo "<h2>Server Ready</h2>" > /var/www/html/index.html
nginx -t && systemctl restart nginx

# ---------------------------------------------------------------------
# HAPROXY CONFIG
# ---------------------------------------------------------------------
cat > /etc/haproxy/haproxy.cfg <<EOF
global
    log /dev/log local0
    maxconn 4096
    daemon
defaults
    log global
    mode tcp
    timeout connect 10s
    timeout client  1m
    timeout server  1m
listen stats
    bind :7000
    mode http
    stats enable
    stats uri /
EOF
systemctl restart haproxy

# ---------------------------------------------------------------------
# DROPBEAR
# ---------------------------------------------------------------------
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear || true
systemctl enable dropbear
systemctl restart dropbear

# ---------------------------------------------------------------------
# VNSTAT
# ---------------------------------------------------------------------
NET_IFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
vnstat -u -i "$NET_IFACE" || true
systemctl enable vnstat
systemctl restart vnstat

# ---------------------------------------------------------------------
# FAIL2BAN
# ---------------------------------------------------------------------
systemctl enable fail2ban
systemctl restart fail2ban

# ---------------------------------------------------------------------
# UDP-MINI (PORT 7300)
# ---------------------------------------------------------------------
curl -fsSL "https://raw.githubusercontent.com/Jpstore1/vip/main/Fls/udp-mini" -o /usr/local/bin/udp-mini \
  && chmod +x /usr/local/bin/udp-mini \
  && log "UDP-Mini berhasil diinstall." \
  || warn "UDP-Mini gagal diunduh."

cat > /etc/systemd/system/udp-mini.service <<EOF
[Unit]
Description=UDP Mini Port 7300
After=network.target

[Service]
ExecStart=/usr/local/bin/udp-mini -l 7300 -r 127.0.0.1:7300
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now udp-mini

# ---------------------------------------------------------------------
# LIMIT-IP STRICT MODE (1 USER = 1 IP)
# ---------------------------------------------------------------------
cat > /usr/local/bin/limit-ip <<'EOF'
#!/bin/bash
MAX=1
USERS=$(awk -F: '$3>=1000 && $1!="nobody"{print $1}' /etc/passwd)

for USER in $USERS; do
    IPS=$(netstat -tunp 2>/dev/null | grep -E "sshd|dropbear" | grep "$USER" \
        | awk '{print $5}' | cut -d: -f1 | sort -u)
    COUNT=$(echo "$IPS" | wc -l)

    if [ "$COUNT" -gt "$MAX" ]; then
        pkill -u "$USER" 2>/dev/null
    fi
done
EOF

chmod +x /usr/local/bin/limit-ip

cat > /etc/systemd/system/limit-ip.service <<EOF
[Unit]
Description=Limit IP Strict Mode
After=network.target

[Service]
ExecStart=/usr/local/bin/limit-ip
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now limit-ip

# ---------------------------------------------------------------------
# MENU
# ---------------------------------------------------------------------
cat > /usr/local/bin/myvpn-menu <<EOF
#!/bin/bash
echo "== MyVPN Status =="
echo -n "Domain: "; [ -f /etc/myvpn/domain ] && cat /etc/myvpn/domain || echo "(none)"
echo "Swap:"; swapon --show || echo "No swap"
echo "Services:"
echo " - nginx:     \$(systemctl is-active nginx)"
echo " - haproxy:   \$(systemctl is-active haproxy)"
echo " - dropbear:  \$(systemctl is-active dropbear)"
echo " - udp-mini:  \$(systemctl is-active udp-mini)"
echo " - limit-ip:  \$(systemctl is-active limit-ip)"
EOF

chmod +x /usr/local/bin/myvpn-menu

# ---------------------------------------------------------------------
apt autoremove -y
apt autoclean -y

log "INSTALL SELESAI!"
log "Cek status: myvpn-menu"

exit
