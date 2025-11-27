
#!/bin/bash
clear
echo "JPVPN OFFICIAL V3 Installer"

apt update -y && apt upgrade -y

apt install -y wget curl unzip jq

wget -q https://raw.githubusercontent.com/Jpstore1/vip/main/menu.zip -O menu.zip
unzip -o menu.zip -d /usr/local/bin/
chmod +x /usr/local/bin/*

echo "Install selesai."
