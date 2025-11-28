JPVPN AUTO INSTALLER

Installer otomatis untuk JPVPN UDP + Panel User Management.

Fitur

Web Panel (Port 5000)

Add / Delete User

User Expired

HWID Lock (Password Lock)

BadVPN UDPGW 7300

ZIVPN UDP (Auto Config)

Auto SSL Certificate


Cara Install

wget https://raw.githubusercontent.com/Jpstore1/vip/main/jpvpn.sh -O jpvpn.sh
chmod +x jpvpn.sh
./jpvpn.sh

VPS akan reboot otomatis setelah install.

Akses Panel

http://IP-VPS:5000

Login:

admin / admin

Lokasi File Penting

/etc/jpvpn/zivpn.json      ← config UDP + HWID lock
/etc/jpvpn/cert.crt        ← SSL cert
/etc/jpvpn/private.key     ← SSL key
/opt/jpvpn/                ← panel folder

Perintah Service

systemctl restart jpvpn-panel
systemctl restart badvpn.service
