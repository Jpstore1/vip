JPVPN — AUTO INSTALLER PREMIUM

Installer otomatis untuk layanan SSH / Websocket / UDP Custom / ZiVPN / Hysteria / BadVPN

Web Panel Premium untuk manajemen user.


Dirancang untuk kebutuhan reseller & provider VPN modern.


---

🚀 FITUR UTAMA

Fitur	Status

Web Panel Premium (Port 5000 → via Nginx :80)	✔ Ready
Create / Delete User	✔
User Expired Control	✔
HWID Lock / IP Lock (Anti Multilogin)	✔
SSH + Websocket	✔
BadVPN UDP (Port 7300)	✔
ZiVPN UDP (Auto Config + Lock)	✔
Hysteria v2 Server	✔
Auto SSL (Let’s Encrypt / Self-signed fallback)	✔
Auto Subdomain JPVPN (*.vpnstore.my.id)	✔
Systemd Service Full	✔
Panel Admin Auto Generate	✔



---

📥 CARA INSTALL

wget https://raw.githubusercontent.com/Jpstore1/vip/main/jpvpn.sh -O jpvpn.sh
chmod +x jpvpn.sh
./jpvpn.sh

✔ VPS akan reboot otomatis setelah instalasi selesai.


---

🌐 AKSES PANEL

Setelah reboot, panel aktif di:

http://IP-VPS

Admin login tersimpan di:

/root/jpvpn_admin_pass.txt


---

🧩 SERVICE JPVPN

Service	Fungsi	Perintah

jpvpn-panel	Web panel backend	systemctl restart jpvpn-panel
jpvpn-zivpn	Layanan UDP ZiVPN	systemctl restart jpvpn-zivpn
jpvpn-badvpn	BadVPN udpgw	systemctl restart jpvpn-badvpn



---

📂 LOKASI FILE PENTING

/etc/jpvpn/                ← SSL, ZiVPN config, lock file
/etc/jpvpn/zivpn-config.json
/opt/jpvpn/                ← Panel + venv + templates
/root/jpvpn_admin_pass.txt ← Password admin panel


---

🛡 PORT YANG DIGUNAKAN

Layanan	Port

Panel JPVPN	5000 (Frontend port 80 via Nginx)
BadVPN UDPGW	7300/udp
ZiVPN UDP	5667/udp
SSH	22
WebSocket SSH	80 / 8080 (opsional)



---

⭐ Kelebihan Installer Ini

Sangat ringan (Flask + Gunicorn)

Tahan reboot

Siap jualan (auto admin, auto service, auto SSL, auto subdomain)

Bisa dipakai semua user tanpa konfigurasi manual

Semua file & service tertata rapi



---

❤️ CREDITS

Developer: JP VPN / JPVPNSTORE
Supported & maintained by komunitas VPN Indonesia.
