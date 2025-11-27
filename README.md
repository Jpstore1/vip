🛡️ JPVPN PRO++ – PREMIUM VPN PANEL INSTALLER

Secure • Stable • Anti-DDoS • Auto-Heal • SSL • Telegram • Cloudflare


---

🚀 Instalasi Cepat (1 Baris)

wget -q https://raw.githubusercontent.com/Jpstore1/vip/main/main_pro.sh -O main_pro.sh && chmod +x main_pro.sh && ./main_pro.sh


---

✨ Fitur Utama

🔥 Panel Python (Flask + Gunicorn)

🔥 Reverse Proxy Nginx

🔥 Auto SSL (Let’s Encrypt)

🔥 Firewall Anti-DDoS Premium

🔥 Fail2Ban Hardened

🔥 Auto-Heal + Monitor (systemd timer)

🔥 Auto Backup

🔥 Telegram Notifier

🔥 Cloudflare API Ready

🔥 100% Full Auto Install



---

📦 Komponen

Python3, pip, virtualenv

Gunicorn WSGI

Nginx

Certbot SSL

UFW + iptables Anti-DDoS

Fail2Ban

Monitor service + timer

Backup system

Telegram alert sender



---

⚙️ Requirements

OS: Ubuntu 20 / 22 / 24

CPU: 1 Core

RAM: 512 MB+

Storage: 5 GB



---

🧩 Cara Install

1. Login root VPS


2. Jalankan:



wget -q https://raw.githubusercontent.com/Jpstore1/vip/main/main_pro.sh -O main_pro.sh && chmod +x main_pro.sh && ./main_pro.sh

3. Isi:

Domain

Telegram Bot Token (opsional)

Chat ID (opsional)

Cloudflare Email + API Key (opsional)





---

🌐 Akses Panel

https://YOUR-DOMAIN


---

🔧 Perintah Berguna

Restart panel:

systemctl restart panel

Cek monitor:

systemctl status jpvpn-monitor.service

Backup manual:

/usr/local/jpvpn/backup.sh


---

🛡️ Anti-DDoS Premium

SYN rate-limit

Burst protection

Drop invalid packets

Hardening Fail2Ban

Enhanced Nginx security



---

📡 Telegram Ready

Instalasi akan mengirim pesan:

JPVPN PRO++ Installed on your domain


---

☁️ Cloudflare Ready

Config tersimpan di:

/etc/jpvpn/cloudflare.conf


---

🛠️ Struktur Folder

/var/www/panel               → Panel Python
/etc/jpvpn                   → Config
/usr/local/jpvpn             → Script premium
/var/log/jpvpn               → Log


---

🏆 Developer

JPVPN | JP_OFFICIAL


---

🔥 Status

FINAL • PREMIUM • STABLE • SIAP TEMPUR
