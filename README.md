🛡️ JPVPN PRO++ — Premium Auto Installer



Installer panel Python (Flask/Django) lengkap dengan fitur PRO++:

✨ Fitur Standar

Python Panel (Flask / Django via Gunicorn)

Nginx Reverse Proxy

SSL otomatis (Let’s Encrypt)

Firewall UFW

Fail2Ban

Autoheal & Monitor panel

Auto-update installer



---

🚀 Cara Install Versi Standar

Klik tombol copy otomatis → tempel di VPS:

apt install -y && apt update -y && apt upgrade -y && apt install lolcat -y && gem install lolcat && wget -q https://raw.githubusercontent.com/Jpstore1/vip/main/main.sh -O main.sh && chmod +x main.sh && ./main.sh


---

🔥 JPVPN PRO++ — Versi Full Premium

Semua fitur standar + fitur PRO++:

🚨 Telegram Alerts otomatis

☁️ Cloudflare API (A Record Auto-update)

🛡️ Anti-DDoS Premium (iptables + nginx + sysctl tuned)

🔄 rclone backup support

⏱️ Auto-monitor panel tiap menit

⚙️ Systemd services & timers PRO

📁 Struktur direktori premium



---

🚀 Install PRO++

TOMBOL COPY OTOMATIS SIAP:

wget -q https://raw.githubusercontent.com/Jpstore1/vip/main/main_pro.sh -O main_pro.sh
chmod +x main_pro.sh
./main_pro.sh


---

📂 Struktur Direktori Setelah Install

/usr/local/jpvpn/      ← skrip internal  
/etc/jpvpn/            ← konfigurasi  
/var/www/panel/        ← panel python  
/var/log/jpvpn/        ← log  
/var/backups/jpvpn/    ← backup


---

🔧 Konfigurasi Penting

Telegram

/etc/jpvpn/jpvpn.conf

TELEGRAM_TOKEN="xxxx"
TELEGRAM_CHATID="xxxx"

Cloudflare

/etc/jpvpn/cloudflare.conf

CF_API_KEY="xxxx"
CF_EMAIL="xxxx"
CF_ZONE_ID="xxxx"
CF_RECORD_ID="xxxx"


---

🌍 Akses Panel

Setelah instalasi berhasil, panel dapat diakses via:

https://domainkamu.com
http://domainkamu.com

(sesuai domain yang kamu setting)


---

🆘 Dukungan

Jika ada error atau ingin menambah fitur, cukup kirim:

1. Screenshot error


2. Bagian script yang ingin diperbaiki



Saya perbaiki langsung tanpa muter-muter. ✔️


---

🏆 Credit

Created by: JPVPN
Refactored & Optimized by: JP_OFFICIAL

Terima kasih telah menggunakan JPVPN PRO++ Installer!
