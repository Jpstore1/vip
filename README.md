JPVPN INSTALLER

Selamat datang di repository JPVPN VIP Installer. Repo ini berisi dua versi script installer:

🚀 Versi Script

1. main.sh — Versi Standar

Installer dasar JPVPN:

Install panel Python (Flask/Django)

Nginx reverse proxy

SSL otomatis (Let's Encrypt)

Firewall UFW

Fail2Ban

Autoheal & Monitor panel

Auto-update script

Jalankan:

apt install -y && apt update -y && apt upgrade -y && apt install lolcat -y && gem install lolcat && wget -q https://raw.githubusercontent.com/Jpstore1/vip/main/main.sh && chmod +x main.sh && ./main.sh

2. main_pro.sh — Versi PRO++

Paket premium, fitur lengkap:

Semua fitur versi standar

🔥 Telegram Alerts (optional)

🔥 Cloudflare API integration (optional)

🔥 Anti-DDoS Premium (iptables + nginx + sysctl)

🔥 rclone backup support

Auto-monitor panel setiap menit

Systemd services & timers

Struktur direktori rapi untuk jangka panjang

Jalankan PRO++:

wget -q https://raw.githubusercontent.com/Jpstore1/vip/main/main_pro.sh
chmod +x main_pro.sh
./main_pro.sh

📁 Struktur Direktori Setelah Install

/usr/local/jpvpn/         ← skrip internal
/etc/jpvpn/               ← file konfigurasi
/var/www/panel/           ← panel python
/var/log/jpvpn/           ← log
/var/backups/jpvpn/       ← backup

Konfigurasi penting:

/etc/jpvpn/jpvpn.conf → Telegram, backup, fitur pro

/etc/jpvpn/cloudflare.conf → Cloudflare API

🌐 URL Panel

Setelah instalasi berhasil, panel dapat diakses melalui domain:

http://domainkamu.com
https://domainkamu.com

(sesuai domain yang kamu setting)

🆘 Dukungan

Jika script error atau ingin modifikasi fitur:

Kirim screenshot

Sebutkan bagian script

Saya akan perbaiki segera

✨ Credit

Created by: JPVPN

Refactored & Optimized by: JP_OFFICIAL

Selamat menggunakan JPVPN Installer!

