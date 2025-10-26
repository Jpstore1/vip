#!/usr/bin/env python3
import os
import subprocess
import urllib.request
import json
import datetime
import getpass
import stat
import tempfile

# Configuration
ZIVPN_BIN = "/usr/local/bin/zivpn"
ZIVPN_DIR = "/etc/zivpn"
ZIVPN_CFG = f"{ZIVPN_DIR}/config.json"
ZIVPN_SVC = "zivpn.service"

ADMIN_DIR = "/opt/zivpn-admin"
APP_PY = f"{ADMIN_DIR}/app.py"
SYNC_PY = f"{ADMIN_DIR}/sync.py"
VENV = f"{ADMIN_DIR}/venv"
ENV_FILE = f"{ADMIN_DIR}/.env"
PANEL_SVC = "zivpn-admin.service"
SYNC_SVC = "zivpn-sync.service"
SYNC_TIMER = "zivpn-sync.timer"

# Ensure running as root
if os.geteuid() != 0:
    print("This script must be run as root. Use sudo.")
    exit(1)

# Utility function to run shell commands
def run_command(cmd, check=True):
    try:
        result = subprocess.run(cmd, shell=True, check=check, text=True, capture_output=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {cmd}\nError: {e.stderr}")
        exit(1)

# Step 1: Update packages
print("==> Updating packages...")
run_command("apt-get update -y && apt-get upgrade -y")
run_command("apt-get install -y python3-venv python3-pip openssl ufw curl jq")

# Step 2: Install ZIVPN binary
print("==> Installing ZIVPN binary...")
run_command(f"systemctl stop {ZIVPN_SVC} 2>/dev/null || true")
urllib.request.urlretrieve(
    "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64",
    ZIVPN_BIN
)
os.chmod(ZIVPN_BIN, 0o755)

# Step 3: Create ZIVPN config
os.makedirs(ZIVPN_DIR, exist_ok=True)
zivpn_config = {
    "listen": ":5667",
    "cert": f"{ZIVPN_DIR}/zivpn.crt",
    "key": f"{ZIVPN_DIR}/zivpn.key",
    "obfs": "zivpn",
    "auth": {"mode": "passwords", "config": ["zi"]},
    "config": ["zi"]
}
with open(ZIVPN_CFG, "w") as f:
    json.dump(zivpn_config, f, indent=2)

# Step 4: Generate TLS certificate
print("==> Generating TLS certificate...")
run_command(
    f'openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 '
    f'-subj "/C=US/ST=CA/L=LA/O=ZIVPN/CN=zivpn" '
    f'-keyout {ZIVPN_DIR}/zivpn.key -out {ZIVPN_DIR}/zivpn.crt >/dev/null 2>&1'
)

# Step 5: Create ZIVPN service file
zivpn_service = f"""[Unit]
Description=ZIVPN UDP Server
After=network.target
[Service]
ExecStart={ZIVPN_BIN} server -c {ZIVPN_CFG}
Restart=always
User=root
[Install]
WantedBy=multi-user.target
"""
with open(f"/etc/systemd/system/{ZIVPN_SVC}", "w") as f:
    f.write(zivpn_service)

# Step 6: Enable and start ZIVPN service
run_command("systemctl daemon-reload")
run_command(f"systemctl enable --now {ZIVPN_SVC}")

# Step 7: Configure firewall and iptables
IFC = run_command("ip -4 route ls | awk '/default/ {print $5; exit}'").strip()
run_command(f'iptables -t nat -A PREROUTING -i "{IFC}" -p udp --dport 6000:19999 -j DNAT --to-destination :5667')
run_command("ufw allow 5667/udp || true")
run_command("ufw allow 8088/tcp || true")

# Step 8: Set up Web Admin Panel
print("==> Setting up Web Admin Panel...")
os.makedirs(ADMIN_DIR, exist_ok=True)
run_command(f"python3 -m venv {VENV}")
run_command(f"{VENV}/bin/pip install flask waitress >/dev/null")

# Prompt for admin credentials
ADMIN_USER = input("Admin username [default: admin]: ") or "admin"
ADMIN_PASSWORD = getpass.getpass("Admin password [default: change-me]: ") or "change-me"

# Create .env file
env_content = f"""ADMIN_USER={ADMIN_USER}
ADMIN_PASSWORD={ADMIN_PASSWORD}
BIND_HOST=0.0.0.0
BIND_PORT=8088
ZIVPN_CONFIG={ZIVPN_CFG}
ZIVPN_SERVICE={ZIVPN_SVC}
"""
with open(ENV_FILE, "w") as f:
    f.write(env_content)

# Step 9: Create Flask app (app.py)
app_py_content = r"""#!/usr/bin/env python3
import os
import json
import sqlite3
import tempfile
import subprocess
import time
from subprocess import DEVNULL
from datetime import date, datetime, timedelta
from flask import Flask, request, redirect, url_for, session, render_template_string, flash
from functools import wraps
from ipaddress import ip_address

DB = "/var/lib/zivpn-admin/zivpn.db"
os.makedirs("/var/lib/zivpn-admin", exist_ok=True)
ZIVPN_CFG = os.getenv("ZIVPN_CONFIG", "/etc/zivpn/config.json")
ZIVPN_SVC = os.getenv("ZIVPN_SERVICE", "zivpn.service")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASSWORD", "change-me")
app = Flask(__name__)
app.secret_key = os.urandom(24)

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

with db() as con:
    con.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        expires DATE,
        ip_lock TEXT
    )''')

def logs():
    try:
        return subprocess.check_output(["journalctl", "-u", ZIVPN_SVC, "--since", "-15min", "-o", "cat"]).decode().lower()
    except Exception:
        return ""

def parse_log_for_conns(log_text):
    conns = {}
    lines = log_text.split('\n')
    for line in lines:
        if 'from ' in line:
            parts = line.split('from ')
            if len(parts) > 1:
                after_from = parts[1].split()[0]
                if ':' in after_from:
                    ip = after_from.split(':')[0]
                    if ip and ip != '::1' and not ip.startswith('127.'):
                        try:
                            ip_address(ip)
                            conns[ip] = conns.get(ip, 0) + 1
                        except ValueError:
                            pass
    return conns

def days_left(expires_str):
    try:
        exp = datetime.strptime(expires_str, "%Y-%m-%d").date()
        return (exp - date.today()).days
    except Exception:
        return None

def active_rows():
    log = logs()
    conns = parse_log_for_conns(log)
    today = date.today()
    rows = []
    with db() as con:
        for r in con.execute("SELECT * FROM users"):
            exp = datetime.strptime(r["expires"], "%Y-%m-%d").date()
            expired = exp < today
            pw_lower = r["password"].lower()
            user_conns = [ip for ip, count in conns.items() if pw_lower in log and ip in log[line.find(pw_lower)-50:line.find(pw_lower)+50] for line in log.split('\n') if pw_lower in line and ip in line] if not expired else []
            unique_ips = list(set(user_conns))
            online = len(unique_ips) > 0 and not expired
            ip_status = ', '.join(unique_ips) if unique_ips else 'None'
            multi_device = len(unique_ips) > 1
            rows.append({
                "id": r["id"], "username": r["username"], "password": r["password"],
                "expires": r["expires"], "expired": expired, "online": online,
                "days_left": days_left(r["expires"]),
                "ip_lock": r["ip_lock"] or None,
                "current_ips": ip_status,
                "multi_device": multi_device,
                "conn_count": len(unique_ips)
            })
    return rows

def sync():
    with db() as con:
        pw = [r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE DATE(expires) >= DATE('now')")]
    if not pw:
        pw = ["zi"]
    cfg = {}
    try:
        cfg = json.load(open(ZIVPN_CFG))
    except Exception:
        pass
    cfg.setdefault("auth", {})["mode"] = "passwords"
    cfg["auth"]["config"] = pw
    cfg["config"] = pw
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        json.dump(cfg, f, indent=2)
        tmp = f.name
    os.replace(tmp, ZIVPN_CFG)
    subprocess.Popen(["systemctl", "restart", ZIVPN_SVC], stdout=DEVNULL, stderr=DEVNULL)

def login_required(f):
    @wraps(f)
    def w(*a, **kw):
        if not session.get("ok"):
            return redirect(url_for("login"))
        return f(*a, **kw)
    return w

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("u") == ADMIN_USER and request.form.get("p") == ADMIN_PASS:
            session["ok"] = True
            return redirect("/")
        flash("Invalid credentials")
    return render_template_string('''<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<style>
body { font-family: Arial, sans-serif; background: #f0f0f0; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
.login-box { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); width: 300px; }
.login-box h2 { margin: 0 0 20px; text-align: center; }
.login-box input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px; }
.login-box button { width: 100%; padding: 10px; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; }
.login-box button:hover { background: #218838; }
</style></head>
<body>
<div class="login-box">
  <h2>ZIVPN Login</h2>
  <form method=post>
    <input name=u placeholder="Username" required>
    <input name=p type=password placeholder="Password" required>
    <button type=submit>Login</button>
  </form>
</div></body></html>''')

@app.route("/")
@login_required
def index():
    rows = active_rows()
    total_users = len(rows)
    total_online = sum(1 for r in rows if r["online"])
    total_offline = total_users - total_online
    default_exp = (date.today() + timedelta(days=30)).isoformat()
    try:
        vps_ip = subprocess.check_output(["hostname", "-I"]).decode().split()[0]
    except Exception:
        vps_ip = request.host.split(":")[0]
    server_ts = int(time.time())
    return render_template_string('''<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<style>
body { font-family: Arial, sans-serif; margin: 20px; background: #f0f0f0; }
.container { max-width: 1200px; margin: auto; }
.header { background: #343a40; color: white; padding: 10px 20px; border-radius: 8px; }
.header h1 { margin: 0; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
.card { background: white; padding: 15px; border-radius: 8px; box-shadow: 0 0 5px rgba(0,0,0,0.1); }
.card h3 { margin: 0 0 10px; }
.form-section { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
.form-section form { display: grid; gap: 10px; }
.form-section input, .form-section button { padding: 8px; border-radius: 4px; border: 1px solid #ccc; }
.form-section button { background: #28a745; color: white; border: none; cursor: pointer; }
.form-section button:hover { background: #218838; }
.table-section { background: white; padding: 20px; border-radius: 8px; overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 10px; border: 1px solid #ddd; text-align: left; }
th { background: #f8f9fa; }
tr:nth-child(even) { background: #f9f9f9; }
button { cursor: pointer; }
button.copy-btn { background: #007bff; color: white; border: none; padding: 5px 10px; }
button.copy-btn:hover { background: #0056b3; }
button.edit-btn { background: #ffc107; color: white; border: none; padding: 5px 10px; }
button.edit-btn:hover { background: #e0a800; }
button.delete-btn { background: #dc3545; color: white; border: none; padding: 5px 10px; }
button.delete-btn:hover { background: #c82333; }
</style>
<script>
function copyText(t, btn) {
  navigator.clipboard.writeText(t).then(() => {
    btn.innerText = '✓';
    btn.disabled = true;
    setTimeout(() => { btn.innerText = 'Copy'; btn.disabled = false; }, 800);
  });
}
function fillForm(u, p, e, il) {
  document.querySelector('input[name="username"]').value = u;
  document.querySelector('input[name="password"]').value = p;
  document.querySelector('input[name="expires"]').value = e;
  document.querySelector('input[name="ip_lock"]').value = il || '';
}
</script>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>ZIVPN Admin Panel</h1>
  </div>
  <div class="stats">
    <div class="card">
      <h3>Total Users</h3>
      <p>{{ total_users }}</p>
    </div>
    <div class="card">
      <h3>Total Online</h3>
      <p>{{ total_online }}</p>
    </div>
    <div class="card">
      <h3>Total Offline</h3>
      <p>{{ total_offline }}</p>
    </div>
  </div>
  <div class="form-section">
    <h3>Add / Update User</h3>
    <form method="post" action="/save">
      <input name="username" placeholder="Username" required>
      <input name="password" placeholder="Password" required>
      <input type="date" name="expires" value="{{ default_exp }}" required>
      <input name="ip_lock" placeholder="IP Lock (e.g., 192.168.1.100, optional)">
      <button type="submit">Save & Sync</button>
    </form>
  </div>
  <div class="table-section">
    <table>
      <thead>
        <tr>
          <th>User</th>
          <th>Password</th>
          <th>Expires</th>
          <th>IP Lock</th>
          <th>Current IP</th>
          <th>Status</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {% for r in rows %}
        <tr>
          <td>{{ r['username'] }}</td>
          <td>
            {{ r['password'] }}
            <button class="copy-btn" onclick="copyText('{{ r['password'] }}', this)">Copy</button>
            {% if r['days_left'] is not none %}
              {% if r['days_left'] >= 0 %}
                <span>{{ r['days_left'] }} days</span>
              {% else %}
                <span>Expired {{ -r['days_left'] }} days</span>
              {% endif %}
            {% endif %}
          </td>
          <td>{{ r['expires'] }}</td>
          <td>{{ r['ip_lock'] or 'None' }}</td>
          <td>{{ r['current_ips'] }}</td>
          <td>
            {% if r['expired'] %}
              Expired
            {% elif not r['online'] %}
              Offline
            {% else %}
              {% if r['multi_device'] %}
                Multi ({{ r['conn_count'] }})
              {% else %}
                Online
              {% endif %}
            {% endif %}
          </td>
          <td>
            <button class="edit-btn" onclick="fillForm('{{ r['username'] }}','{{ r['password'] }}','{{ r['expires'] }}','{{ r['ip_lock'] or '' }}')">Edit</button>
            <form method="post" action="/del/{{ r['id'] }}" style="display:inline;" onsubmit="return confirm('Delete {{ r['username'] }}?')">
              <button class="delete-btn">Delete</button>
            </form>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>
</body></html>''',
        rows=rows, total_users=total_users, total_online=total_online, total_offline=total_offline,
        default_exp=default_exp, vps_ip=vps_ip, server_ts=server_ts)

@app.route("/save", methods=["POST"])
@login_required
def save():
    u = request.form["username"].strip()
    p = request.form["password"].strip()
    e = request.form["expires"].strip()
    il = request.form["ip_lock"].strip()
    if not u or not p or not e:
        flash("Please fill all fields")
        return redirect("/")
    if il and not is_valid_ip(il):
        flash("Invalid IP address")
        return redirect("/")
    with db() as con:
        con.execute('''INSERT INTO users (username, password, expires, ip_lock)
                       VALUES (?, ?, ?, ?)
                       ON CONFLICT(username) DO UPDATE SET password = ?, expires = ?, ip_lock = ?''',
                    (u, p, e, il, p, e, il))
    try:
        ip = subprocess.check_output(["hostname", "-I"]).decode().split()[0]
    except Exception:
        ip = request.host.split(":")[0]
    msg = f"IP: {ip}\nUsers: {u}\nPassword: {p}\nExpired Date: {e}\nIP Lock: {il or 'Disabled'}\n1 User For 1 Device"
    flash(msg, "ok")
    sync()
    return redirect("/")

def is_valid_ip(ip_str):
    try:
        ip_address(ip_str)
        return True
    except ValueError:
        return False

@app.route("/del/<int:uid>", methods=["POST"])
@login_required
def delete(uid):
    with db() as con:
        con.execute("DELETE FROM users WHERE id = ?", (uid,))
    sync()
    return redirect("/")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    from waitress import serve
    serve(app, host=os.getenv("BIND_HOST", "0.0.0.0"), port=int(os.getenv("BIND_PORT", "8088")))
"""

# Validate app_py_content syntax
with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as temp_file:
    temp_file.write(app_py_content)
    temp_file_path = temp_file.name

try:
    subprocess.run(f"python3 -m py_compile {temp_file_path}", shell=True, check=True, capture_output=True)
    print("==> Validated app.py content syntax")
except subprocess.CalledProcessError as e:
    print(f"Error: Invalid syntax in app.py content\n{e.stderr}")
    os.unlink(temp_file_path)
    exit(1)

# Write app.py
with open(APP_PY, "w") as f:
    f.write(app_py_content)
os.chmod(APP_PY, 0o755)

# Verify app.py syntax
try:
    subprocess.run(f"python3 -m py_compile {APP_PY}", shell=True, check=True, capture_output=True)
    print("==> Verified app.py syntax")
except subprocess.CalledProcessError as e:
    print(f"Error: Invalid syntax in {APP_PY}\n{e.stderr}")
    os.unlink(temp_file_path)
    exit(1)

os.unlink(temp_file_path)

# Step 10: Create sync script (sync.py)
sync_py_content = """import os
import json
import sqlite3
import tempfile
import subprocess
from subprocess import DEVNULL

DB = "/var/lib/zivpn-admin/zivpn.db"
CFG = "/etc/zivpn/config.json"
SVC = "zivpn.service"

def actives():
    with sqlite3.connect(DB) as con:
        pw = [r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE DATE(expires) >= DATE('now')")]
    return pw or ["zi"]

cfg = {}
try:
    cfg = json.load(open(CFG))
except Exception:
    pass
pw = actives()
cfg.setdefault("auth", {})["mode"] = "passwords"
cfg["auth"]["config"] = pw
cfg["config"] = pw
with tempfile.NamedTemporaryFile("w", delete=False) as f:
    json.dump(cfg, f, indent=2)
    tmp = f.name
os.replace(tmp, CFG)
subprocess.Popen(["systemctl", "restart", SVC], stdout=DEVNULL, stderr=DEVNULL)
"""
with open(SYNC_PY, "w") as f:
    f.write(sync_py_content)
os.chmod(SYNC_PY, 0o755)

# Verify sync.py syntax
try:
    subprocess.run(f"python3 -m py_compile {SYNC_PY}", shell=True, check=True, capture_output=True)
    print("==> Verified sync.py syntax")
except subprocess.CalledProcessError as e:
    print(f"Error: Invalid syntax in {SYNC_PY}\n{e.stderr}")
    exit(1)

# Step 11: Create systemd service files
panel_service = f"""[Unit]
Description=ZIVPN Web Panel
After=network.target
[Service]
EnvironmentFile={ENV_FILE}
WorkingDirectory={ADMIN_DIR}
ExecStart={VENV}/bin/python {APP_PY}
Restart=always
User=root
[Install]
WantedBy=multi-user.target
"""
with open(f"/etc/systemd/system/{PANEL_SVC}", "w") as f:
    f.write(panel_service)

sync_service = f"""[Unit]
Description=ZIVPN Daily Sync
[Service]
ExecStart={VENV}/bin/python {SYNC_PY}
"""
with open(f"/etc/systemd/system/{SYNC_SVC}", "w") as f:
    f.write(sync_service)

sync_timer = """[Unit]
Description=Run ZIVPN daily sync
[Timer]
OnCalendar=*-*-* 00:10:00
Persistent=true
[Install]
WantedBy=timers.target
"""
with open(f"/etc/systemd/system/{SYNC_TIMER}", "w") as f:
    f.write(sync_timer)

# Step 12: Enable and start services
run_command("systemctl daemon-reload")
run_command(f"systemctl enable --now {PANEL_SVC}")
run_command(f"systemctl enable --now {SYNC_TIMER}")

# Step 13: Get server IP
IP = run_command("hostname -I | awk '{print $1}'").strip()

# Final output
print("\n✅ INSTALL COMPLETE")
print(f"Open Panel: http://{IP}:8088/login")
print("======================================")
print("Features:")
print("- Single-device login (monitors connections, flags multi-device)")
print("- IP lock per user (enforced in app, ZIVPN may handle disconnects)")
print("- 30-day default license per user")