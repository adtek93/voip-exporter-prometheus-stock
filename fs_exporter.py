#!/usr/bin/env python3
import subprocess, time, logging, re, socket
from prometheus_client import start_http_server, Gauge

PORT = 9256
INTERVAL = 5
TIMEOUT = 10
HOSTNAME = socket.gethostname()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# === METRICS ===
active_calls = Gauge('freeswitch_active_calls', 'Total current active calls', ['host'])
calls_processed = Gauge('freeswitch_calls_processed', 'Total calls processed since startup', ['host'])
sip_total = Gauge('freeswitch_sip_registrations_total', 'Total SIP AORs', ['host'])
sip_online = Gauge('freeswitch_sip_registrations_online', 'Total online SIP AORs', ['host'])
sip_offline = Gauge('freeswitch_sip_registrations_offline', 'Total offline SIP AORs', ['host'])
uptime_sec = Gauge('freeswitch_core_uptime', 'Total core uptime in seconds', ['host'])

# GIỮ NGUYÊN label: endpoint + ip_wan + user_agent
reg_info = Gauge(
    'freeswitch_sip_registration_info',
    'Detailed SIP registration info (1=registered)',
    ['endpoint', 'host', 'ip_local', 'ip_wan', 'user_agent']
)

# === KEY DUY NHẤT: (endpoint, ip_wan, user_agent) ===
previous_registrations = {}  # {(endpoint, ip_wan, user_agent): True}

def run(cmd):
    try:
        r = subprocess.run(['fs_cli', '-x', cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=TIMEOUT)
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception as e:
        log.warning(f"fs_cli error ({cmd}): {e}")
        return ""

def collect():
    global previous_registrations
    label_base = {'host': HOSTNAME}
    current_registrations = {}  # {(endpoint, ip_wan, user_agent): True}

    # === 1. STATUS: uptime + calls processed ===
    status = run("status")
    if status:
        for line in status.splitlines():
            if line.startswith("UP "):
                m = re.search(r'UP\s+(.+?)\s+\(', line)
                if m:
                    t = m.group(1)
                    sec = 0
                    if (x := re.search(r'(\d+)\s+year', t)): sec += int(x.group(1)) * 365 * 86400
                    if (x := re.search(r'(\d+)\s+day', t)): sec += int(x.group(1)) * 86400
                    if (x := re.search(r'(\d+):(\d+):(\d+)', t)):
                        h, mn, s = map(int, x.groups())
                        sec += h * 3600 + mn * 60 + s
                    uptime_sec.labels(**label_base).set(sec)

            if "session(s) since startup" in line:
                m = re.search(r'(\d+)', line)
                if m: calls_processed.labels(**label_base).set(int(m.group(1)))

    # === 2. ACTIVE CALLS ===
    calls_out = run("show calls count")
    active = int(re.search(r'\d+', calls_out).group(0)) if re.search(r'\d+', calls_out) else 0
    active_calls.labels(**label_base).set(active)

    # === 3. TOTAL REGISTRATIONS ===
    regs_out = run("show registrations")
    total_regs = 0
    if regs_out:
        last_line = regs_out.strip().splitlines()[-1]
        m = re.search(r'(\d+)\s+total\.', last_line)
        if m: total_regs = int(m.group(1))
    sip_total.labels(**label_base).set(total_regs)

    # === 4. REGISTRATION: DỮ LIỆU CHI TIẾT ===
    sofia_reg = run("sofia status profile internal reg")
    if sofia_reg and "Registrations:" in sofia_reg:
        lines = sofia_reg.splitlines()
        in_reg = False
        current = {}

        for line in lines:
            line = line.strip()
            if line == "Registrations:":
                in_reg = True
                continue
            if not in_reg or not line:
                continue

            if line.startswith("Call-ID:"):
                if current:
                    endpoint = current.get('user', 'unknown')
                    agent = current.get('agent', 'unknown')
                    ip_wan = current.get('ip_wan', 'unknown')
                    key = (endpoint, ip_wan, agent)  # KEY DUY NHẤT

                    current_registrations[key] = True

                    reg_info.labels(
                        endpoint=endpoint,
                        host=HOSTNAME,
                        ip_local='',
                        ip_wan=ip_wan,
                        user_agent=agent
                    ).set(1.0)
                current = {}
                continue

            if ":" not in line:
                continue
            key_name, val = line.split(":", 1)
            key_name = key_name.strip().lower().replace(" ", "_")
            val = val.strip()

            if key_name == "user":
                current['user'] = val.split("@")[0]
            elif key_name == "contact":
                m = re.search(r'@([^:]+):\d+', val)
                if m:
                    current['ip_wan'] = m.group(1)
            elif key_name == "agent":
                current['agent'] = val

        # Xử lý bản ghi cuối
        if current:
            endpoint = current.get('user', 'unknown')
            agent = current.get('agent', 'unknown')
            ip_wan = current.get('ip_wan', 'unknown')
            key = (endpoint, ip_wan, agent)

            current_registrations[key] = True
            reg_info.labels(
                endpoint=endpoint,
                host=HOSTNAME,
                ip_local='',
                ip_wan=ip_wan,
                user_agent=agent
            ).set(1.0)

    # === CẬP NHẬT ONLINE / OFFLINE ===
    online_count = len(current_registrations)
    sip_online.labels(**label_base).set(online_count)
    sip_offline.labels(**label_base).set(total_regs - online_count)

    # === SET VỀ 0 CHO CÁC KẾT NỐI CŨ ĐÃ UNREGISTER ===
    for old_key in previous_registrations:
        if old_key not in current_registrations:
            endpoint, ip_wan, agent = old_key
            reg_info.labels(
                endpoint=endpoint,
                host=HOSTNAME,
                ip_local='',
                ip_wan=ip_wan,
                user_agent=agent
            ).set(0.0)

    # === CẬP NHẬT previous_registrations ===
    previous_registrations = current_registrations.copy()

    # === LOG ===
    log.info(f"OK | Active:{active} | Regs:{total_regs} | Online:{online_count}")

# === MAIN ===
if __name__ == '__main__':
    log.info(f"FreeSWITCH Exporter → :{PORT} | host={HOSTNAME}")
    start_http_server(PORT)
    while True:
        try:
            collect()
        except Exception as e:
            log.error(f"Error: {e}")
        time.sleep(INTERVAL)