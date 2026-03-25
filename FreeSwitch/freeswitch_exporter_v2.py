#!/usr/bin/env python3
"""
FreeSWITCH / FusionPBX Prometheus Exporter v3
- Chia theo domain (multi-tenant FusionPBX)
- 1 user nhiều thiết bị → phân biệt bằng (user, domain, agent, network_ip)
- Labels cứng, không chứa expsecs
- ping-status + ping-time
"""

import subprocess, time, logging, re, socket
import xml.etree.ElementTree as ET
from prometheus_client import start_http_server, Gauge, Info

PORT = 9256
INTERVAL = 15
TIMEOUT = 10
HOSTNAME = socket.gethostname()
FS_CLI = '/usr/bin/fs_cli'

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("fs_exporter")

# ============================================================
# METRICS
# ============================================================

# -- Core --
uptime_seconds        = Gauge('freeswitch_uptime_seconds',                'Uptime seconds',              ['host'])
sessions_total        = Gauge('freeswitch_sessions_total',                'Total sessions since startup',['host'])
sessions_current      = Gauge('freeswitch_sessions_current',              'Current sessions',            ['host'])
sessions_peak         = Gauge('freeswitch_sessions_peak',                 'Peak sessions',               ['host'])
sessions_peak_5min    = Gauge('freeswitch_sessions_peak_5min',            'Peak sessions 5min',          ['host'])
sessions_per_second   = Gauge('freeswitch_sessions_per_second',           'Current CPS',                 ['host'])
sessions_per_sec_peak = Gauge('freeswitch_sessions_per_second_peak',      'Peak CPS',                    ['host'])
sessions_per_sec_5min = Gauge('freeswitch_sessions_per_second_peak_5min', 'Peak CPS 5min',               ['host'])
sessions_max          = Gauge('freeswitch_sessions_max',                  'Max allowed sessions',        ['host'])
idle_cpu              = Gauge('freeswitch_idle_cpu_percent',              'Min idle CPU %',              ['host'])
active_channels       = Gauge('freeswitch_channels_active',              'Active channels',             ['host'])
active_calls          = Gauge('freeswitch_calls_active',                 'Active calls',                ['host'])

# -- Registrations: chia theo domain --
registrations_total   = Gauge('freeswitch_registrations_total',
    'Total registrations per domain',
    ['host', 'profile', 'domain'])

registration_up       = Gauge('freeswitch_registration_up',
    'Endpoint registered (1) or not (0)',
    ['host', 'profile', 'domain', 'user', 'agent', 'network_ip', 'network_port', 'transport'])

registration_expire   = Gauge('freeswitch_registration_expire_seconds',
    'Seconds until registration expires',
    ['host', 'profile', 'domain', 'user', 'network_ip'])

registration_ping     = Gauge('freeswitch_registration_ping_seconds',
    'SIP OPTIONS ping RTT in seconds',
    ['host', 'profile', 'domain', 'user', 'network_ip'])

registration_ping_status = Gauge('freeswitch_registration_ping_reachable',
    'Ping reachable (1) or not (0)',
    ['host', 'profile', 'domain', 'user', 'network_ip'])

# -- Gateways --
gateway_up         = Gauge('freeswitch_gateway_up',           'GW status 1=REGED 0.5=TRYING 0=DOWN', ['host', 'profile', 'gateway', 'proxy', 'scheme', 'state'])
gateway_calls_in   = Gauge('freeswitch_gateway_calls_in',     'GW inbound calls',                    ['host', 'profile', 'gateway'])
gateway_calls_out  = Gauge('freeswitch_gateway_calls_out',    'GW outbound calls',                   ['host', 'profile', 'gateway'])
gateway_ping_time  = Gauge('freeswitch_gateway_ping_time_ms', 'GW ping ms',                          ['host', 'profile', 'gateway'])

freeswitch_info    = Info('freeswitch', 'FreeSWITCH build info')

# ============================================================
# STATE
# ============================================================
_prev_reg_keys = set()
_prev_gw_keys  = set()

# ============================================================
# HELPERS
# ============================================================
def fs_cli(cmd):
    try:
        r = subprocess.run([FS_CLI, '-x', cmd],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=TIMEOUT)
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception as e:
        log.warning("fs_cli (%s): %s", cmd, e)
        return ""

def fs_cli_xml(cmd):
    raw = fs_cli(cmd)
    if not raw:
        return None
    raw = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', raw)
    try:
        return ET.fromstring(raw)
    except ET.ParseError as e:
        log.warning("XML (%s): %s", cmd, e)
        return None

def parse_count(text):
    m = re.search(r'(\d+)\s+total', text)
    return int(m.group(1)) if m else 0

def parse_status_field(raw):
    transport, expsecs = 'unknown', 0
    m = re.search(r'Registered\(([^)]+)\)', raw)
    if m: transport = m.group(1)
    m = re.search(r'expsecs\((\d+)\)', raw)
    if m: expsecs = int(m.group(1))
    return transport, expsecs

def parse_user_domain(user_raw):
    if '@' in user_raw:
        parts = user_raw.split('@', 1)
        return parts[0], parts[1]
    return user_raw, 'unknown'

# ============================================================
# COLLECTORS
# ============================================================
def collect_status():
    out = fs_cli("status")
    if not out: return
    lbl = {'host': HOSTNAME}

    for line in out.splitlines():
        line = line.strip()

        if line.startswith("UP "):
            sec = 0
            for val, unit in re.findall(r'(\d+)\s+(year|day|hour|minute|second)', line):
                v = int(val)
                if   'year'   in unit: sec += v*365*86400
                elif 'day'    in unit: sec += v*86400
                elif 'hour'   in unit: sec += v*3600
                elif 'minute' in unit: sec += v*60
                else:                  sec += v
            uptime_seconds.labels(**lbl).set(sec)

        if 'session(s) since startup' in line:
            m = re.search(r'(\d+)\s+session', line)
            if m: sessions_total.labels(**lbl).set(int(m.group(1)))

        m = re.match(r'(\d+)\s+session\(s\)\s+-\s+peak\s+(\d+),\s+last\s+5min\s+(\d+)', line)
        if m:
            sessions_current.labels(**lbl).set(int(m.group(1)))
            sessions_peak.labels(**lbl).set(int(m.group(2)))
            sessions_peak_5min.labels(**lbl).set(int(m.group(3)))

        m = re.match(r'(\d+)\s+session\(s\)\s+per\s+Sec\s+out\s+of\s+max\s+(\d+),\s+peak\s+(\d+),\s+last\s+5min\s+(\d+)', line)
        if m:
            sessions_per_second.labels(**lbl).set(int(m.group(1)))
            sessions_max.labels(**lbl).set(int(m.group(2)))
            sessions_per_sec_peak.labels(**lbl).set(int(m.group(3)))
            sessions_per_sec_5min.labels(**lbl).set(int(m.group(4)))

        m = re.match(r'(\d+)\s+session\(s\)\s+max', line)
        if m: sessions_max.labels(**lbl).set(int(m.group(1)))

        m = re.search(r'min idle cpu\s+([\d.]+)', line)
        if m: idle_cpu.labels(**lbl).set(float(m.group(1)))

    ver = re.search(r'FreeSWITCH\s*\(Version\s+([^)]+)\)', out)
    if ver:
        freeswitch_info.info({'version': ver.group(1).strip(), 'host': HOSTNAME})

def collect_channels_calls():
    lbl = {'host': HOSTNAME}
    active_channels.labels(**lbl).set(parse_count(fs_cli("show channels count")))
    active_calls.labels(**lbl).set(parse_count(fs_cli("show calls count")))

def get_profiles():
    root = fs_cli_xml("sofia xmlstatus")
    if root is None: return ['internal']
    profiles = []
    for p in root.iter('profile'):
        if p.findtext('type','') == 'profile':
            name = p.findtext('name','')
            if name: profiles.append(name)
    return profiles or ['internal']

def collect_registrations(profile):
    global _prev_reg_keys
    root = fs_cli_xml(f"sofia xmlstatus profile {profile} reg")

    current_keys = set()
    domain_counts = {}

    if root is not None:
        regs_node = root.find('registrations')
        if regs_node is None:
            regs_node = root

        for reg in regs_node.iter('registration'):
            user_raw   = reg.findtext('user', 'unknown')
            user, domain = parse_user_domain(user_raw)

            agent      = reg.findtext('agent', 'unknown')
            raw_status = reg.findtext('status', 'unknown')
            net_ip     = reg.findtext('network-ip', '')
            net_port   = reg.findtext('network-port', '')
            ping_stat  = reg.findtext('ping-status', '')
            ping_time  = reg.findtext('ping-time', '0')

            transport, expsecs = parse_status_field(raw_status)

            key = (profile, domain, user, agent, net_ip, net_port, transport)
            current_keys.add(key)

            domain_counts[domain] = domain_counts.get(domain, 0) + 1

            registration_up.labels(
                host=HOSTNAME, profile=profile, domain=domain,
                user=user, agent=agent, network_ip=net_ip,
                network_port=net_port, transport=transport
            ).set(1.0)

            registration_expire.labels(
                host=HOSTNAME, profile=profile, domain=domain,
                user=user, network_ip=net_ip
            ).set(expsecs)

            try:
                registration_ping.labels(
                    host=HOSTNAME, profile=profile, domain=domain,
                    user=user, network_ip=net_ip
                ).set(float(ping_time))
            except ValueError:
                pass

            registration_ping_status.labels(
                host=HOSTNAME, profile=profile, domain=domain,
                user=user, network_ip=net_ip
            ).set(1.0 if ping_stat.lower() == 'reachable' else 0.0)

    for domain, cnt in domain_counts.items():
        registrations_total.labels(
            host=HOSTNAME, profile=profile, domain=domain
        ).set(cnt)

    # Cleanup stale
    for old in (_prev_reg_keys - current_keys):
        p, d, u, a, nip, nport, tr = old
        try:
            registration_up.labels(
                host=HOSTNAME, profile=p, domain=d, user=u,
                agent=a, network_ip=nip, network_port=nport, transport=tr
            ).set(0.0)
            registration_expire.labels(
                host=HOSTNAME, profile=p, domain=d,
                user=u, network_ip=nip
            ).set(0)
            registration_ping_status.labels(
                host=HOSTNAME, profile=p, domain=d,
                user=u, network_ip=nip
            ).set(0.0)
        except Exception:
            pass

    prev_domains = {k[1] for k in _prev_reg_keys if k[0] == profile}
    curr_domains = set(domain_counts.keys())
    for gone_domain in (prev_domains - curr_domains):
        try:
            registrations_total.labels(
                host=HOSTNAME, profile=profile, domain=gone_domain
            ).set(0)
        except Exception:
            pass

    _prev_reg_keys = current_keys

def collect_gateways(profile):
    global _prev_gw_keys
    root = fs_cli_xml(f"sofia xmlstatus profile {profile}")
    if root is None: return

    current = set()
    for gw in root.iter('gateway'):
        name   = gw.findtext('name', 'unknown')
        proxy  = gw.findtext('proxy', '')
        scheme = gw.findtext('scheme', 'sip')
        state  = gw.findtext('state', 'NOREG')
        status = gw.findtext('status', 'DOWN')

        current.add((profile, name, proxy))
        val = 1.0 if 'REGED' in status else (0.5 if 'TRYING' in status else 0.0)

        gateway_up.labels(host=HOSTNAME, profile=profile, gateway=name,
                          proxy=proxy, scheme=scheme, state=state).set(val)
        try:
            gateway_calls_in.labels(host=HOSTNAME, profile=profile, gateway=name).set(
                int(gw.findtext('calls-in','0')))
            gateway_calls_out.labels(host=HOSTNAME, profile=profile, gateway=name).set(
                int(gw.findtext('calls-out','0')))
        except ValueError: pass
        try:
            gateway_ping_time.labels(host=HOSTNAME, profile=profile, gateway=name).set(
                float(gw.findtext('ping-time','0')))
        except ValueError: pass

    for old in (_prev_gw_keys - current):
        p, gn, px = old
        try:
            gateway_up.labels(host=HOSTNAME, profile=p, gateway=gn,
                              proxy=px, scheme='', state='DOWN').set(0.0)
        except Exception: pass
    _prev_gw_keys = current

# ============================================================
# MAIN
# ============================================================
def collect():
    collect_status()
    collect_channels_calls()
    profiles = get_profiles()
    for p in profiles:
        collect_registrations(p)
        collect_gateways(p)
    log.info("OK | profiles=%s", ','.join(profiles))

if __name__ == '__main__':
    log.info("FreeSWITCH Exporter v3 (multi-domain) → :%d | host=%s", PORT, HOSTNAME)
    test = fs_cli("version")
    if test: log.info("FS: %s", test)
    start_http_server(PORT)
    while True:
        try: collect()
        except Exception as e: log.error("Error: %s", e, exc_info=True)
        time.sleep(INTERVAL)
