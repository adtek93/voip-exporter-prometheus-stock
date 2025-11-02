# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import os
import time
import socket
import threading
import logging
import re
import json
from prometheus_client import Gauge, CollectorRegistry, make_wsgi_app
from wsgiref.simple_server import make_server, WSGIRequestHandler

# --- Cấu hình ---
PORT = 9256
registry = CollectorRegistry()
host = socket.gethostname()

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

# Tắt log HTTP của wsgiref
logging.getLogger('wsgiref').setLevel(logging.CRITICAL + 1)
logging.getLogger('wsgiref').propagate = False

class QuietWSGIRequestHandler(WSGIRequestHandler):
    def log_message(self, format, *args):
        pass

# --- Metric định nghĩa ---
asterisk_total_active_calls_metric = Gauge("asterisk_active_calls", "Total current active calls", ["host"], registry=registry)
asterisk_total_calls_processed_metric = Gauge("asterisk_calls_processed", "Total current calls processed", ["host"], registry=registry)
asterisk_total_pjsip_aors_metric = Gauge("asterisk_pjsip_aors", "Total PJSIP AORs", ["host"], registry=registry)
asterisk_total_pjsip_online_metric = Gauge("asterisk_pjsip_online", "Total online PJSIP AORs", ["host"], registry=registry)
asterisk_total_pjsip_offline_metric = Gauge("asterisk_pjsip_offline", "Total offline PJSIP AORs", ["host"], registry=registry)
asterisk_total_core_uptime_metric = Gauge("asterisk_core_uptime", "Total core uptime in seconds", ["host"], registry=registry)

# Metric chi tiết đăng ký (5 labels) - LƯU Ý: thứ tự labels không quan trọng nếu dùng keyword args khi .labels(...)
asterisk_pjsip_registration_info = Gauge(
    "asterisk_pjsip_registration_info",
    "Detailed PJSIP registration info (1=registered)",
    ["host", "endpoint", "ip_wan", "ip_local", "user_agent"],
    registry=registry
)

def debug_app(environ, start_response):
    status = '200 OK'
    headers = [('Content-type', 'text/plain; charset=utf-8')]
    start_response(status, headers)
    output_aor = os.popen("sudo -u asterisk asterisk -rx 'pjsip show aors'").read()
    return [output_aor.encode('utf-8')]

def parse_registrar_contacts():
    """
    Parse output of `database show registrar/contact`.
    Returns list of dicts: {endpoint, ip_wan, ip_local, user_agent}
    """
    DATA = os.popen("sudo -u asterisk asterisk -rx 'database show registrar/contact' 2>/dev/null").read()
    results = []

    if not DATA.strip():
        return results

    # Try to find JSON blobs and parse them robustly (supports multiline)
    # Pattern: <somekey>: { ...json... }
    for m in re.finditer(r'^[^:]+:\s*(\{.*?\})', DATA, flags=re.MULTILINE | re.DOTALL):
        raw = m.group(1)
        try:
            obj = json.loads(raw)
        except Exception:
            # fallback: try to normalize to one-line JSON-like and extract fields with regex
            obj = {}
            try:
                # endpoint
                e = re.search(r'"endpoint"\s*:\s*"([^"]+)"', raw)
                if e: obj['endpoint'] = e.group(1)
                va = re.search(r'"via_addr"\s*:\s*"([^"]+)"', raw)
                if va: obj['via_addr'] = va.group(1)
                uri = re.search(r'"uri"\s*:\s*"([^"]+)"', raw)
                if uri: obj['uri'] = uri.group(1)
                ua = re.search(r'"user_agent"\s*:\s*"([^"]+)"', raw)
                if ua: obj['user_agent'] = ua.group(1)
            except Exception:
                pass

        # Extract fields from obj safely
        endpoint = obj.get('endpoint') or obj.get('Endpoint') or ""
        ip_local = obj.get('via_addr') or obj.get('viaAddr') or obj.get('via_addr', "") or ""
        uri = obj.get('uri') or ""
        ip_wan = ""
        if uri:
            # uri may be like sip:36505522@42.118.213.186:60686;...
            m_uri = re.search(r'@([^;:]+)', uri)
            if m_uri:
                ip_wan = m_uri.group(1)
        user_agent = obj.get('user_agent') or obj.get('userAgent') or ""
        # Normalize whitespace and truncate user_agent to sane length
        user_agent = re.sub(r'\s+', ' ', user_agent).strip()
        if len(user_agent) > 200:
            user_agent = user_agent[:197] + '...'

        if endpoint:
            results.append({
                "endpoint": str(endpoint),
                "ip_wan": str(ip_wan),
                "ip_local": str(ip_local),
                "user_agent": str(user_agent)
            })

    # Fallback: if nothing collected via JSON parsing, try line-based extraction
    if not results:
        for m in re.finditer(r'"endpoint"\s*:\s*"([^"]+)"', DATA):
            endpoint = m.group(1)
            # try extracting surrounding fields by searching the larger text for that endpoint
            block_re = re.compile(r'"endpoint"\s*:\s*"%s".{0,200}' % re.escape(endpoint), re.DOTALL)
            mb = block_re.search(DATA)
            block = mb.group(0) if mb else ""
            ip_local = re.search(r'"via_addr"\s*:\s*"([^"]+)"', block)
            uri = re.search(r'"uri"\s*:\s*"([^"]+)"', block)
            user_agent = re.search(r'"user_agent"\s*:\s*"([^"]+)"', block)
            ip_local = ip_local.group(1) if ip_local else ""
            ip_wan = ""
            if uri:
                m_uri = re.search(r'@([^;:]+)', uri.group(1))
                if m_uri:
                    ip_wan = m_uri.group(1)
            ua = user_agent.group(1) if user_agent else ""
            ua = re.sub(r'\s+', ' ', ua).strip()
            if len(ua) > 200:
                ua = ua[:197] + '...'
            results.append({
                "endpoint": endpoint,
                "ip_wan": ip_wan,
                "ip_local": ip_local,
                "user_agent": ua
            })

    return results

def run_metrics_collector():
    os.chdir("/var/lib/asterisk")  # tránh permission issues

    while True:
        try:
            # tiện ích lấy số nguyên
            def get_int(cmd):
                out = os.popen(cmd).read().strip()
                return int(out) if out.isdigit() else 0

            active_calls = get_int("sudo -u asterisk asterisk -rx 'core show calls' | grep 'active call' | awk '{print $1}'")
            calls_processed = get_int("sudo -u asterisk asterisk -rx 'core show channels' | grep 'calls processed' | awk '{print $1}'")
            core_uptime = get_int("sudo -u asterisk asterisk -rx 'core show uptime seconds' | awk '/System uptime/ {print $3}'")

            output_aor = os.popen("sudo -u asterisk asterisk -rx 'pjsip show aors' 2>/dev/null").read()
            total_aor_matches = re.findall(r'^\s*Aor:\s+(\S+)\s+\d+\s*$', output_aor, re.MULTILINE)
            total_aor = len(total_aor_matches)
            blocks = re.split(r'^\s*Aor:', output_aor, flags=re.MULTILINE)[1:]
            online_aor = sum(1 for b in blocks if re.search(r'Contact:.*\bAvail\b', b, re.MULTILINE))
            offline_aor = max(total_aor - online_aor, 0)

            # Update summary metrics
            asterisk_total_active_calls_metric.labels(host=host).set(active_calls)
            asterisk_total_calls_processed_metric.labels(host=host).set(calls_processed)
            asterisk_total_core_uptime_metric.labels(host=host).set(core_uptime)
            asterisk_total_pjsip_aors_metric.labels(host=host).set(total_aor)
            asterisk_total_pjsip_online_metric.labels(host=host).set(online_aor)
            asterisk_total_pjsip_offline_metric.labels(host=host).set(offline_aor)

            # --- Update registration detail: clear then repopulate ---
            try:
                asterisk_pjsip_registration_info.clear()
            except Exception:
                # older prometheus_client may not implement clear(); fallback to safe removal
                try:
                    for s in list(asterisk_pjsip_registration_info._metrics.keys()):
                        asterisk_pjsip_registration_info.remove(*s)
                except Exception:
                    logging.debug("Không thể clear() metric bằng fallback. Tiếp tục.")

            registrations = parse_registrar_contacts()
            logging.debug(f"Found {len(registrations)} registrations")

            for r in registrations:
                # Defensive: ensure keys exist
                ep = r.get("endpoint", "") or ""
                ipw = r.get("ip_wan", "") or ""
                ipl = r.get("ip_local", "") or ""
                ua = r.get("user_agent", "") or ""

                # Ensure strings (no None)
                ep = str(ep)
                ipw = str(ipw)
                ipl = str(ipl)
                ua = str(ua)

                # Try to set labels using keyword args to avoid ordering mistakes
                try:
                    asterisk_pjsip_registration_info.labels(
                        host=host,
                        endpoint=ep,
                        ip_wan=ipw,
                        ip_local=ipl,
                        user_agent=ua
                    ).set(1.0)
                except Exception as ex:
                    # Log full detail for debugging label count issues
                    logging.error("Lỗi khi set metric asterisk_pjsip_registration_info: %s", ex)
                    logging.error("Tried labels: host=%s, endpoint=%s, ip_wan=%s, ip_local=%s, user_agent=%s", host, ep, ipw, ipl, ua)
                    continue

        except Exception as e:
            logging.error("Lỗi collector: %s", e)

        time.sleep(10)

def make_app():
    app = make_wsgi_app(registry)
    def composite_app(environ, start_response):
        if environ.get('PATH_INFO') == '/debug':
            return debug_app(environ, start_response)
        return app(environ, start_response)
    return composite_app

if __name__ == "__main__":
    # Start collector thread
    collector_thread = threading.Thread(target=run_metrics_collector, daemon=True)
    collector_thread.start()

    # Serve /metrics
    httpd = make_server('', PORT, make_app(), handler_class=QuietWSGIRequestHandler)
    logging.info("Serving metrics on port %d", PORT)
    httpd.serve_forever()
