# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import os
import time
import socket
import threading
import logging
import re
from prometheus_client import Gauge, CollectorRegistry, make_wsgi_app, generate_latest
from wsgiref.simple_server import make_server, WSGIRequestHandler

# Tắt log của wsgiref
logging.getLogger('wsgiref').setLevel(logging.CRITICAL + 1)
logging.getLogger('wsgiref').propagate = False

PORT = 9256

class QuietWSGIRequestHandler(WSGIRequestHandler):
    def log_message(self, format, *args):
        pass  # Không ghi log request

registry = CollectorRegistry()
host = socket.gethostname()

# Metric definitions (chỉ AORs)
asterisk_total_active_calls_metric = Gauge(
    "asterisk_active_calls", "Total current active calls", ["host"], registry=registry)
asterisk_total_calls_processed_metric = Gauge(
    "asterisk_calls_processed", "Total current calls processed", ["host"], registry=registry)
asterisk_total_pjsip_aors_metric = Gauge(
    "asterisk_pjsip_aors", "Total PJSIP AORs", ["host"], registry=registry)
asterisk_total_pjsip_online_metric = Gauge(
    "asterisk_pjsip_online", "Total online PJSIP AORs", ["host"], registry=registry)
asterisk_total_pjsip_offline_metric = Gauge(
    "asterisk_pjsip_offline", "Total offline PJSIP AORs", ["host"], registry=registry)
asterisk_total_core_uptime_metric = Gauge(
    "asterisk_core_uptime", "Total core uptime in seconds", ["host"], registry=registry)

def debug_app(environ, start_response):
    """Endpoint /debug để xem output CLI"""
    status = '200 OK'
    headers = [('Content-type', 'text/plain; charset=utf-8')]
    start_response(status, headers)
    output_aor = os.popen("sudo -u asterisk asterisk -rx 'pjsip show aors'").read()
    return [output_aor.encode('utf-8')]

def run_metrics_collector():
    os.chdir("/var/lib/asterisk")  # Tránh Permission denied

    while True:
        try:
            # Hàm tiện ích chạy lệnh shell và lấy số nguyên
            def get(cmd):
                result = os.popen(cmd).read().strip()
                return int(result) if result and result.isdigit() else 0

            # --- Core metrics ---
            active_calls = get("sudo -u asterisk asterisk -rx 'core show calls' | grep 'active call' | awk '{print $1}'")
            calls_processed = get("sudo -u asterisk asterisk -rx 'core show channels' | grep 'calls processed' | awk '{print $1}'")
            core_uptime = get("sudo -u asterisk asterisk -rx 'core show uptime seconds' | awk '/System uptime/ {print $3}'")

            # --- PJSIP AOR metrics ---
            output_aor = os.popen("sudo -u asterisk asterisk -rx 'pjsip show aors'").read()
            
            # Log output CLI (giới hạn 500 ký tự)
           #  logging.info(f"AOR CLI Output: {repr(output_aor[:500])}...")

            if not output_aor.strip():
               #  logging.error("Output 'pjsip show aors' RỖNG! Kiểm tra sudo -u asterisk asterisk -rx 'pjsip show aors'")
                total_aor = online_aor = offline_aor = 0
            else:
                # Tổng AOR: Match "Aor: [tên] [số]"
                total_aor_matches = re.findall(r'^\s*Aor:\s+(\S+)\s+\d+\s*$', output_aor, re.MULTILINE)
                total_aor = len(total_aor_matches)

                # Fallback nếu =0
                if total_aor == 0:
                    objects_match = re.search(r'Objects found:\s*(\d+)', output_aor)
                    total_aor = int(objects_match.group(1)) if objects_match else 0

                # Online AOR: Split blocks và đếm có Avail
                blocks = re.split(r'^\s*Aor:', output_aor, flags=re.MULTILINE)[1:]
                online_aor = 0
                for block in blocks:
                    if re.search(r'Contact:.*\bAvail\b', block, re.MULTILINE):
                        online_aor += 1

                # Offline
                offline_aor = max(total_aor - online_aor, 0)

            # Log giá trị
           #  logging.info(f"AOR Metrics: Total={total_aor}, Online={online_aor}, Offline={offline_aor} | Matches={total_aor_matches if 'total_aor_matches' in locals() else 'N/A'}")

            # Set metrics
            asterisk_total_active_calls_metric.labels(host=host).set(active_calls)
            asterisk_total_calls_processed_metric.labels(host=host).set(calls_processed)
            asterisk_total_core_uptime_metric.labels(host=host).set(core_uptime)
            asterisk_total_pjsip_aors_metric.labels(host=host).set(total_aor)
            asterisk_total_pjsip_online_metric.labels(host=host).set(online_aor)
            asterisk_total_pjsip_offline_metric.labels(host=host).set(offline_aor)

        except Exception as e:
             logging.error(f"Lỗi: {e}")

        time.sleep(5)

def make_app():
    app = make_wsgi_app(registry)
    def composite_app(environ, start_response):
        if environ['PATH_INFO'] == '/debug':
            return debug_app(environ, start_response)
        return app(environ, start_response)
    return composite_app

if __name__ == "__main__":
   #  logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    collector_thread = threading.Thread(target=run_metrics_collector, daemon=True)
    collector_thread.start()

    httpd = make_server('', PORT, make_app(), handler_class=QuietWSGIRequestHandler)
   #  logging.info(f"Phục vụ metrics tại http://localhost:{PORT}/ | Debug tại http://localhost:{PORT}/debug")
    httpd.serve_forever()
