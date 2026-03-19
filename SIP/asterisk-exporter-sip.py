
# -*- coding: utf-8 -*-
#!/usr/bin/env python3
import os
import time
import socket
import threading
import logging
from prometheus_client import Gauge, CollectorRegistry, make_wsgi_app
from wsgiref.simple_server import make_server, WSGIRequestHandler

# Tắt toàn bộ logging của wsgiref để loại bỏ log "Remote UNIX connection"
logging.getLogger('wsgiref').setLevel(logging.CRITICAL + 1)
logging.getLogger('wsgiref').propagate = False

PORT = 9255

# Lớp tùy chỉnh để tắt log từ các yêu cầu HTTP
class QuietWSGIRequestHandler(WSGIRequestHandler):
    def log_message(self, format, *args):
        pass  # Không ghi log

# Khởi tạo Registry và Metrics
registry = CollectorRegistry()
host = socket.gethostname()

asterisk_total_active_calls_metric = Gauge(
    "asterisk_active_calls", "Total current active calls", ["host"], registry=registry)
asterisk_total_calls_processed_metric = Gauge(
    "asterisk_calls_processed", "Total current calls processed", ["host"], registry=registry)
asterisk_total_sip_peers_metric = Gauge(
    "asterisk_sip_peers", "Total sip peers", ["host"], registry=registry)
asterisk_total_sip_peers_online_metric = Gauge(
    "asterisk_sip_peers_online", "Total sip peers online", ["host"], registry=registry)
asterisk_total_sip_peers_offline_metric = Gauge(
    "asterisk_sip_peers_offline", "Total sip peers offline", ["host"], registry=registry)
asterisk_total_core_uptime_metric = Gauge(
    "asterisk_core_uptime", "Total core uptime in seconds", ["host"], registry=registry)

def run_metrics_collector():
    while True:
        try:
            def get(cmd): return int(os.popen(cmd).read().strip() or 0)

            active_calls = get("asterisk -rx 'core show calls' | grep 'active call' | awk '{print $1}'")
            calls_processed = get("asterisk -rx 'core show channels' | grep 'calls processed' | awk '{print $1}'")
            sip_peers = get("asterisk -rx 'sip show peers' | grep 'sip peers' | awk '{print $1}'")
            sip_peers_online = get("asterisk -rx 'sip show peers' | grep 'sip peers' | awk '{print $5}'")
            sip_peers_offline = get("asterisk -rx 'sip show peers' | grep 'sip peers' | awk '{print $7}'")
            core_uptime = get("asterisk -rx 'core show uptime seconds' | grep 'System uptime' | awk '{print $3}'")

            asterisk_total_active_calls_metric.labels(host=host).set(active_calls)
            asterisk_total_calls_processed_metric.labels(host=host).set(calls_processed)
            asterisk_total_sip_peers_metric.labels(host=host).set(sip_peers)
            asterisk_total_sip_peers_online_metric.labels(host=host).set(sip_peers_online)
            asterisk_total_sip_peers_offline_metric.labels(host=host).set(sip_peers_offline)
            asterisk_total_core_uptime_metric.labels(host=host).set(core_uptime)

        except Exception as e:
            print(f"Error gathering metrics: {e}")

        time.sleep(5)

if __name__ == "__main__":
    # Khởi động thread thu thập metrics
    collector_thread = threading.Thread(target=run_metrics_collector)
    collector_thread.daemon = True
    collector_thread.start()

    # Khởi chạy server với lớp xử lý tùy chỉnh
    app = make_wsgi_app(registry)
    with make_server('', PORT, app, handler_class=QuietWSGIRequestHandler) as httpd:
        print(f"Serving metrics on http://localhost:{PORT}/")
        httpd.serve_forever()
