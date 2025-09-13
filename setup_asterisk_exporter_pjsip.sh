#!/bin/bash
# Script tạo và khởi động systemd service cho Asterisk PJSIP Prometheus Exporter

SERVICE_FILE="/etc/systemd/system/asterisk_exporter.service"

echo "[1/4] Tạo file service..."
cat <<EOF | sudo tee $SERVICE_FILE > /dev/null
[Unit]
Description=Asterisk PJSIP Prometheus Exporter
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /usr/local/bin/asterisk_exporter_pjsip.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

echo "[2/4] Reload systemd..."
sudo systemctl daemon-reload

echo "[3/4] Enable service..."
sudo systemctl enable asterisk_exporter.service

echo "[4/4] Start service..."
sudo systemctl start asterisk_exporter.service

echo "-------------------------------------"
echo "Trạng thái service:"
sudo systemctl status asterisk_exporter.service --no-pager

echo "-------------------------------------"
echo "Logs mới nhất (Ctrl+C để thoát):"
sudo journalctl -u asterisk_exporter.service -n 20 --no-pager
