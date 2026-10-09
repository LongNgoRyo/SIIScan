#!/bin/bash
# Script don dep log cu an toan (khong co reverse shell)
find /var/log/myapp -name "*.log" -mtime +30 -delete
echo "Da xoa log cu hon 30 ngay"
