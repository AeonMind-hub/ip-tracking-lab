#!/usr/bin/env bash
set -eux
bash /vagrant/provision/common.sh
cp -r /vagrant/apps /vagrant/lab /vagrant/tools /lab/ 2>/dev/null || true
cd /lab && nohup python3 apps/app.py --port 80 --mode naive --backend-ip 192.168.60.20 >/lab/app.log 2>&1 &
# deliberately NO default route here, so nothing you generate can reach the internet
ip route del default 2>/dev/null || true
echo "target up on 192.168.60.20:80 (mode=naive)"
