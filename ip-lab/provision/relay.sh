#!/usr/bin/env bash
set -eux
bash /vagrant/provision/common.sh
sysctl -w net.ipv4.ip_forward=1
cp /vagrant/proxy_lab/relay/relay.conf /etc/nginx/nginx.conf
# relay is the "VPN exit": it appends the peer it saw, correctly
sed -i 's|proxy_pass http://172.30.0.20:8085;|proxy_pass http://192.168.60.20:80;|; s|listen 127.0.0.1:8081;|listen 192.168.50.11:80;|; s|out/|/lab/out/|g' /etc/nginx/nginx.conf
mkdir -p /lab/out; chown -R www-data /lab/out
# the relay's own log is the second witness; keep it out of /var/log so the host can grab it
nginx -t
systemctl restart nginx
echo "relay up: 192.168.50.11:80 -> 192.168.60.20:80"
