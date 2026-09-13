#!/usr/bin/env bash
set -eux
bash /vagrant/provision/common.sh
cp /vagrant/proxy_lab/nginx/edge_naive.conf /etc/nginx/nginx.conf
sed -i 's|proxy_pass http://127.0.0.1:8085;|proxy_pass http://192.168.50.11:80;|; s|listen 127.0.0.1:8080;|listen 192.168.50.10:8080;|; s|out/|/lab/out/|g' /etc/nginx/nginx.conf
cp /vagrant/proxy_lab/nginx/edge_safe.conf /etc/nginx/edge_safe.conf
sed -i 's|proxy_pass http://127.0.0.1:8081;|proxy_pass http://192.168.50.11:80;|; s|listen 127.0.0.1:8088;|listen 192.168.50.10:8088;|; s|out/|/lab/out/|g' /etc/nginx/edge_safe.conf
mkdir -p /lab/out; chown -R www-data /lab/out
nginx -t; systemctl restart nginx
echo "edge up: :8080 naive, :8088 safe"
