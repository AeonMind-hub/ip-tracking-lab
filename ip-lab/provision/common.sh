#!/usr/bin/env bash
set -eux
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nginx-core curl jq tcpdump net-tools python3 traceroute mtr-tiny whois dnsutils nmap >/dev/null
mkdir -p /lab
