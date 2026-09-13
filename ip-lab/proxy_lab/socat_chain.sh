#!/usr/bin/env bash
# Requires `socat` (apt/brew; on Windows use WSL - choco has a port but it is not
# what this script expects). Nothing here touches anything but 127.0.0.1.
# The "VPN exit" hop, without needing nginx: socat appends the peer address the
# honest way is *not* possible with socat alone (it does not rewrite HTTP), so this
# script runs TWO socat forwards and you observe that the XFF you typed survives
# every hop that does not deliberately strip it. Pair it with apps/app.py --mode naive
# to watch a spoofed IP ride through two "proxies" into the log.
set -u
cd "$(dirname "$0")/.."
PIDS=""
cleanup(){ [ -n "$PIDS" ] && kill $PIDS 2>/dev/null; }
trap cleanup EXIT INT TERM
echo "[chain] relay :8081 -> 127.0.0.1:8085 (target)"
socat -v TCP-LISTEN:8081,fork,reuseaddr,bind=127.0.0.1 TCP:127.0.0.1:8085 2>out/relay8081.log & PIDS="$PIDS $!"
echo "[chain] edge  :8080 -> 127.0.0.1:8081 (relay)"
socat TCP-LISTEN:8080,fork,reuseaddr,bind=127.0.0.1 TCP:127.0.0.1:8081 2>/dev/null & PIDS="$PIDS $!"
echo "[chain] up. now:"
echo "  python3 apps/app.py --port 8085 --mode naive &"
echo "  curl -s -H 'X-Forwarded-For: 1.1.1.1' http://127.0.0.1:8080/echo | head -c 400"
echo "  ...and out/target_access_sim.log will contain 1.1.1.1 as the 'attacker'."
wait
