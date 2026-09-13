#!/usr/bin/env bash
# Three-hop attribution demo, end to end, in one command. No nginx, no Docker,
# no root, nothing outside 127.0.0.1.
#
#   client ─> edge:8080 (naive)              ┐
#   client ─> edge:8088 (correct, recursive) ├─> relay:8081 ("the VPN") ─> target:8085
#   client ─> edge:8089 (correct, no recur.) ┘
#
# The same forged header produces three different stories in the logs. That is the
# whole of Module 6: the client address in a log is a *policy outcome*, not a fact.
set -u
cd "$(dirname "$0")/.."
# Which interpreter to spawn. Git Bash on Windows normally only has `python`, and the
# sandbox-less macOS/Linux boxes normally only have `python3`. Override with PY=... if you
# keep several (e.g. PY=/c/Python312/python.exe).
PY="${PY:-$(command -v python3 || command -v python || echo python3)}"
OUT=out; mkdir -p $OUT
PORTS="8085 8081 8080 8088 8089"
PIDS=""

cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; }
trap cleanup EXIT INT TERM

# Kill leftovers from an aborted run before they make this demo confusing.
# (The sweep below needs /proc: on Git Bash it finds nothing and simply skips.)
"$PY" - <<'PY'
import os, re, signal, socket, time
want = {"8085", "8081", "8080", "8088", "8089"}
killed = []
proc = "/proc"
for d in (sorted(os.listdir(proc)) if os.path.isdir(proc) else []):
    if not d.isdigit():
        continue
    try:
        cmd = open(f"{proc}/{d}/cmdline", "rb").read().decode(errors="ignore").replace("\x00", " ")
    except OSError:
        continue
    if ("proxy_sim.py" in cmd or "apps/app.py" in cmd):
        m = re.search(r"--(?:port|listen) \S*?(\d+)", cmd)
        if m and m.group(1) in want:
            try:
                os.kill(int(d), signal.SIGTERM)
                killed.append(f"{m.group(1)}(pid {d})")
            except OSError:
                pass
if killed:
    time.sleep(1.0)
    print(f"  [init] cleared leftovers on: {', '.join(killed)}")
PY

rm -f $OUT/proxy_*_access.log $OUT/target_access_sim.log $OUT/*.stderr

start() { # name port cmd...
  local name=$1 port=$2; shift 2
  "$@" > "$OUT/$name.out" 2>&1 &
  PIDS="$PIDS $!"
  echo "  started $name (pid $!) on :$port"
}

wait_port() { # port
  "$PY" - "$1" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
for _ in range(160):
    s = socket.socket(); s.settimeout(0.2)
    ok = s.connect_ex(("127.0.0.1", port)) == 0
    s.close()
    if ok:
        sys.exit(0)
    time.sleep(0.25)
import os
sys.stderr.write("port %d never came up; tail of out/%s.out:\n" % (port, os.environ.get("NAME", "?")))
sys.exit(1)
PY
}

echo "[init] spawning origin + relay + three edges"
start target 8085 "$PY" apps/app.py --port 8085 --mode safe --backend-ip 127.0.0.1
start relay 8081 "$PY" proxy_lab/proxy_sim.py --listen 127.0.0.1:8081 --upstream 127.0.0.1:8085 \
      --mode correct --trusted 127.0.0.0/8 --real-ip-header X-Forwarded-For --real-ip-recursive on
start edge_naive 8080 "$PY" proxy_lab/proxy_sim.py --listen 127.0.0.1:8080 --upstream 127.0.0.1:8081 \
      --mode naive
start edge_safe 8088 "$PY" proxy_lab/proxy_sim.py --listen 127.0.0.1:8088 --upstream 127.0.0.1:8081 \
      --mode correct --trusted 127.0.0.0/8 --real-ip-header X-Forwarded-For --real-ip-recursive on
start edge_plain 8089 "$PY" proxy_lab/proxy_sim.py --listen 127.0.0.1:8089 --upstream 127.0.0.1:8081 \
      --mode correct --trusted 127.0.0.0/8 --real-ip-header X-Forwarded-For --real-ip-recursive off
for p in $PORTS; do wait_port "$p" || exit 1; done
lines_before() { [ -f "$1" ] && wc -l < "$1" || echo 0; }

FORGED='X-Forwarded-For: 198.51.100.23, 8.8.8.8'
bomb() { # port
  for i in 1 2 3 4 5 6 7; do
    curl -s -o /dev/null -w "    attempt $i -> %{http_code}\n" -H "$FORGED" \
         -d 'email=victim@acme.ng&password=guess'$i http://127.0.0.1:$1/login
  done
  curl -s -H "$FORGED" -d 'email=victim@acme.ng&password=letmein123' -o /dev/null \
       -w "    correct password -> %{http_code}\n" http://127.0.0.1:$1/login
}
logged_as() { # logfile lines_already_seen  -> the distinct first fields added since
  [ -f "$1" ] || { echo "(no log)"; return; }
  tail -n +"$((${2:-0} + 1))" "$1" | awk '{print $1}' | sort | uniq -c | sort -rn \
    | awk '{printf "%s x%s  ", $2, $1}'
}

echo; echo "=== A. through the BUGGY edge (:8080) — log_format uses \$http_x_forwarded_for ==="
b=$(lines_before $OUT/proxy_8080_access.log); bomb 8080
echo "    this hop logged the client as: $(logged_as $OUT/proxy_8080_access.log "$b")"

echo; echo "=== B. through the CORRECT edge (:8088) — real_ip + real_ip_recursive on ==="
b=$(lines_before $OUT/proxy_8088_access.log); bomb 8088
echo "    this hop logged the client as: $(logged_as $OUT/proxy_8088_access.log "$b")"

echo; echo "=== C. same request, real_ip_recursive OFF (:8089) ==="
b9=$(lines_before $OUT/proxy_8089_access.log); b8=$(lines_before $OUT/proxy_8088_access.log)
curl -s -o /dev/null -H "$FORGED" http://127.0.0.1:8089/echo
curl -s -o /dev/null -H "$FORGED" http://127.0.0.1:8088/echo
echo "    both hops, plain forged chain '$FORGED':"
echo "      :8089 (off) logged $(logged_as $OUT/proxy_8089_access.log "$b9")| :8088 (on) logged $(logged_as $OUT/proxy_8088_access.log "$b8")"
b9=$(lines_before $OUT/proxy_8089_access.log); b8=$(lines_before $OUT/proxy_8088_access.log)
curl -s -o /dev/null -H 'X-Forwarded-For: 203.0.113.66, 127.0.0.1' http://127.0.0.1:8089/echo
curl -s -o /dev/null -H 'X-Forwarded-For: 203.0.113.66, 127.0.0.1' http://127.0.0.1:8088/echo
echo "    same request, chain ending in an address inside set_real_ip_from:"
echo "      :8089 (off) logged $(logged_as $OUT/proxy_8089_access.log "$b9")| :8088 (on) logged $(logged_as $OUT/proxy_8088_access.log "$b8")"
echo "    with a chain whose right-most entry is inside the trust list,"
echo "    'off' records the loopback (loudly wrong, easy to spot) while 'on' walks past it"
echo "    and records 203.0.113.66 (quietly attacker-chosen). Neither is a 'client IP'."

echo; echo "=== what each hop recorded (field 1 = 'the client address' per that hop's config) ==="
for f in $OUT/proxy_8080_access.log $OUT/proxy_8081_access.log $OUT/proxy_8088_access.log \
         $OUT/proxy_8089_access.log $OUT/target_access_sim.log; do
  [ -f "$f" ] || continue
  printf "%-30s %3s lines | %s\n" "$(basename "$f")" "$(wc -l < "$f")" \
         "$(awk '{print $1}' "$f" | sort | uniq -c | sort -rn | awk '{printf "%s x%s  ", $2, $1}')"
done

echo; echo "=== the analyst's verdict on the ORIGIN's log (the one you would actually use) ==="
"$PY" tools/dossier.py $OUT/target_access_sim.log --xff --no-net 2>&1 | sed -n '1,12p'

echo; echo "=== read the XFF chain the origin saw, hop by hop ==="
tail -1 $OUT/proxy_8080_access.log | sed 's/^/  buggy edge  : /'
tail -1 $OUT/proxy_8081_access.log | sed 's/^/  vpn relay   : /'
tail -1 $OUT/target_access_sim.log  | sed 's/^/  origin      : /'

echo; echo "=== audit the two nginx configs the same topology would use ==="
"$PY" tools/audit.py proxy_lab/nginx/edge_naive.conf --diff proxy_lab/nginx/edge_safe.conf \
        --patch out/hardened_edge.conf

echo
echo "done. read notes/06-proxy-lab.md (why B and C disagree, and why the trust list is"
echo "the real bug) and notes/08-audit-and-web.md §8.1 (what the audit tool can and cannot see)."
