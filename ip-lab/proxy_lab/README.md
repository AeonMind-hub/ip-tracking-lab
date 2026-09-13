# proxy-lab — three hops, one truth (Module 6)

Purpose: make "attribution dies at a proxy" something you can *see*, and prove that
your log's meaning is decided by config text, not by your intentions.

```
you ──> edge (nginx, :8080 = NAIVE bug) ──> relay (:8081, "the VPN") ──> target (:8085)
you ──> edge2 (nginx, :8088 = SAFE config) ─> relay (:8081)          ──> target (:8085)
```

| host | port | what it is |
|---|---|---|
| edge | 8080 | nginx with `proxy_set_header X-Forwarded-For $http_x_forwarded_for;` — **the classic bug**: forwards whatever the client typed |
| edge | 8088 | nginx with `set_real_ip_from 127.0.0.0/8; real_ip_recursive on; real_ip_header X-Forwarded-For;` — **the trap**: syntax correct, semantics attacker-controlled (the trust list includes anything local) |
| edge | 8087 | the same as 8088 plus `--strip-inbound-xff`, i.e. strip-then-set — the fix, shown side by side |
| relay | 8081 | the "commercial VPN exit": socat appends its peer address the honest way |
| target | 8085 | `apps/app.py --mode safe` (trusts the socket peer only) or `--mode naive` |

## Run it here (no Docker, no nginx, no Vagrant) — verified

```bash
cd ip-lab
# one command: origin + relay + buggy edge + correct edge + recursive-off edge,
# the ATO battery through each, the per-hop log table, the dossier verdict, the audit diff
bash chain_demo.sh
```

Or drive it yourself, so the flags are yours rather than a script's:

```bash
python3 apps/app.py --port 8085 --mode naive &                    # origin, buggy logging
python3 proxy_lab/proxy_sim.py --listen 127.0.0.1:8080 --upstream 127.0.0.1:8085 --mode naive &
python3 proxy_lab/proxy_sim.py --listen 127.0.0.1:8088 --upstream 127.0.0.1:8085 --mode correct \
        --trusted 127.0.0.0/8 --real-ip-header X-Forwarded-For --real-ip-recursive on &
python3 proxy_lab/proxy_sim.py --listen 127.0.0.1:8087 --upstream 127.0.0.1:8085 --mode correct \
        --trusted 127.0.0.0/8 --real-ip-header X-Forwarded-For --real-ip-recursive on \
        --strip-inbound-xff &                                        # the FIX, for comparison

python3 tools/probe.py --naive 8080 --debug-vars     # through the buggy edge
curl -s -o /dev/null -H 'X-Forwarded-For: 1.1.1.1, 8.8.8.8, 203.0.113.66, 127.0.0.1' http://127.0.0.1:8088/echo
curl -s -o /dev/null -H 'X-Forwarded-For: 1.1.1.1, 8.8.8.8, 203.0.113.66, 127.0.0.1' http://127.0.0.1:8087/echo
python3 tools/dossier.py out/target_access_sim.log --xff --no-net
```

What you should see (from this exact run): the origin's log is a mix of `127.0.0.1` and
`8.8.8.8` — every line whose header the naive edge forwarded verbatim; `:8088` records
`203.0.113.66` (an attacker-chosen address reached by a legitimate walk past a trusted
tail) while `:8087`, the same config plus `--strip-inbound-xff`, records `127.0.0.1`,
which is the only true statement that hop can make. `tools/selftest.py` pins all four of
those outcomes ("strip-then-append", "recursive off takes the right-most entry",
"narrow trust + client junk => attacker wins", "no trusted proxy -> peer wins"), so if
you refactor the decision away, the tests fail.

The nginx path, when you have nginx (host or container) — both files are complete
standalone configs (`worker_processes`/`events`/`http`, with `pid`/`error_log` under
`out/`), so `-p` matters:

```bash
nginx -t -p $PWD -c $PWD/proxy_lab/nginx/edge_naive.conf      # then run with -g 'daemon off;'
nginx -t -p $PWD -c $PWD/proxy_lab/nginx/edge_safe.conf
```


## Run it in Docker (same shape, isolated)

```bash
docker compose -f proxy_lab/docker-compose.yml up --build
docker compose exec edge curl -s -H 'X-Forwarded-For: 1.1.1.1' http://target:8085/echo | jq '.logged_ip, .log_reason'
```

## Run it in VMs (Vagrantfile at repo root, `ip-lab/Vagrantfile`)

```bash
cd ip-lab && vagrant up          # generic/ubuntu2404, 512 MB each, three VMs
```

Provisioning does the whole topology, so there is nothing to copy by hand:

| VM | address | what `provision/*.sh` leaves running |
|---|---|---|
| `edge` | 192.168.50.10 | nginx with `edge_naive.conf` as `/etc/nginx/nginx.conf` (**:8080**) and `edge_safe.conf` at `/etc/nginx/edge_safe.conf` (**:8088**), both `proxy_pass` to the relay; logs rewritten to `/lab/out/` |
| `relay` | 192.168.50.11 / 192.168.60.10 | `net.ipv4.ip_forward=1`, nginx listening `192.168.50.11:80` → `192.168.60.20:80`, logging the raw XFF chain to `/lab/out/relay_xffchain.log` |
| `target` | 192.168.60.20 | `python3 /lab/apps/app.py --port 80 --mode naive`, and **no default route** (`ip route del default`) |

That last line is the lesson, not a typo: with no route out, the *only* way to reach the
origin is through `edge`, which is what makes the two edges' log lines comparable. It also
means `apt`/`curl https://example.com` fail on the target — install packages first, which
`provision/common.sh` does before the route is deleted.

The three witnesses, for one request:

```bash
vagrant ssh target -c 'sudo tcpdump -i any -nn -w /lab/live.pcap port 80' &      # the wire
vagrant ssh edge   -c 'curl -s -o /dev/null -H "X-Forwarded-For: 198.51.100.23, 8.8.8.8" http://192.168.50.10:8080/'
vagrant ssh edge   -c 'curl -s -o /dev/null -H "X-Forwarded-For: 198.51.100.23, 8.8.8.8" http://192.168.50.10:8088/'
vagrant ssh target -c 'sudo killall -INT tcpdump; sudo chmod 644 /lab/live.pcap'
vagrant scp target:/lab/live.pcap out/live.pcap
vagrant ssh edge   -c 'sudo grep -h . /lab/out/*access.log | tail -6'
python3 tools/triage.py --pcap out/live.pcap            # the pcap disagrees with both logs
```

Read `X-Forwarded-For` off the wire at hop 3 (`tcpdump -A`): the header is different text
at each hop, and every field that a hop *carried* unchanged is only as trustworthy as the
first hop that wrote it. TTL lies too, because each proxy re-originates the connection.

## Do this on your laptop and phone (the exercise people skip)

1. Laptop: `python3 apps/app.py --port 8085 --mode safe`, then `ip addr`/`ipconfig` to
   find your LAN IP (e.g. `192.168.1.24`).
2. Phone on the **same Wi-Fi**: open `http://192.168.1.24:8085/echo`. Your log now shows
   `192.168.1.24` — your router's DHCP lease, not a person, and nothing else about the
   phone was needed. Read the `all_headers` the server received: model, language, timezone,
   `Accept-Encoding`. That is the whole "track" capability, no exploit.
3. Turn Wi-Fi **off**, use mobile data, hit the same URL through your laptop's public IP
   (or a tunnel you own). The logged address is now your carrier's CGNAT address.
   Now try to say anything about *which subscriber*. You can't — and that is the exact
   wall an investigator hits, and why the answer is "ISP + legal process", never a tool.
4. Bonus: from the phone, browse to `tools/canary.py serve --port 8090`'s token URL and
   inspect `out/canary_state.json`: watch `Accept-Language: en-US` on a Nigerian SIM,
   the timezone, and (if WebRTC is enabled) the private IP — the fingerprint, not the IP,
   is what identifies a *device*.

`audit.py` (in `tools/`) will then tell you, from a config file, which of the four
attribution behaviours your own setup has. That's the deliverable: a verdict + a patch.

## What is verified here and what is not

* **Executed in this workspace (Python only, loopback):** `chain_demo.sh` end to end,
  `proxy_sim.py` in all four modes (`naive`, `correct`+recursive on/off, `--strip-inbound-xff`),
  the per-hop log table, `tools/dossier.py` on the resulting logs, and `tools/audit.py`
  on both nginx configs (`tools/selftest.py`: 165 checks, including the forwarded-header trust walk on both nginx configs).
* **Written, not executed here** — no Docker/Vagrant/nginx/raw sockets in this sandbox:
  `docker-compose.yml` (+ its entrypoint), `Vagrantfile` and `provision/*.sh`,
  `nginx/{edge_naive,edge_safe}.conf`, `relay/relay.conf`. Those are checked statically
  (`bash -n`, `yaml.safe_load`, `tools/audit.py`) and are *meant* to run on your laptop.
  `nginx -t` has never been run against the two site files: treat them as reviewed drafts,
  not as tested config. That distinction is itself lesson 6 — say which of your claims are
  executed and which are read.
