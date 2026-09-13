# Module 6 — The proxy lab: three hops, one truth

Run it: `bash proxy_lab/chain_demo.sh` (no root, no Docker, no nginx; verified in this
workspace). Topology:

```
client ─> edge:8080 (naive: forwards the client's XFF verbatim, and LOGS it)
      ─> relay:8081 ("commercial VPN exit": appends the peer it saw)
      ─> target:8085 (origin, --mode safe: trusts only its socket peer)

client ─> edge:8088 (correct: real_ip + trust list, recursive on)      ─┐
client ─> edge:8089 (correct: same, real_ip plain mode, recursive off) ─┴─> relay:8081 ─> target
```

## 6.1 What it printed, and what to learn from each line

Every request carried the same lie: `X-Forwarded-For: 198.51.100.23, 8.8.8.8`.

| hop | field 1 of its log | why |
|---|---|---|
| buggy edge :8080 | `198.51.100.23` | it logs `$http_x_forwarded_for` — i.e. the client's own words |
| relay :8081 | `8.8.8.8` | trusts its peer (loopback), walks right-to-left over the trusted prefix, stops on the first non-trusted value — which the client typed |
| edge :8088 (`recursive on`) | `8.8.8.8` | same walk one hop earlier; it *then* appends `127.0.0.1`, which is why the relay sees a longer chain than the client sent |
| origin :8085 | `127.0.0.1` | its only trusted fact is the TCP peer. That is the **truth**, and the truth here is "unattributable" |

**The lesson that actually matters:** there is no "correct value for the client
IP" living inside the header. There are only per-hop statements ("I saw X connect to
me"), and any hop that lets a client *write* one of those statements has broken the
chain. The origin's `127.0.0.1` looks useless — but it is the only honest fact, and
combined with the raw chain it lets you prove *someone was spoofing*, which is itself
an incident.

`dossier.py` on the origin log shows exactly that verdict:

```
### 127.0.0.1
    xff: chain=['198.51.100.23', '8.8.8.8', '127.0.0.1'] verdict=127.0.0.1 confidence=high
      ! XFF SENT TO A NON-PROXIED SERVER -> client is lying or testing you
```

## 6.2 `real_ip_recursive on` vs `off`: the demo's section C

Same two configs, one request whose chain ends in an address inside
`set_real_ip_from 127.0.0.0/8` — `X-Forwarded-For: 203.0.113.66, 127.0.0.1`:

```
:8089 (recursive off)  logged 127.0.0.1     # right-most entry, taken blindly
:8088 (recursive on)   logged 203.0.113.66  # walks past the trusted tail, lands on the attacker's value
```

Both are wrong, in *different and instructive* ways. `off` is loud: a loopback address
in the client field is trivially detected (that is a real Sigma rule — `where
c_client_ip in (127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16) and c_socket_ip not in same`).
`on` is quiet: `203.0.113.66` looks like a customer, and it is attacker-chosen, so it
lands in your blocklist, your geo gate and your report. Worse, the poisoned value
**propagates**: `proxy_8081_access.log` in the same run has two lines logged as
`203.0.113.66`, because the relay's *input* was the edge's *output*. A single
mis-configured hop upstream rewrites reality for every hop downstream — which is exactly
why "who may speak" must be decided once, at the outermost hop, not per-service.

If you take one line from Module 6: **the recursion flag is a rounding error next to the
trust list.** Fix the trust list (or, better, strip-and-set), and both modes agree.

## 6.3 Why `real_ip_recursive on` was *wrong* here (this is the part people get wrong once and then never correctly)

```nginx
set_real_ip_from 127.0.0.0/8;   # "my proxy is local"
real_ip_header X-Forwarded-For;
real_ip_recursive on;
```
Recursive mode keeps walking left **while the value is trusted**. Since the client
*also* got to write `8.8.8.8` into the chain, and `8.8.8.8`… is not trusted, so it
stopped there and believed it. Your trust list included the address range the attacker
could reach through (loopback), so the attacker *is* inside your trusted topology from
the config's point of view. Rules of thumb:

1. `set_real_ip_from` = the **exact** address/subnet of the hop that fronts you, never
   a convenience range. If your proxy is `127.0.0.1` and other local processes can also
   reach you, you have already lost the property you think you configured — put the
   origin on a separate host/VPC subnet, or a unix socket + peer-cred.
2. Plain mode (no `real_ip_recursive`) removes exactly one hop. Recursive mode removes
   as many as match, so it is only safe when *every* trusted prefix belongs to hops you
   physically control in order.
3. The only genuinely spoof-proof header is a **signed** one from an edge you operate
   (`True-Client-IP` with a verification key, your own JWT, mTLS between edge and origin).
   Signature beats position.
4. Never let a client *append*: strip inbound `X-Forwarded-For` at the outermost hop
   unless that hop is the one computing it.

## 6.4 The `--mode` matrix, and what each combination teaches

| target `--mode` | proxy | request | origin log | lesson |
|---|---|---|---|---|
| naive | none | plain | real peer | fine |
| naive | none | forged XFF | **the forged value** | the bug in `notes/02` |
| naive | buggy edge | forged XFF | the forged value | the bug *with* deniability |
| safe | buggy edge | forged XFF | `127.0.0.1` | truth, but you need the chain field to explain it |
| safe | correct edge | real client | real client | the goal |

`apps/app.py --mode naive` is the app-side version of the same sin (TrustProxies /
`trust proxy = true` / Symfony `HEADER_ALL`). Both halves have to be right: **who may
speak** (the proxy) and **who is believed** (the app).

## 6.5 Doing it in Docker / VMs

* `docker compose -f proxy_lab/docker-compose.yml up --build` — target/relay/edge on an
  isolated `172.30.0.0/24`. Then inside `edge`:
  `curl -s -H 'X-Forwarded-For: 1.1.1.1' http://target:8085/echo | jq '.logged_ip, .log_reason'`.
  Note: the compose file was authored and syntax-checked here, but **Docker is not
  installed in this sandbox**, so that path is unverified-by-execution; the `proxy_sim`
  version above is fully exercised.
* `vagrant up` (repo root `Vagrantfile`) gives you `edge/relay/target` on
  192.168.50/60.0/24 with the target having **no default route**. Same reason as above:
  no Vagrant here to run it. In the VMs you additionally get the real tools:
  ```bash
  # on target
  sudo tcpdump -i any -nn -s0 port 80 -w /lab/hop3.pcap
  # then read the XFF bytes off the wire - you will see the header CHANGE between hops
  # and you will see that TTL is a lie when a proxy re-originates the connection
  ```
* **Wire-level homework:** diff `hop1.pcap` (client↔edge) against `hop3.pcap`
  (relay↔target). Every field that changed at a hop is a field you may trust about that
  hop, and every field that was *carried* unchanged is only as trustworthy as the first
  writer. That single exercise explains XFF, `Forwarded`, `Via`, and MTI-style signed
  headers better than any doc.

## 6.6 Phone + laptop (the CGNAT lesson you cannot fake)

`proxy_lab/README.md` §"Do this on your laptop and phone" — same Wi-Fi gives you the
router's `192.168.1.x`, mobile data gives you a carrier address shared with a city.
Record both log lines side by side and write, in your own words, why the second one is
worse evidence, not better.

## 6.7 Exercises

1. Make the origin log `1.1.1.1` while the target runs `--mode safe` and the edge is
   `edge_safe.conf`. (Answer: you can't — that's the point. The closest is making the
   *relay* log it, which you did.)
2. Make the demo's :8088 line log `127.0.0.1` instead of `8.8.8.8`, without deleting
   `real_ip_header`. (Answer: narrowing `set_real_ip_from` to `127.0.0.1/32` does NOT
   work — the client's own `8.8.8.8` still sits in the chain and is what the walk lands
   on; `tools/selftest.py` pins that as *"narrow trust + client junk => attacker wins"*.
   The fix is at the *outermost* hop: strip inbound, then set — nginx
   `proxy_set_header X-Forwarded-For $remote_addr;` instead of
   `$proxy_add_x_forwarded_for`. The sim has that switch so you can watch it:
   ```bash
   python3 proxy_lab/proxy_sim.py --listen 127.0.0.1:8087 --upstream 127.0.0.1:8081 \
     --mode correct --trusted 127.0.0.0/8 --real-ip-header X-Forwarded-For \
     --real-ip-recursive on --strip-inbound-xff
   curl -s -o /dev/null -H 'X-Forwarded-For: 1.1.1.1, 8.8.8.8, 203.0.113.66, 127.0.0.1' \
        http://127.0.0.1:8087/echo      # -> out/proxy_8087_access.log logs 127.0.0.1
   curl -s -o /dev/null -H 'X-Forwarded-For: 1.1.1.1, 8.8.8.8, 203.0.113.66, 127.0.0.1' \
        http://127.0.0.1:8088/echo      # -> without the flag, logs 203.0.113.66
   ```
   Same four forged addresses in, opposite outcomes. That is why "strip, then append"
   beats "configure the trust list carefully".)
3. Add a fourth hop that *signs* the header (HMAC over `ip|timestamp|nonce` in
   `X-Lab-Signature`) and make the app believe only that one. Write the two lines of
   config/code and the one line of docs explaining what it prevents.
4. `audit.py proxy_lab/nginx/edge_naive.conf` finds the critical rule. Now write a rule
   for "edge trusts a range that includes loopback" and add it to `lab_rules`. (This is
   literally how detection-engineering jobs are done: a config-shape that predicts a
   class of future incident.)
