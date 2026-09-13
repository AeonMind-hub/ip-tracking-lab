# Module 9 — reference card (the whole lab on one page)

Print this, tape it near the keyboard. Nothing here is new; it is the six modules
reduced to commands, offsets and tables.

## 9.1 Command map

| goal | command |
|---|---|
| prove the lab is intact | `python3 tools/selftest.py` (158 checks; `--offline` skips the 2 TLS probes) |
| regenerate everything | `python3 tools/run_all.py` ; `python3 tools/gen_pcap.py` |
| log → who/what/when | `python3 tools/dossier.py data/target_access.log --xff --only-sus` |
| …timeline of one address | `--timeline 60 --ip 177.154.220.44` |
| …IPv6 /64 rollup | `--v6-rollup` |
| write the report | `python3 tools/casefile.py data/target_access.log --title "case1" --out out/case1.md` |
| one address, live | `python3 tools/dossier.py --ip 185.220.101.34` |
| header-forgery battery | `python3 apps/app.py --port 8080 --mode naive &` then `python3 tools/probe.py --naive 8080 --debug-vars` |
| passive intel | `python3 tools/passive.py --domain example.com --subdomains` / `--ip 1.1.1.1` |
| canary lifecycle | `tools/canary.py {consent,issue,serve --port 8090,report,revoke} selftest` |
| **edge trust demo** | `bash proxy_lab/chain_demo.sh` (+`--real-ip-recursive off`) |
| dumb-proxy lesson | `bash proxy_lab/socat_chain.sh` |
| three boxes | `vagrant up` → `proxy_lab/README.md` §"Run it in VMs" |
| capture → alerts | `python3 tools/gen_pcap.py && python3 tools/triage.py` |
| flows only / one rule / JSON | `--flows-only` / `--rule ssh_bruteforce` / `--json out/a.json` |
| rebuild a request | `python3 tools/triage.py --re 10.0.0.20 --dport 8443` |
| Sigma-style export | `python3 tools/triage.py --sigma` |
| **web surface: run the playground** | `python3 apps/shop.py --port 8099 --seats 1` (vulnerable) · `--port 8098 --mode hard` (fixed) |
| web surface: prove every class | `python3 tools/webcheck.py` → 23 rows, `FIRES/quiet`, exit 1 on mismatch |
| web surface: guard logic, no socket | `python3 apps/shop.py --selftest` |
| **what a site learns about your device** | `python3 tools/eyeball.py serve --port 8097`, then `analyze` / `diff` |
| cloned session / beacon, from the wire | `python3 tools/triage.py --rule session_split_brain` / `--rule beacon_periodicity` |
| read a suspicious link or .eml | `python3 tools/phish.py url <link>` / `tools/phish.py msg mail.eml` / `--selftest` |
| audit your own LAN (read-only) | `arp -a \| python3 tools/netinv.py scan --arp - 192.168.1.0/24 --i-own-this [--live]` |
| one web payload by hand | `curl -s 'http://127.0.0.1:8099/search?q=x%27%20UNION%20SELECT%20id%2Cemail%2C0%2Chash%20FROM%20users--'` |
| audit a config | `python3 tools/audit.py FILE --diff FILE2 --patch out/hardened_edge.conf` |
| web exercises (self only) | `python3 tools/web.py --port 8095` (after starting `apps/app.py --mode naive`) |
| solve the SSRF exercise | read `ssrf_guarded()` in `apps/app.py`, then `--mode safe` |
| who can see me, and what they keep | `python3 tools/footprint.py --egress --report out/footprint.md` |
| the OPSEC model only | `python3 tools/footprint.py --scenario tor --explain --no-local` |
| authorisation before touching anything | `tools/roe.py generate --client X --slug x` → edit → `sign` → `check` |
| gate a tool run on that scope | `python3 tools/web.py --port 8095 --scope out/scope-x.json` |
| the "stealth" detection rules | `tools/triage.py --rule uniform_cadence_automation` / `low_and_slow_port_probe` / `distributed_credential_stuffing` / `logging_gap_on_http_flow` |

## 9.2 Byte offsets you will want at 2 a.m.

```
Global header (24 B)  : magic(4) ver_major(2) ver_minor(2) thiszone(4) sigfigs(4) snaplen(4) network(4)
                        magic 0xa1b2c3d4 (us) / 0xa1b23c4d (ns) / 0x0a0d0d0a = pcapng → convert first
                        network: 1=Ethernet 113=Linux cooked (tcpdump -i any) 12=SLL2 0=NULL/loopback
Packet record (16 B)  : ts_sec ts_usec incl_len orig_len     incl_len < orig_len ⇒ truncated capture
Ethernet   (14 B)      : dst[0:6] src[6:12] ethertype[12:14]   0x0800 IPv4  0x86dd IPv6  0x0806 ARP
ARP        (28 B)      : htype[14:16] proto[16:18] hlen[18] plen[19] oper[20:22]
                         SHA[22:28] SPA[28:32] THA[32:38] TPA[38:42]      (1 request + 4 replies = 5 frames)
IPv4       (20 B)      : ver_ihl[0] tos[1] total[2:4] id[4:6] frag[6:8] ttl[8] proto[9] csum[10:12] src[12:16] dst[16:20]
TCP        (20 B)      : sport[0:2] dport[2:4] seq[4:8] ack[8:12] data_off[12]>>4 flags[13] window[14:16]
flags                    FIN1 SYN2 RST4 PSH8 ACK16  (0x12 = SYN+ACK, 0x18 = PSH+ACK, 0x14 = RST+ACK)
UDP        (8 B)       : sport dport len csum
VLAN                     ethertype 0x8100 at [12:14] ⇒ +4 bytes before the L3 header
ICMP                     proto 1: type[0] code[1] cksum[2:4]; echo reply = type 0
```

## 9.3 The header decision table (Modules 2 + 6 in four lines)

```
Believe a forwarded value only if its SENDER is trusted, and stop at the first untrusted
address scanning right-to-left. No trust list ⇒ the TCP peer is the only witness.
nginx: set_real_ip_from <exactly the proxies> + real_ip_header X-Forwarded-For
       + real_ip_recursive on   +   proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for
       + server_tokens off + 403 on any inbound proxy header + mTLS between edge and origin
CDN:   CF-Connecting-IP / X-Forwarded-For + CF-Ray (POP + attempt id) + verify the
       connecting IP against the published ranges; beware duplicated-header injection.
```

## 9.4 Trust-list traps seen in the wild and in this lab

| setup | what the log says | verdict |
|---|---|---|
| no trust list, `xff=$http_x_forwarded_for` at edge | whatever the client typed | broken; audit `xff_forwarded_verbatim` |
| `set_real_ip_from 127.0.0.1` + app on same host, client from loopback | the client's *second-to-last* value | broken; audit `trusted_too_wide` |
| `set_real_ip_from 127.0.0.0/8` + real_ip_recursive + client sends `8.8.8.8, 127.0.0.1` | `8.8.8.8` | broken, and *looks* correct |
| `real_ip_header CF-Connecting-IP`, inbound CF header not stripped | last duplicate wins | broken; see `notes/02` §2.6 |
| edge→relay→target, `set_real_ip_from 10.0.0.0/8`, no client junk | the client | correct |
| target bound to `0.0.0.0` with `--trusted-proxy 127.0.0.0/8` | spoofable by anything on the host | correct config, wrong boundary: bind `127.0.0.1:8085` |

## 9.5 Detection rules shipped (and the numbers on the planted capture)

| rule | sev | evidence on `data/lab_capture.pcap` | first ack step |
|---|---|---|---|
| `spoofed_forwarded_header` | medium | 10 lines, `peer=10.0.0.1`, claims `198.51.100.23, 8.8.8.8` | did a real proxy sit in front? |
| `http_auth_burst_then_success` | high | src `10.0.0.1`, fails 7, ok 1, span 18 s | did the account do anything new after? |
| `ssh_bruteforce` | high | 12 conns/20 s, payload 297, ttl 52, 0 bytes back | `grep sshd /var/log/auth.log \| tail` |
| `egress_anomaly` | high | 220 260 B out / 163 B in, ratio 1351 | is that host a backup/AV node? |
| `port_sweep_single_source` | medium | `203.0.113.7 → 10.0.0.20`, 19 ports | `ss -tlnp` on the target |
| `truncated_capture` | medium | 2 flows with bytes-on-wire > bytes-parsed | check `-s` snaplen + collector disk |
| `ttl_outlier_source` | low | `10.0.0.20` ttl `64,52` (46 flows); `102.89.33.4` `52,64` | two OSes behind one address? |
| `retrans_burst` | low | `102.89.33.4:8443` 6 retrans in 1.06 s (the MTU decoy) | path MTU/tunnel, not an attack |
| `http_500_after_probe` | high | no hits here | expected zero — that is what good tuning looks like |

## 9.6 Retention, in one line each

```
nginx log_format main → 15 min at the box, 30 d hot in the SIEM, 90 d cold.
CF Ray id → 24 h at the CDN (only window in which a full header dump is retrievable).
CloudFront server access logs → yours, forever, if you enabled them.
VPC Flow Logs → 1–7 d (S3: up to 400 d).  CloudTrail → 90 d events, S3 for longer.
GCP VPC flow logs → 30–35 d default.  Azure NSG flow → 0–9 d + storage account.
auth.log/journal → 12 mo (why journald default is not enough).
```
If a system you depend on retains less than your investigation window, the fix is
`logrotate + ship to cold storage`, not "be faster".

## 9.7 The five artefacts an incident packet needs

1. the log file(s) with hash (`sha256sum`), the time range, and the *parser* used;
2. the trust statement: which peers were trusted, quoting the config, with `git blame`;
3. the enrichment, cited: RDAP objects, PTR, geo with `anycast:true` noted, dates;
4. the ceiling sentence, verbatim: `log line → abuse contact / subnet owner. Full stop.`
5. the fix + the detection rule that prevents recurrence (and the re-audit showing it).

`tools/casefile.py` writes 1–4 automatically; 5 is yours, and it is the paragraph that
gets you hired.

## 9.8 The five witnesses (module 10, on one line each)

```
link     router/AP/carrier: session start-stop, CGNAT port maps, DHCP lease by MAC, sometimes NetFlow
sync     Google/Apple/Microsoft backup: your name is the key of that database
money    card / mobile money / KYC'd VPS order + control-plane logins + abuse tickets
target   edge+app+auth logs, WAF decisions, JA3/JA4 + HTTP2 fingerprint, EDR telemetry shipped off-network
you      reuse: handles, emails, keys, payment, phrasing, timezone, tool defaults
```

`ghostability = 100 - 10 x max(identify over the hops)` — a minimum, not a sum, so the
chain is only as invisible as its worst witness, and the worst one is rarely a network hop.
Full model + your machine's own inventory: `python3 tools/footprint.py`.
Detection of the four "quiet" shapes: `uniform_cadence_automation` (cv < 0.12),
`low_and_slow_port_probe` (≥6 ports, ≥600 s span, ≤600 s/port),
`distributed_credential_stuffing` (≥5 sources on ONE account), `logging_gap_on_http_flow`
(HTTP-port flow ≥300 s with no logged request). What the config audit says about log
suppression: `audit.py` + `LINES.md` §1 row "log_or_audit_tampering".
