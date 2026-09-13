# Module 7 — Reading the wire: pcap, flows, and a detection pipeline you can audit

```bash
python3 tools/gen_pcap.py                      # 226 flows, one access log, same traffic
python3 tools/triage.py                        # pcap + log -> SQLite -> 15 rules -> alerts
python3 tools/triage.py --re 10.0.0.20 --dport 8443   # reassemble the exfil POST
python3 tools/triage.py --sigma                # the rule set, with FP lists + ack procs
python3 tools/triage.py --rule ssh_bruteforce  # one rule
sqlite3 out/triage.sqlite 'select rule,src,summary from alert'
```

## 7.1 Reading the file without any tools

`file data/lab_capture.pcap` → `tcpdump capture file (little-endian) - version 2.4 (Ethernet, capture length 65535)`.
If it says `pcapng`, you need `tshark -r x.pcapng -w x.pcap` first — the formats are not
interchangeable and a surprising number of "corrupt capture" tickets are that.

Then, from byte 0: `d4 c3 b2 a1` (or `a1 b2 c3 d4`) magic → linktype at the last 4 bytes
of the 24-byte global header (`1` = Ethernet, `113` = Linux "cooked", which is what
`tcpdump -i any` gives you and it has a **16-byte** header, which is why off-by-2
parsers "mysteriously" show garbage ARP). Per-packet: `ts_sec ts_usec incl_len orig_len`.
`incl_len < orig_len` = truncated capture. `lab/pcap.py` is 150 lines and does all of
this with no dependencies — read it once, then you actually know pcap.

## 7.2 The four things a pcap shows that a log never will

1. **What the socket really was.** In the lab, the origin's log says `127.0.0.1` and the
   pcap's `X-Forwarded-For` bytes say what was *claimed*. Only the wire lets you hold
   both at once (do it: `tcpdump -i any -nn -s0 port 8085 -A` while running
   `proxy_lab/chain_demo.sh`).
2. **Half-open and unanswered SYN** — your access log records *requests*, so port
   scans, and every request that never completed a handshake, are invisible there.
3. **RST behaviour, window sizes, TTL, options.** A flow of 12 SYN→RST to port 22 in 20 s
   (`ssh_bruteforce` in the rule set) is only visible on the wire; `auth.log` shows the
   same thing more authoritatively, which is why you correlate rather than pick a winner.
4. **Retransmission / MTU / path problems** — the decoy flow in this pcap has 6
   retransmits and a 40 KB response. In a ticket queue that is "possible exfil tooling";
   with `retrans` + MSS/PMTU thinking it's a VPN with a 1280-byte tunnel MTU. Know which
   one you're looking at before you escalate.

## 7.3 The pipeline, and the two properties that make it auditable

```
pcap ─┐
      ├─> sqlite (flow, http_req, event) ─> rules (SQL) ─> alert(rule,sev,t,src,dst,evidence)
log ──┘
```

* **Everything joins on `flow_id`.** `http_req` rows carry the 5-tuple, so an alert is
  reproducible from the raw files alone. If your "alert" cannot be re-derived from an
  immutable source, you have an opinion, not a finding.
* **Every rule ships `false_positives` and `ack`.** The `ack` is the procedure that
  closes or escalates an alert. A rule with no ack path is a queue you are paying to
  fill. `triage.py` prints them; `--sigma` shows all 9 with their SQL.

## 7.4 What fired on the planted capture (and what that teaches)

```
14/15 rules fired, 17 alerts written.

```
[ALERT] http_auth_burst_then_success  hits=1  {src: 10.0.0.1, fails: 7, oks: 1, span: 18.0}
[ALERT] ssh_bruteforce                hits=1  {src: 203.0.113.7, conns: 12, payload: 297, ttl: 52}
[ALERT] egress_anomaly                hits=1  {10.0.0.20 -> 203.0.113.99:8443, sent: 220260, ratio: 1351.3}
[ALERT] port_sweep_single_source      hits=1  {203.0.113.7 -> 10.0.0.20, ports: 19}
[ALERT] spoofed_forwarded_header      hits=1  {src: 10.0.0.1, claims: "198.51.100.23, 8.8.8.8"}
[ALERT] truncated_capture             hits=1
[ALERT] ttl_outlier_source            hits=2   (the 52/64 split, i.e. the proxy hop)
[ALERT] distributed_credential_stuffing  hits=1  {account: admin, srcs: 9, fails: 18, span: 24.0}
[ALERT] logging_gap_on_http_flow       hits=1  {10.0.0.77 -> :80, silent 1300 s, 2 pkts}
[ALERT] low_and_slow_port_probe        hits=1  {203.0.113.200, 12 ports, 137 s per port, span 1650 s}
[ALERT] uniform_cadence_automation     hits=1  {10.0.0.99, n=24, mean gap 2.0 s, cv 0.0}
[ALERT] retrans_burst                  hits=1   (the MTU decoy - a false positive by design)
no hits for: http_500_after_probe
```

The four `low_and_slow`/`uniform_cadence`/`distributed_*`/`logging_gap` rules are the
Module 10 set: they exist to answer "can I do this quietly?", and the answer is in their
SQL — none of them look for a *payload*, they look for a *distribution*.

Read the first alert again: the ATO's `src` is **10.0.0.1**, because that is what the
origin logged through the broken proxy. The *wire* says `198.51.100.23`. That single
disagreement is the whole of Modules 2, 6 and 7: **your app log and your pcap are two
different witnesses, and the one that lies is the one that trusted a header.**

## 7.5 Where to practise, for real

* `Malware-Traffic-Analysis.net` — the best free pcap corpus for intrusion triage; work
  the 2019-0x and Slowloris/Emotet ones with `tools/triage.py` pointed at them.
* `stratosphereips/Stratosphere-Lab-Machine-Learning-Dataset` pcaps (labels included →
  you can measure your rules' precision/recall, which is what detection engineering
  actually is).
* `SANS Netwars`, `CyberDefenders` (Blue Team) — pcap + log challenge sets.
* `SANS "Packet Analysis" Free Tools` + Wireshark *Exercise* PDFs — for the GUI skills.
* Capture **your own**: `tcpdump -i any -w lab.pcap port 8085` during `chain_demo.sh`,
  then diff the pcap's claims against `out/*.log`. This is the exercise nobody assigns
  and everybody regrets skipping.
* For `tshark`: `tshark -r x.pcap -q -z conv,tcp`, `-z http,stat`, `-z io,phs`,
  `-Y "http.request.method == POST && tcp.len > 10000" -T fields -e ip.src -e
  tcp.dstport -e http.content_length`. Learn those five and you can work on any pcap box.

## 7.6 Two rules for two shapes people actually run (the tracking and device modules)

**`beacon_periodicity`** - the check-in. Group every flow by (src, dst, dport), take the gaps
between successive `first` timestamps, and ask for a period with almost no variance:

```
src        dst           dport  redials  span     mean_gap  cv_squared  payload
10.0.0.88  203.0.113.9   443    9        482.0 s  60.2 s    0.01        333
```

`redials` is one fewer than the connection count by construction (the first connection has no
previous one to be late relative to). `cv_squared` is variance/mean^2 - computed that way so the
rule needs no `sqrt()`, and 0.01 means the interval is a metronome. `payload` 333 bytes over nine
connections: nothing is being downloaded, they are asking a question. Three conditions, all
necessary: a period in a human-plausible range (15-900 s), low jitter, small volume. Cron and
telemetry agents are the false positives, which is why the `ack` is "look at the process, then at
whether the interval survives a reboot".

**`session_split_brain`** - the cloned session. One session identifier, two source addresses
*and* two client profiles:

```
sid    ips  uas  hits  span     srcs                          uas_l
S777   2    2    2     60.0 s   10.0.0.31,198.51.100.77      Mozilla/5.0 (iPhone ...) + curl/8.4.0
```

Requiring *both* to move is the whole design: an IP change alone is a train journey, a UA change
alone is a browser upgrade, and either one firing would put a human on-call into a queue of
harmless events. Together, within a minute, on one session - that is `apps/shop.py`'s H1 replay
seen from the log side instead of the app side, and it is the highest-signal ATO indicator you can
compute without an agent. Parsing `sid=` out of the path is deliberately naive here; say so in the
rule's own FP list, and use a session column in production.

## 7.7 Limits of this implementation (know these before you trust them)

* `reassemble()` concatenates payloads **in capture order**; real reassembly needs
  sequence-number bookkeeping, gap detection and duplicate suppression. It lies
  precisely when `retrans`/out-of-order are nonzero — that's why the flow table prints
  `retrans` first.
* Flow accounting is by 5-tuple with no connection-tracking: NATed/persistent-KP
  connections, connection reuse, and HTTP keep-alive pipelines all blur "who".
* SQL rules have no window semantics beyond `first/last` arithmetic — real SIEMs give
  you tumbling windows, cardinality aggregates and lookback joins.
* There is no TLS decryption path here by design: without a key log you get SNI and
  certificates (which is a lot: `lab/passive.py`), not content. Encrypted exfil is
  found by *shape* — bytes out, cadence, destination reputation — and that's exactly
  why `egress_anomaly` compares volumes rather than matching strings.
