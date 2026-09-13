# Module 1 — Logs: the only evidence you actually own

## 1.1 What the server really sees

When a browser (or curl, or nmap) talks to your server, the *only* fact about
the other side that is structurally hard to fake is the **TCP peer address** of
that connection. For a full 3-way handshake it is not forgeable at all, because
the SYN-ACK has to come back somewhere. Everything else — every header — is
text the client chose to type.

```
client ──TCP──> [your edge / nginx] ──TCP──> [app] ──TCP──> [db]
   203.0.113.9        remote_addr = 203.0.113.9
```

The moment you put anything between the client and your app (proxy, load
balancer, CDN, WAF, sidecar), `remote_addr` becomes that hop's address, and you
need a header to carry the original. That header is attacker-influenced by
default. This single sentence is the origin of 90 % of "the hackers traced the
wrong guy" stories — and of most real log-forensics mistakes.

## 1.2 The log line that is worth keeping

Standard `combined` format is a minimum, not a good answer. What you want:

| field | why |
|---|---|
| `remote_addr` (the TCP peer) | **never** overwrite it. This is your anchor. |
| a separate field for `XFF`, `True-Client-IP`, `CF-Connecting-IP` raw values | so a later analyst can tell "the proxy said" from "the client typed" |
| `time_local` **with timezone**, or UTC + a documented offset | one DST bug destroyed the timeline of a real intrusion I read about |
| full request line + status + bytes | 401 → 302 on `/login` is the classic break-in shape |
| `user_id` once authenticated | IP without an account is half the story |
| a per-request `X-Request-Id` echoed in the response | lets you join app log ↔ proxy log ↔ WAF log ↔ DB log. Without it you are pattern-matching on vibes. |
| `nginx error.log` | the `open() "/var/www/.env" failed …, client: …` lines record probes that never even reach your app code |
| auth events: MFA sent/verified, reset token issued/used, password changed | account takeover is decided here, not in the access log |

`lab/logs.py` parses combined, CLF, and error.log. That last one matters: run
it against an error log and you will find probe sources that are absent from the
access log entirely (blocked by the edge before your app exists).

## 1.3 The pivots you actually use

```bash
# how many distinct sources, and who hit the auth endpoint
awk '$7 ~ /login/ {print $1}' access.log | sort | uniq -c | sort -rn | head

# the money sequence: failures then a success, per source
grep -E '" (401|302) ' access.log | awk '{print $1, $9, $4}' | sort | uniq -c

# everything one address did, in order
grep -F "177.154.220.44 " access.log | sort -k4

# did anything ever come from a private address? (spoof, SSRF, or a dev proxy left on)
awk '{print $1}' access.log | grep -E '^(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)'
```

Now do it with the lab's analyser, which also classifies behaviour:

```bash
python3 tools/dossier.py data/target_access.log --xff --only-sus
python3 tools/dossier.py data/target_access.log --ip 177.154.220.44 --timeline 20
```

What `summarise()` looks for, and why:

- **`successes_after_failures`** — ≥3 `401/403` then a `200/302` on an auth
  path. This is the highest-signal rule in existence for credential stuffing.
- **`swept_paths`** — `.env`, `.git/config`, `phpmyadmin`, `xmlrpc.php`,
  `server-status`. Automated enumeration, essentially everyone on the internet.
- **`botlike_ua`** — `curl`, `python-requests`, `Nmap Scripting Engine`,
  `masscan`, `zgrab`. (Remember: UA is a *claim*. Attackers copy Chrome's.)
- **cadence** — `median_gap_s`, `rps`. Machines keep a metronome; humans do not.
  A 4.0 s ± 0.05 s gap over 300 requests is a loop, always.
- **activity window** — cluster hits by hour and compare against the source's
  *local* time. Traffic that only happens 03:00–06:00 local for days suggests a
  human asleep at the other end of a scheduled job. Probabilistic tell, never proof.

## 1.4 Exercise 1 answer key (the planted dataset)

`data/gen_dataset.py` planted 5 cases; `data/key.json` has the verdicts. The
walk-through:

1. **`45.148.10.66`** — 38 requests in 69 minutes, all on probe paths, mixed
   `curl`/`python-requests`/Nmap UAs, and `X-Forwarded-For: 127.0.0.1, 8.8.8.8`.
   The XFF is the tell: a loopback value *in a chain arriving from a public
   address* cannot be a real forwarding decision. Your app is not behind a
   proxy, so that header was typed by the client. Everything else about this
   address is uninteresting: rented VPS, datacenter ASN, geo = where the box is.
   `traceability 15/100 → abuse report`.
2. **`177.154.220.44`** — 9× `401 /login` in 10 minutes, then `302`, then
   `/api/profile/email` ×2 and `/api/billing/invoices/export`. No XFF at all, so
   `remote_addr` is authoritative. PTR: `44customer-220-154-177.tcm10.com.br`
   → an ISP CPE pool where the customer IP is encoded in the hostname. That is
   real, and it is still only a *network*. Ceiling: the ISP, via legal process.
3. **`102.89.44.7`** — looks like probing (`/.env` 404, `/api/v1/report` 500)
   but is an authorized tester; your own `/debug/vars` was answering with
   `X-Backend-IP` and an internal hostname. The incident here is the leak, not
   the visitor.
4. **IPv6 from `2001:4488:1060:1c4a::/64`** — 29 hosts, all `/login` 401s from
   `python-requests`. The AS belongs to a university network. You can name the
   building. You cannot name a laptop, because the log kept the first 4 groups.
5. **`185.220.101.34`** — Tor exit, 6× `200` on a public webhook, referer from
   a customer's app. False positive, and the lesson: *presence on an anonymity
   network is not an attack.*

## 1.5 Why your timeline might still be wrong

Before you write "at 11:53 the attacker…", check three things:

1. **Clock skew.** Your server's NTP is not the client's. Log timestamps are only
   comparable *within* one machine. Cross-service correlation needs a request ID
   or a shared upstream clock, not eyeballs.
2. **Log order ≠ event order.** Buffered loggers, async handlers and `rsyslog`
   retries reorder lines. Sort by timestamp, then treat ±2 s as noise.
3. **Deduplication.** A `502` retried by the load balancer looks like two attacks
   and is one. Same IP + same path + sub-second gap = one event.

---
Next: `02-headers.md` — the part everyone thinks they know.
