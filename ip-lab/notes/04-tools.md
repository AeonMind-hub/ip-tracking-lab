# Module 4 — Tools, honest limits, and the hardening half

## 4.1 What each tool is actually for

| tool | real use | movie version |
|---|---|---|
| `journalctl -u nginx` / `tail -F access.log` | the entire plot | "typing" |
| `dig`, `drill`, `whois`/RDAP (`curl https://rdap.org/ip/…`) | ownership, PTR, DNS history | instant identity |
| `nmap -sV -p- -T4` / `masscan` | *your own* network's exposure inventory | cracking a remote box in 8 s |
| `tcpdump -i any -nn -s0 port 443 -w x.pcap` | see what your server actually received (the ground truth for the XFF lesson) | sniffing a coffee shop |
| `Wireshark` + `Follow TLS stream` | debugging handshakes, HTTP/2 framing | decrypting traffic |
| `traceroute`/`mtr` | hop path, MTU/blackhole bugs | locating a person |
| `openssl s_client -servername X -connect IP:443` | what cert answers for what name (Module 3) | "bypassing the firewall" |
| `jq`, `awk`, SQLite, DuckDB | the actual analysis work | GUI hologram |
| `sigma` + `elasticsearch`/`osquery`/`wazuh`/`suricata` | detection at scale — where a SOC job lives | one magic terminal |
| `ffuf`, `nuclei`, `sqlmap` | scanning *authorised* targets (bounty scope, your own stack) | everything they're used for in film |

Install in this container: `apt-get install -y bind9-utils whois tcpdump traceroute nmap` —
note this sandbox denies raw sockets (`SOCK_RAW` → `Operation not permitted`), so
`traceroute`/`nmap -sS`/`hping3` will not work *here*. That is not a lab bug; it is
a good reminder to build a VM or container you control (see 4.4).

## 4.2 The limits, stated plainly

- **NAT/CGNAT.** One IP = 1 household, or 1 tower of 20 000 mobile users. In Nigeria,
  as in most places, mobile traffic arrives from carrier ranges where city-level geo
  is the best you will ever do.
- **VPNs and residential proxies.** The logged IP is the provider's. No amount of
  cleverness changes the ceiling: their terms of service and their abuse desk.
- **Anycast.** `cf-ray` and PTR can be geographically nonsense; `traceability` docks 20
  points for it precisely so you stop over-reading.
- **Shared hosting / serverless / egress pools.** "Origin IP found" often means
  "IP of the platform's egress", shared by 40 000 tenants.
- **Time skew and log rotation.** Rotation is the number one reason an incident
  timeline has a hole in it. `logrotate` with `copytruncate`, or `delaycompress`,
  can lose or misdate lines — check the file's first line before trusting "the attack
  stopped at 03:00".
- **Spoofed everything else.** UA, `Accept-Language`, `Referer`, TLS-looking JA3,
  even the shape of a request. Behaviour under load (retries, jitter, keep-alive
  reuse) is harder to fake than a header, which is why cadence beats strings.

## 4.3 The three detection rules that pay for themselves

```yaml
# credential stuffing: >=5 auth failures then a success, same source, <15 min
- id: auth_burst_then_success
  logsource: {product: nginx, service: access}
  detection:
    selection_fail: {status: [401, 403], http.url|re: "^(POST )?/(login|api/(v[0-9]+/)?(auth|login))"}
    selection_ok:   {status: [200, 302], http.url|re: "^(POST )?/(login|api/(v[0-9]+/)?(auth|login))"}
    condition: selection_fail > 5 and selection_ok
  timeseries: 15m
  level: high
- id: enumerated_then_500          # probe finds a bug
  detection: {status: 500, http.url|re: "\\.(env|git|bak|old)$|/(debug|wp-admin|phpmyadmin)"}
  level: high
- id: internal_addr_in_public_log  # your config is on fire
  detection: {c_ip|re: "^(10\\.|127\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)"}
  level: critical
```

`dossier.py` implements the same three heuristics against a flat file so you can see
them fire without a SIEM.

## 4.4 Build the network lab you're actually allowed to break things in

```
Your laptop ── host-only NAT ── [ Kali/Debian ]  attacker VM
                    ├── [ Ubuntu Server + nginx + a vuln app ]  target 1
                    ├── [ OpenVPN/WireGuard exit VM ]            "the VPN" you trace through
                    └── [ another VM behind NAT ]                "the residential attacker"
```

1. Two VMs on a host-only network. One runs `apps/app.py`, one runs `tools/probe.py`
   and `nmap`. Nothing touches the internet, so nothing is unauthorised, and you can
   be as noisy as you like.
2. Put `socat`/`nginx` on the "VPN exit" VM and forward it to the target. Now the
   target logs the VPN's address, and you have *felt* why attribution dies at the proxy.
3. Add a second proxy VM and compare `remote_addr`, the XFF chain, and what
   `real_ip()` decides — three configs, three different stories about the same attack.
4. Intentionally-vulnerable targets for the offensive half (your own box or these
   hosted platforms, never "some random IP"): TryHackMe (their `Advent of Cyber`,
   `Intro to Networking`, `Ciham`/`Log Analiser` rooms are exactly this material),
   HackTheBox Academy (`Log Analysis`, `Network Services`, `OSINT`),
   OverTheWire (`nmap`, `bandit` for CLI fluency), `VulnHub` images, `PortSwigger
   Web Security Academy` for the header/SSRF/XSS parts, `LetsDefend`/`Blue Team
   Labs Online`/`MalwareTech` samples for defensive triage, `CyberDefenders` and
   `BlueLotusLabs` for real pcaps and logs, `Nahamcon`/`Defcon quals` `TraceHeads`
   and the `Flare-On` style log/pcap challenges.
5. Public datasets to practise on: `Stratosphere IPS` pcaps, `CICIDS` pcap sets,
   `Malware-Traffic-Analysis.net` (best free pcap corpus for intrusion triage),
   `SANS NetWars`, Cloudflare's public `cf-trace`/`1.1.1.1` docs, and your own
   server logs after you add consent-and-notice.

## 4.5 Harden — the part that gets you paid

Checklist, each item with the config that satisfies it:

- log `remote_addr` verbatim + raw forwarded headers in separate fields (§1.2)
- explicit `set_real_ip_from` + `real_ip_recursive on`; nothing trusts `*` (§2.2)
- strip inbound `X-Forwarded-*`, `CF-Connecting-IP`, `X-Real-IP`, `X-Original-URL` at the edge
- `server_tokens off`, hide `X-Powered-By`, no versioned `Server`
- `/debug/*`, `/server-status`, `/.git`, `.env*`, sourcemaps: not on public vhosts
- retention: 90 d+ full fidelity on auth events; document *why*; no silent IPv6 masking
- HSTS, CSP (`report-uri` so you learn what would have been blocked), cookie
  `Secure; HttpOnly; SameSite=Lax` minimum, `Referrer-Policy: strict-origin-when-cross-origin`
- rate-limit + progressive backoff on auth, **not** blanket IP bans (they break every
  school, carrier and office behind one address, and block exactly the people who
  cannot afford a VPN)
- publish `security.txt` and a bounty/abuse intake, so the good actors have a door
- alert on the three rules in §4.3, not on 4000 rules nobody reads

Then, and this is not optional: **an incident report is a document**. `tools/casefile.py`
generates one with a disclaimer, a method section, per-address findings, an explicit
"ceiling", and a reproduction command. If your write-up doesn't let someone else
reproduce it *and* doesn't state what it can't prove, it isn't evidence, it's a story.
