# ip-lab — the "how do hackers trace an IP" thing, minus the fiction

Built for you. Everything here runs on `127.0.0.1` (or on VMs/containers you
own), reads public registries, and analyses logs and captures you generate yourself. No
package to install. No third-party target. No "identify-the-human" capability anywhere in
the tree — that capability is not a skill gap, it is a legal wall (see `notes/05`).

Three batches: **1** = the IP-attribution pipeline on one machine. **2** = real multi-hop
networks, pcap + detection engineering, config auditing with PR-ready output, and the web
classes that touch IP work (IDOR / SSRF / header differentials / disclosure). **3** = the OPSEC
and authorisation layer, plus **`notes/11` + `apps/shop.py`: every major web vulnerability
class in one deliberately broken app**, each one proven to fire and proven to be fixed by
`tools/webcheck.py`. All of it self-targeted.

```
quickstart (60 seconds, no privileges)
  cd ip-lab
  python3 tools/selftest.py            # 159 checks: prove the lab works, then trust it
  python3 tools/selftest.py --offline  # same, minus the two checks that need outbound TLS
  # Windows? read WINDOWS.md first: `py` instead of `python3`, no pip, no admin - same commands
  python3 tools/dossier.py data/target_access.log --xff --only-sus
  python3 tools/casefile.py data/target_access.log --title "triage"
  bash proxy_lab/chain_demo.sh         # the whole Module-6 lesson in one command
  python3 tools/webcheck.py            # web attack surface, both modes: 27 classes A/B'd
  python3 apps/app.py --port 8080 --mode naive      # then, in another shell:
  python3 tools/probe.py --naive 8080 --debug-vars
  python3 apps/shop.py --port 8099 --seats 1        # the 27-class lab app (notes/11) to curl
```

## The one mental model that matters

```
   human  ──?──  device  ──?──  NAT / tunnel  ──?──  IP address  ── log line
   ↑ you can lawfully reach: the IP, the network that owns it, the abuse desk,
     the *flow* (five-tuple + timing), and the *config* that produced all of it.
   ↑ you cannot reach by tooling: the person. Only their ISP knows, and only a
     court/subpoena (or the ISP's own abuse process) gets it out of them.
```

Every technique in this lab lives **right of the IP**. The movies put the camera left of
it, which is why it looks like typing and doesn't require a warrant. `traceability_score`
in `lab/tracer.py` is the honest version of the dramatic "location found" beat: for most
real incidents it prints `15/100 → abuse report to the network operator`.

## Curriculum

| # | Module | File to read | What you run |
|---|---|---|---|
| 1 | Logs: the only evidence you actually own | `notes/01-pipeline.md` | `tools/dossier.py data/target_access.log --timeline 30 --ip 177.154.220.44` |
| 2 | Headers: what's real, what's typed | `notes/02-headers.md` | `apps/app.py --mode naive` + `tools/probe.py` |
| 3 | Enrichment: RDAP, PTR, geo, TLS, co-hosting | `notes/03-infrastructure.md` | `tools/dossier.py`, `tools/passive.py` |
| 4 | Attribution ceiling & abuse reporting | `notes/04-tools.md` | `tools/casefile.py` |
| 5 | Canaries, browser fingerprints, consent | `notes/05-boundaries.md` | `tools/canary.py serve --port 8090` |
| 6 | Defensive half (the part that gets you hired) | `notes/04-tools.md` §"harden" | fix the leaky mode in `apps/app.py` |
| 7 | **The proxy chain on real networks** (batch 2) | `notes/06-proxy-lab.md` | `bash proxy_lab/chain_demo.sh`, then `vagrant up` |
| 8 | **pcap + detection engineering** | `notes/07-detection.md` | `tools/gen_pcap.py` + `tools/triage.py` |
| 9 | **Audit the config before the incident** | `notes/08-audit-and-web.md` §8.1 | `tools/audit.py <conf> --diff <conf> --patch out/hardened_edge.conf` |
| 10 | **Web classes, self-targeted** | `notes/08-audit-and-web.md` §8.2 | `apps/app.py --mode naive` + `tools/web.py --port 8095` |
| 11 | **OPSEC, footprints, and the paperwork** | `notes/10-opsec-and-ghosts.md` + `LINES.md` | `tools/footprint.py`, `tools/roe.py generate/check/sign` |
| 12 | **The web attack surface, all of it in one place** | `notes/11-web-attack-surface.md` | `apps/shop.py` (27 planted classes) + `python3 tools/webcheck.py` |
| 13 | **"Real tracking": correlation, the ceiling, and the lawful escalation** | `notes/12-real-tracking.md` | `python3 tools/eyeball.py serve`, then `triage.py --rule session_split_brain` |
| 14 | **Devices: compromise anatomy, detection, and your own network** | `notes/13-device-compromise.md` | `triage.py --rule beacon_periodicity`, `netinv.py scan`, `phish.py msg` |
| 0 | **How the whole thing is built** (read first if you want the machine, not the syllabus) | `notes/00-mechanics.md` | `python3 tools/selftest.py` |

## Exercises (work them in order; the key is at the bottom of each note)

1. **Find the liar.** One address in `data/target_access.log` has a header field that
   could not be true. Which line, which field, and how do you prove it from the line
   alone? (`data/key.json` → `case1`.)
2. **Prove the break-in, not the guess.** For `177.154.220.44`, build the 9-line
   timeline that shows *authentication succeeded*, then state the single next lawful
   action. Wrong answer: "find who owns it". Right answer: abuse report + your own
   containment.
3. **Break your own log.** Run the target in `--mode naive`, spoof yourself as `1.1.1.1`,
   and watch `dossier.py` treat Google as an attacker. Write the 2-line nginx config that
   would have prevented it.
4. **Follow the money of a false positive.** `185.220.101.34` is a Tor exit and is *not*
   an attack here. Show, from the log alone, the three facts that make it benign.
5. **The leak inside your house.** Case 3 in the dataset is not an attacker at all — it's
   your own response headers plus an authorized tester. List every header you'd delete
   before production.
6. **Retention policy as case policy.** Roll the IPv6 attackers up (`--v6-rollup`) and
   write the sentence you'd put in a report explaining why you cannot name a host. Then
   write the config line that keeps that option open for you.
7. **Three boxes, and the packet capture that settles it.** `vagrant up` — provisioning
   already installs nginx on `edge` with *both* configs (`:8080` naive, `:8088` correct),
   makes `relay` a forwarding "VPN exit" (`192.168.50.11:80` → `192.168.60.20:80`), and
   starts the target on `:80` with **its default route deleted** (so nothing you generate
   leaves the host-only network, and `curl example.com` from the target failing is a
   *feature*). Then:
   ```bash
   vagrant ssh target -c 'sudo tcpdump -i any -nn -w /lab/live.pcap port 80' &   # witness 3
   vagrant ssh edge   -c 'curl -s -o /dev/null -H "X-Forwarded-For: 198.51.100.23, 8.8.8.8" http://192.168.50.10:8080/'
   vagrant ssh edge   -c 'curl -s -o /dev/null -H "X-Forwarded-For: 198.51.100.23, 8.8.8.8" http://192.168.50.10:8088/'
   vagrant ssh target -c 'sudo killall -INT tcpdump; sudo chmod 644 /lab/live.pcap'
   vagrant scp target:/lab/live.pcap out/live.pcap
   vagrant ssh edge   -c 'sudo tail -2 /lab/out/proxy_*access.log'   # witnesses 1 and 2
   python3 tools/triage.py --pcap out/live.pcap                        # the wire's version
   ```
   Write the two-line incident note: *what the edge logged, what the target logged, what
   the pcap shows was claimed, and which one you would put in an abuse report.* Full
   background: `proxy_lab/README.md` §"Run it in VMs" and `notes/06-proxy-lab.md` §6.5,
   plus §6.2–6.3 for why `:8088`'s answer is still wrong even though its config is right.

8. **Detection on your own traffic.** `tcpdump -i any -w home.pcap not port 22` for ten
   minutes while you browse, then `python3 tools/triage.py --pcap home.pcap`. Every alert
   fires on your house's shape; read each `false_positives` list and name which alert is
   your laptop's update daemon. (Delete the pcap: it contains you.)
9. **Become the ghost, then get caught.** `python3 tools/footprint.py --egress --report
   out/footprint.md` — then `python3 tools/triage.py --rule uniform_cadence_automation` and
   `--rule low_and_slow_port_probe`. Explain, in three sentences, why the score is 0/100 in
   every scenario including Tor and a two-VPS chain, and which record is the binding
   constraint. Then do exercise 10.
10. **Paperwork before packets.** `python3 tools/roe.py generate --client "Acme NG" --slug
   acme`, fill in the placeholders, `sign` it, and run `check` against your lab target. It
   refuses until `authorised_by.signed_at` is set — that refusal is the entire professional
   skill in one flag. Now re-run `python3 tools/web.py --port 8095 --scope out/scope-acme.json`
   and watch `--scope` gate every request. Write the answer to: *what in that document could
   you not produce if the client's ISP called them instead of you?*
11. **Ship the fix.** `python3 tools/audit.py proxy_lab/nginx/edge_naive.conf --diff
   proxy_lab/nginx/edge_safe.conf --patch out/hardened_edge.conf`, open a PR in one of
   your own repos with the patch + a two-line note of what the tool cannot see. Then write
   the detection rule that catches the finding reappearing (`tools/triage.py --sigma` is
   the template).

12. **A/B the whole web surface.** `python3 tools/webcheck.py --keep`, then reproduce three
    rows by hand with `curl` against both instances (the commands are in `notes/11` §11.7). Then
    work exercises 13–15 in that file: break a fix, write the report, and see which of the 23
    classes an access log can even see.

## Batch 2 — the commands

```bash
# Module 6: proxy chain / header trust — no root, no docker, works here
bash proxy_lab/chain_demo.sh
bash proxy_lab/socat_chain.sh                    # same lesson with a dumb TCP proxy
python3 proxy_lab/proxy_sim.py --help            # the edge/relay sim, all the flags

# The three-box network on your laptop (VirtualBox) — configs shipped, execution is yours
vagrant up
vagrant ssh edge   -c 'sudo tcpdump -r /vagrant/out/live.pcap -nn -A | head'

# Module 8: pcap + detection
python3 tools/gen_pcap.py                        # 226 flows: pcap + matching access log + key
python3 tools/triage.py                          # 14/15 rules fire, 17 alerts -> out/triage_alerts.json + triage.sqlite
python3 tools/triage.py --flows-only             # the table you'd paste in a ticket
python3 tools/triage.py --re 10.0.0.20 --dport 8443    # rebuild the exfil POST
python3 tools/triage.py --sigma                  # rules + false_positives + ack procedures
python3 tools/triage.py --rule egress_anomaly --json out/a.json

# Module 9: audit
python3 tools/audit.py --selftest
python3 tools/audit.py proxy_lab/nginx/edge_naive.conf --diff proxy_lab/nginx/edge_safe.conf \
        --patch out/hardened_edge.conf
python3 tools/audit.py                           # scans /etc/nginx, apache, Caddyfile, compose

# Module 10: web classes, self-targeted only (refuses any non-local host)
python3 apps/app.py --port 8095 --mode naive &
python3 tools/web.py --port 8095 --chain-canary --canary-port 8090
kill %1

# Module 11: footprints + the authorisation layer
python3 tools/footprint.py --egress --report out/footprint.md
python3 tools/footprint.py --scenario tor --explain
python3 tools/triage.py --rule uniform_cadence_automation     # how the "quiet" shapes are seen
python3 tools/roe.py generate --client "Acme NG" --slug acme
python3 tools/roe.py check --scope out/scope-acme.json --target http://127.0.0.1:8095/
python3 tools/roe.py sign --scope out/scope-acme.json

# Module 12: the whole web attack surface, self-hosted (notes/11)
python3 apps/shop.py --port 8099 --seats 1          # vulnerable
python3 apps/shop.py --port 8098 --mode hard        # same app, fixed
python3 tools/webcheck.py                             # A/B all 27 classes, exits 1 on any mismatch

# Modules 13-14: attribution on yourself, devices on your own network (notes/12, notes/13)
python3 tools/eyeball.py serve --port 8097              # open it: what your browser volunteers
python3 tools/eyeball.py diff out/eyeball/visit-1.json out/eyeball/visit-2.json
python3 tools/triage.py --rule session_split_brain      # a cloned session, seen from the log
python3 tools/triage.py --rule beacon_periodicity       # an implant's check-in cadence
arp -a | python3 tools/netinv.py scan --arp - 192.168.1.0/24 --i-own-this        # plans, sends nothing
python3 tools/netinv.py scan --arp out/arp.txt 192.168.1.0/24 --i-own-this --live --report out/netinv.md
python3 tools/phish.py corpus                           # 13 planted cases, and the verdicts
python3 tools/phish.py msg mail.eml                     # a real .eml: score + reasons + next steps
python3 tools/webcheck.py --keep                      # leaves both up for hand-driven curl

# Nothing left unverified
python3 tools/selftest.py     # 159 checks: parsers, trust walk, pcap round-trip, rules, configs, shop guards
python3 tools/selftest.py --offline   # skip the two that need outbound TLS (a filtered network is not a defect)
python3 tools/run_all.py      # batch 1: 7 stages (selftest -> dataset -> dossier -> casefile -> v6 rollup -> canary -> web A/B)
```

A sample of what real enrichment produces here (live RDAP + ipinfo, run it yourself):

```
45.148.10.66  38/100  AS48090 "TECHOFF SRV"  Amsterdam/NL  netname=DMZHOST  abuse=dmzhostabuse@…
185.220.101.34 6/100  Tor exit (netname=TOR-EXIT)  DE 0.0.0.0/0  → "abuse report to the network operator"
177.154.220.44 14/100 AS26293 "Sistema Oeste"  Mossoró/BR  ptr=44customer-220-154-177.tcm10.com.br
```
That last PTR string is the entire "Hollywood vs reality" lesson in one line: the ISP
hands a *customer* to the police in 15 minutes and hands you a hostname.

## Files

```
ip-lab/
├── README.md                  you are here
├── lab/
│   ├── net.py                 IP classification, DoH (no dig needed), cert parsing, cache
│   ├── logs.py                access + error log parsers, XFF trust walk, summaries, timeline
│   ├── tracer.py              RDAP / geo / PTR / TLS / reputation / traceability score
│   ├── passive.py             DNS + cert + response-header intel, leak dictionary
│   ├── canary.py              consent-gated honey-token server library
│   ├── pcap.py                write + read pcap, flows, TCP reassembly — no dependencies
│   └── detect.py              rule set over SQLite: 15 rules, each with FP list + ack procedure
├── tools/
│   ├── selftest.py            159 checks; run it after every edit
│   ├── gen_dataset.py         regenerate the fictional incident set (seeded)
│   ├── gen_pcap.py            one script → pcap + truncated pcap + matching access log + key
│   ├── dossier.py             CLI: log → per-address dossier + ranking
│   ├── casefile.py            CLI: dossier → incident markdown with disclaimers
│   ├── probe.py               CLI: header-forgery battery against YOUR lab target
│   ├── passive.py             CLI: DNS/cert/header intel for a domain you own
│   ├── canary.py              CLI: issue/report the honey-token server
│   ├── triage.py              CLI: pcap + logs → flows → alerts → triage artefacts
│   ├── audit.py               CLI: nginx/apache/caddy/compose audit → diff + hardened fragment
│   ├── web.py                 CLI: IDOR/SSRF/differential/disclosure against apps/app.py only
│   ├── webcheck.py            CLI: spawn shop.py twice, A/B all 27 classes, write out/webcheck.json
│   ├── eyeball.py             CLI+server: what your browser volunteers to a site, and which of it
│   │                          never changes between visits (the honest tracking demo, loopback)
│   ├── phish.py               CLI: read a URL or a whole .eml like an analyst - score, reasons,
│   │                          next actions. Detector only: there is no kit in this repo (LINES §7)
│   ├── netinv.py              CLI: audit the devices on your OWN network. Read-only GETs, refuses
│                              public addresses and undeclared ranges, never sends credentials
│   ├── footprint.py           CLI: who can see you (records/retention/compellability) + your box's own inventory
│   ├── roe.py                 CLI: scope JSON, ROE letter, custody log, check/sign/verify, SOC notice
│   └── run_all.py             batch 1, end to end
├── proxy_lab/                 Module 6: proxy_sim.py, chain_demo.sh, socat_chain.sh,
│                              nginx/{edge_naive,edge_safe}.conf, relay/relay.conf,
│                              docker-compose.yml, README.md (VM/Docker/manual variants)
├── Vagrantfile + provision/   three isolated boxes, broken routes on purpose
├── apps/app.py              deliberately leaky local web app (never deploy): naive/safe/
│                              cloudflare modes, SSRF-able /fetch with a *bypassable*
│                              allow-list + ssrf_guarded() as the exercise, /admin differential
├── apps/shop.py             second lab app: 27 planted web classes (SQLi, XSS, traversal,
│                              open redirect, JWT alg=none, IDOR, mass assignment, CSRF-by-GET,
│                              coupon race, upload, disclosure), --mode hard = the fixes
├── data/                      generated logs + captures + key.json (the answer keys)
├── notes/00-mechanics.md      what is built, what it does, how it is implemented
├── notes/01…09*.md            the nine lessons + 09-reference.md (the cheat sheet)
├── notes/10-opsec-and-ghosts.md  footprints, detection primitives, the discipline list
├── notes/11-web-attack-surface.md  the map: chain, 27 classes, chains, toolchain, defence, reporting
├── notes/12-real-tracking.md   correlation vs the wall; the lawful escalation path; see yourself
├── notes/13-device-compromise.md  five stages, per-OS detection commands, incident order, LAN audit
├── LINES.md                   where it stops: capability × authorisation × evidence × consequence
├── WINDOWS.md                 running all of the above on Windows: `py`, no pip, no admin
└── out/                       reports, alerts, patches land here
```

## Career ladder this maps onto

| run this well | the skill it demonstrates | where it is tested |
|---|---|---|
| `dossier.py`, `casefile.py` | log analysis + enrichment + evidence discipline | BTL1 Log Analysis, GCIH, CyberDefenders |
| `chain_demo.sh`, `audit.py`, Vagrant | edge/proxy architecture, header trust, PR-quality hardening | the networking half of eJPT/OSCP, platform/security-engineer interviews |
| `gen_pcap.py`, `triage.py` | detection engineering: rule → false positives → ack procedure | BTL1/Hunt+, JCDA, SANS SEC503/555 |
| `web.py` + PortSwigger | web app sec: IDOR, SSRF, differentials, disclosure | Web Security Academy, eJPT, OSCP |
| `canary.py` + `notes/05` | privacy engineering, consent, lawful process | anything with "incident" or "response" in the title |
| `tools/footprint.py`, `LINES.md` | seeing yourself clearly: which records exist, who holds them, what is authorised | anything with "OPSEC", "red team" or "responsible disclosure" in the description |
| `tools/roe.py` | scope, authorisation, custody, notification — the artefacts that make testing a job | every consulting/contract role, and your own legal safety |
| the ceiling tables in `notes/05` | knowing when to stop and writing it down | the difference between a contractor and a liability |

## Where the line is

**`LINES.md`** in this directory. It is one page, it is written to be used *while* you work
(five questions to answer before a tool runs, and a table of what is fine / what needs
written authorisation / what no signature can make legal), and it is why this lab is a
portfolio piece rather than a liability. `notes/05-boundaries.md` is the long version.

## Rules I built this around

- **Own your target.** Anything probed must be `127.0.0.1`/RFC1918 you own, a
  purpose-built lab box (THM/HTB/OverTheWire/Vulnhub), a bug-bounty scope you've read, or
  your own deployment. `tools/probe.py` and `tools/web.py` refuse non-local targets on
  purpose; don't remove that.
- **Capture ≠ pursue.** Your server's logs are yours. Acting on an uninvolved stranger's
  address — messaging them, their ISP, their employer, showing up — is harassment
  territory, and in many jurisdictions (Nigeria's NDPR/Cybercrime Act, GDPR, CFAA
  analogues) the gathering itself becomes the offence.
- **Canaries need named consent.** `tools/canary.py` refuses to issue a token unless you
  state who it's for and the scope; hits outside that scope are recorded with a "review
  then delete" flag, because that is the correct handling.
- **No person-identification tooling.** This is not a scoping preference: nothing in the
  tree joins an address to a named human, and nothing will be added. The lawful route
  (police request → ISP) is documented in `notes/05` §5.3 because it is part of the skill.
- **Honesty about what was executed.** The Python is run and checked here (67 selftest
  checks + 9 detection rules on a generated capture + `chain_demo.sh` end to end). The
  Vagrant and Docker paths are written, `bash -n`-clean and `yaml.safe_load`-clean, but
  **not executed** in this sandbox — no VirtualBox/Docker here. Same for the two nginx
  site files: `tools/audit.py` checks them, `nginx -t` never ran. Say so in any write-up.
- **The bugs here are intentional and pinned by tests.** `apps/app.py`'s SSRF allow-list
  is a string prefix, so `localhost` and the redirect hop bypass it while decimal/IPv6 are
  blocked — that asymmetry *is* the lesson; `ssrf_guarded()` below it is the answer. And
  `chain_demo.sh` prints `8.8.8.8` on the *correctly*-configured edge, because the trust
  list (`127.0.0.1/32`, then `127.0.0.0/8`) is what makes the answer wrong —
  `tools/audit.py::trusted_too_wide` calls that out. Don't "fix" either before you can
  explain out loud why it is wrong.
- **The skill that actually pays**: log the truth, strip the disclosures, keep records
  long enough to matter, write the report someone can audit. Modules 6–10 are that, with
  the drama removed.
