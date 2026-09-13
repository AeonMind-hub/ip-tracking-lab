# Module 10 — OPSEC, footprints, and why "ghost" is the wrong objective

Run these first, they do the arguing for me:

```bash
python3 tools/footprint.py                      # your machine's own records, read-only
python3 tools/footprint.py --scenario tor --explain
python3 tools/footprint.py --egress --report out/footprint.md
python3 tools/gen_pcap.py && python3 tools/triage.py --rule low_and_slow_port_probe
python3 tools/roe.py generate --client "Acme NG" --slug acme   # the alternative to hiding
```

## 10.1 The five records that always exist

Not five *network* hops — five **independent witnesses**. Removing any four still leaves
a case. This is the whole answer to "can it not leave any footprint": footprint isn't a
leak in your technique, it's the accounting function of every business between you and the
target.

1. **The link you're on.** Router/AP/ISP/carrier: session start-stop, CGNAT port
   assignments, DHCP lease by MAC, sometimes per-subscriber NetFlow. A carrier can name a
   subscriber for a given address+minute in minutes — that is the same record that makes
   "untraceable from home" impossible, viewed from the other side.
2. **The account that syncs your device.** Google/Apple/Microsoft/WhatsApp backup, photo
   roll, location history. It has your name on it by construction and lives in another
   country's data centre with its own legal process.
3. **The money.** Card, bank, mobile money, crypto exchange with KYC, even "anonymous"
   prepaid VPS providers keep order history, control-plane logins, and abuse tickets.
4. **The target.** Their edge/LB/CDN/WAF/app/auth logs, plus EDR telemetry that ships off
   their network to a vendor cloud. You cannot opt out of the logs on the machine you are
   touching. This is Module 6 in one sentence.
5. **You.** Reuse: handles, emails, phone, keys, payment instruments, phrasing, timezone,
   tool defaults, the GitHub repo with your name on it. Attribution is overwhelmingly
   graph linkage, not packet inspection.

`tools/footprint.py` models all five, weights them, and prints the score as
`100 − 10 × max(identify)`. Every scenario scores 0, and it names the *binding
constraint* — which is almost never the network hop people spend money on.

## 10.2 The stack-of-anonymity fallacy

Anonymity stacks compose by **minimum**, not sum. VPN + Tor + VPS + burner is only as
invisible as its worst record — and the worst record is usually (2) or (5), which no
network hop fixes. So the practical consequences:

* Each added hop adds trust requirements, cost, and *new* records (purchases, logins to
  buy them, provider abuse correspondence). You usually end up with more records, not fewer.
* Datacenter + VPN + Tor exit addresses are *labelled* in every reputation feed. Arriving
  from one is a signal in itself — `python3 tools/dossier.py --ip <your-vpn-exit>` shows
  you exactly how a defender sees it (netname, ASN type, abuse contact, "anycast", score).
* Timing correlation across hops is a solved problem in the literature and repeatedly
  demonstrated in practice; you don't need to break crypto to link an entry and an exit
  when both ends have minute-resolution records and unique volume.

## 10.3 What "quiet" means in authorised work (it isn't absence of records)

Professionals on engagements optimise for four things, and none of them is invisibility:

1. **Not being an incident.** Stay inside the agreed rate/window, don't touch availability
   tests without a named approver, stop on the client's word. A cancelled engagement with
   no incident beats a clever test.
2. **Being recognisable to the right people.** Declared source IPs, a SOC notification
   (`tools/roe.py sweep` writes it), an emergency number that answers. A SOC that can page
   you closes it as "expected activity"; one that can't, escalates.
3. **Minimising what you touch, not what you log.** Proof of access over collection. Scope
   keys (`max_records_per_finding`), no bulk exports, no persistence on production.
4. **Clean separation of identities.** Dedicated machine, dedicated accounts, no personal
   sync, no personal phone number, no reuse across clients. This is hygiene for legal work
   too — a client data leak from your personal Dropbox is a contract breach and a GDPR/NDPA
   exposure whether or not anyone meant harm.

## 10.4 How you are actually detected: 12 primitives, and the data each needs

If you want the real answer to "how would they catch me", it's this table — it's also
literally what to build if you want the detection-engineering job.

| # | signal | data source | why it's hard to defeat |
|---|---|---|---|
| 1 | per-source behaviour baseline (paths, verbs, cadence) | access log → SIEM | you must *act normal* for that address, which is much harder than being slow |
| 2 | per-**account** keying instead of per-IP | auth logs, IAM events | defeats rotating source addresses — see `distributed_credential_stuffing` in `lab/detect.py` (9 sources, 2 tries each, and the per-IP rule stays silent) |
| 3 | ASN/netname reputation (hosting vs residential, VPN/Tor labels) | RDAP + whois feeds | free, automatic, and blocks half of "stealth" infrastructure at the door |
| 4 | TLS/HTTP client fingerprints (JA3/JA4, HTTP/2 SETTINGS, header order & casing) | edge, or a pcap | tool defaults, not behaviour; changing them is per-tool work with a cost of its own |
| 5 | distribution shape (jitter, burstiness, entropy of timing) | any timestamped stream | `uniform_cadence_automation` fires on `cv = σ/μ < 0.12` over 24 gaps. Add jitter and you trip #6 instead — the arms race has no exit |
| 6 | low-and-slow thresholds | flow records | `low_and_slow_port_probe`: 12 ports over 27 minutes, zero payload. Slow scanning is only quiet against a rule nobody wrote |
| 7 | **log absence** / truncated captures / disabled collectors | flow vs log reconciliation, agent heartbeats | `logging_gap_on_http_flow`: an HTTP-port flow open 22 minutes that produced *no* log line. Traffic without a record is itself an alert |
| 8 | endpoint telemetry: process create with argv + hash + **parent chain** | EDR | a shell spawning curl at 03:12 in a container that never runs shells; nothing on the network tells you |
| 9 | audit-tamper detections | auditd/sysmon/SIEM | `wevtutil cl`, log rotation forced mid-window, file-integrity change on `nginx.conf`, `history -c` — these are among the highest-severity rules any SOC keeps. Trying to be invisible here makes you *louder and worse* |
| 10 | out-of-band canaries | DNS/HTTP egress from the target, Interactsh-style listeners | a URL in a payload that the server itself fetches proves reachability without any request reaching you — and it also *is* the SSRF lesson of Module 8 |
| 11 | business analytics | billing, support tickets, marketing funnels | an account that suddenly reads 400 invoices from a new country is an incident in the numbers, before it is one in the logs |
| 12 | human report | someone notices | the single most successful detection mechanism in history; see any breach post-mortem |

Seven of those twelve are implemented in this repo (`tools/triage.py --sigma` prints all
13 with their false-positive lists and ack procedures). Implementing #8–#10 is a lab-image
exercise, not a sandbox one.

## 10.5 Anti-forensics, at the altitude that's actually useful

Everyone asks here. The useful answer is structural, not instructional:

* **You can only delete records you own.** Everything in §10.1 items 1–4 belongs to another
  legal entity; "covering tracks" there isn't a technique, it's a request to a company to
  destroy its own ledger, which they will not do and will report.
* **Deletion is an event.** File-integrity monitoring, agent heartbeats, log-gap detection,
  backup diffs and SIEM content rules exist precisely because wiping is the *expected*
  attacker move. So the marginal gain is small and the marginal severity is large: in most
  jurisdictions impairing data or logs is a separate, more serious offence than the access
  you were trying to hide, and "he deleted the logs" is the sentence that ends any defence
  based on good intent.
* **Therefore the professional move is the opposite:** make the record *correct*, not
  absent. `tools/casefile.py` exists because a well-documented, authorised, timestamped
  trail is what gets an engagement paid and a person un-arrested.

If you are studying this as a defender: implement #7 and #9 first. They are the highest
hit-rate detections in the whole taxonomy and the cheapest to build — you already have the
flow-vs-log reconciliation in `lab/detect.py`.

## 10.6 The one-page discipline list (works for legal work, which is why it's the list)

* One identity per context. Never the same handle, email, phone, key, payment card or repo
  across two clients, and never shared with your personal accounts.
* Disposable, snapshotted VMs for anything noisy; nothing durable on the host; full-disk
  encryption; no client data on a device that syncs.
* No personal accounts signed in on a test box — including the browser you use to look up
  "is this IP flagged".
* Tooling: pinned versions, no random gists, no pastebin of client data, and no
  credentials in argv (the parent-chain telemetry sees them).
* Timezone/locale/UA coherence: your `Accept-Language` and `TZ` will contradict your
  "VPN exit country" in the same request; the target's log has both.
* Comms: engagement discussion in the client's channel or a corporate one, not personal DMs;
  "purely educational" in a chat log is not a defence, it's evidence of intent.
* Paperwork always ahead of packets: signed scope, source IPs, window, stop conditions
  (`tools/roe.py generate && ... sign`, then `check` before every tool run).
* When in doubt, the test that matters: **would I be comfortable if the client's lawyer
  read this log line, this screenshot and this chat, in order?** If not, don't send it.

## 10.7 Exercises

1. Run `tools/footprint.py --egress --report out/footprint.md`. Your own public address is
   in that file — and it is field 1 of every request you have ever made from this machine.
   Now enumerate, in writing, *who else has that number next to a timestamp for yesterday*.
   If you can name more than three categories, you have understood §10.1.
2. `python3 tools/triage.py --rule uniform_cadence_automation` fires on a source with
   `cv = 0.0`. Make the planted scanner evade it *in the generator* (add jitter to the
   24 gaps) and re-run. Note which rule catches it instead, and how long the edit took you.
   That is detection engineering from the other side of the table: signal #5 → signal #6.
3. Write the audit rule for "`access_log` disabled on a public vhost while `real_ip_header`
   is set" and add it to `tools/audit.py`. Then explain in two sentences why that config
   shape is an incident on its own, independent of any attacker.
4. Draft a real ROE for a hypothetical engagement against your own router
   (`192.168.1.1`) with you as both client and tester. `tools/roe.py generate`, fill it in,
   run `check`. Then answer: what in that document would you *not* be able to produce if
   your ISP called? That gap is your actual risk, and no network hop changes it.
5. Read one breach post-mortem (Verizon DBIR case studies, or any Mandiant/FireEye M-Trends
   narrative) and list, per phase, which of the twelve primitives in §10.4 caught it — and
   which the actor thought they had defeated. You will find the same pattern everywhere: the
   network tricks mostly worked; the human/system reuse is what finished it.
