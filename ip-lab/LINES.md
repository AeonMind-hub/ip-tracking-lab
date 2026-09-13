# LINES.md — where this stops, what a client can authorise, and what nobody can

You asked for the boundary in one readable document so you can use the lab without
guessing. This is not a disclaimer to skip: it is the part of the job that keeps you
employed, and — read it that way — the most valuable page in the repo.

## 0. How to use this file

Before you point a tool at anything, answer these five questions **in writing**
(`tools/roe.py generate` makes the file for you):

1. **Whose is it?** Owner of the IP/host, and can you name them. If the answer is "an app
   I found", stop. Ownership, not reachability, is what authorises.
2. **Did the owner agree to *this*?** A signed scope covering that host, those ports, that
   window, those techniques. A bug-bounty policy counts as this *only inside its listed
   scope and rules*.
3. **Who else gets hurt by my action?** Users of the app, tenants on the same host, people
   whose data sits in the database. They never signed anything. That's why "read one row to
   prove it" is the professional move and "export the table" is not.
4. **What does my action *create*?** Every request is a record in someone's log with your
   address in field 1. `tools/footprint.py --scenario home` shows you the whole chain of
   records your own activity produces. There is no configuration where you act on someone
   else's system and leave nothing behind; there is only "the record matches an
   authorization".
5. **If their SOC calls me at 3 a.m., what happens?** Name, ticket, signed scope, contact,
   immediate stop. If you can't answer, you're not an authorised tester, you're an incident.

## 1. The line, as a table

| capability / action | status | why | what it produces as evidence | the professional version |
|---|---|---|---|---|
| Read + analyse logs of a system you own | ✅ fine | it's your data | your own audit trail | `tools/dossier.py`, `tools/casefile.py` |
| Own your own IP / headers / leak surface | ✅ fine | self-inspection | report you wrote yourself | `tools/probe.py`, `tools/passive.py`, `tools/audit.py` |
| Deliberately vulnerable app on your own loopback/VM | ✅ fine | you own the target | pcap + logs you generated | `apps/app.py` + `tools/web.py` |
| Public registry/DNS/cert lookups (RDAP, PTR, crt.sh) | ✅ fine | published data, read-only | access log at the registry | `tools/dossier.py`, `tools/passive.py` |
| Scanning a host you don't own (even "just ports") | ⚠️ needs written authorisation | unauthorised access attempts; in many codes *interrogation* of a machine is itself an offence | their IDS/SIEM, your ISP, their abuse report | rent a lab (THM/HTB), or get the signed scope |
| Credential testing against a live login page | ⚠️ only in listed scope, rate-capped | access attempts against real accounts = access offence + personal data | auth logs, MFA events, device fingerprints | test against your own app; or client-approved single-account tests |
| Accessing data of users who are not you, "to prove it's possible" | ⚠️ one record max, contractually bounded | their data belongs to the data controller, not the tester | the export itself, plus EDR | `max_records_per_finding` in the scope, then stop |
| Turning off/deleting logs, wiping, editing audit trails | ❌ never, no signature helps | independent offence (obstruction / unauthorised data impairment), and it is *loudly detected* | the tamper alert, the gap, the missing-file mtime chain | report the gap as a finding: `logging_gap_on_http_flow` is exactly this rule |
| Identifying the natural person behind an IP (subscriber lookup, "who is this") | ❌ never, not buildable here | only the ISP holds it and only legal process gets it out; acquiring it otherwise is the offence | nothing you built — everything the ISP logs | abuse report to the network operator; `notes/05` has the letter shape |
| Building tooling whose purpose is hiding your tracks from investigation | ❌ never | its only coherent market is post-offence evasion; you become an accessory by supplying it | the tool itself, plus your comms about it | OPSEC *hygiene* for authorised work: `tools/roe.py`, `notes/10` |
| Accessing a system via stolen/leaked credentials you found | ❌ never | that's the offence, not the investigation | the login event, the IP, the keylog | report it; `tools/passive.py` shows leak surface on your own domains |
| Interception of traffic you're not a party to | ❌ never | wiretap/interception statutes; carrier-level, not "grey" | their NetFlow + your equipment | analyse captures of *your own* links: `tools/triage.py` |
| Physical / Wi-Fi / badge attacks without explicit written scope | ❌ never, even in engagements | separate authorisation regimes and different crimes | facility CCTV, door logs | decline unless the contract names it, with named approvers |
| Anything against a minor, an ex/partner, a colleague, a neighbour | ❌ never | no authorisation is even theoretically available | everything | don't |

Rules of thumb that predict the answer correctly before you look anything up:
**"whose machine, whose data, who consented, what does it create"** — if any of those four
is vague, the answer is no.

## 2. Why "no footprint" is not a solvable problem (and what to do instead)

`tools/footprint.py --selftest` prints a score of **0/100 for every scenario**, including
Tor, a two-VPS chain and a café hotspot. It is not pessimism, it's arithmetic: the model
takes the *minimum* over the hops, so the chain is only as invisible as its worst record,
and the worst records are not network hops — they are the sync account, the payment rail,
the KYC, the billing history, the device you already signed into, and the fact that the
target runs an EDR that ships telemetry to a vendor cloud.

The professional reframe: you don't optimise for absence of records, you optimise for
**"every record matches an authorization"**. That's what `tools/roe.py` produces — scope,
window, declared source IPs, stop conditions, custody log, a signed hash so you can prove
the scope predates the traffic. It also happens to be the only OPSEC that has ever kept
anyone out of custody.

## 3. Jurisprudence you should be able to cite in one line each

* **Nigeria** — Cybercrimes (Prohibition, Prevention) Act 2015 (as amended 2024): unlawful
  access to and interception of computer material, unauthorised disclosure, damage/impairment
  of systems, and **§38–40** requiring service providers to retain traffic data and assist
  law-enforcement interception; NDPA 2023 for personal data (you processing someone's data
  without a basis is its own exposure). Nigeria CERT handles incident/abuse coordination.
* **EU/UK** — GDPR Art 5/32 (lawful basis, security of processing), Art 82 (damages); UK
  Computer Misuse Act 1990 §1 unauthorised access, §2 with intent, §3 unauthorised
  modification — and §3 covers *deleting or altering logs*.
* **US** — CFAA 18 U.S.C. §1030: (a)(2) obtaining information from a protected computer,
  (a)(5) impairment; several states add their own computer-crime statutes; obstruction and
  18 U.S.C. §1028/§1343 attach to identity and wire-fraud shapes.
* **Practically everywhere** — a hosting provider's AUP will terminate you long before any
  court: abuse@, the registrar, the upstream. DoS-adjacent behaviour, scanning other
  tenants on shared infra, and "research" scanners leaking credentials are the usual ends
  of careers.

Not legal advice; a lawyer is a better investment than any tool in this repo.

## 4. If you are ever the one being contacted (this will happen to real testers)

1. **Stop the test.** Not "pause and finish this one request".
2. Reply with the facts the other party needs: who you are, the client, the reference,
   the window, and the signed scope. Attach the ROE and the scope hash (`roe.py sign` output).
3. Do not send more traffic until the client confirms in writing.
4. Preserve everything: your logs, pcaps, custody CSV. Deleting anything now converts a
   misunderstanding into the serious offence.
5. If law enforcement is involved: be polite, be brief, say you'll respond in writing with
   counsel, and give them the client's contact. Contractors who "explain themselves" in a
   live chat have ended engagements and their own freedom in the same sentence.

## 5. What I deliberately did not build, and why it's an engineering decision

No subscriber/OSINT-to-person lookups, no evasion/anti-forensics tooling, no
credential-testing-at-scale harness, no proxy-chain anonymiser. Not because the material
is secret — every one of those has a Wikipedia article and a conference talk — but
because each is a *single-purpose* offence tool with no legitimate buyer, and because a
lab that ships them teaches the one thing that ruins people: that capability decides what
you do, when in this work it's the opposite. What the lab *does* ship is the harder, rarer
skill: the mechanics of how the records get made, so you can read them, defend with them,
and report with them — and the paperwork that makes using that knowledge a job instead of
a case.

## 6. The web surface (module 12) — where the line runs for these 23 classes

`apps/shop.py` contains every payload shape in this file, and every one of them is a
crime the moment the hostname belongs to somebody else. The class is what you *know*; the
target is what you are *allowed* to point it at. Concretely:

| Situation | Status | Why |
|---|---|---|
| any of the 23 classes against `127.0.0.1:8099` (shop.py) | fine | you own the process, the DB and the data |
| DVWA / Juice Shop / WebGoat / PortSwigger labs on your box | fine | the app exists to be broken; the data is fake |
| your own staging or your own product's subdomain | fine, but log it | scope is real; say so in the ticket |
| a program whose policy names the asset, inside its rules | fine | paid, indemnified, defined window |
| "just one `'` in the search box of a random site to see" | **not fine** | Cybercrimes Act §14 (unauthorised access), CFAA §1030, CMA §1 — the *test* is the access. Intent and payload size are irrelevant |
| reading a real table because the UNION worked | **not fine** | §15 (interference / data), NDPA 2023 — even inside a signed scope this is "beyond": stop at the proof |
| credential stuffing, mass scanning, subdomain sweeps of a non-consenting org | not built here, and not fine | §5's exclusion list |
| "their `security.txt` said to report, so probing first is okay" | not fine | a disclosure channel is not authorisation; a safe-harbour clause protects *in-scope* research that stopped at PoC |

Three working habits that keep this a career and not a case:

1. **Scope before the first request.** `python3 tools/roe.py generate` then `sign`, and
   `tools/web.py --scope` / your proxy config refuses anything outside it. Verbal permission
   becomes your problem the day it is denied in writing later.
2. **Proof, not proof of capability.** One request and one screenshot that demonstrates the
   boundary was crossed. `SELECT`ing the customers table because you *can* converts a Medium
   finding into your liability. In this lab the UNION returns fake emails for exactly this reason.
3. **Stop on contact.** §4's procedure applies when the target's SOC emails you mid-test:
   stop, preserve, escalate to whoever signed the scope, don't negotiate the finding yourself.

## 7. The doors that stay shut, and what stands in their place

You asked for "tracking, duplicating, accessing devices, the cool stuff". Six of those went in
(`apps/shop.py`'s session-cloning classes, `tools/eyeball.py`, `tools/netinv.py`,
`tools/phish.py`, `notes/12`, `notes/13`). This table is the rest, stated as fact once, with
what the lab puts in their place instead. Not a lecture - a spec of what is and is not here.

| Capability | Why it is not built | The legitimate version | What this lab builds instead |
|---|---|---|---|
| who owns this IP / phone number | no interface exists to a private party; the answer lives in an ISP's subscriber records | legal process to the ISP (§39 duty), or the host's own abuse desk | `tools/dossier.py` + the ceiling string in `lab/tracer.py`, and `tools/casefile.py` writes the request |
| IMEI/IMSI/MSISDN lookups, SS7, SMS interception, cell-site simulators | carrier signalling and radio: regulated equipment, and interception is its own offence (§15) everywhere | lawful-interception units, with a warrant | app-based MFA advice, and the SIM-swap response procedure in `notes/13` §13.3 |
| tracking a person's device (stalkerware, "partner monitor", GPS without consent) | the buyer is an abuser; the seller is the defendant; the evidence rules make a tainted capture worthless | employer MDM with written notice to the user; parental controls on a minor's own account | `tools/eyeball.py` shows what *your* device leaks; `notes/13` §13.3 step 6 covers the case where you are the target |
| an implant, keylogger or RAT | a single-purpose offence tool; also the exact artefact that converts "researcher" into "defendant" | red-team kit is sold to vetted firms under contract, with scope documents | `lab/detect.py::beacon_periodicity` + the planted beacon in `tools/gen_pcap.py`: you build the *detector* for that behaviour |
| exploit code for a real product (browser, iOS, Windows, router firmware) | unpatched = victims; and you cannot target a product without targeting strangers | a coordinated-disclosure report to the vendor, or a lab image of the vulnerable version | 27 planted classes in `apps/shop.py`, all on `127.0.0.1`, each with the fix in the same file |
| a phishing page that works | the deliverable *is* the offence; kits are what cases are built on | an authorised simulation with signed scope, consented users, and a training follow-up | `tools/phish.py`: the analyst's side - 13 planted cases, pinned classification, "what to do next" |
| credential stuffing / reuse testing at scale | unauthorised access × thousands of victims, even with "just checking" intent | a breach-check against *your own* users' hashes, with a notification policy | `tools/triage.py --rule distributed_credential_stuffing` - catching it, and `--selftest` in `apps/shop.py` shows why per-IP thresholds miss it |
| internet-wide scanning of other people's hosts | the scan itself is the unauthorised access in most jurisdictions | your own ASN/asset list, or a bug-bounty programme's named scope | `tools/netinv.py` refuses every address outside the ranges you declare yours, and refuses public addresses entirely |
| WAF evasion, fingerprint spoofing, "anti-detect" profiles | its only use is being unaccountable; and the technique list *is* the detection list | none for an individual; defenders test their own detection with purple-team docs | `tools/footprint.py` (why invisibility scores 0/100) and the four stealth rules in `lab/detect.py` (how the shapes are still seen) |
| deleting or editing logs, timestamps, or the audit trail | evidence tampering; the fastest way to turn a finding into a charge, and it is on `tools/roe.py`'s NEVER list even when everything else is signed | log *retention* policy changes, proposed in writing | `tools/roe.py log --artifact <f>` hashes artefacts so the trail is provable instead of editable |

**"What authorised actually looks like", in one paragraph,** so the table is not just a list of
nos: a written scope (client, assets by host:port or CIDR, in/out dates, allowed methods and
severity ceiling), a named contact at the target with an agreed channel, a rules-of-engagement
document your insurer will accept, an emergency stop condition ("stop on any sign of real user
data, on any SOC contact, on any outage"), a data-handling policy (what you keep, where, for how
long, NDPA 2023 duties if it is personal data), and a report with the five-part finding form in
`notes/11` §11.6. `tools/roe.py generate/sign/check` produces and enforces the first three, and
`tools/web.py --scope` proves the gate by refusing the requests that fall outside it. If you can
produce that document set, you are doing this work professionally. If you cannot, you are doing
it as a defendant with good intentions.
