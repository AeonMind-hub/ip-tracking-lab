# 12 — "Real tracking": what the professionals actually do, and the wall next to it

You asked for the real version of the movie skill. Here it is, honestly divided:

```
   arrow A:  identity  ->  where that person is right now
   arrow B:  record    ->  what happened, on whose network, and what to fix
```

Arrow A is not a skill gap. It is a legal wall with a technical shape: no ISP, carrier or
platform hands a subscriber location to a private individual, and the tooling that claims to
("IP locator" sites, "phone tracker" APKs, "IMSI lookup" services) is either a city-level
geolocation API in a wrapper, a scam, or a crime in progress. Everything in this lab is
arrow B — which is, coincidentally, the arrow that gets paid.

Then the useful reframe: the thing people *imagine* is "tracking by IP" is really
**correlation**, and correlation is a legitimate, learnable, largely mechanical skill. That is
what this note teaches.

---

## 12.1 The signal stack, ranked by what it can prove

| Signal | What it identifies | Persistence | Admissible as |
|---|---|---|---|
| session cookie / bearer token | one authenticated session | minutes–weeks | strong (it *is* the account) |
| account id, device id, install uuid | one user across everything they do there | years | strong, but only the platform has it |
| canvas / WebGL / font set | the machine's render stack | stable through IP change | medium — "same device class", not "same human" |
| TLS + HTTP2 client fingerprint (JA3/JA4, Akamai) | the HTTP client library/version | stable per tool | medium; useless the moment they rotate it (module 10) |
| egress IP + /64 (v6) | a network, sometimes one line | hours–weeks | medium: an *address owner*, not a person |
| ASN / org name via RDAP | hosting provider or ISP | years | context, and the abuse contact |
| PTR hostname | sometimes the ISP encodes a customer line | years | weak-to-medium; a hint to ask about |
| timing/behavioural cadence | automation, and co-located activity | n/a | corroborating only |
| geolocation (any API) | a city, sometimes a metro | n/a | **never** "where they are" |

The arithmetic that matters: independent low-cardinality signals multiply. `Accept-Language`
alone is worth little; canvas + fonts + timezone + screen + a stable storage id is a
device-class identifier that survives VPN use, and `tools/eyeball.py` will show it to you on
your own machine in about ten seconds (§12.5). This is why "hide my IP" and "don't be tracked"
are different projects.

The other arithmetic: the traceability ceiling in `lab/tracer.py` is a *maximum*, not an
estimate. 0/100 = hosting-provider noise; 15/100 = you can name the network and its abuse
desk; 40/100 = a residential line where the PTR encodes the customer — and even then the
subscriber name is only ever released by the ISP, to a court or its own abuse process.

---

## 12.2 The six techniques that are actually used

All of these are runnable in this lab against data you generated.

1. **Flow correlation.** Same five-tuple + timing across two observation points, or a
   connection that appears at the edge and at the origin with different source addresses (the
   XFF lie in module 2). Tool: `tools/triage.py`, `proxy_lab/chain_demo.sh`.
2. **Session pivot.** One session identifier seen from two client profiles = the account moved
   machines. This is the single highest-value detection for account takeover, and it is the
   thing "duplicating" a session looks like in a log. Rule: `session_split_brain`.
3. **Client-fingerprint pivot.** Same JA3/JA4 or Akamai hash across addresses → same tool,
   probably the same actor; same canvas+font set across sessions → probably the same machine.
   `tools/eyeball.py diff` demonstrates the concept on your own two captures.
4. **Infrastructure co-occurrence.** Passive DNS, certificate transparency, shared TLS certs,
   same favicon hash, same ASN + same open-port shape → clusters *infrastructure*, i.e. "these
   five hosts are one operator", which is how you get from one IP to a campaign.
   `tools/passive.py --domain <yours> --subdomains`.
5. **Follow the money, not the packets.** Where a case involves a crypto address, an exchange
   or a payment rail, attribution happens through the KYC'd intermediary by legal process —
   which is why a good analyst writes the request that names the wallet, the timestamp and the
   transaction id instead of trying to be clever.
6. **Human artefacts.** Order confirmations, invoice PDFs, support tickets, file names in an
   upload directory (`/uploads/` in `apps/shop.py`), and `X-Backend-IP` headers — i.e. the app
   describing itself. `tools/web.py` finds these on your own target in four requests.

---

## 12.3 The escalation path, in Nigeria, in order

Knowing *how to ask* is the professional skill; it is also the only path that ends in an answer.

| You have | You go to | With | Realistic outcome |
|---|---|---|---|
| abuse from your own service | your log + `tools/casefile.py` | nothing external needed | the fix, and a report |
| an IP that is a hosting VPS | its abuse contact from RDAP (`tools/dossier.py --ip`) | evidence bundle, timestamps, the requests themselves | the VPS gets shut down or its customer is identified *by the host*, to law enforcement |
| an IP on an ISP (residential/mobile) | the ISP's abuse/Lawful-Interception unit **via** a VDP/CERT or police referral | incident number, log excerpts, preservation request | nothing to you; possibly action to them |
| an incident at an organisation in Nigeria | **CERTN_UG** (ncert, `cert.org.ug`-style intake for Nigeria is `cert.ng`) and the **NITDA**-defined CDR process | a written CDR request: your details, the target, the *why*, the time window | the regulator asks the provider for records; you may get a redacted answer |
| a real crime (fraud, extortion, stalking) | **EFCC** / **ICPC** / state police CID, with an affidavit | preserved logs, hashes, chain of custody | a subpoena/warrant to the ISP or platform — the only lawful route to a name |
| a foreign host | through the same agency, via mutual legal assistance | everything above + translation of the request | weeks-to-months; this is why "just email them" fails |
| data about a Nigerian citizen that *you* hold | NDPA 2023 (formerly NDPR) duties: purpose, minimisation, security, breach notification | your own policy documents | you are the regulated party — a reason to keep the smallest dataset that works |

Statute anchors to be able to name: Cybercrimes Act 2015 **§14** unauthorised access, **§15**
unauthorised interception of *communications*, **§22–24** cyberstalking/harassment and
unauthorised disclosure, **§38–40** the preservation-and-disclosure duties that make the table
above work. UK CMA **§1–3**, US **18 U.S.C. §1030**, GDPR **Art 5/32/82** if any personal data
is in your dataset. Full list with what each one means for you: `LINES.md` §3.

**The request that works** looks like this: *"On 13 Sep 2026 between 02:11 and 02:19 UTC, the
following requests were made against my service from 45.148.10.66 (AS48090, DMZHOST, abuse
contact below), attempting authentication to /api/v1/report. I attach 737 lines of access log,
their sha256, and the response codes. I request preservation and identification of the
subscriber under §39."* — Specific, time-bounded, evidence-attached, and it cites the duty
rather than asking for a favour. `tools/casefile.py` produces this shape.

---

## 12.4 A worked correlation, in this lab

```
python3 tools/gen_pcap.py && python3 tools/triage.py --rule session_split_brain
```

```
[ALERT] session_split_brain  (high)  hits=1
        sid=S777  ips=2  uas=2  hits=2  span=60.0
        10.0.0.31 (Mozilla/5.0 iPhone) and 198.51.100.77 (curl/8.4.0)
```

Read that the way an analyst does. It is not proof of a thief. It is a *decision point*: the
same session, two machines, one minute apart, one of them a command-line client. Now the
sequence you would run for real: pull MFA/step-up events for the principal → check whether the
second profile changed a recovery contact → look for an inbox rule or auto-forward → revoke the
session family, not the IP → then, and only then, decide whether this is a case for §12.3.

And the mirror exercise, which is the same skill inverted:

```
python3 tools/triage.py --rule beacon_periodicity
```

Two hosts talking to `203.0.113.9:443` on a 60-second period with 9 s of jitter and nothing
else going on: `cv_squared ≈ 0.02`, small payload, fresh socket every time. Machines are
boring on purpose; humans are noisy. That contrast is the whole of "advanced persistent threat"
detection, and you just read its SQL.

---

## 12.5 Seeing it on yourself (this is the exercise, not a lecture)

```
python3 tools/eyeball.py serve --port 8097     # open http://127.0.0.1:8097 in your browser
python3 tools/eyeball.py analyze               # what the page volunteered
python3 tools/eyeball.py diff out/eyeball/visit-1.json out/eyeball/visit-3.json
```

Output from two captures the lab stored a session apart (here the two visits were scripted
POSTs to `/collect`, so the IP differs and a browser profile does not; run it yourself in a
real browser and the `changed` list shrinks to nothing but the IP):

```
"stable":  canvas, fonts, screen, storage-id, timezone, user-agent, webgl
"changed": peer-ip
verdict: 7 of 9 signals identical across the two visits - the stable ones are exactly
         what a tracker keys on
```

That is the honest answer to "can they follow me": the *IP moved* and the *profile did not*.
Which brings you to the real defensive list, because now you know what has to change:

1. Fewer, more mainstream things. Uniformity is the only defence that works — a browser that
   looks like 40 million others is hard to key on. Deliberately weird setups *increase*
   uniqueness (this is why "anti-detect" fingerprint spoofers are a red flag to a defender and
   a gift to a tracker: an inconsistent canvas/screen/timezone combination is itself a signal).
2. Storage is the strongest identifier a site can get, because it is designed to persist. Block
   third-party cookies/storage, clear it per site, sign out when you mean it.
3. One profile per life. Do not log into the same account from the "research" browser.
4. Timezone/locale consistency: a `Africa/Lagos` timezone with an `en-US` locale and a VPN exit
   in Amsterdam is three signals that disagree, and disagreement is interesting.
5. Extensions are a fingerprint: each one is a bit of entropy in your font/canvas/DOM profile.
6. HTTPS-only, ETP/SafeBrowsing on, and `DNT/GPC` understood for what they are: a preference,
   not a cloak (the lab's `dnt/sec-gpc` row exists precisely because it *is* identifying).

For the anti-forensic/ghost side of the question — what an *operator* tries to hide, and how
that shows up in telemetry — that is `notes/10-opsec-and-ghosts.md` plus the four stealth rules
in `lab/detect.py`. The arithmetic there is 0/100 for total invisibility; the reason is per-hop
retention and the fact that you cannot be in two places without two records.

---

## 12.6 What is *not* in this lab, with the technical reason

- No IMEI/MSISDN/IMSI lookups, no SS7 or SMS interception, no cell-site simulator, no GPS from
  a phone number. Not because I have access to a secret API — because those interfaces exist
  only inside carriers and lawful-interception systems, and every product sold to a private
  individual claiming them is fake or illegal. (For the record: SS7 attacks are a
  telecom-infrastructure problem defended by signalling firewalls and by moving MFA off SMS —
  that's the part you can act on.)
- No "who owns this address" answer, only "which network, which abuse desk, what ceiling".
- No stalkerware, no keylogger, no "monitor someone's WhatsApp" tooling. That category is the
  single most-prosecuted form of this work, and the lab's version of it points the other way:
  `notes/13` covers detecting a device that is *already* compromised, including by a partner.
- No evasion kit. `tools/footprint.py` explains the ceiling; it does not try to beat it.

Exercises 16–18 are at the bottom of `notes/13-device-compromise.md`, because they need the
device side of the picture first.
