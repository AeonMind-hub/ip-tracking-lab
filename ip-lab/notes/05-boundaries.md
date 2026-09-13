# Module 5 — Boundaries: consent, law, canaries, and why "IP → person" is not a tool

This is not a lecture bolted onto the end. It is the constraint that shapes the
design of the code in this repo, and the difference between someone who gets
hired to do this and someone who gets a knock on the door doing it.

## 5.1 The bright lines

**Fine (and useful)**
- Reading logs of systems you own or are contracted to defend.
- Looking up any public address in RDAP / DNS / geo / CT logs / Shodan-style indexes.
- Testing a machine you own, in an isolated network (§4.4), or a deliberately-vulnerable
  target (HTB, THM, VulnHub, OverTheWire).
- Testing a real third party **inside a written scope** — a bug bounty's policy page,
  a pentest SOW with dates and target lists, a signed rules-of-engagement doc.
- Reporting abuse to `abuse@` of a network that is hammering *you*, with evidence.
- Building and instrumenting your own services so *you* can attribute *to* you.

**Grey — do it with judgement and, ideally, written permission**
- Passive OSINT on a person you are investigating for your employer (this is DFIR/
  threat-intel work; it needs authorisation, a purpose, and a record).
- A canary link on your *public* repo/website (see 5.3 — capture is fine, *pursuing*
  a stranger isn't).
- "Hacking back" is never grey. It is a crime in most jurisdictions, including
  against a machine that is currently attacking you.

**Crimes (everywhere I know of), regardless of intent**
- Any access, even a `GET` on a port nobody advertised, to a system you don't own
  and aren't authorised to test. Nigeria's **Cybercrimes (Prohibition, Prevention) Act
  2015** §6–§8 covers unauthorised access, interception and interference; the EU has
  the equivalent in national implementations of 2013/40/EU; the US has the CFAA. Same shape.
- Any processing of someone's personal data (which an IP address + behaviour profile
  *is*, per CJEU Breyer and the GDPR's own definition) with no lawful basis — that's
  **NDPA/GDPR** territory, and "I was just looking" is not a basis.
- Intercepting traffic you aren't a party to (NDPA Art. 21, GDPR, wiretap statutes).
- Publishing, "outing", or confronting the person behind an address — doxxing,
  harassment, intimidation. Also how innocent people get attacked, since the address
  is usually wrong or shared (ask anyone whose CGNAT got reported).
- Selling/using "IP to address lookup" services or datasets of subscribers.

## 5.2 Consent, in the order it matters

1. **Owner consent** — is the system, the network, the log file yours or delegated to you in writing?
2. **Subject awareness** — did the person know they were being measured, at the granularity
   you're measuring? "We log IPs" in a 40-page privacy policy is a legal fiction; a
   lab is a lab, a production service is a production service.
3. **Purpose limitation** — you collected it for incident triage; now it's a dossier on
   an ex-partner. Same bytes, different crime.
4. **Proportionality** — a 404 on `/.env` from a Tor exit does not warrant anything except
   the config change that removes `/.env`.
5. **Retention and minimisation** — delete what you no longer need; it's the one control
   that has saved more than one researcher from a data-breach-of-theirs-about-others.

The reason the `real_ip()` function and the canary ledger in this repo are written the way
they are: they make the *capture* boundary explicit in code, so you never have to remember
it in the moment. Good tooling encodes the policy.

## 5.3 Canaries: what they are, what they must not become

```bash
python3 tools/canary.py consent --cidr 127.0.0.0/8 --cidr 10.10.4.0/24 \
        --note "lab VLAN + loopback; agreed with the two testers on 2026-09-13"
python3 tools/canary.py issue --who "me (lab box)" --scope "self-test of my own doc link"
python3 tools/canary.py serve --port 8090      # then open http://127.0.0.1:8090/c/<token> in your browser
python3 tools/canary.py report
python3 tools/canary.py revoke <token>
```

Open that URL in a real browser and read `out/canary_state.json`. The server needed no
vulnerability, no packet inspection and no magic — it received: your remote address,
`User-Agent`, `Accept-Language`, `Accept-Encoding`, the `Referer` (because the page sets
`Referrer-Policy: unsafe-url` on purpose), and whatever your JavaScript chose to
volunteer: timezone (`Africa/Lagos`), `Intl` locale, screen size and DPR, CPU cores,
device memory, touch points, a canvas rendering hash (your font rasteriser + GPU),
whether `localStorage` is available, and — if WebRTC is on — **your private LAN
addresses from ICE candidates**.

That last one is why the movie scene is wrong twice over: the interesting identifier
isn't the IP at all, it's the browser, and the IP is the *least* specific fact in the
payload. (Modern browsers mDNS-obfuscate ICE candidates; if yours didn't, you just saw
a 10.x/192.168.x address — the same thing you'd see in an SSRF against yourself, §2.4.)

What this instrument legitimately is:
- a document watermark: "did the client actually open the file we sent, and did it leak?"
- a honeypot on *your* infrastructure: a token nobody should request, that fires if a
  config you fixed is reverted.
- an accountability check inside a company, with a DPA/policy behind it.

What makes it a stalking tool: sending it to a *specific person* without their knowledge
or any authorisation, then using the results to find them. `tools/canary.py` therefore
(i) refuses to issue a token without a named recipient and a stated scope, (ii) records
`consent.allowed_cidrs` and marks every hit with `consented: true/false`, and (iii) attaches
an explicit `action_required` string to any out-of-scope hit. There is deliberately no
`--notify-slack`, no `--geolocate-and-text`, no `--whois-person`. That's not a missing
feature; that's the boundary.

The `open.png` 204 (rather than a redirect) exists for a technical reason worth knowing:
mail clients and link scanners **pre-fetch** links, so a redirect-based beacon reports
"opened" for a bot. The second, confirmed request for the image is what makes a hit real.

## 5.4 When something *is* actually happening to you

In order, because the order is the skill:

1. **Stop the bleeding.** Invalidate sessions/tokens for the affected accounts, rotate
   what was exposed, force MFA, block the *behaviour* (path + rate), not the address.
2. **Freeze the evidence.** Copy the log files (they rotate), note their hashes
   (`sha256sum access.log*`), the server timezone, and NTP offset. Do not "clean up" the box.
3. **Establish what the logs can and cannot say.** Run `tools/dossier.py … --xff`: if a
   forwarded header is unverifiable, say so in the report — the movies' "we know it was
   him" is exactly the mistake that ends an investigation.
4. **Report it.** For a service: your provider's abuse/security contact. For the source
   network: `abuse@` from RDAP (Module 3). For a crime: your national cyber-crime unit —
   in Nigeria, the NPF Cybercrime Unit / the appropriate state unit, with an FIR; if you
   are a business with users' data, the NDPC has a breach-notification expectation. Include
   timestamps in UTC, the log excerpt, the hash, and what you've already contained.
5. **Tell the affected users, plainly.** It is legally required in many regimes and it's
   the only thing that actually reduces the blast radius.
6. **Ship the fix and the detection** (§4.5), then write the post-mortem: timeline, root
   cause, what would have caught it earlier, and what you changed.

## 5.5 Turning this into work

The market pays for the *defensive* version of this skill, and it is a real,
in-demand, boring-in-a-good-way career: SOC analyst → detection engineering; DFIR;
Cloudflare-style trust & safety incident response; bug-bounty triage → researcher;
product-security engineer ("you built the thing that logs the wrong IP, fix it").
Concretely: do the §4.4 lab, write 5 case files with `casefile.py`, put two of them on
your GitHub with the *reasoning* visible, then go get an authorised scope and do it for
real on HackTheBox/TryHackMe/SOC-range platforms. Certifications that open doors:
CompTIA Security+ (baseline), BTL1 (Blue Team Level 1, hands-on logs/SIEM — the closest
match to what you built here), eJPT then OSCP for the offensive side, GCIH/GCIA for IR.

And: the fastest credibility you can build from Ibadan with the skills in this repo is a
public `security.txt`, a documented log-attribution config, and a write-up of
"here's how our app stopped being spoofable" — that's a portfolio piece that hiring
managers actually recognise. Not a tracking tool.
