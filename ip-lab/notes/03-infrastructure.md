# Module 3 — Enrichment: RDAP, PTR, geo, TLS. What each one can and cannot prove.

Everything here is public and read-only. This is also the exact workflow for
"who is hosting this thing I built", which is the legitimate half of the same skill.

## 3.1 Registry first, geography second

```bash
# 1) who owns the block, and who do you email about abuse
curl -s https://rdap.org/ip/45.148.10.66 | jq '{name,country,handle,entities:[.entities[].roles]}'
# 2) reverse DNS — the cheapest intelligence there is
curl -s "https://dns.google/resolve?name=66.10.148.45.in-addr.arpa&type=PTR" | jq '.Answer'
# 3) only then: a geo estimate
curl -s https://ipinfo.io/45.148.10.66/json
```

From this sandbox, the lab just printed (real data, real answers):

```
source ip        hits  ...  org                                      geo            network    traceable
45.148.10.66     38       AS48090 TECHOFF SRV LIMITED              Amsterdam/NL   DMZHOST    15/100
177.154.220.44   14       AS262293 Sistema Oeste de Serviços LTDA  Mossoró/BR     ...        40/100
185.220.101.34   6        (Tor)                                     DE             TOR-EXIT   0/100
```

Notes from those three:

- `45.148.10.66`: RDAP says the block is registered in **AD** (Andorra) to
  `DMZHOST` with `abuse@` of a Gmail address; geo says **Amsterdam**, ASN owner is
  `TECHOFF SRV LIMITED` in BG. Three sources, three "locations" — all of them
  correct, none of them where a human is. Rented box, someone's VPN exit,
  bulletproof-ish hoster. This is the normal case.
- `177.154.220.44`: PTR is `44customer-220-154-177.tcm10.com.br` — the ISP put
  the customer's *IP in the hostname* inside a CPE pool name. That's a real
  pattern (BR154/`vtnerb`/`pool` style), and it means "one dynamic pool", not
  one person.
- `185.220.101.34`: RDAP `network_name` is literally **TOR-EXIT**, abuse contact
  `abuse@for-privacy.net`. Attribution ceiling: the exit node. Full stop.

## 3.2 What each field is worth

| data | what it really tells you | typical error |
|---|---|---|
| geo city/country | where the *network* terminates | treating it as evidence of a person's location |
| `accuracy`/radius | 20–100 km broadband, region-wide mobile, meaningless for DCs | quoting "37.97 N, 23.72 E" to 4 decimals |
| ASN + org | who you complain to | assuming the ASN is the attacker's employer |
| PTR | the operator's naming scheme; sometimes the customer IP | forgetting the block owner can write anything there |
| `Accept-Language`, timezone | how the *client was configured* | "they speak Greek, therefore Athens" — it's a browser setting |
| TTL / hop count | distance in router hops, if nothing rewrote it | anycast, CDN, tunnels, containers → garbage |
| registration date of the /24 | a rented VPS created 3 days ago is a strong signal of disposable infra | ignoring it — this one is actually useful |
| RDAP `abuse` contact | where you legitimately report | emailing it to accuse a stranger |
| TLS cert SAN/issuer | which platform/account fronts an IP | trusting a default cert on a misconfigured edge |

## 3.3 Finding what's behind a CDN (defensively: the same tool, pointed at your own box)

```bash
python3 tools/passive.py --domain app.aeonlabs.test --common-subdomains
```

What the lab does, in order of usefulness:

1. **Resolve, then SNI-probe.** Connect to the resolved IP and request the cert
   *with* and *without* your SNI. If a Cloudflare-ish IP answers with a cert
   containing 400 SANs, it's a shared edge. If it answers with `CN=staging-3.internal`
   then your edge is misconfigured and the origin is public. `tls_cert()` returns
   `presented_name_matches` for exactly this check.
2. **Which edge ASN.** `front_of()` labels it (CF / Akamai / Fastly / AWS / Azure /
   Vercel / Netlify) or tells you "this is not a CDN, this IP *is* the origin".
3. **Email headers** — `Received:` chains are an entire OSINT course in one
   header. Read them right-to-left, remember the first hop (client → its own
   provider) is the only one that says anything about the sender, and that every
   later hop is the assertion of a server you don't control. Verify with SPF /
   DKIM / DMARC before believing a single word, and treat `X-Originating-IP`
   (which some webmail adds, and which phishers strip) as decoration.
4. **Response header chain** — `X-Served-By`, `X-Amz-Cf-Id`, `cf-ray`, `X-Vercel-ID`
   are breadcrumbs to the platform account, which for a site *you* run is how you
   find your own forgotten origin.
5. **Passive data, not active probing.** Certificate transparency logs (crt.sh),
   Rapid7/Push pulls, SecurityTrails/RiskIQ historical DNS, `Shodan` for open resolvers
   and hostnames: this is the legitimate, effective version of "scanning the internet".
   It is *reading other people's published data*, which is a completely different
   risk profile than sending traffic at a target.

What is *not* clever, and is mostly movie: the "ping it / traceroute it" reflex.
Anycast breaks it, load balancers break it, and it tells you nothing about the human.

## 3.4 The `traceability_score` in `lab/tracer.py`

It's deliberately blunt: PTR present +25, residential ISP +40, datacenter −25,
Tor −45, anycast −20, private range → capped at 25, 5+ requests +15 (enough
behaviour to fingerprint), behind an unverified proxy −30. The output is a
*ceiling*, and the ceiling is almost always one of three things:

1. `nothing actionable` — you have an address in a shared NAT and no other fact.
2. `abuse report to the network operator` — you can stop the traffic (block, rate-limit,
   require auth) and tell the operator that their IP is hitting you.
3. `ISP subscriber identification, via law enforcement / legal process` — a crime
   happened, there is a report on file, and an officer or the ISP's own process does
   the last hop. Nothing you write can or should bypass that.

## 3.5 Exercise 4 & 6 answers

**Ex. 4 (Tor false positive).** Three facts from the log alone: (a) 6 requests, all
`200`, all to one public webhook path — a *working integration*, not enumeration;
(b) a `Referer` from a customer domain, i.e. they came from inside an app; (c) no
probe paths, no auth failures, no cadence anomaly. Plus the address is a known Tor
exit, which changes *how you treat* it (rate-limit, don't trust geo) but says nothing
about intent.

**Ex. 6 (IPv6 /64).** The sentence: "Traffic attributable to the prefix
`2001:4488:1060:1c4a::/64`, assigned to AS4538 for research and education; the
logging configuration in force at the time truncated the host portion, so no single
device in that /64 can be identified from these records." The config that keeps the
option open is simply **not** masking: in nginx, log `$remote_addr` verbatim (there is
no auto-truncation — the failure mode is people *adding* privacy masking, or a
load-balancer rewriting the logged field), with retention defined by policy and a
documented legal basis. Truncate on *publish*, keep on *retain*, and write down which
one you chose.
