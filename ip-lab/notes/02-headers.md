# Module 2 — Headers: what is real, what is typed

## 2.1 Trust model, in one table

| Field | Where it comes from | Who can fake it | Verdict |
|---|---|---|---|
| `remote_addr` (socket peer) | kernel TCP stack | nobody, for a full handshake (bare SYN can be spoofed, but then no HTTP response comes back — nothing you'd log) | **anchor** |
| `X-Forwarded-For` | each proxy *appends* its peer on the **right** | the client appends/pref anything it likes on the **left** | trusted only right-to-left, hop by hop |
| `X-Real-IP` | nginx `proxy_set_header X-Real-IP $remote_addr` | the client, if you copy an inbound one | same rules |
| `CF-Connecting-IP` | Cloudflare edge, after verifying the peer | the client, unless you verified the peer is Cloudflare | strong **with** peer check |
| `True-Client-IP` | Cloudflare's signed header (`http_true_client_ip`) | the client, unless the `True-Client-Key` JWT checks out | strongest, rarely configured |
| `Forwarded` (RFC 7239) | the standard, `for=…;by=…;host=…` | nobody adopts it | correct, rare |
| `Forwarded` from Akamai/GCP LB | vendor-specific, e.g. `X-Client-Data`, `Via` | peer-verify | use the vendor's doc |
| `X-Original-URL` / `X-Rewrite-URL` | old load-balancer/CDN rewriting | the client | **delete at the edge**; these are a WAF-bypass technique, not identity |
| `X-Forwarded-Proto` | the proxy's TLS state | the client | used in "redirect to http://", auth links, cookie `Secure` decisions |
| `X-Forwarded-Host`, `Host` | routing/cache key | the client | cache-poisoning and password-reset-poisoning vector |
| `Via` | each proxy adds itself | the client can add junk lines | good for discovering your own chain |
| `Accept-Language`, `Timezone`, UA | the client's browser | the client | OSINT colour only, never identity |
| `Referer` | the previous page | the client (or stripped by policy) | tells you *how they got here* |

Two things people get wrong every single time:

1. **Leftmost is not the client.** It is "the first thing the first proxy saw",
   which the client fully controls. If you must have one value, walk from the
   **right**, and stop at the first address that is *not* in your trusted-proxy
   list — that address is what that proxy saw. If your trusted list is empty,
   the answer is `remote_addr`, full stop.
2. **"Behind Cloudflare" is not a config you can assert, it's a fact you verify.**
   A site on Cloudflare's IPs can be origin-pulled around in a minute of
   misconfiguration; a `CF-Connecting-IP` header can be delivered by a client
   that has never met Cloudflare. Verify the peer, or verify the signature.

`lab/logs.py::real_ip()` implements the walk. Test it against the lab target:

```bash
python3 apps/app.py --port 8080 --mode naive &       # the classic bug
python3 apps/app.py --port 8082 --mode safe  &       # the correct config
python3 tools/probe.py --naive 8080 --safe 8082
```

You will watch `logged_as=8.8.8.8` appear in the log of the naive instance from a
request sent by *your own* loopback interface, and nothing at all change on the
safe one. Then run `python3 tools/dossier.py out/target_access_sim.log --xff`
and note that the analyser calls the naive one's log a liar:

```
### 8.8.8.8
    xff: chain=['8.8.8.8'] verdict=8.8.8.8 confidence=high
      ! XFF SENT TO A NON-PROXIED SERVER -> client is lying or testing you
```

## 2.2 The fixes, verbatim

```nginx
# nginx as the outermost proxy: THE ONLY SAFE WAY TO LOG A CLIENT IP
set_real_ip_from 10.0.0.0/8;        # your cloud's internal ranges
set_real_ip_from 173.245.48.0/20;   # …and if (only if) Cloudflare is in front:
set_real_ip_from 103.21.244.0/22;
real_ip_header   CF-Connecting-IP;   # or X-Forwarded-For with real_ip_recursive
real_ip_recursive on;

access_log /var/log/nginx/access.log main buffer=64k flush=5s
           '$remote_addr - $remote_user [$time_local] "$request" '
           '$status $body_bytes_sent "$http_referer" "$http_user_agent" '
           'rid=$request_id xff="$http_x_forwarded_for" tcip="$http_true_client_ip"';
# note: the raw claims live in SEPARATE fields. Never overwrite $remote_addr.
```

```nginx
# kill the disclosures (Module 2.3) and the client-supplied junk
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;  # appends correctly
proxy_set_header X-Real-IP $remote_addr;
fastcgi_hide_header X-Powered-By;
server_tokens off;
```

```php
// Laravel: wrong (client-controlled)  | right
// 'proxies' => '*'                          'proxies' => '10.0.0.0/8, 173.245.48.0/20'
// Symfony: setTrustedProxies([...], Request::HEADER_X_FORWARDED_FOR | HEADER_X_FORWARDED_HOST)
// Express: app.set('trust proxy', ['loopback','linklocal','public'])  <-- 'true' is the bug
```

## 2.3 The other direction: what *your* responses say about you

Every header below is a gift to whoever is poking. `lab/passive.py::LEAKY_HEADERS`
is the dictionary; `tools/passive.py --url <a site you own>` reads them.

- `X-Backend-IP: 10.0.0.7`, `X-Debug-Trace: origin-web-03.fra.internal` → internal
  topology, and sometimes a routable-on-VPC address for lateral movement.
- `X-Served-By: cache-lhr7432-LHR`, `CF-Ray: 8f…-LHR` → which POP you hit; combine
  with `cf-cache-status` and you can map an anycast fleet's edge cities in an hour.
- `X-Amz-Cf-Id`, `X-Azure-Ref`, `X-Vercel-ID`, `X-Nf-Request-Id` → an internal
  request ID that, for some vendors, is a *public lookup* of the origin.
- `Server: nginx/1.18.0 (Ubuntu)`, `X-Powered-By: PHP/7.4.3` → CVE shopping list.
- `Set-Cookie: session=…` without `Secure`/`HttpOnly`/`SameSite` → this is how an
  "IP leak" story usually turns into a "session hijack" story, via XSS + no CSP.
- `Access-Control-Allow-Origin: *` with `Allow-Credentials: true` → other people's
  browsers, other people's data.
- HTML comments, sourcemaps, `/.git/`, `/vendor/debug` → "who hosts this" is often
  answered by a `.env.bak` with the SSH key path in it.

## 2.4 The leak you can cause against yourself (and why canaries work)

SSRF is the real-world version of "the hacker saw my IP": your *own* server
fetches a user-supplied URL, and the fetch arrives at your listener with the
*server's* address, not the client's. Two consequences:

1. An attacker validating "is this URL reachable" against you can learn your egress
   IP, and by following redirects to `169.254.169.254` or `localhost:*`, your cloud
   metadata and internal ports.
2. Anyone who can get a server to load one image reads the IP of the *server*, which
   is why "IP leak" links posted in issue trackers reveal infrastructure, not people.

The canary in Module 5 demonstrates exactly this asymmetry from your side, with a
consent ledger attached, because the same code is a diagnostic and a stalking tool.

## 2.5 Answers to exercises 3 and 5

**Ex. 3** — two lines that fix it:
`real_ip_header CF-Connecting-IP;` + `set_real_ip_from <only your proxy ranges>;`
(and no `real_ip_recursive` with an empty `set_real_ip_from`, which is how you end
up trusting the client's word). Also strip inbound `X-Forwarded-For` at the edge.

**Ex. 5** — remove: `X-Backend-IP`, `X-Debug-Trace`, `X-Powered-By`, versioned
`Server`, `X-Amz-Cf-*` if you don't want the account mapped, the `/debug/*`
routes entirely (or bind them to an admin interface + auth), `Referrer-Policy:
unsafe-url` (default to `strict-origin-when-cross-origin`), sourcemaps in prod,
and every `traceparent`/request-id that encodes a hostname.

## 2.6 Duplicate-header injection (the thing that bites people who "did everything right")

`X-Forwarded-For` is append-friendly *inside one value* (comma list) **and**
duplicated across lines, and clients control both. Two rules follow from that:

1. nginx's `real_ip_header X` uses the **last** occurrence of `X`. So if your CDN is
   configured to *append* rather than *set*, or you forgot to strip the inbound header,
   `curl -H 'CF-Connecting-IP: 8.8.8.8' -H 'CF-Connecting-IP: 1.1.1.1'` lets you
   choose what the origin believes, *even with a correct trust list*.
2. `get_all()`/`http_x_forwarded_for`-style joins: a proxy that copies
   `$http_x_forwarded_for` collapses the duplicates into one comma list and thereby
   *legitimises* the attacker's values, because they are now left of yours.

Verified on this repo's target (`--mode cloudflare --trusted-proxy 127.0.0.0/8`, i.e.
a peer that passes verification):

```
one header : -H 'CF-Connecting-IP: 8.8.8.8'                                  -> logged 8.8.8.8
two headers: -H 'CF-Connecting-IP: 8.8.8.8' -H 'CF-Connecting-IP: 1.1.1.1'    -> logged 1.1.1.1
               reason: "... from verified proxy (DUPLICATED HEADER - the CDN did not strip inbound CF-Connecting-IP)"
```

Defences, in order of strength: **mTLS between edge and origin** (kills the whole
class); a signed header the origin verifies (`True-Client-IP` + key, or your own
`X-Lab-Signature: hmac(ip|ts|nonce)`); strip-then-set at the outermost hop
(`proxy_set_header CF-Connecting-IP $http_cf_connecting_ip` is a bug — set it to a
computed value, never copy); reject requests carrying a duplicate of any
identity-bearing header at the edge (400, log it); and if you log a claim, log *which*
occurrence it came from. `tools/selftest.py` has four checks pinning this behaviour, so
if you refactor it away the tests will tell you.
