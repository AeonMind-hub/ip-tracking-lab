"""
Module 7b - the sigma-style rule engine, in SQL over SQLite (stdlib).

Design notes (these are the real lessons, more than any rule):
  * A "rule" here is: a detection query + an acknowledgement query. Every
    detection must say how an analyst closes it (ack), otherwise your alert
    queue is a landfill.
  * Every rule carries a `false_positives` list, because a rule without known
    FPs is a rule nobody trusts.
  * Everything is deterministic and joins on `flow_id`, so an alert is
    reproducible from the pcap alone - that is what makes it evidence.
"""
from __future__ import annotations

import datetime as _dt
import json
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS flow (
  flow_id INTEGER PRIMARY KEY,
  src TEXT, sport INT, dst TEXT, dport INT,
  first REAL, last REAL, duration REAL, pkts INT, bytes INT, payload INT,
  syn INT, synack INT, fin INT, rst INT, retrans INT, ttl INT, wins TEXT
);
CREATE TABLE IF NOT EXISTS http_req (
  req_id INTEGER PRIMARY KEY,
  flow_id INT, t REAL, src TEXT, user TEXT, method TEXT, path TEXT,
  status INT, size INT, ref TEXT, ua TEXT, xff TEXT, rid TEXT
);
CREATE TABLE IF NOT EXISTS event (
  ev_id INTEGER PRIMARY KEY, flow_id INT, t REAL, kind TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS alert (
  rule TEXT, sev TEXT, t REAL, src TEXT, dst TEXT, summary TEXT, evidence TEXT
);
"""

RULES: list[dict] = [
    {
        "id": "http_auth_burst_then_success",
        "title": ">=5 auth failures then a success from one source (credential stuffing)",
        "severity": "high",
        "sql": """
          WITH f AS (SELECT src,
                            SUM(CASE WHEN status IN (401,403,429) THEN 1 ELSE 0 END) fails,
                            SUM(CASE WHEN status IN (200,302) AND path LIKE '%login%' THEN 1 ELSE 0 END) oks,
                            MIN(t) t0, MAX(t) t1
                     FROM http_req WHERE path LIKE '%login%' OR path LIKE '%/auth%'
                     GROUP BY src)
          SELECT src, fails, oks, t0, t1, ROUND(t1-t0,1) span FROM f
          WHERE fails >= 5 AND oks >= 1 AND (t1-t0) < 1800
        """,
        "false_positives": ["kiosk/TV apps with a saved stale password",
                            "CI runners re-authenticating after token rotation",
                            "one office behind CGNAT (fails from 30 different humans)"],
        "ack": "for the winning session id, check MFA step-up, device fingerprint and IP continuity "
               "before calling it an ATO; then rotate, don't just block.",
    },
    {
        "id": "port_sweep_single_source",
        "title": "one source touching many ports on one host in a short window",
        "severity": "medium",
        "sql": """
          SELECT src, dst, COUNT(DISTINCT dport) ports, COUNT(*) pkts, MAX(rst) rst,
                 CASE WHEN src GLOB '10.*' OR src GLOB '192.168.*' OR src GLOB '127.*'
                      THEN 'own infra - likely a false positive' ELSE 'external' END AS classify
          FROM flow GROUP BY src, dst HAVING ports >= 10 AND classify = 'external'
        """,
        "false_positives": ["load balancer health checks to a node pool",
                            "service mesh sidecar probes", "monitoring (Zabbix/Prometheus blackbox)"],
        "ack": "confirm the source is not your own infra; a sweep is reconnaissance, "
               "not a compromise - the follow-up request is the story.",
    },
    {
        "id": "ssh_bruteforce",
        "title": "repeated short SSH sessions from one source (no successful interactive byte volume)",
        "severity": "high",
        "sql": """
          SELECT src, COUNT(*) conns, SUM(payload) payload, MAX(ttl) ttl, MIN(first) t0
          FROM flow WHERE dport = 22 GROUP BY src
          HAVING conns >= 8 AND SUM(payload) < 4000
        """,
        "false_positives": ["a script retrying with a rotated key", "git-over-ssh CI with host-key churn",
                            "your own fail2ban restarting sessions"],
        "ack": "check auth.log for the same timestamps; if any 'Accepted' line pairs with a "
               "new authorized_keys mtime, that's an intrusion, not noise.",
    },
    {
        "id": "egress_anomaly",
        "title": "one flow sending far more than it received to an external address (exfil shape)",
        "severity": "high",
        "sql": """
          SELECT f.src, f.dst, f.dport, f.payload sent, COALESCE(r.payload,0) received,
                 ROUND(1.0*f.payload/NULLIF(COALESCE(r.payload,1),0),1) ratio, f.first t
          FROM flow f LEFT JOIN flow r
            ON r.src=f.dst AND r.dst=f.src AND r.dport=f.sport AND r.flow_id>f.flow_id
          WHERE f.payload > 200000
            AND f.payload > 20*COALESCE(r.payload,1)
            AND f.dst NOT IN ('10.0.0.1','127.0.0.1')
            AND f.dport NOT IN (443,80)
        """,
        "false_positives": ["backups/replication to a storage endpoint on a nonstandard port",
                            "video/rtc streams", "a big API response your client requested"],
        "ack": "correlate with process accounting (auditd/execve) and the credential that "
               "authenticated; size alone is never proof.",
    },
    {
        "id": "ttl_outlier_source",
        "title": "same source seen at inconsistent TTLs (tunnel/proxy chain or spoofed-looking traffic)",
        "severity": "low",
        "sql": """
          SELECT src, COUNT(DISTINCT ttl) ttls, GROUP_CONCAT(DISTINCT ttl) list, COUNT(*) flows
          FROM flow GROUP BY src HAVING ttls >= 2 AND flows >= 3
        """,
        "false_positives": ["anycast/multipath routing", "mobile handover (Wi-Fi -> LTE changes hops)",
                            "a cloud provider's ECMP"],
        "ack": "TTL differences are a hint about the path, NOT about the person. Never put this "
               "in a report as attribution - only as 'source may be proxied'.",
    },
    {
        "id": "http_500_after_probe",
        "title": "probe path returned a server error (a bug got found)",
        "severity": "high",
        "sql": """
          SELECT src, path, status, t FROM http_req
          WHERE status >= 500 AND (path LIKE '%.env%' OR path LIKE '%debug%' OR path LIKE '%.git%'
                                   OR path LIKE '%admin%' OR path LIKE '%phpmyadmin%')
        """,
        "false_positives": ["a crawler hitting a genuinely broken route", "synthetic monitoring"],
        "ack": "read the response body: a traceback means paths, versions and often secrets "
               "left the building - treat as a disclosure incident, not a scan.",
    },
    {
        "id": "spoofed_forwarded_header",
        "title": "client-supplied X-Forwarded-For on a server that is not behind a proxy",
        "severity": "medium",
        "sql": """
          SELECT src, COUNT(*) n, GROUP_CONCAT(DISTINCT xff) claims FROM http_req
          WHERE xff IS NOT NULL AND xff != '' AND xff != '-' GROUP BY src
        """,
        "false_positives": ["you actually are behind a proxy and the log is right and your config doc is wrong",
                            "a legit app using XFF for internal routing"],
        "ack": "if any decision (rate limit, blocklist, geo gate, audit trail) consumed that field, "
               "it was attacker-controlled: enumerate every consumer, then fix the config.",
    },
    {
        "id": "truncated_capture",
        "title": "captured length < wire length (your -s/snaplen is hiding evidence)",
        "severity": "medium",
        "sql": """
          SELECT 'flows truncated' k, COUNT(*) n FROM event WHERE kind='truncation'
        """,
        "false_positives": ["intentional size-limited capture to keep disk usage sane"],
        "ack": "re-run with -s 0 if the payload matters, or capture on a SPAN/TAP you control; "
               "state the truncation in the report or it will be read as a cover-up.",
    },
    {
        "id": "retrans_burst",
        "title": "retransmission burst on a long-lived flow (MTU blackhole, tunnel, or lossy link)",
        "severity": "low",
        "sql": """
          SELECT src, dst, dport, MAX(retrans) retrans, MAX(duration) dur FROM flow
          GROUP BY src,dst,dport HAVING retrans >= 3
        """,
        "false_positives": ["Wi-Fi congestion", "a VPN with a mistuned MTU (classic: 1280 on IPv6 tunnels)"],
        "ack": "compare MSS/PMTU before blaming 'attackers'; half of all 'we're under attack' tickets "
               "are a broken MTU.",
    },
    # ---- the four "someone is trying to be quiet" rules -------------------------------
    # These exist because stealth is a *statistical* claim: you do not catch a careful
    # operator by matching a signature, you catch them by noticing the distribution is
    # wrong. Read each rule's false_positives first - they are all boring on purpose.
    {
        "id": "low_and_slow_port_probe",
        "title": "one source, many ports, minutes between probes (deliberately slow scan)",
        "severity": "medium",
        "sql": """
          SELECT src, COUNT(DISTINCT dport) ports, ROUND(MAX(last)-MIN(first),0) span_seconds,
                 CAST(MAX(last)-MIN(first) AS INT) / MAX(1, COUNT(DISTINCT dport)) AS seconds_per_port,
                 SUM(pkts) pkts, SUM(payload) payload
          FROM flow WHERE syn > 0 AND dst = (SELECT dst FROM flow GROUP BY dst ORDER BY COUNT(*) DESC LIMIT 1)
          GROUP BY src
          HAVING ports >= 6 AND span_seconds >= 600 AND seconds_per_port <= 600 AND payload <= 4000
        """,
        "false_positives": ["internal vulnerability scanners on a throttled schedule (they declare themselves - check the source against the scanner inventory)",
                            "uptime/monitoring probing a health port repeatedly",
                            "a laptop on a flaky link retrying one service, seen as many short flows"],
        "ack": "correlate the source's ASN/netname (lab/tracer.py) and check whether ANY of those ports answered; "
               "a scan that got zero SYN/ACKs is recon, not exploitation - respond with rate limiting, not panic.",
    },
    {
        "id": "uniform_cadence_automation",
        "title": "request intervals too regular for a human (missing jitter)",
        "severity": "medium",
        "sql": """
          WITH g AS (SELECT src, t - LAG(t) OVER (PARTITION BY src ORDER BY t) AS gap,
                            COUNT(*) OVER (PARTITION BY src) AS n
                     FROM http_req),
               st AS (SELECT src, n, AVG(gap) mean_gap,
                             MAX(gap*gap) - AVG(gap)*AVG(gap) AS var_loose
                      FROM g WHERE gap IS NOT NULL GROUP BY src HAVING COUNT(*) >= 12)
          SELECT src, n, ROUND(mean_gap,3) mean_gap_seconds,
                 ROUND(SQRT(MAX(0.0, var_loose)) / MAX(mean_gap, 0.001), 3) cv
          FROM st WHERE mean_gap BETWEEN 0.2 AND 30 AND
                        SQRT(MAX(0.0, var_loose)) / MAX(mean_gap, 0.001) < 0.12
        """,
        "false_positives": ["polling clients and SPA dashboards (they are also uniform - this is the point: uniformity is not proof of malice)",
                            "CI/CD status checks, mobile apps refreshing a token",
                            "load tests you forgot were running"],
        "ack": "look at what the cadence *does*: uniform + enumerating ids/paths = scraping or fuzzing; uniform + hitting one endpoint = a client library. "
               "Then check JA3/UA/cookie continuity before calling it hostile.",
    },
    {
        "id": "distributed_credential_stuffing",
        "title": "many source addresses, one account (per-IP blocking is defeated)",
        "severity": "high",
        "sql": """
          SELECT COALESCE(NULLIF(user,''),'-') AS account, path, COUNT(DISTINCT src) srcs,
                 SUM(CASE WHEN status IN (401,403,429) THEN 1 ELSE 0 END) fails,
                 ROUND(MAX(t)-MIN(t),0) span_seconds
          FROM http_req WHERE path LIKE '%login%' OR path LIKE '%auth%' OR path LIKE '%signin%'
          GROUP BY account, path
          HAVING srcs >= 5 AND fails >= 5 AND (MAX(t)-MIN(t) < 3600)
        """,
        "false_positives": ["a shared family/office NAT where several people mistype the same shared account",
                            "one user roaming across mobile/Wi-Fi (their addresses differ, their session does not)",
                            "an enterprise SSO gateway whose egress pool rotates"],
        "ack": "switch the key from IP to identity: check MFA prompts, device fingerprint and session continuity for that account, "
               "then force a password reset + step-up - blocking addresses here does nothing.",
    },
    {
        "id": "logging_gap_on_http_flow",
        "title": "an HTTP-port flow stayed open with zero logged requests (silent or disabled logging)",
        "severity": "high",
        "sql": """
          SELECT f.src, f.dst, f.dport, ROUND(f.duration,0) silent_seconds, f.pkts, f.syn, f.rst
          FROM flow f
          WHERE f.dport IN (80, 443, 8080, 8085, 8443) AND f.duration >= 300
            AND NOT EXISTS (SELECT 1 FROM http_req h WHERE h.flow_id = f.flow_id)
          ORDER BY f.duration DESC LIMIT 25
        """,
        "false_positives": ["idle keep-alive connections a browser held open",
                            "SSE / websocket / long-polling sessions that never issue a second request on that socket",
                            "health checks and port-forwarded tunnels (kubectl port-forward is exactly this shape)",
                            "and yes: rsyslog/nginx dying, a full disk, or log_format being changed mid-incident"],
        "ack": "check the collector, not the packet: is access_log still enabled and pointing where the shipper reads? "
               "compare file mtime + rotation state against the flow window, then look for `nginx -s reopen`, "
               "`systemctl stop rsyslog`, `wevtutil cl` and truncations around the same minute - those ARE the detection, on the host.",
    },
    {
        "id": "beacon_periodicity",
        "title": "outbound connections on a fixed period with only light jitter (implant check-in shape)",
        "severity": "high",
        # One row per (src, dst, dport). `redials` is COUNT(distinct sport) over rows that HAVE a
        # previous connection, so it is one fewer than the total - the first connection has no gap.
        # cv_squared = variance/mean^2 is the jitter ratio without needing sqrt(): the classic
        # beacon signature is "a period you could set an alarm by", typically 0.01-0.15.
        "sql": """
          WITH g AS (SELECT src, dst, dport, sport, first, payload,
                            first - LAG(first) OVER (PARTITION BY src, dst, dport ORDER BY first) gap
                     FROM flow),
               s AS (SELECT src, dst, dport, COUNT(DISTINCT sport) redials,
                            MIN(first) t0, MAX(first) t1, SUM(payload) payload,
                            AVG(gap) mean_g, AVG(gap*gap) - AVG(gap)*AVG(gap) var_g
                     FROM g WHERE gap IS NOT NULL GROUP BY src, dst, dport)
          SELECT src, dst, dport, redials, ROUND(t1-t0,1) span, ROUND(mean_g,1) mean_gap,
                 ROUND(var_g/(mean_g*mean_g),3) cv_squared, payload
          FROM s
          WHERE redials >= 4 AND mean_g BETWEEN 15 AND 900
            AND var_g < 0.07 * mean_g * mean_g AND payload < 200000
          ORDER BY mean_gap
        """,
        "false_positives": ["cron/systemd timers hitting an API on a round interval (the #1 FP - look at the user-agent)",
                            "mobile push keep-alives and MDM enrollment pings (a *fleet* doing it is normal; one host doing it is not)",
                            "metrics/telemetry agents, license servers, backup daemons, health checks",
                            "NTP-ish or polling UI polling a status endpoint at a fixed rate"],
        "ack": "two questions decide it: is the destination reputation-relevant (new domain, bulletproof hoster, "
               "DGA-looking label, TLS cert issued days ago), and does the *process* on the host have any reason "
               "to talk to it? Then check whether the period survives reboot and whether the payload size is "
               "constant - a config change moving the interval by a round number is the confession.",
    },
    {
        "id": "session_split_brain",
        "title": "one session id used from two addresses AND two client profiles (stolen cookie replayed)",
        "severity": "high",
        # Session-cloning detection: the token is valid, so nothing else fires. What gives it
        # away is that the *same* principal is in two places at once with two different clients.
        "sql": """
          WITH s AS (SELECT substr(path, instr(path, 'sid=') + 4) sid, src, ua,
                            MIN(t) t0, MAX(t) t1, COUNT(*) hits
                     FROM http_req WHERE path LIKE '%sid=%'
                     GROUP BY sid, src, ua),
               g AS (SELECT sid, COUNT(DISTINCT src) ips, COUNT(DISTINCT ua) uas, SUM(hits) hits,
                            MIN(t0) t0, MAX(t1) t1,
                            group_concat(DISTINCT src) srcs, group_concat(DISTINCT ua) uas_l
                     FROM s GROUP BY sid)
          SELECT sid, ips, uas, hits, ROUND(t1-t0,1) span, srcs, uas_l FROM g
          WHERE ips >= 2 AND uas >= 2
          ORDER BY hits DESC
        """,
        "false_positives": ["a corporate NAT where two humans share an egress IP but keep one shared session (kiosk, lab cart, smart TV)",
                            "an app that reuses one service token across an iOS/Android pair by design",
                            "vpn-or-egress IP change mid-session on the *same* device - that is why both ips and uas must move",
                            "this rule parses `sid=` out of the path, which is deliberately naive; on a real stack key it on the session cookie column, not the URL"],
        "ack": "treat it as an ATO until disproved: pull the step-up/MFA events for that principal, compare the "
               "two device profiles (does one look scripted?), then revoke the session - not just block the IP - "
               "and check whether the second profile performed a password or recovery-contact change in the same window.",
    },
]


def connect(path: str) -> sqlite3.Connection:
    db = sqlite3.connect(path)
    db.executescript(SCHEMA)
    return db


def load_flows(db: sqlite3.Connection, flows: dict) -> int:
    n = 0
    for key, f in flows.items():
        src, _, dst = key.partition("->")
        s, sp = src.rsplit(":", 1)
        d, dp = dst.rsplit(":", 1)
        db.execute("INSERT INTO flow(src,sport,dst,dport,first,last,duration,pkts,bytes,payload,syn,synack,"
                   "fin,rst,retrans,ttl,wins) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (s, int(sp), d, int(dp), f["first"], f["last"], f["duration"], f["pkts"], f["bytes"],
                    f["payload"], f["syn"], f["synack"], f["fin"], f["rst"], f["retrans"], f["ttl"],
                    json.dumps(f.get("win_sizes", []))))
        n += 1
    db.commit()
    return n


def load_http(db: sqlite3.Connection, entries: list[dict]) -> int:
    """Insert parsed access-log rows, joined to the flow that carries them."""
    for e in entries:
        t = e["dt"].timestamp() if e.get("dt") else 0.0
        fid = db.execute("SELECT flow_id FROM flow WHERE src=? AND dport=80 ORDER BY first LIMIT 1",
                         (e["ip"],)).fetchone()
        db.execute("INSERT INTO http_req(flow_id,t,src,user,method,path,status,size,ref,ua,xff) "
                   "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                   (fid[0] if fid else None, t, e["ip"], e.get("user"), e.get("method"), e.get("path"),
                    e["status"], e.get("size"), e.get("ref"), e.get("ua"), e.get("xff") or "-"))
    db.commit()
    return len(entries)


def run_rules(db: sqlite3.Connection, only: str | None = None) -> list[dict]:
    out = []
    for rule in RULES:
        if only and rule["id"] != only:
            continue
        try:
            cur = db.execute(rule["sql"])
            cols = [d[0] for d in cur.description] if cur.description else []
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        except sqlite3.Error as exc:
            out.append({"rule": rule["id"], "error": f"{type(exc).__name__}: {exc}", "hits": []})
            continue
        out.append({**{k: rule[k] for k in ("id", "title", "severity", "false_positives", "ack")},
                    "hits": rows, "count": len(rows)})
    db.commit()
    return out


def write_alerts(db: sqlite3.Connection, results: list[dict]) -> int:
    n = 0
    for r in results:
        for hit in r["hits"]:
            src = hit.get("src") or hit.get("k") or "-"
            dst = hit.get("dst") or "-"
            t = hit.get("t") or hit.get("t0")
            ts = _dt.datetime.fromtimestamp(t, _dt.timezone.utc).isoformat() if isinstance(t, (int, float)) else "-"
            db.execute("INSERT INTO alert(rule,sev,t,src,dst,summary,evidence) VALUES(?,?,?,?,?,?,?)",
                       (r["id"], r["severity"], ts, src, dst, r["title"][:120], json.dumps(hit, default=str)))
            n += 1
    db.commit()
    return n


def triage(db: sqlite3.Connection, results: list[dict]) -> str:
    """The analyst's answer sheet: what fired, what it excludes, how you close it."""
    lines = []
    fired = [r for r in results if r.get("count")]
    quiet = [r for r in results if not r.get("count")]
    lines.append(f"{len(fired)}/{len(RULES)} rules fired")
    for r in sorted(fired, key=lambda x: {"high": 0, "medium": 1, "low": 2}[x["severity"]]):
        lines.append(f"\n[ALERT] {r['id']}  ({r['severity']})  hits={r['count']}")
        lines.append(f"        {r['title']}")
        for h in r["hits"][:5]:
            lines.append(f"        · {json.dumps(h, default=str)[:170]}")
        if len(r["hits"]) > 5:
            lines.append(f"        · … {len(r['hits']) - 5} more")
        lines.append(f"        before you escalate, rule out: {'; '.join(r['false_positives'])}")
        lines.append(f"        ack procedure: {r['ack']}")
    if quiet:
        lines.append("\nno hits for: " + ", ".join(r["id"] for r in quiet))
    return "\n".join(lines)
