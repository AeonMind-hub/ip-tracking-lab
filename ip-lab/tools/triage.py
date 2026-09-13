#!/usr/bin/env python3
"""
Module 7 - the detection pipeline: pcap + access log -> SQLite -> rules -> alerts.

  python3 tools/triage.py                          # full run on data/lab_capture.*
  python3 tools/triage.py --pcap mine.pcap --log my_access.log --rule ssh_bruteforce
  python3 tools/triage.py --flows-only             # no rules, just the flow table
  python3 tools/triage.py --sigma                  # show the rule set (with ack procedures)

This is the shape of every real detection job: two independent sources of truth
(wire + app), a deterministic store, rules that each carry their own
false-positive list and an acknowledgement procedure.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from lab import detect as D  # noqa: E402
from lab import logs as L  # noqa: E402
from lab import pcap as K  # noqa: E402
from lab.net import human_table  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", default=os.path.join(ROOT, "data", "lab_capture.pcap"))
    ap.add_argument("--log", default=os.path.join(ROOT, "data", "lab_capture_access.log"))
    ap.add_argument("--trunc-pcap", default=os.path.join(ROOT, "data", "lab_capture_truncated.pcap"))
    ap.add_argument("--db", default=os.path.join(ROOT, "out", "triage.sqlite"))
    ap.add_argument("--rule", help="run one rule id")
    ap.add_argument("--flows-only", action="store_true")
    ap.add_argument("--sigma", action="store_true")
    ap.add_argument("--re", dest="reassemble", help="reassemble HTTP from the pcap for this IP (either direction)")
    ap.add_argument("--dport", type=int, default=None, help="restrict --re to one port")
    a = ap.parse_args()

    if a.sigma:
        for r in D.RULES:
            print(f"[{r['severity']:<6}] {r['id']}\n    {r['title']}")
            print(f"    FP: {'; '.join(r['false_positives'])}")
            print(f"    ack: {r['ack']}\n    sql: {' '.join(r['sql'].split())[:150]}...\n")
        return 0

    os.makedirs(os.path.dirname(a.db), exist_ok=True)
    if os.path.exists(a.db):
        os.remove(a.db)
    db = D.connect(a.db)

    print(f"== 1. wire: {os.path.basename(a.pcap)} ==")
    if not os.path.exists(a.pcap):
        print("   no pcap; run  python3 tools/gen_pcap.py")
        return 1
    n_pkts = sum(1 for _ in K.read_pcap(a.pcap))
    fl = K.flows(a.pcap)
    print(f"   {n_pkts} packets -> {len(fl)} flows (stdlib parser, no scapy)")
    nf = D.load_flows(db, fl)
    print(f"   loaded {nf} flow rows into {os.path.relpath(a.db, ROOT)}")

    if os.path.exists(a.trunc_pcap):
        tf = K.flows(a.trunc_pcap)
        for k, v in tf.items():
            print(f"   TRUNCATION: {k} incl={v['bytes']} payload={v['payload']} "
                  f"-> you are missing {v['bytes'] - v['payload'] - 40} bytes of the stream")
            db.execute("INSERT INTO event(flow_id,t,kind,detail) VALUES((SELECT flow_id FROM flow WHERE flow_id=?),"
                       "?,?,?)", (1, 0, "truncation", json.dumps({"flow": k, "incl": v["bytes"], "payload": v["payload"]})))

    print("\n== 2. app: top talkers by bytes / packets ==")
    rows = db.execute("""SELECT src||':'||sport||'->'||dst||':'||dport f, pkts, payload, syn, rst, retrans, ttl,
                                 ROUND(duration,2) dur FROM flow ORDER BY payload DESC LIMIT 12""").fetchall()
    print(human_table([[r[0][:40], r[1], r[2], r[3], r[4], r[5], r[6], r[7]] for r in rows],
                      ["flow", "pkts", "payload", "syn", "rst", "retrans", "ttl", "dur"]))

    print("\n== 3. the thing pcap people forget: what the SAME traffic looks like from the app ==")
    if os.path.exists(a.log):
        entries = L.parse_file(a.log)
        D.load_http(db, entries)
        sus = [e for e in entries if e.get("xff_list")]
        print(f"   {len(entries)} access-log rows joined to flows; {len(sus)} of them carry X-Forwarded-For")
        for e in entries:
            if e["path"].startswith("/login") or e.get("xff_list"):
                v = L.real_ip(e, [])   # this app has NO trusted proxy list => peer wins
                print(f"   {e['status']} {e['method']} {e['path']:<22} logged_as={e['ip']:<12} "
                      f"xff={','.join(e['xff_list']) or '-':<28} verdict={v['verdict_ip']}")
                if v["flags"]:
                    print(f"      ! {'; '.join(v['flags'])}")
    else:
        print(f"   no log at {a.log} - rules over http_req will be empty")

    if a.reassemble:
        print(f"\n== 2b. reassembly for {a.reassemble} (dport={a.dport or 'any'}) ==")
        for f in K.reassemble(a.pcap, a.reassemble, a.dport):
            print(f"   {f['flow']}  stream={f['bytes']}B  pkts={f['pkts']}  requests={len(f['requests'])}")
            for r in f["requests"][:4]:
                print(f"      {r['request']}")
                for hk in ("host", "user-agent", "cookie", "x-forwarded-for", "content-length"):
                    if hk in r["headers"]:
                        print(f"        {hk}: {r['headers'][hk][:100]}")
                if r["body_len"]:
                    print(f"        body {r['body_len']}B head={r['body_head'][:90]!r}")
            print("      note: naive concatenation - out-of-order/retransmitted segments would need "
                  "real sequence-number bookkeeping. Check 'retrans' in the flow table first.")

    if a.flows_only:
        print("\n(flows-only mode, skipping rules)")
        return 0

    print("\n== 4. rules ==")
    results = D.run_rules(db, only=a.rule)
    n_al = D.write_alerts(db, results)
    print(D.triage(db, results))

    out = os.path.join(ROOT, "out", "triage_alerts.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"pcap": os.path.basename(a.pcap), "log": os.path.basename(a.log),
                   "packets": n_pkts, "flows": len(fl), "alerts": n_al,
                   "results": results}, fh, indent=2, default=str)
    print(f"\nalerts: {n_al} written -> {os.path.relpath(out, ROOT)}")
    print(f"query it yourself:  sqlite3 {os.path.relpath(a.db, ROOT)} \"select rule,src,summary from alert\"")
    print("next: notes/07-detection.md - reassemble the exfil body from the pcap and diff it")
    print("      against what the app logged; then write your own rule for the retrans decoy.")
    return 0


if __name__ == "__main__":
    try:                            # Windows console/encoding shim; no-op elsewhere
        import sys as _sys, os as _os
        _sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "lab"))
        import win
        win.ready()
    except ImportError:
        pass
    raise SystemExit(main())
