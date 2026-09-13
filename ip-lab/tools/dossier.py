#!/usr/bin/env python3
"""
Lab exercise: pull every source IP out of a log, build a dossier for each one,
rank them by traceability, and write a case file.

  python3 tools/dossier.py data/target_access.log
  python3 tools/dossier.py data/target_access.log --ip 45.148.10.66 --xff
  python3 tools/dossier.py data/canary.log --trusted-proxy 10.0.0.0/8
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lab import logs as L          # noqa: E402
from lab import tracer as T        # noqa: E402
from lab.net import human_table, v6_subnet    # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="offline IP attribution lab")
    ap.add_argument("logfile", nargs="?", default="data/target_access.log")
    ap.add_argument("--ip", help="only this IP")
    ap.add_argument("--xff", action="store_true", help="run the XFF trust analysis for each IP")
    ap.add_argument("--trusted-proxy", action="append", default=[], help="CIDR of YOUR proxy (repeat). None = app is exposed directly")
    ap.add_argument("--timeline", type=int, default=0, help="print N timeline lines for --ip")
    ap.add_argument("--only-sus", action="store_true", help="drop background-noise IPs: show only IPs with 4xx/5xx/scan-path/bot signals")
    ap.add_argument("--min-hits", type=int, default=1, help="hide IPs with fewer hits than this")
    ap.add_argument("--v6-rollup", action="store_true", help="collapse IPv6 hosts to their /64 -> this is what a truncating log forces on you")
    ap.add_argument("--no-net", action="store_true", help="skip RDAP/geo/DNS lookups (offline mode)")
    ap.add_argument("--out", default="out", help="directory for case files")
    args = ap.parse_args()

    path = args.logfile
    if not os.path.isabs(path):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), path)
    entries = L.parse_file(path)
    print(f"parsed {len(entries)} lines from {os.path.basename(path)}")

    summary = L.summarise(entries)
    if args.v6_rollup:
        merged = {}
        for ip, prof in summary.items():
            k = v6_subnet(ip) or ip
            if k not in merged:
                merged[k] = dict(prof, n=0, status_classes={}, _path_agg={}, ips=set(), v6=k != ip)
                merged[k]["top_paths"] = []
            m = merged[k]
            m["n"] += prof["n"]
            m["ips"].add(ip)
            for c, n in prof["status_classes"].items():
                m["status_classes"][c] = m["status_classes"].get(c, 0) + n
            agg = dict(m["top_paths"])
            for name, cnt in prof["top_paths"]:
                agg[name] = agg.get(name, 0) + cnt
            m["_path_agg"] = agg
            m["top_paths"] = sorted(agg.items(), key=lambda x: -x[1])[:8]
        summary = merged
        print("NOTE roll-up merges the first host's behaviour profile for fields other than counts, "
              "so 'interesting' flags on a rolled-up prefix are indicative, not exhaustive.")

    if args.only_sus:
        summary = {k: v for k, v in summary.items() if v["interesting"] or v["status_classes"].get("5xx", 0) or v["status_classes"].get("4xx", 0) >= 3}
    summary = {k: v for k, v in summary.items() if v["n"] >= args.min_hits}
    if args.ip:
        summary = {k: v for k, v in summary.items() if k == args.ip}
        if not summary:
            print("   IPs present:", ", ".join(sorted(L.summarise(entries))))
            return 1

    rows = []
    files = []
    for ip, prof in summary.items():
        if prof.get("v6"):
            print(f"NOTE {ip} rolls up {len(prof['ips'])} distinct hosts -> a /64 is a building, not a person. No PTR, no geo beyond prefix: attribution stops here unless the network owner kept the last 64 bits.")
        row = [ip, prof["n"], f"{prof['span_s']}s", prof["status_classes"].get("4xx", 0), prof["status_classes"].get("5xx", 0)]
        d: dict = {"ip": ip, "profile": prof}
        if prof["interesting"]:
            d["flags"] = prof["interesting"]
        if args.xff:
            evs = [e for e in entries if not e.get("malformed") and e["ip"] == ip]
            verdicts = [L.real_ip(e, args.trusted_proxy) for e in evs[:1]]
            d["xff_analysis"] = verdicts[0]
            row.append(verdicts[0]["verdict_ip"] + ("" if verdicts[0]["confidence"] == "high" else " (?)"))
        if not args.no_net and ":" not in ip:
            dossier = T.dossier(ip, log_lines=prof["n"], direct=not args.trusted_proxy)
            d["dossier"] = dossier
            g = dossier["geo"]
            r = dossier["rdap"]
            row += [g.get("org") or "?", (g.get("city") or "?") + "/" + (g.get("country") or "?"),
                    r.get("network_name") or "?",
                    f"{dossier['traceability']['traceability_score']}/100"]
        elif ":" in ip and not args.no_net:
            row += ["(v6: geo is subnet-level)", "?", "?", f"{T.traceability(ip, prof['n'])['traceability_score']}/100"]
        rows.append(row)
        files.append(d)

    headers = ["source ip", "hits", "span", "4xx", "5xx"] + (["verdict ip"] if args.xff else []) + (["org", "geo", "network", "traceable"] if not args.no_net else [])
    print()
    print(human_table(rows, headers))
    print()
    for d in sorted(files, key=lambda x: -(x.get("dossier", {}).get("traceability", {}).get("traceability_score", 0))):
        tr = d.get("dossier", {}).get("traceability")
        print(f"### {d['ip']}")
        if tr:
            print(f"    ceiling: {tr['ceiling']}")
            for n in tr["notes"]:
                print(f"      - {n}")
        if d.get("flags"):
            print(f"    behaviour: {json.dumps(d['flags'], default=str)[:400]}")
        if d.get("xff_analysis"):
            a = d["xff_analysis"]
            print(f"    xff: chain={a['xff_chain'] or 'none'} verdict={a['verdict_ip']} confidence={a['confidence']}")
            print(f"         {a['why']}")
            for fl in a["flags"]:
                print(f"         ! {fl}")
        if d.get("dossier", {}).get("rdap", {}).get("abuse_email"):
            print(f"    abuse contact (report YOUR incidents here, never to 'the owner of the human'): {d['dossier']['rdap']['abuse_email']}")
        print()

    os.makedirs(args.out, exist_ok=True)
    out_json = os.path.join(args.out, os.path.basename(path) + ".report.json")
    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump({"generated_from": path, "trusted_proxies": args.trusted_proxy, "cases": files}, fh, indent=2, default=str)
    print(f"case file written -> {out_json}")
    if args.timeline and args.ip:
        print()
        for line in L.timeline(entries, args.ip, args.timeline):
            print(line)
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
