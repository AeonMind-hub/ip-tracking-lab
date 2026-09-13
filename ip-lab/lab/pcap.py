"""
Module 7a - a *tiny* pcap writer + reader in pure standard library.

Why hand-rolled instead of scapy: so you are forced to look at the bytes once.
The "magic number" at offset 0 is the single fastest way to know what a capture
file even is, and the per-packet header (ts, captured length, wire length) is
why truncations and interface offload (TSO/LRO) make naive analysis lie to you.

Global header (24 bytes, little-endian unless magic says otherwise):
  magic(4) ver_major(2) ver_minor(2) thiszone(4) sigfigs(4) snaplen(4) network(4)
Per-packet header (16 bytes): ts_sec ts_usec incl_len orig_len, then the bytes.
"""
from __future__ import annotations

import socket
import struct

PCAP_MAGIC = 0xA1B2C3D4          # microseconds, native byte order
LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL = 113          # "cooked", what `tcpdump -i any` writes


# --------------------------------------------------------------- constructors
def eth(src: bytes, dst: bytes, typ: int = 0x0800, payload: bytes = b"") -> bytes:
    return dst + src + struct.pack("!H", typ) + payload


def arp(sha: bytes, spa: str, tha: bytes, tpa: str, op: int = 1) -> bytes:
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + sha + socket.inet_aton(spa) + tha + socket.inet_aton(tpa)


def ipv4(total_len: int, proto: int, src: str, dst: str, ttl: int = 64, payload: bytes = b"",
         frag_off: int = 0, ident: int = 0x1234, flags: int = 0x40, tos: int = 0) -> bytes:
    """flags=0x40 -> don't fragment. `frag_off` carries MF bit + offset/8."""
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, tos, 20 + total_len, ident, frag_off, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    # checksum deliberately zero: readers must not trust it, writers must recompute
    return hdr + payload


def tcp(sport: int, dport: int, seq: int, ack: int, flags: int, window: int = 64240,
        payload: bytes = b"", urgent: int = 0) -> bytes:
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, (5 << 4), flags, window, urgent, 0)
    return hdr + payload


# flags
FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


# --------------------------------------------------------------- writer
class PcapWriter:
    def __init__(self, path: str, snaplen: int = 65535, network: int = LINKTYPE_ETHERNET):
        self.fh = open(path, "wb")
        self.fh.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, snaplen, network))
        self.n = 0

    def write(self, frame: bytes, sec: float, usec: int = 0, wire_len: int | None = None) -> None:
        """wire_len differs from len(frame) when the capture was truncated."""
        if isinstance(sec, float):
            sec, usec = int(sec), int(round((sec - int(sec)) * 1e6)) % 1_000_000
        self.fh.write(struct.pack("<IIII", sec, usec, len(frame), wire_len or len(frame)) + frame)
        self.n += 1

    def close(self) -> None:
        self.fh.close()


# --------------------------------------------------------------- reader
def read_pcap(path: str):
    """Yield (sec, usec, incl_len, orig_len, linktype, frame). Pure stdlib."""
    with open(path, "rb") as fh:
        head = fh.read(24)
        if len(head) < 24:
            raise ValueError("too short to be a pcap")
        magic = struct.unpack("<I", head[:4])[0]
        if magic == PCAP_MAGIC:
            endian = "<"
        elif magic == 0xD4C3B2A1:
            endian = ">"
        else:
            raise ValueError(f"not a libpcap file (magic 0x{magic:08x}); pcapng uses 0a0d0d0a - use tshark")
        _, _, _, _, snaplen, network = struct.unpack(endian + "HHIIII", head[4:])
        while True:
            ph = fh.read(16)
            if len(ph) < 16:
                return
            sec, usec, incl, orig = struct.unpack(endian + "IIII", ph)
            frame = fh.read(incl)
            if len(frame) < incl:
                return
            yield sec, usec, incl, orig, network, frame


def parse_ip(frame: bytes, linktype: int = LINKTYPE_ETHERNET) -> dict:
    """Decode just far enough to build flow records. Returns {} on non-IP."""
    off = 10 if linktype == LINKTYPE_LINUX_SLL else 14
    if linktype == LINKTYPE_ETHERNET:
        etype = struct.unpack("!H", frame[12:14])[0]
        if etype == 0x0806:
            a = struct.unpack("!HHBBH", frame[14:22])   # htype2+proto2+hlen1+plen1+oper2 = 8 bytes
            # absolute offsets: eth 14 | htype 2 | proto 2 | hlen 1 | plen 1 | oper 2 | SHA 6 | SPA 4 | THA 6 | TPA 4
            sha, spa = frame[22:28], socket.inet_ntoa(frame[28:32])
            tha, tpa = frame[32:38], socket.inet_ntoa(frame[38:42])
            return {"proto": "arp", "op": a[4], "sha": ":".join(f"{b:02x}" for b in sha), "spa": spa,
                    "tha": ":".join(f"{b:02x}" for b in tha), "tpa": tpa}
        if etype != 0x0800:
            return {}
    ip = frame[off:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return {}
    ihl = (ip[0] & 0x0F) * 4
    total, ident, fragoff = struct.unpack("!HHH", ip[2:8])
    ttl, proto_n = ip[8], ip[9]
    src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
    out = {"proto": {6: "tcp", 17: "udp", 1: "icmp"}.get(proto_n, str(proto_n)), "src": src, "dst": dst,
           "ttl": ttl, "ip_ident": ident, "ip_flags": fragoff >> 13, "frag_off": (fragoff & 0x1FFF) * 8,
           "total_len": total, "ihl": ihl}
    l4 = ip[ihl:]
    if proto_n in (6, 17) and len(l4) >= 4:
        sp, dp = struct.unpack("!HH", l4[:4])
        out["sport"], out["dport"] = sp, dp
        if proto_n == 6 and len(l4) >= 20:
            seq, ack = struct.unpack("!II", l4[4:12])
            data_off, flags = (l4[12] >> 4), l4[13]
            win = struct.unpack("!H", l4[14:16])[0]
            out.update(seq=seq, acknum=ack, flags=flags, window=win,
                       payload=l4[data_off * 4:], tcphdr_len=data_off * 4)
        else:
            out["payload"] = l4[8:]
    elif proto_n == 1 and len(l4) >= 8:
        out["icmp_type"], out["icmp_code"] = l4[0], l4[1]
        out["payload"] = l4[8:]     # the original IP header + 8 bytes, i.e. what a TTL-expiry shows you
    return out


FLAGS_NAMES = {0x02: "SYN", 0x10: "ACK", 0x12: "SYN-ACK", 0x18: "PSH-ACK", 0x11: "FIN-ACK",
               0x14: "RST-ACK", 0x04: "RST", 0x01: "FIN"}


def flagstr(flags: int) -> str:
    if flags in FLAGS_NAMES:
        return FLAGS_NAMES[flags]
    names = [n for b, n in (("FIN", FIN), ("SYN", SYN), ("RST", RST), ("PSH", PSH), ("ACK", ACK), ("URG", URG)) if flags & b]
    return "|".join(names) or hex(flags)


def reassemble(pcap_path: str, peer_ip: str, dport: int | None = None,
               max_flows: int = 4) -> list[dict]:
    """
    Concatenate TCP payloads per flow touching `peer_ip` (either direction), then
    split HTTP requests out of it. Naive on purpose - real reassembly has to deal
    with out-of-order segments, retransmits and window stalls; knowing that this
    version is naive is exactly the point.
    """
    buf: dict[str, bytearray] = {}
    meta: dict[str, dict] = {}
    for sec, usec, incl, orig, linktype, frame in read_pcap(pcap_path):
        p = parse_ip(frame, linktype)
        if not p or p.get("proto") != "tcp":
            continue
        if p["src"] != peer_ip and p["dst"] != peer_ip:
            continue
        if dport and p.get("dport") != dport and p.get("sport") != dport:
            continue
        key = f"{p['src']}:{p['sport']}->{p['dst']}:{p['dport']}"
        buf.setdefault(key, bytearray()).extend(p.get("payload") or b"")
        m = meta.setdefault(key, {"first": sec, "last": sec, "pkts": 0})
        m["pkts"] += 1
        m["last"] = sec
    out = []
    for key, data in list(buf.items())[:max_flows]:
        reqs, rem = [], bytes(data)
        while b"\r\n\r\n" in rem[:200000]:
            head, _, rest = rem.partition(b"\r\n\r\n")
            line0 = head.split(b"\r\n", 1)[0].decode("latin-1")
            hdrs = {}
            for hl in head.split(b"\r\n")[1:]:
                k, _, v = hl.partition(b":")
                hdrs[k.decode("latin-1").lower().strip()] = v.decode("latin-1").strip()
            n = int(hdrs.get("content-length", 0) or 0)
            body, rem = rest[:n], rest[n:]
            reqs.append({"request": line0, "headers": hdrs, "body_len": len(body),
                         "body_head": body[:120].decode("latin-1", "replace")})
        out.append({"flow": key, "bytes": len(data), "requests": reqs, **meta[key]})
    return out


def flows(pcap_path: str) -> dict[str, dict]:
    """
    Reassemble per-5-tuple flow summaries. Not a full TCP stack: this is what you
    actually use in triage - byte counts, direction, SYN presence, RSTs, retransmits.
    """
    out: dict[str, dict] = {}
    for sec, usec, incl, orig, linktype, frame in read_pcap(pcap_path):
        p = parse_ip(frame, linktype)
        if not p or p.get("proto") != "tcp":
            continue
        key = f"{p['src']}:{p['sport']}->{p['dst']}:{p['dport']}"
        rev = f"{p['dst']}:{p['dport']}->{p['src']}:{p['sport']}"
        f = out.get(key)
        if f is None:
            f = out.setdefault(key, {"first": sec + usec / 1e6, "last": sec + usec / 1e6, "pkts": 0, "bytes": 0,
                                     "payload": 0, "syn": 0, "synack": 0, "fin": 0, "rst": 0,
                                     "ttl": p["ttl"], "wins": set(), "retrans": 0, "_seen_seq": set(),
                                     "reverse_seen": rev in out, "peer": rev})
        f["pkts"] += 1
        f["bytes"] += orig
        f["payload"] += len(p.get("payload") or b"")
        f["last"] = sec + usec / 1e6
        f["ttl"] = p["ttl"]
        f["wins"].add(p.get("window"))
        fl = p.get("flags", 0)
        if fl & SYN:
            f["syn"] += 1
            if fl & ACK:
                f["synack"] += 1
        if fl & FIN:
            f["fin"] += 1
        if fl & RST:
            f["rst"] += 1
        if p.get("seq") in f["_seen_seq"]:
            f["retrans"] += 1
        else:
            f["_seen_seq"].add(p.get("seq"))
        if rev in out:
            out[rev]["reverse_seen"] = True
    for f in out.values():
        f["win_sizes"] = sorted(x for x in f.pop("wins", []) if x is not None)
        f["duration"] = round(f["last"] - f["first"], 3)
        f.pop("_seen_seq", None)
    return out
