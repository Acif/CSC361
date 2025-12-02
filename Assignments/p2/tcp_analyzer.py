#!/usr/bin/env python3
import sys
import struct
from collections import defaultdict, deque, namedtuple
from statistics import mean

# --------------------------
# PCAP parsing (no 3rd-party)
# --------------------------
PCAP_GLOBAL_HDR_FMT = "IHHIIII"
PCAP_PKT_HDR_FMT    = "IIII"

ETH_HDR_LEN = 14

def parse_pcap(path):
    """
    Yields (rel_time_seconds_float, raw_eth_frame_bytes)
    """
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            raise ValueError("Truncated pcap global header")
        magic = gh[0:4]
        # endianness
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        elif magic == b"\x4d\x3c\xb2\xa1":  # nanosecond variants
            endian = "<"
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian = ">"
        else:
            raise ValueError("Unknown pcap magic number")

        vers_major, vers_minor, thiszone, sigfigs, snaplen, network = struct.unpack(
            endian + "HHiiii", gh[4:]
        )

        first_ts = None
        while True:
            ph = f.read(16)
            if not ph:
                break
            if len(ph) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + PCAP_PKT_HDR_FMT, ph)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break

            # relative time from first packet
            if first_ts is None:
                first_ts = ts_sec + ts_usec / 1_000_000.0
            rel_t = (ts_sec + ts_usec / 1_000_000.0) - first_ts
            yield rel_t, data

# --------------------------
# IPv4 + TCP parsing helpers
# --------------------------
def is_ipv4(eth_bytes):
    if len(eth_bytes) < ETH_HDR_LEN + 1:
        return False
    ether_type = struct.unpack("!H", eth_bytes[12:14])[0]
    return ether_type == 0x0800

def parse_ipv4(eth_bytes):
    """
    Returns (ip_header_len, total_len, proto, src_ip_str, dst_ip_str, ip_payload_start)
    """
    ip_start = ETH_HDR_LEN
    b = eth_bytes
    if len(b) < ip_start + 20:
        return None
    vihl = b[ip_start]
    version = vihl >> 4
    ihl = (vihl & 0x0F) * 4
    if version != 4 or ihl < 20:
        return None
    total_len = struct.unpack("!H", b[ip_start+2:ip_start+4])[0]
    proto = b[ip_start+9]
    src = b[ip_start+12:ip_start+16]
    dst = b[ip_start+16:ip_start+20]
    src_ip = ".".join(str(x) for x in src)
    dst_ip = ".".join(str(x) for x in dst)
    payload_start = ip_start + ihl
    return ihl, total_len, proto, src_ip, dst_ip, payload_start

def parse_tcp(ip_payload_bytes):
    """
    Returns dict with fields: sport, dport, seq, ack, data_offset, flags_dict, win, payload_len
    """
    if len(ip_payload_bytes) < 20:
        return None
    sport, dport, seq, ack, off_flags, win = struct.unpack("!HHIIHH", ip_payload_bytes[:16])
    data_offset = ((off_flags >> 12) & 0xF) * 4
    flags = off_flags & 0x01FF  # lower 9 bits
    # Flags per RFC 793 order: NS CWR ECE URG ACK PSH RST SYN FIN (but many pcaps store only last 6)
    # We'll decode the usual 6: URG, ACK, PSH, RST, SYN, FIN = bits 5..0 in many stacks
    # Safer mapping for typical libpcap:
    FIN = flags & 0x001
    SYN = flags & 0x002
    RST = flags & 0x004
    PSH = flags & 0x008
    ACK = flags & 0x010
    URG = flags & 0x020
    # window
    if data_offset < 20 or len(ip_payload_bytes) < data_offset:
        return None
    payload_len = max(0, len(ip_payload_bytes) - data_offset)
    return {
        "sport": sport,
        "dport": dport,
        "seq": seq,
        "ack": ack,
        "doff": data_offset,
        "flags": {"FIN": bool(FIN), "SYN": bool(SYN), "RST": bool(RST), "PSH": bool(PSH), "ACK": bool(ACK), "URG": bool(URG)},
        "win": win,
        "payload_len": payload_len,
    }

# --------------------------
# Connection tracking
# --------------------------
ConnKey = namedtuple("ConnKey", ["src", "sport", "dst", "dport"])

class ConnStats:
    __slots__ = (
        "initiator", "responder",
        "syn_count", "fin_count", "has_rst",
        "first_syn_time", "last_fin_time",
        "pkts_fwd", "pkts_rev",
        "bytes_fwd", "bytes_rev",
        "win_values",  # list of all advertised window values (both sides)
        "saw_data_after_fin",  # if any data after any FIN
        "preexisting",  # first segment was not SYN
        "rtt_samples",  # list of RTT floats (sec)
        # RTT matching state
        "_inflight_by_side",
    )

    def __init__(self, initiator, responder, first_was_syn):
        self.initiator = initiator
        self.responder = responder
        self.syn_count = 1 if first_was_syn else 0
        self.fin_count = 0
        self.has_rst = False
        self.first_syn_time = None
        self.last_fin_time = None
        self.pkts_fwd = 0
        self.pkts_rev = 0
        self.bytes_fwd = 0
        self.bytes_rev = 0
        self.win_values = []
        self.saw_data_after_fin = False
        self.preexisting = not first_was_syn
        self.rtt_samples = []
        # For RTT: for each side track a map from next_expected_ack_value -> first_sent_time
        self._inflight_by_side = {
            "fwd": {},  # initiator -> responder
            "rev": {},  # responder -> initiator
        }

    def status_string(self):
        s = f"S{self.syn_count}F{self.fin_count}"
        if self.has_rst:
            s += " R"
        return s

    def is_complete(self):
        return self.syn_count >= 1 and self.fin_count >= 1

    def register_packet(self, t, direction, tcp, is_synack=False, is_first_syn=False):
        # Count SYN (SYN+ACK counts as SYN per spec)
        if tcp["flags"]["SYN"]:
            self.syn_count += 1
            if self.first_syn_time is None and is_first_syn:
                self.first_syn_time = t

        # FIN bookkeeping
        if tcp["flags"]["FIN"]:
            self.fin_count += 1
            self.last_fin_time = t

        # RST
        if tcp["flags"]["RST"]:
            self.has_rst = True

        # Window values (advertised by sender)
        self.win_values.append(tcp["win"])

        # Packet counts and data bytes by direction
        if direction == "fwd":
            self.pkts_fwd += 1
            self.bytes_fwd += tcp["payload_len"]
        else:
            self.pkts_rev += 1
            self.bytes_rev += tcp["payload_len"]

        # Data-after-FIN detection
        if self.last_fin_time is not None and tcp["payload_len"] > 0 and t > self.last_fin_time:
            self.saw_data_after_fin = True

        # RTT estimation:
        # For a data segment with payload_len>0, we expect an ACK (ack number = seq + payload_len).
        # We record the send time keyed by expected_ack_value. On receiving such an ACK (with ACK flag),
        # if not seen before, we compute RTT = t_ack - t_send.
        if tcp["payload_len"] > 0:
            next_ack = (tcp["seq"] + tcp["payload_len"]) & 0xFFFFFFFF
            inflight = self._inflight_by_side["fwd" if direction == "fwd" else "rev"]
            # only record the first send time (ignore retransmissions)
            inflight.setdefault(next_ack, t)
        elif tcp["flags"]["ACK"]:
            # An ACK acknowledges data sent by the opposite side
            opposite = "rev" if direction == "fwd" else "fwd"
            inflight = self._inflight_by_side[opposite]
            acknum = tcp["ack"]
            # Find any keys <= acknum in modulo-32 space.
            # Approximation: check exact match first (common case).
            if acknum in inflight:
                t0 = inflight.pop(acknum)
                rtt = t - t0
                if rtt >= 0:
                    self.rtt_samples.append(rtt)
            else:
                # Optional: attempt tight match on small cumulative ACK progression
                # (kept simple—acceptable per Q&A guidance).
                pass

# --------------------------
# Driver
# --------------------------
def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} sample-capture-file.cap", file=sys.stderr)
        sys.exit(1)
    path = sys.argv[1]

    conns = {}  # key = ConnKey(initiator src, sport, responder dst, dport) as first-seen tuple
    # map to find existing connection regardless of direction
    reverse_index = {}  # (src, sport, dst, dport) -> canonical key

    first_syn_seen = set()

    for rel_t, frame in parse_pcap(path):
        if not is_ipv4(frame):
            continue  # per Q&A, ignore non-TCP/non-IPv4 :contentReference[oaicite:3]{index=3}
        ip_parsed = parse_ipv4(frame)
        if ip_parsed is None:
            continue
        ihl, ip_total_len, proto, sip, dip, ip_payload_start = ip_parsed
        if proto != 6:
            continue  # TCP only

        ip_payload = frame[ip_payload_start:ETH_HDR_LEN + ip_total_len]
        tcp = parse_tcp(ip_payload)
        if tcp is None:
            continue

        four_tuple = (sip, tcp["sport"], dip, tcp["dport"])
        rev_four_tuple = (dip, tcp["dport"], sip, tcp["sport"])

        # Is this an already-known connection (in either direction)?
        key = reverse_index.get(four_tuple)
        if key is None:
            # Maybe this is the first time we see this 4-tuple; create a new connection
            # Per assignment, identify a connection by the 4-tuple; Use the FIRST packet’s tuple as canonical,
            # and define "Source"/"Destination" as the initiator (sender of the first observed segment) and its peer.
            initiator = (sip, tcp["sport"])
            responder = (dip, tcp["dport"])
            first_was_syn = bool(tcp["flags"]["SYN"])
            key = ConnKey(sip, tcp["sport"], dip, tcp["dport"])
            conns[key] = ConnStats(initiator, responder, first_was_syn)
            reverse_index[four_tuple] = key
            reverse_index[rev_four_tuple] = key

            # record first SYN time only when this *first* packet is a SYN (per Q&A start time rule) :contentReference[oaicite:4]{index=4}
            if first_was_syn:
                conns[key].first_syn_time = rel_t

        # Determine direction relative to canonical initiator/responder
        cs = conns[key]
        if (sip, tcp["sport"]) == cs.initiator:
            direction = "fwd"  # initiator → responder
        elif (sip, tcp["sport"]) == cs.responder:
            direction = "rev"  # responder → initiator
        else:
            # Rare pathological case (shouldn't happen with stable 4-tuples)
            direction = "fwd"

        is_first_syn = cs.first_syn_time is None and tcp["flags"]["SYN"]
        cs.register_packet(rel_t, direction, tcp, is_first_syn=is_first_syn)

    # --------------------------
    # Produce outputs
    # --------------------------
    # A) Total number of connections
    total_connections = len(conns)

    # B) Per-connection details (Source/Destination = initiator/responder of first seen packet)
    # C) General stats
    reset_connections = 0
    still_open_at_end = 0
    established_before_capture = 0
    complete_count = 0

    for key, cs in conns.items():
        if cs.has_rst:
            reset_connections += 1
        # per Q&A: a TCP connection is considered "established before capture" if its first segment is not SYN :contentReference[oaicite:5]{index=5}
        if cs.preexisting:
            established_before_capture += 1
        # "open when capture ended" (assignment/Q&A rule):
        # If a TCP connect has no data segment after FIN, consider it closed; otherwise open. :contentReference[oaicite:6]{index=6}
        if cs.saw_data_after_fin:
            still_open_at_end += 1
        if cs.is_complete():
            complete_count += 1

    # D) Aggregations over complete connections
    durations = []
    rtt_pool = []
    packets_both_dirs = []
    recv_win_values = []

    for key, cs in conns.items():
        if not cs.is_complete():
            continue
        # duration: first SYN to last FIN (ignore whether acked) :contentReference[oaicite:7]{index=7}
        if cs.first_syn_time is not None and cs.last_fin_time is not None:
            durations.append(max(0.0, cs.last_fin_time - cs.first_syn_time))
        # RTT samples
        rtt_pool.extend(cs.rtt_samples)
        # total packets
        packets_both_dirs.append(cs.pkts_fwd + cs.pkts_rev)
        # advertised recv window values
        recv_win_values.extend(cs.win_values)

    def safe_min(x): return min(x) if x else 0
    def safe_max(x): return max(x) if x else 0
    def safe_mean(x): return mean(x) if x else 0

    # Print report in required format (exact headings) :contentReference[oaicite:8]{index=8}
    # A)
    print("A) Total number of connections:")
    print(total_connections)
    print()

    # B)
    print("B) Connections' details:")
    idx = 1
    for key, cs in conns.items():
        print(f"Connection {idx}:")
        print(f"Source Address: {key.src}")
        print(f"Destination address: {key.dst}")
        print(f"Source Port: {key.sport}")
        print(f"Destination Port: {key.dport}")
        print(f"Status: {cs.status_string()}")
        if cs.is_complete():
            start_time = 0.0 if cs.first_syn_time is None else cs.first_syn_time
            end_time = 0.0 if cs.last_fin_time is None else cs.last_fin_time
            duration = max(0.0, end_time - start_time)
            print(f"Start time: {start_time:.6f} s")
            print(f"End Time: {end_time:.6f} s")
            print(f"Duration: {duration:.6f} s")
            print(f"Number of packets sent from Source to Destination: {cs.pkts_fwd}")
            print(f"Number of packets sent from Destination to Source: {cs.pkts_rev}")
            print(f"Total number of packets: {cs.pkts_fwd + cs.pkts_rev}")
            print(f"Number of data bytes sent from Source to Destination: {cs.bytes_fwd}")
            print(f"Number of data bytes sent from Destination to Source: {cs.bytes_rev}")
            print(f"Total number of data bytes: {cs.bytes_fwd + cs.bytes_rev}")
        print("END\n")
        idx += 1

    # C)
    print("C) General")
    print(f"The total number of complete TCP connections: {complete_count}")
    print(f"The number of reset TCP connections: {reset_connections}")
    print(f"The number of TCP connections that were still open when the trace capture ended: {still_open_at_end}")
    print(f"The number of TCP connections established before the capture started: {established_before_capture}")
    print()

    # D)
    print("D) Complete TCP connections:")
    print(f"Minimum time duration: {safe_min(durations):.6f} s")
    print(f"Mean time duration: {safe_mean(durations):.6f} s")
    print(f"Maximum time duration: {safe_max(durations):.6f} s")
    print(f"Minimum RTT value: {safe_min(rtt_pool):.6f} s")
    print(f"Mean RTT value: {safe_mean(rtt_pool):.6f} s")
    print(f"Maximum RTT value: {safe_max(rtt_pool):.6f} s")
    print(f"Minimum number of packets including both send/received: {safe_min(packets_both_dirs)}")
    print(f"Mean number of packets including both send/received: {safe_mean(packets_both_dirs):.6f}")
    print(f"Maximum number of packets including both send/received: {safe_max(packets_both_dirs)}")
    print(f"Minimum receive window size including both send/received: {safe_min(recv_win_values)}")
    print(f"Mean receive window size including both send/received: {safe_mean(recv_win_values):.6f}")
    print(f"Maximum receive window size including both send/received: {safe_max(recv_win_values)}")

if __name__ == "__main__":
    main()
