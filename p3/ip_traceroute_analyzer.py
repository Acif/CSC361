#!/usr/bin/env python3
"""
IP Traceroute Analyzer
CSC 361 Assignment 3
"""

import struct
import sys
from collections import defaultdict
from typing import Dict, List, Tuple, Set, Optional
import math


# Constants
TRACEROUTE_PORT_MIN = 33434
TRACEROUTE_PORT_MAX = 33529
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_TIME_EXCEEDED = 11
ICMP_DEST_UNREACHABLE = 3
PROTOCOL_ICMP = 1
PROTOCOL_UDP = 17


class IPPacket:
    """Represents an IP packet with relevant fields"""
    
    def __init__(self, data: bytes, timestamp: float):
        self.timestamp = timestamp
        self.data = data
        self.parse_ip_header()
        
    def parse_ip_header(self):
        """Parse IP header fields"""
        # Validate minimum packet size (Ethernet + IP header)
        if len(self.data) < 34:
            raise ValueError("Packet too small for IP header")
        
        # IP header starts at offset 14 (after Ethernet header)
        ip_header = self.data[14:34]
        
        # Unpack IP header
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        
        version_ihl = iph[0]
        self.version = version_ihl >> 4
        self.ihl = version_ihl & 0xF
        self.tos = iph[1]
        self.total_length = iph[2]
        self.identification = iph[3]
        
        # Flags and fragment offset
        flags_fragoffset = iph[4]
        self.flags = flags_fragoffset >> 13
        self.fragment_offset = flags_fragoffset & 0x1FFF
        self.mf_flag = (self.flags & 0x1) != 0  # More Fragments flag
        self.df_flag = (self.flags & 0x2) != 0  # Don't Fragment flag
        
        self.ttl = iph[5]
        self.protocol = iph[6]
        self.checksum = iph[7]
        self.src_ip = self.ip_to_string(iph[8])
        self.dst_ip = self.ip_to_string(iph[9])
        
        # Calculate header length in bytes
        self.header_length = self.ihl * 4
        
        # Parse protocol-specific data
        self.payload_start = 14 + self.header_length
        
        if self.protocol == PROTOCOL_ICMP:
            self.parse_icmp()
        elif self.protocol == PROTOCOL_UDP:
            self.parse_udp()
    
    def parse_icmp(self):
        """Parse ICMP header"""
        icmp_start = self.payload_start
        if len(self.data) < icmp_start + 8:
            self.icmp_type = None
            return
            
        icmp_header = self.data[icmp_start:icmp_start + 8]
        icmp_data = struct.unpack('!BBHHH', icmp_header)
        
        self.icmp_type = icmp_data[0]
        self.icmp_code = icmp_data[1]
        self.icmp_checksum = icmp_data[2]
        self.icmp_id = icmp_data[3]
        self.icmp_seq = icmp_data[4]
        
        # For ICMP error messages (type 11, type 3), extract original packet info
        if self.icmp_type == ICMP_TIME_EXCEEDED or self.icmp_type == ICMP_DEST_UNREACHABLE:
            self.parse_icmp_error()
    
    def parse_icmp_error(self):
        """Parse the original IP header included in ICMP error message"""
        # ICMP error message contains original IP header + 64 bits of original data
        # Skip ICMP header (8 bytes)
        orig_ip_start = self.payload_start + 8
        
        if len(self.data) < orig_ip_start + 20:
            self.orig_protocol = None
            return
        
        # Parse original IP header
        orig_ip_header = self.data[orig_ip_start:orig_ip_start + 20]
        orig_iph = struct.unpack('!BBHHHBBH4s4s', orig_ip_header)
        
        self.orig_protocol = orig_iph[6]
        self.orig_src_ip = self.ip_to_string(orig_iph[8])
        self.orig_dst_ip = self.ip_to_string(orig_iph[9])
        self.orig_identification = orig_iph[3]
        
        orig_ihl = orig_iph[0] & 0xF
        orig_header_length = orig_ihl * 4
        
        # Parse original transport layer
        if self.orig_protocol == PROTOCOL_UDP:
            udp_start = orig_ip_start + orig_header_length
            if len(self.data) >= udp_start + 4:
                udp_header = self.data[udp_start:udp_start + 4]
                udp_data = struct.unpack('!HH', udp_header)
                self.orig_src_port = udp_data[0]
                self.orig_dst_port = udp_data[1]
        elif self.orig_protocol == PROTOCOL_ICMP:
            icmp_start = orig_ip_start + orig_header_length
            if len(self.data) >= icmp_start + 8:
                icmp_header = self.data[icmp_start:icmp_start + 8]
                icmp_data = struct.unpack('!BBHHH', icmp_header)
                self.orig_icmp_id = icmp_data[3]
                self.orig_icmp_seq = icmp_data[4]
    
    def parse_udp(self):
        """Parse UDP header"""
        udp_start = self.payload_start
        if len(self.data) < udp_start + 8:
            self.src_port = None
            return
            
        udp_header = self.data[udp_start:udp_start + 8]
        udp_data = struct.unpack('!HHHH', udp_header)
        
        self.src_port = udp_data[0]
        self.dst_port = udp_data[1]
        self.udp_length = udp_data[2]
        self.udp_checksum = udp_data[3]
    
    @staticmethod
    def ip_to_string(ip_bytes: bytes) -> str:
        """Convert IP address bytes to string"""
        return '.'.join(map(str, ip_bytes))


class TracerouteAnalyzer:
    """Analyzes traceroute pcap files"""
    
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.packets: List[IPPacket] = []
        self.source_ip: Optional[str] = None
        self.ultimate_dest_ip: Optional[str] = None
        self.intermediate_routers: Dict = {}  # hop_count -> router_ip
        self.protocols: Set[int] = set()
        self.fragments: Dict[int, List[IPPacket]] = defaultdict(list)
        self.rtts: Dict[str, List[float]] = defaultdict(list)
        self.fragmentation_info: Dict = {}
        
    def read_pcap(self):
        """Read and parse pcap file"""
        try:
            with open(self.pcap_file, 'rb') as f:
                # Read global header (24 bytes)
                global_header = f.read(24)
                if len(global_header) < 24:
                    print(f"Error: Invalid pcap file (header too small)")
                    return
                
                # Parse global header
                # Read magic number in native byte order first to detect format
                magic_native = struct.unpack('=I', global_header[0:4])[0]
                
                # Determine byte order and time precision
                if magic_native == 0xa1b2c3d4:
                    endian = '>'  # Big endian
                    time_precision = 1000.0  # microseconds
                elif magic_native == 0xd4c3b2a1:
                    endian = '<'  # Little endian
                    time_precision = 1000.0  # microseconds
                elif magic_native == 0xa1b23c4d:
                    # Nanosecond precision pcap - little endian
                    # Note: Despite the "big endian" magic marker, these files are often little endian
                    endian = '<'
                    time_precision = 1000000.0  # nanoseconds
                elif magic_native == 0x4d3cb2a1:
                    # Nanosecond precision pcap - big endian
                    endian = '>'
                    time_precision = 1000000.0  # nanoseconds
                else:
                    print(f"Error: Unknown pcap format: {magic_native:08x}")
                    return
                
                # Read packets
                while True:
                    # Read packet header (16 bytes)
                    packet_header = f.read(16)
                    if len(packet_header) < 16:
                        break
                    
                    # Parse packet header
                    ph = struct.unpack(endian + 'IIII', packet_header)
                    ts_sec = ph[0]
                    ts_usec = ph[1]
                    incl_len = ph[2]
                    orig_len = ph[3]
                    
                    # Calculate timestamp in milliseconds
                    # time_precision is 1000.0 for microseconds, 1000000.0 for nanoseconds
                    timestamp = ts_sec * 1000.0 + ts_usec / time_precision
                    
                    # Read packet data
                    packet_data = f.read(incl_len)
                    if len(packet_data) < incl_len:
                        break
                    
                    # Parse packet
                    try:
                        packet = IPPacket(packet_data, timestamp)
                        self.packets.append(packet)
                    except (ValueError, struct.error) as e:
                        # Skip malformed packets
                        continue
                    except Exception as e:
                        # Log unexpected errors but continue
                        print(f"Warning: Unexpected error parsing packet: {e}")
                        continue
        except FileNotFoundError:
            print(f"Error: File '{self.pcap_file}' not found")
            sys.exit(1)
        except IOError as e:
            print(f"Error reading file: {e}")
            sys.exit(1)
    
    def analyze(self):
        """Analyze the traceroute packets"""
        # First pass: identify source and collect all packets
        outgoing_packets = []  # Packets sent from source
        icmp_responses = []    # ICMP error responses
        all_udp_ids = set()    # Track all UDP datagram IDs we've seen
        
        # First, identify all traceroute UDP datagrams by their first fragments
        for packet in self.packets:
            if packet.protocol == PROTOCOL_UDP:
                # Check if it's a traceroute packet (port range 33434-33529)
                # This will only match first fragments (which have the UDP header)
                if hasattr(packet, 'dst_port') and packet.dst_port and \
                   TRACEROUTE_PORT_MIN <= packet.dst_port <= TRACEROUTE_PORT_MAX:
                    all_udp_ids.add(packet.identification)
                    if self.source_ip is None:
                        self.source_ip = packet.src_ip
        
        # Now process all packets
        for packet in self.packets:
            self.protocols.add(packet.protocol)
            
            # Identify outgoing traceroute packets
            if packet.protocol == PROTOCOL_UDP:
                # Check if this packet belongs to a traceroute datagram
                is_traceroute = False
                if hasattr(packet, 'dst_port') and packet.dst_port and \
                   TRACEROUTE_PORT_MIN <= packet.dst_port <= TRACEROUTE_PORT_MAX:
                    is_traceroute = True
                elif self.source_ip and packet.identification in all_udp_ids and \
                     packet.src_ip == self.source_ip:
                    # This is a subsequent fragment of a traceroute datagram
                    is_traceroute = True
                
                if is_traceroute:
                    outgoing_packets.append(packet)
                    if self.ultimate_dest_ip is None:
                        self.ultimate_dest_ip = packet.dst_ip
                    
                    # Track ALL fragments (including first fragment with offset=0, MF=True)
                    if packet.fragment_offset > 0 or packet.mf_flag:
                        self.fragments[packet.identification].append(packet)
                        
            elif packet.protocol == PROTOCOL_ICMP:
                if hasattr(packet, 'icmp_type'):
                    # ICMP echo request (traceroute in Windows)
                    if packet.icmp_type == ICMP_ECHO_REQUEST:
                        outgoing_packets.append(packet)
                        if self.source_ip is None:
                            self.source_ip = packet.src_ip
                        if self.ultimate_dest_ip is None:
                            self.ultimate_dest_ip = packet.dst_ip
                        
                        # Track ICMP fragments too
                        if packet.fragment_offset > 0 or packet.mf_flag:
                            self.fragments[packet.identification].append(packet)
                    
                    # ICMP error responses (TTL exceeded or Destination unreachable)
                    elif packet.icmp_type == ICMP_TIME_EXCEEDED or \
                         packet.icmp_type == ICMP_DEST_UNREACHABLE:
                        icmp_responses.append(packet)
        
        # Match outgoing packets with ICMP responses to calculate RTTs
        self.match_packets_and_calculate_rtt(outgoing_packets, icmp_responses)
        
        # Analyze fragments
        self.analyze_fragments()
    
    def match_packets_and_calculate_rtt(self, outgoing_packets: List[IPPacket], 
                                       icmp_responses: List[IPPacket]):
        """Match outgoing packets with ICMP responses and calculate RTT
        
        FIXED: Only calculates one RTT per probe, not one per fragment
        """
        
        # Build a mapping to identify probes
        # For fragmented packets, we need to group fragments by identification
        probe_groups = defaultdict(lambda: {'packets': [], 'ttl': None, 'key': None})
        
        for pkt in outgoing_packets:
            if pkt.protocol == PROTOCOL_UDP and hasattr(pkt, 'src_port'):
                # For UDP, use source port as the probe identifier
                key = ('udp', pkt.src_port)
                probe_groups[key]['packets'].append(pkt)
                if probe_groups[key]['ttl'] is None:
                    probe_groups[key]['ttl'] = pkt.ttl
                probe_groups[key]['key'] = pkt.src_port
                
            elif pkt.protocol == PROTOCOL_UDP:
                # This is a fragment without UDP header - match by identification
                # Find the corresponding probe group by identification
                for group_key, group_data in probe_groups.items():
                    if group_key[0] == 'udp' and group_data['packets']:
                        if any(p.identification == pkt.identification for p in group_data['packets']):
                            group_data['packets'].append(pkt)
                            break
                            
            elif pkt.protocol == PROTOCOL_ICMP and hasattr(pkt, 'icmp_seq'):
                # For ICMP, use sequence number as the probe identifier
                key = ('icmp', pkt.icmp_seq)
                probe_groups[key]['packets'].append(pkt)
                if probe_groups[key]['ttl'] is None:
                    probe_groups[key]['ttl'] = pkt.ttl
                probe_groups[key]['key'] = pkt.icmp_seq
        
        # Now match ICMP responses to probe groups
        for response in icmp_responses:
            router_ip = response.src_ip
            
            if not hasattr(response, 'orig_protocol'):
                continue
            
            # Match based on protocol
            if response.orig_protocol == PROTOCOL_UDP:
                if not hasattr(response, 'orig_src_port'):
                    continue
                
                orig_port = response.orig_src_port
                key = ('udp', orig_port)
                
                if key not in probe_groups:
                    continue
                
                probe_group = probe_groups[key]
                matched_ttl = probe_group['ttl']
                
                # FIXED: Calculate RTT only ONCE per probe
                # Use the earliest fragment's timestamp (typically the first fragment)
                if probe_group['packets']:
                    earliest_pkt = min(probe_group['packets'], key=lambda p: p.timestamp)
                    rtt = response.timestamp - earliest_pkt.timestamp
                    self.rtts[router_ip].append(rtt)
                    
                    # Track intermediate router by TTL
                    if router_ip != self.ultimate_dest_ip:
                        self._add_intermediate_router(matched_ttl, router_ip)
            
            elif response.orig_protocol == PROTOCOL_ICMP:
                if not hasattr(response, 'orig_icmp_seq'):
                    continue
                
                orig_seq = response.orig_icmp_seq
                key = ('icmp', orig_seq)
                
                if key not in probe_groups:
                    continue
                
                probe_group = probe_groups[key]
                matched_ttl = probe_group['ttl']
                
                # FIXED: Calculate RTT only ONCE per probe
                if probe_group['packets']:
                    earliest_pkt = min(probe_group['packets'], key=lambda p: p.timestamp)
                    rtt = response.timestamp - earliest_pkt.timestamp
                    self.rtts[router_ip].append(rtt)
                    
                    # Track intermediate router
                    if router_ip != self.ultimate_dest_ip:
                        self._add_intermediate_router(matched_ttl, router_ip)
    
    def _add_intermediate_router(self, ttl: int, router_ip: str):
        """Add an intermediate router, handling load balancing cases
        
        FIXED: Improved load balancing detection with proper key generation
        """
        if ttl not in self.intermediate_routers:
            self.intermediate_routers[ttl] = router_ip
        elif self.intermediate_routers[ttl] != router_ip:
            # Multiple routers at same TTL (load balancing)
            # Find next available sub-index for this TTL
            sub_index = 1
            while True:
                key = f"{ttl}.{sub_index}"
                if key not in self.intermediate_routers:
                    self.intermediate_routers[key] = router_ip
                    break
                elif self.intermediate_routers[key] == router_ip:
                    # Already recorded this router
                    break
                sub_index += 1
    
    def analyze_fragments(self):
        """Analyze IP fragmentation information"""
        self.fragmentation_info = {}
        
        for frag_id, frag_list in self.fragments.items():
            if len(frag_list) == 0:
                continue
                
            # Check if actually fragmented
            has_fragments = len(frag_list) > 1 or any(f.mf_flag for f in frag_list)
            
            if not has_fragments:
                continue
            
            # Sort by fragment offset
            frag_list.sort(key=lambda x: x.fragment_offset)
            
            num_fragments = len(frag_list)
            last_fragment = frag_list[-1]
            # Offset is in 8-byte units, convert to bytes
            last_offset_bytes = last_fragment.fragment_offset * 8
            
            self.fragmentation_info[frag_id] = {
                'num_fragments': num_fragments,
                'last_offset': last_offset_bytes
            }
    
    def calculate_statistics(self, values: List[float]) -> Tuple[float, float]:
        """Calculate average and standard deviation"""
        if not values:
            return 0.0, 0.0
        
        avg = sum(values) / len(values)
        
        if len(values) == 1:
            return avg, 0.0
        
        variance = sum((x - avg) ** 2 for x in values) / len(values)
        std_dev = math.sqrt(variance)
        
        return avg, std_dev
    
    @staticmethod
    def sort_key(item):
        """Sort key function for router entries (handles both int and string keys)"""
        key = item[0]
        if isinstance(key, str):
            # For keys like "3.1", extract the numeric part
            parts = key.split('.')
            return (int(parts[0]), int(parts[1]) if len(parts) > 1 else 0)
        else:
            return (int(key), 0)
    
    def print_results(self):
        """Print analysis results"""
        print(f"The IP address of the source node: {self.source_ip}")
        print(f"The IP address of ultimate destination node: {self.ultimate_dest_ip}")
        
        # Print intermediate routers in order
        print("The IP addresses of the intermediate destination nodes:")
        
        sorted_routers = sorted(self.intermediate_routers.items(), key=self.sort_key)
        
        # Number routers sequentially (1, 2, 3...) but show TTL for each
        router_num = 1
        total_routers = len(sorted_routers)
        
        for ttl, router_ip in sorted_routers:
            # Extract base TTL for display
            base_ttl = int(str(ttl).split('.')[0])
            
            if router_num < total_routers:
                print(f"\trouter {router_num}: {router_ip} (TTL={base_ttl})")
            else:
                # Last router doesn't have comma in expected output
                print(f"\trouter {router_num}: {router_ip} (TTL={base_ttl})")
            
            router_num += 1
        
        print("=" * 64)
        
        # Print protocol values (only ICMP and UDP as per Q&A)
        print("The values in the protocol field of IP headers:")
        protocol_names = {PROTOCOL_ICMP: "ICMP", PROTOCOL_UDP: "UDP"}
        relevant_protocols = set(self.protocols) & {PROTOCOL_ICMP, PROTOCOL_UDP}
        for proto in sorted(relevant_protocols):
            proto_name = protocol_names.get(proto, "Unknown")
            print(f"\t{proto}: {proto_name}")
        
        print("=" * 64)
        
        # Print fragmentation info
        if self.fragmentation_info:
            frag_patterns = [(info['num_fragments'], info['last_offset']) 
                           for info in self.fragmentation_info.values()]
            unique_patterns = set(frag_patterns)
            
            if len(unique_patterns) == 1:
                pattern = frag_patterns[0]
                print(f"The number of fragments created from the original datagram is: {pattern[0]}")
                print(f"The offset of the last fragment is: {pattern[1]}")
            else:
                for frag_id, info in self.fragmentation_info.items():
                    print(f"The number of fragments created from the original datagram D{frag_id} is: {info['num_fragments']}")
                    print(f"The offset of the last fragment is: {info['last_offset']}")
                    print()
        else:
            print("The number of fragments created from the original datagram is: 0")
            print("The offset of the last fragment is: 0")
        
        print("=" * 64)
        
        # Print RTT statistics for each router
        for ttl, router_ip in sorted(self.intermediate_routers.items(), key=self.sort_key):
            if router_ip in self.rtts:
                avg, std = self.calculate_statistics(self.rtts[router_ip])
                print(f"The avg RTT between {self.source_ip} and {router_ip} is: {avg:.6f} ms, the s.d. is: {std:.6f} ms")
        
        # Ultimate destination RTT
        if self.ultimate_dest_ip and self.ultimate_dest_ip in self.rtts:
            avg, std = self.calculate_statistics(self.rtts[self.ultimate_dest_ip])
            print(f"The avg RTT between {self.source_ip} and {self.ultimate_dest_ip} is: {avg:.6f} ms, the s.d. is: {std:.6f} ms")
        
        print("=" * 64)
        
        # Print TTL summary table
        print("TTL      Average RTT in this Trace File (ms)")
        
        # Group RTTs by base TTL value
        ttl_rtts = defaultdict(list)
        for ttl, router_ip in self.intermediate_routers.items():
            base_ttl = int(str(ttl).split('.')[0])
            if router_ip in self.rtts:
                ttl_rtts[base_ttl].extend(self.rtts[router_ip])
        
        # Also include destination RTTs (these will be at higher TTL values)
        if self.ultimate_dest_ip and self.ultimate_dest_ip in self.rtts:
            # Find the maximum TTL used
            max_ttl = max(int(str(ttl).split('.')[0]) for ttl in self.intermediate_routers.keys())
            # Destination responses come from TTL values beyond the last intermediate router
            for pkt in self.packets:
                if pkt.protocol == 17 and hasattr(pkt, 'dst_port') and pkt.dst_port and \
                   33434 <= pkt.dst_port <= 33529:
                    if pkt.ttl > max_ttl:
                        ttl_rtts[pkt.ttl] = []  # Ensure TTL exists in dict
            
            # Add destination RTTs to appropriate TTL values
            # Need to match destination responses to their TTL values
            for pkt in self.packets:
                if pkt.protocol == 1 and hasattr(pkt, 'icmp_type') and pkt.icmp_type == 3:
                    if pkt.src_ip == self.ultimate_dest_ip:
                        # Find the original packet's TTL
                        if hasattr(pkt, 'orig_dst_port'):
                            for orig_pkt in self.packets:
                                if orig_pkt.protocol == 17 and hasattr(orig_pkt, 'dst_port') and \
                                   orig_pkt.dst_port == pkt.orig_dst_port:
                                    if orig_pkt.ttl not in ttl_rtts or orig_pkt.ttl > max_ttl:
                                        rtt = pkt.timestamp - orig_pkt.timestamp
                                        ttl_rtts[orig_pkt.ttl].append(rtt)
                                    break
        
        # Print the summary table
        for ttl in sorted(ttl_rtts.keys()):
            if ttl_rtts[ttl]:
                avg_rtt = sum(ttl_rtts[ttl]) / len(ttl_rtts[ttl])
                print(f"{ttl:<8} {avg_rtt:>8.2f}")
            else:
                print(f"{ttl:<8} {'N/A':>8}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ip_traceroute_analyzer.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    analyzer = TracerouteAnalyzer(pcap_file)
    analyzer.read_pcap()
    analyzer.analyze()
    analyzer.print_results()


if __name__ == "__main__":
    main()