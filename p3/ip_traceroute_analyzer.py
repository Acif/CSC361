#!/usr/bin/env python3
"""
IP Traceroute Analyzer
CSc 361 Assignment 3
Analyzes IP datagrams from traceroute pcap files
"""

import struct
import sys
from collections import defaultdict
from typing import Dict, List, Tuple, Set
import math


class IPPacket:
    """Represents an IP packet with relevant fields"""
    def __init__(self, data, timestamp):
        self.timestamp = timestamp
        self.data = data
        self.parse_ip_header()
        
    def parse_ip_header(self):
        """Parse IP header fields"""
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
        
        if self.protocol == 1:  # ICMP
            self.parse_icmp()
        elif self.protocol == 17:  # UDP
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
        if self.icmp_type == 11 or self.icmp_type == 3:
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
        if self.orig_protocol == 17:  # UDP
            udp_start = orig_ip_start + orig_header_length
            if len(self.data) >= udp_start + 4:
                udp_header = self.data[udp_start:udp_start + 4]
                udp_data = struct.unpack('!HH', udp_header)
                self.orig_src_port = udp_data[0]
                self.orig_dst_port = udp_data[1]
        elif self.orig_protocol == 1:  # ICMP
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
    def ip_to_string(ip_bytes):
        """Convert IP address bytes to string"""
        return '.'.join(map(str, ip_bytes))


class TracerouteAnalyzer:
    """Analyzes traceroute pcap files"""
    
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = []
        self.source_ip = None
        self.ultimate_dest_ip = None
        self.intermediate_routers = {}  # hop_count -> router_ip
        self.protocols = set()
        self.fragments = defaultdict(list)  # identification -> list of fragments
        self.rtts = defaultdict(list)  # router_ip -> list of RTTs
        
    def read_pcap(self):
        """Read and parse pcap file"""
        with open(self.pcap_file, 'rb') as f:
            # Read global header (24 bytes)
            global_header = f.read(24)
            if len(global_header) < 24:
                return
            
            # Parse global header
            magic = struct.unpack('I', global_header[0:4])[0]
            
            # Determine byte order
            if magic == 0xa1b2c3d4:
                endian = '!'
            elif magic == 0xd4c3b2a1:
                endian = '<'
            elif magic == 0xa1b23c4d or magic == 0x4d3cb2a1:
                # pcapng format - use little endian
                endian = '<'
            else:
                print(f"Unknown pcap format: {magic:08x}")
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
                timestamp = ts_sec * 1000.0 + ts_usec / 1000.0
                
                # Read packet data
                packet_data = f.read(incl_len)
                if len(packet_data) < incl_len:
                    break
                
                # Parse packet
                try:
                    packet = IPPacket(packet_data, timestamp)
                    self.packets.append(packet)
                except:
                    continue
    
    def analyze(self):
        """Analyze the traceroute packets"""
        # First pass: identify source and collect all packets
        outgoing_packets = []  # Packets sent from source
        icmp_responses = []    # ICMP error responses
        all_udp_ids = set()    # Track all UDP datagram IDs we've seen
        
        # First, identify all traceroute UDP datagrams by their first fragments
        for packet in self.packets:
            if packet.protocol == 17:  # UDP
                # Check if it's a traceroute packet (port range 33434-33529)
                # This will only match first fragments (which have the UDP header)
                if hasattr(packet, 'dst_port') and packet.dst_port and 33434 <= packet.dst_port <= 33529:
                    all_udp_ids.add(packet.identification)
                    if self.source_ip is None:
                        self.source_ip = packet.src_ip
        
        # Now process all packets
        for packet in self.packets:
            self.protocols.add(packet.protocol)
            
            # Identify outgoing traceroute packets
            if packet.protocol == 17:  # UDP
                # Check if this packet belongs to a traceroute datagram
                # (either it has the right port, or its ID matches a known traceroute datagram)
                is_traceroute = False
                if hasattr(packet, 'dst_port') and packet.dst_port and 33434 <= packet.dst_port <= 33529:
                    is_traceroute = True
                elif self.source_ip and packet.identification in all_udp_ids and packet.src_ip == self.source_ip:
                    # This is a subsequent fragment of a traceroute datagram
                    is_traceroute = True
                
                if is_traceroute:
                    outgoing_packets.append(packet)
                    if self.ultimate_dest_ip is None:
                        self.ultimate_dest_ip = packet.dst_ip
                    
                    # Track all fragments
                    if packet.fragment_offset > 0 or packet.mf_flag:
                        self.fragments[packet.identification].append(packet)
                        
            elif packet.protocol == 1:  # ICMP
                if hasattr(packet, 'icmp_type'):
                    # ICMP echo request (traceroute in Windows)
                    if packet.icmp_type == 8:
                        outgoing_packets.append(packet)
                        if self.source_ip is None:
                            self.source_ip = packet.src_ip
                        if self.ultimate_dest_ip is None:
                            self.ultimate_dest_ip = packet.dst_ip
                        
                        # Track ICMP fragments too
                        if packet.fragment_offset > 0 or packet.mf_flag:
                            self.fragments[packet.identification].append(packet)
                    
                    # ICMP error responses (TTL exceeded or Destination unreachable)
                    elif packet.icmp_type == 11 or packet.icmp_type == 3:
                        icmp_responses.append(packet)
        
        # Match outgoing packets with ICMP responses to calculate RTTs
        self.match_packets_and_calculate_rtt(outgoing_packets, icmp_responses)
        
        # Analyze fragments
        self.analyze_fragments()
    
    def match_packets_and_calculate_rtt(self, outgoing_packets, icmp_responses):
        """Match outgoing packets with ICMP responses and calculate RTT"""
        
        # Build a mapping of source ports to outgoing packets for quick lookup
        port_to_packets = defaultdict(list)
        for pkt in outgoing_packets:
            if pkt.protocol == 17 and hasattr(pkt, 'src_port'):
                port_to_packets[pkt.src_port].append(pkt)
            elif pkt.protocol == 1 and hasattr(pkt, 'icmp_seq'):
                # For ICMP, use sequence number as key
                port_to_packets[('icmp', pkt.icmp_seq)].append(pkt)
        
        for response in icmp_responses:
            router_ip = response.src_ip
            
            if not hasattr(response, 'orig_protocol'):
                continue
            
            # Match based on protocol
            if response.orig_protocol == 17:  # Original was UDP
                # Match by source port only (identification field doesn't match)
                if not hasattr(response, 'orig_src_port'):
                    continue
                
                orig_port = response.orig_src_port
                
                # Find all matching outgoing packets (all fragments with same port)
                matched_packets = port_to_packets.get(orig_port, [])
                
                if not matched_packets:
                    continue
                
                # Get the TTL from the first matched packet
                matched_ttl = matched_packets[0].ttl
                
                # Calculate RTT for all matched packets (all fragments)
                for pkt in matched_packets:
                    rtt = response.timestamp - pkt.timestamp
                    self.rtts[router_ip].append(rtt)
                
                # Track intermediate router by TTL
                if router_ip != self.ultimate_dest_ip:
                    if matched_ttl not in self.intermediate_routers:
                        self.intermediate_routers[matched_ttl] = router_ip
                    elif self.intermediate_routers[matched_ttl] != router_ip:
                        # Multiple routers at same TTL (load balancing)
                        # Add with a unique key
                        key = f"{matched_ttl}.{len([k for k in self.intermediate_routers if str(k).startswith(str(matched_ttl))])}"
                        self.intermediate_routers[key] = router_ip
            
            elif response.orig_protocol == 1:  # Original was ICMP (Windows traceroute)
                # Match by ICMP sequence number
                if not hasattr(response, 'orig_icmp_seq'):
                    continue
                
                orig_seq = response.orig_icmp_seq
                
                # Find matching outgoing ICMP echo
                matched_packets = port_to_packets.get(('icmp', orig_seq), [])
                
                if not matched_packets:
                    continue
                
                matched_ttl = matched_packets[0].ttl
                
                for pkt in matched_packets:
                    rtt = response.timestamp - pkt.timestamp
                    self.rtts[router_ip].append(rtt)
                
                # Track intermediate router
                if router_ip != self.ultimate_dest_ip:
                    if matched_ttl not in self.intermediate_routers:
                        self.intermediate_routers[matched_ttl] = router_ip
    
    def analyze_fragments(self):
        """Analyze IP fragmentation information"""
        self.fragmentation_info = {}
        
        for frag_id, frag_list in self.fragments.items():
            # A datagram is fragmented if it has more than one fragment OR if MF flag is set
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
    
    def calculate_statistics(self, values):
        """Calculate average and standard deviation"""
        if not values:
            return 0, 0
        
        avg = sum(values) / len(values)
        
        if len(values) == 1:
            return avg, 0
        
        variance = sum((x - avg) ** 2 for x in values) / len(values)
        std_dev = math.sqrt(variance)
        
        return avg, std_dev
    
    def print_results(self):
        """Print analysis results"""
        print(f"The IP address of the source node: {self.source_ip}")
        print(f"The IP address of ultimate destination node: {self.ultimate_dest_ip}")
        
        # Print intermediate routers in order
        print("The IP addresses of the intermediate destination nodes:")
        # Sort by converting all keys to strings with proper sorting
        def sort_key(item):
            key = item[0]
            if isinstance(key, str):
                # For keys like "3.1", extract the numeric part
                parts = key.split('.')
                return (int(parts[0]), int(parts[1]) if len(parts) > 1 else 0)
            else:
                return (int(key), 0)
        
        sorted_routers = sorted(self.intermediate_routers.items(), key=sort_key)
        for idx, (ttl, router_ip) in enumerate(sorted_routers, 1):
            if idx < len(sorted_routers):
                print(f"    router {idx}: {router_ip},")
            else:
                print(f"    router {idx}: {router_ip}.")
        
        print()
        
        # Print protocol values (only ICMP and UDP as per Q&A)
        print("The values in the protocol field of IP headers:")
        protocol_names = {1: "ICMP", 17: "UDP"}
        relevant_protocols = set(self.protocols) & {1, 17}
        for proto in sorted(relevant_protocols):
            proto_name = protocol_names.get(proto, "Unknown")
            print(f"    {proto}: {proto_name}")
        
        print()
        
        # Print fragmentation info - only once if all datagrams have same pattern
        if self.fragmentation_info:
            # Check if all datagrams have the same fragmentation pattern
            frag_patterns = [(info['num_fragments'], info['last_offset']) 
                           for info in self.fragmentation_info.values()]
            unique_patterns = set(frag_patterns)
            
            if len(unique_patterns) == 1:
                # All datagrams have same pattern, print once
                pattern = frag_patterns[0]
                print(f"The number of fragments created from the original datagram is: {pattern[0]}")
                print(f"The offset of the last fragment is: {pattern[1]}")
            else:
                # Different patterns, print each
                for frag_id, info in self.fragmentation_info.items():
                    print(f"The number of fragments created from the original datagram D{frag_id} is: {info['num_fragments']}")
                    print(f"The offset of the last fragment is: {info['last_offset']}")
                    print()
        else:
            print("The number of fragments created from the original datagram is: 0")
            print("The offset of the last fragment is: 0")
        
        print()
        
        # Print RTT statistics
        for ttl, router_ip in sorted(self.intermediate_routers.items(), key=sort_key):
            if router_ip in self.rtts:
                avg, std = self.calculate_statistics(self.rtts[router_ip])
                print(f"The avg RTT between {self.source_ip} and {router_ip} is: {avg:.0f} ms, the s.d. is: {std:.0f} ms")
        
        # Ultimate destination RTT
        if self.ultimate_dest_ip in self.rtts:
            avg, std = self.calculate_statistics(self.rtts[self.ultimate_dest_ip])
            print(f"The avg RTT between {self.source_ip} and {self.ultimate_dest_ip} is: {avg:.0f} ms, the s.d. is: {std:.0f} ms")


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