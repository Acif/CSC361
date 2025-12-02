#!/usr/bin/env python3
"""
Requirement 2 Analysis Script
Analyzes groups of traceroute files to compare routes and RTTs
"""

import sys
import os
from ip_traceroute_analyzer import TracerouteAnalyzer
from collections import defaultdict


def analyze_group(trace_files, group_name):
    """Analyze a group of trace files"""
    print(f"\n{'='*60}")
    print(f"Analysis for {group_name}")
    print(f"{'='*60}\n")
    
    all_routes = []
    all_rtts = []  # List of dictionaries: TTL -> list of RTTs
    all_probes_per_ttl = []
    
    for i, trace_file in enumerate(trace_files, 1):
        print(f"\nAnalyzing trace file {i}: {trace_file}")
        print("-" * 40)
        
        analyzer = TracerouteAnalyzer(trace_file)
        analyzer.read_pcap()
        analyzer.analyze()
        
        # Extract route
        def sort_key(item):
            key = item[0]
            if isinstance(key, str):
                parts = key.split('.')
                return (int(parts[0]), int(parts[1]) if len(parts) > 1 else 0)
            else:
                return (int(key), 0)
        
        route = [router_ip for ttl, router_ip in sorted(analyzer.intermediate_routers.items(), key=sort_key)]
        all_routes.append(route)
        
        print(f"  Source: {analyzer.source_ip}")
        print(f"  Destination: {analyzer.ultimate_dest_ip}")
        print(f"  Number of hops: {len(route)}")
        print(f"  Route: {' -> '.join(route)}")
        
        # Calculate probes per TTL
        # Count how many packets were sent per TTL value
        ttl_counts = defaultdict(int)
        for pkt in analyzer.packets:
            if pkt.protocol == 17 and hasattr(pkt, 'dst_port') and pkt.dst_port and 33434 <= pkt.dst_port <= 33529:
                ttl_counts[pkt.ttl] += 1
            elif pkt.protocol == 1 and hasattr(pkt, 'icmp_type') and pkt.icmp_type == 8:
                ttl_counts[pkt.ttl] += 1
        
        # Account for fragmentation - if packets are fragmented, divide by number of fragments
        if analyzer.fragmentation_info:
            # Get the number of fragments from the first fragmented datagram
            num_fragments = list(analyzer.fragmentation_info.values())[0]['num_fragments']
            ttl_counts = {ttl: count // num_fragments for ttl, count in ttl_counts.items()}
        
        if ttl_counts:
            # Most common probe count
            from collections import Counter
            probe_counts = list(ttl_counts.values())
            most_common = Counter(probe_counts).most_common(1)[0][0]
            all_probes_per_ttl.append(most_common)
            print(f"  Probes per TTL: {most_common}")
        
        # Collect RTT data
        rtt_dict = {}
        for ttl, router_ip in sorted(analyzer.intermediate_routers.items(), key=sort_key):
            if router_ip in analyzer.rtts:
                rtt_dict[ttl] = analyzer.rtts[router_ip]
        all_rtts.append(rtt_dict)
    
    # Compare routes
    print(f"\n{'='*60}")
    print("Route Comparison")
    print(f"{'='*60}\n")
    
    # Check if all routes are the same
    routes_identical = all(route == all_routes[0] for route in all_routes)
    
    if routes_identical:
        print("The sequence of intermediate routers is THE SAME in all trace files.")
        print(f"\nCommon route ({len(all_routes[0])} hops):")
        for i, router in enumerate(all_routes[0], 1):
            print(f"  Hop {i}: {router}")
    else:
        print("The sequence of intermediate routers is DIFFERENT in the trace files.")
        print("\nDifferences found:")
        
        # Find max route length
        max_len = max(len(route) for route in all_routes)
        
        for hop in range(max_len):
            routers_at_hop = set()
            for route in all_routes:
                if hop < len(route):
                    routers_at_hop.add(route[hop])
            
            if len(routers_at_hop) > 1:
                print(f"\n  Hop {hop + 1}: Multiple routers observed")
                for router in routers_at_hop:
                    count = sum(1 for route in all_routes if hop < len(route) and route[hop] == router)
                    print(f"    - {router} (in {count}/{len(all_routes)} traces)")
        
        print("\nPossible explanation:")
        print("  The difference in routes is likely due to load balancing at one or more")
        print("  intermediate routers. Load balancing distributes traffic across multiple")
        print("  paths to improve performance and reliability. Different traceroute attempts")
        print("  may take different paths through the network due to this load balancing.")
    
    # Probes per TTL
    print(f"\n{'='*60}")
    print("Probes per TTL")
    print(f"{'='*60}\n")
    
    if all_probes_per_ttl:
        unique_probes = set(all_probes_per_ttl)
        if len(unique_probes) == 1:
            print(f"All trace files use {all_probes_per_ttl[0]} probes per TTL.")
        else:
            print("Different trace files use different numbers of probes per TTL:")
            for i, probes in enumerate(all_probes_per_ttl, 1):
                print(f"  Trace {i}: {probes} probes per TTL")
    
    # RTT Comparison Table
    if routes_identical and all_rtts:
        print(f"\n{'='*60}")
        print("RTT Comparison Table")
        print(f"{'='*60}\n")
        
        # Build RTT table
        # Get all TTL values
        all_ttls = sorted(set(ttl for rtt_dict in all_rtts for ttl in rtt_dict.keys()), 
                         key=lambda x: (int(str(x).split('.')[0]), int(str(x).split('.')[1]) if '.' in str(x) else 0))
        
        # Print header
        print(f"{'TTL':<5}", end="")
        for i in range(len(trace_files)):
            print(f"{'Trace ' + str(i+1):>15}", end="")
        print()
        print("-" * (5 + 15 * len(trace_files)))
        
        # Print rows
        for ttl in all_ttls:
            print(f"{ttl:<5}", end="")
            for rtt_dict in all_rtts:
                if ttl in rtt_dict:
                    avg_rtt = sum(rtt_dict[ttl]) / len(rtt_dict[ttl])
                    print(f"{avg_rtt:>14.1f}ms", end="")
                else:
                    print(f"{'N/A':>15}", end="")
            print()
        
        print("\nAnalysis of Maximum Delay:")
        print("-" * 40)
        
        # Find which hop has the maximum increase in RTT
        avg_rtts_by_hop = {}
        for ttl in all_ttls:
            rtts_for_ttl = []
            for rtt_dict in all_rtts:
                if ttl in rtt_dict:
                    avg_rtt = sum(rtt_dict[ttl]) / len(rtt_dict[ttl])
                    rtts_for_ttl.append(avg_rtt)
            if rtts_for_ttl:
                avg_rtts_by_hop[ttl] = sum(rtts_for_ttl) / len(rtts_for_ttl)
        
        # Calculate RTT increases
        sorted_ttls = sorted(avg_rtts_by_hop.keys(), 
                            key=lambda x: (int(str(x).split('.')[0]), int(str(x).split('.')[1]) if '.' in str(x) else 0))
        
        if len(sorted_ttls) >= 2:
            max_increase = 0
            max_increase_hop = None
            
            for i in range(1, len(sorted_ttls)):
                prev_ttl = sorted_ttls[i-1]
                curr_ttl = sorted_ttls[i]
                increase = avg_rtts_by_hop[curr_ttl] - avg_rtts_by_hop[prev_ttl]
                
                if increase > max_increase:
                    max_increase = increase
                    max_increase_hop = i + 1  # Convert to 1-indexed hop number
            
            if max_increase_hop:
                print(f"The hop with the maximum delay increase is hop {max_increase_hop}")
                print(f"This hop added approximately {max_increase:.1f} ms to the RTT.")
                print("\nThis suggests that hop {} is likely a long-distance link or".format(max_increase_hop))
                print("experiences significant queueing delays.")


def main():
    # Check if trace files directory exists
    trace_dir = "PcapTracesAssignment3"
    if not os.path.exists(trace_dir):
        print(f"Error: Directory '{trace_dir}' not found!")
        print("Please ensure the PcapTracesAssignment3 directory is in the current directory.")
        sys.exit(1)
    
    # Group 1 files
    group1_files = [os.path.join(trace_dir, f"group1-trace{i}.pcap") for i in range(1, 6)]
    
    # Group 2 files
    group2_files = [os.path.join(trace_dir, f"group2-trace{i}.pcap") for i in range(1, 6)]
    
    # Check if all files exist
    all_files = group1_files + group2_files
    missing_files = [f for f in all_files if not os.path.exists(f)]
    
    if missing_files:
        print("Error: The following files are missing:")
        for f in missing_files:
            print(f"  - {f}")
        sys.exit(1)
    
    print("\n" + "="*60)
    print("CSc 361 Assignment 3 - Requirement 2 Analysis")
    print("="*60)
    
    # Analyze Group 1
    analyze_group(group1_files, "Group 1")
    
    # Analyze Group 2
    analyze_group(group2_files, "Group 2")
    
    print("\n" + "="*60)
    print("Analysis Complete")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
