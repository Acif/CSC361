# CSc 361 Assignment 3: Analysis of IP Protocol

## Author Information
- Course: CSc 361 - Computer Communications and Networks
- Assignment: Assignment 3
- Due Date: November 30, 2025

## Overview
This assignment analyzes IP datagrams from traceroute pcap files. It consists of two main requirements:

1. **Requirement 1 (R1)**: Analyze a single traceroute pcap file to extract IP addresses, protocols, fragmentation information, and RTT statistics.
2. **Requirement 2 (R2)**: Compare multiple traceroute files to analyze routing patterns and RTT variations.

## Files Included

### Main Programs
- `ip_traceroute_analyzer.py` - Main analyzer for R1 (also used by R2)
- `analyze_requirement2.py` - Analysis script for R2

### Documentation
- `README.txt` - This file (instructions and documentation)

## Requirements

### Software Requirements
- Python 3.6 or higher
- No external packages required (uses only Python standard library)

### Input Files
Place the `PcapTracesAssignment3` directory in the same location as the Python scripts. This directory should contain:
- `traceroute-frag.pcap`
- `win_trace1.pcap`, `win_trace2.pcap`
- `group1-trace1.pcap` through `group1-trace5.pcap`
- `group2-trace1.pcap` through `group2-trace5.pcap`

## How to Run

### Requirement 1 (R1): Analyze a Single Trace File

To analyze a single traceroute pcap file:

```bash
python3 ip_traceroute_analyzer.py <pcap_file>
```

**Examples:**

```bash
# Analyze a Linux traceroute with fragmentation
python3 ip_traceroute_analyzer.py PcapTracesAssignment3/traceroute-frag.pcap

# Analyze a Windows traceroute
python3 ip_traceroute_analyzer.py PcapTracesAssignment3/win_trace1.pcap

# Analyze Group 1, Trace 1
python3 ip_traceroute_analyzer.py PcapTracesAssignment3/group1-trace1.pcap
```

**Output Format:**

The program outputs:
1. Source IP address
2. Ultimate destination IP address
3. Intermediate router IP addresses (in order)
4. Protocol field values (ICMP and UDP only)
5. Fragmentation information (number of fragments and last fragment offset)
6. Average RTT and standard deviation for each router

### Requirement 2 (R2): Compare Multiple Trace Files

To analyze both groups of trace files and compare routes and RTTs:

```bash
python3 analyze_requirement2.py
```

**Note:** This script expects the `PcapTracesAssignment3` directory to be in the current working directory.

**Output:**

The script provides:
1. Analysis of each trace file in both groups
2. Comparison of routes (identical or different)
3. Number of probes per TTL
4. RTT comparison table (if routes are identical)
5. Analysis of which hop causes maximum delay

## Implementation Details

### Packet Parsing

The analyzer reads pcap files without using high-level packet parsing libraries (as required). It:
- Parses the pcap global header
- Reads packet headers and data
- Extracts Ethernet, IP, UDP, and ICMP headers manually
- Handles both big-endian and little-endian byte ordering

### Supported Traceroute Implementations

The analyzer supports two traceroute implementations:

1. **Linux traceroute (UDP-based)**:
   - Sends UDP packets to ports 33434-33529
   - Matches packets by source port number
   - Handles fragmented datagrams

2. **Windows traceroute (ICMP-based)**:
   - Sends ICMP Echo Request (Type 8)
   - Matches packets by ICMP sequence number
   - Receives ICMP Time Exceeded (Type 11) responses

### Fragmentation Handling

The analyzer properly handles IP fragmentation:
- Identifies all fragments of a datagram (by MF flag and fragment offset)
- Groups fragments by IP identification field
- Calculates the number of fragments and last fragment offset
- Handles RTT calculation for fragmented datagrams (as per RFC 792)

### RTT Calculation

Round-Trip Time (RTT) is calculated as:
```
RTT = timestamp(ICMP_response) - timestamp(outgoing_packet)
```

For fragmented datagrams, the same ICMP response timestamp is used for all fragments of that datagram, as routers only send one ICMP error per datagram (for fragment zero).

### Load Balancing Detection

The R2 analysis script detects load balancing when:
- Different trace files show different routers at the same hop position
- This is identified and explained as likely load balancing behavior

## Technical Notes

### Known Issues and Limitations

1. **Timestamp Resolution**: RTT values are in milliseconds. Some pcap files may have timing issues or clock synchronization problems, leading to unusual RTT values.

2. **Protocol Filtering**: The analyzer only reports ICMP (protocol 1) and UDP (protocol 17) in the protocol field output, as these are the relevant protocols for traceroute analysis.

3. **Port Range**: The analyzer uses the port range 33434-33529 to identify traceroute UDP packets, which covers the default range used by most traceroute implementations.

4. **Pcap Format Support**: Supports both standard pcap format (magic: 0xa1b2c3d4 or 0xd4c3b2a1) and pcapng format (magic: 0xa1b23c4d or 0x4d3cb2a1).

### Algorithm Details

**Matching Algorithm:**
1. For UDP traceroute: Match by source port number
2. For ICMP traceroute: Match by ICMP sequence number
3. Group all fragments of the same datagram using IP identification field
4. Calculate RTT for each fragment using the same ICMP response

**Route Construction:**
1. Extract TTL value from each outgoing packet
2. Match with ICMP response to identify router at that TTL
3. Order routers by TTL value
4. Handle multiple routers at same TTL (load balancing)

## Testing

The code has been tested with:
- Linux traceroute with fragmentation (`traceroute-frag.pcap`)
- Windows traceroute traces (`win_trace1.pcap`, `win_trace2.pcap`)
- Multiple trace files for route comparison (Group 1 and Group 2)

## Example Output

### R1 Example:

```
The IP address of the source node: 192.168.0.17
The IP address of ultimate destination node: 8.8.8.8
The IP addresses of the intermediate destination nodes:
    router 1: 142.104.69.243,
    router 2: 142.104.68.1,
    router 3: 192.168.9.5,
    ...

The values in the protocol field of IP headers:
    1: ICMP
    17: UDP

The number of fragments created from the original datagram is: 2
The offset of the last fragment is: 1480

The avg RTT between 192.168.0.17 and 142.104.69.243 is: 1079 ms, the s.d. is: 53 ms
...
```

### R2 Example:

```
============================================================
Analysis for Group 2
============================================================

✓ The sequence of intermediate routers is THE SAME in all trace files.

Common route (8 hops):
  Hop 1: 192.168.0.1
  Hop 2: 24.108.0.1
  ...

RTT Comparison Table:
TTL          Trace 1        Trace 2        Trace 3        Trace 4        Trace 5
--------------------------------------------------------------------------------
1            3329.7ms        2710.7ms        7854.0ms        3415.3ms        1745.7ms
2           15811.7ms       17118.3ms       11835.3ms       13245.0ms       16153.7ms
...
```

## Contact

For questions or issues, please contact the course instructor or TA.

## References

- RFC 791: Internet Protocol
- RFC 792: Internet Control Message Protocol
- RFC 2151: A Primer On Internet and TCP/IP Tools and Utilities
- Assignment 3 specification document
- Assignment 3 Q&A document
