CSC 361 – Programming Assignment 2  
Name: Lucas Hewgill  
Student ID: V01033481


------------------------------------------------------------
How to Run
------------------------------------------------------------
Usage:
    python3 tcp_analyzer.py sample-capture-file.cap

The program reads the given pcap file and prints TCP connection
statistics in the format specified in outputformat.pdf.

No external libraries are required.

------------------------------------------------------------
Implemented Features
------------------------------------------------------------
• Parses Ethernet → IPv4 → TCP packets.  
• Identifies connections by 4-tuple (src IP, src port, dst IP, dst port).  
• Tracks SYN, FIN, and RST flags (S#F# R).  
• Reports start time (first SYN), end time (last FIN), and duration.  
• Counts packets and data bytes in both directions.  
• Detects reset, open, and pre-existing connections.  
• Computes min/mean/max of duration, RTT, total packets, and window size.  
• Output matches assignment format (Sections A–D).