#!/usr/bin/env python3
"""
Test script to verify the assignment code works correctly
"""

import os
import sys

def test_file_exists(filepath):
    """Check if a file exists"""
    if os.path.exists(filepath):
        print(f"Found: {filepath}")
        return True
    else:
        print(f"Missing: {filepath}")
        return False

def main():
    print("="*60)
    print("CSc 361 Assignment 3 - Installation Test")
    print("="*60 + "\n")
    
    # Check Python version
    print("Python Version Check:")
    print(f"  Current version: {sys.version}")
    if sys.version_info >= (3, 6):
        print("  Python 3.6+ detected\n")
    else:
        print("  Python 3.6+ required\n")
        return False
    
    # Check for required files
    print("Required Files Check:")
    all_good = True
    
    required_files = [
        "ip_traceroute_analyzer.py",
        "analyze_requirement2.py",
        "README.txt"
    ]
    
    for f in required_files:
        if not test_file_exists(f):
            all_good = False
    
    print()
    
    # Check for trace files directory
    print("Trace Files Directory Check:")
    if test_file_exists("PcapTracesAssignment3"):
        print("  Checking for trace files...")
        trace_files = [
            "PcapTracesAssignment3/traceroute-frag.pcap",
            "PcapTracesAssignment3/win_trace1.pcap",
            "PcapTracesAssignment3/group1-trace1.pcap",
            "PcapTracesAssignment3/group2-trace1.pcap"
        ]
        
        for f in trace_files:
            if not test_file_exists(f"  {f}"):
                all_good = False
    else:
        all_good = False
    
    print()
    
    # Try to import the analyzer
    print("Code Import Test:")
    try:
        from ip_traceroute_analyzer import TracerouteAnalyzer
        print("   Successfully imported TracerouteAnalyzer\n")
    except Exception as e:
        print(f"  ✗ Failed to import: {e}\n")
        all_good = False
    
    # Summary
    print("="*60)
    if all_good:
        print(" All tests passed! You're ready to run the assignment.")
        print("\nQuick start:")
        print("  For R1: python3 ip_traceroute_analyzer.py PcapTracesAssignment3/win_trace1.pcap")
        print("  For R2: python3 analyze_requirement2.py")
    else:
        print(" Some tests failed. Please check the missing files.")
    print("="*60)
    
    return all_good

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
