#!/usr/bin/env python3
"""
Piter sniffer — macOS version using subprocess (pcap via tcpdump).
More reliable than raw sockets on Mac.
"""

import subprocess
import sys
import re
import time
from datetime import datetime

PITER_IP = "103.129.148.178"
PITER_PORT = "17091"

def main():
    print(f"[*] Sniffing UDP {PITER_PORT} via tcpdump...")
    print(f"[*] Target: {PITER_IP}:{PITER_PORT}")
    print(f"[*] Press Ctrl+C, then start Growtopia and login\n")
    
    cmd = [
        "sudo", "tcpdump", "-l", "-n", "-A",
        f"udp port {PITER_PORT}",
    ]
    
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    
    count = 0
    stdout = proc.stdout
    if stdout is None:
        print("[!] Failed to capture tcpdump output")
        sys.exit(1)

    try:
        for line in stdout:
            line = line.strip()
            if not line:
                continue
            
            ts = datetime.now().strftime("%H:%M:%S")
            
            # IP packet line
            ip_match = re.match(
                r'(\d+:\d+:\d+\.\d+)\s+IP\s+([\d.]+)\.(\d+)\s+>\s+([\d.]+)\.(\d+):',
                line
            )
            if ip_match:
                src_ip = ip_match.group(2)
                src_port = ip_match.group(3)
                dst_ip = ip_match.group(4)
                dst_port = ip_match.group(5)
                direction = ">" if dst_ip == PITER_IP else "<"
                count += 1
                print(f"\n{'─'*50}")
                print(f"[{ts}] #{count} {src_ip}:{src_port} → {dst_ip}:{dst_port}")
            
            # HEX line
            elif line.startswith('0x'):
                hex_str = line.split(':', 1)[1].strip() if ':' in line else line
                print(f"  HEX: {hex_str[:100]}")
            
            # ASCII / content line
            elif any(c.isalpha() for c in line[:10]):
                # Filter out tcpdump noise
                if 'tcpdump:' not in line and 'listening on' not in line:
                    # Highlight tank fields
                    if 'tankIDName' in line or 'tankIDPass' in line:
                        print(f"  ⚡ {line[:200]}")
                    else:
                        print(f"  ASCII: {line[:200]}")
    
    except KeyboardInterrupt:
        proc.terminate()
        print(f"\n[*] Stopped. {count} packets.")
    except Exception as e:
        print(f"[!] {e}")
        proc.terminate()

if __name__ == "__main__":
    main()
