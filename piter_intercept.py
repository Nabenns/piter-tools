#!/usr/bin/env python3
"""
Piter Tools — Mac Interceptor (pf-based MITM)
=============================================
Full man-in-the-middle for Growtopia on macOS.
Redirects all outbound UDP port 17091 traffic through our proxy
where we can READ, MODIFY, DROP, or REPLAY any packet.

SETUP (one time):
  sudo pfctl -e                                    # enable packet filter
  sudo echo "rdr pass on en0 proto udp from any to any port 17091 -> 127.0.0.1 port 7091" | sudo pfctl -f -
  sudo python3 piter_intercept.py                  # start intercept
  # Open Growtopia and login

CLEANUP:
  sudo pfctl -d                                    # disable packet filter
"""

import socket
import struct
import sys
import time
import select
import threading
import json
import os
from datetime import datetime
from collections import defaultdict

PITER_IP = "103.129.148.178"
PITER_PORT = 17091
PROXY_PORT = 7091  # Redirect pf 17091→7091 here

# ──── Colors ────
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
BOLD = '\033[1m'
RESET = '\033[0m'


class PiterInterceptor:
    """MITM proxy that intercepts ALL GT→Piter traffic."""
    
    def __init__(self):
        self.client_sock = None
        self.server_sock = None
        self.running = True
        self.packet_count = 0
        
        # Track what we've seen
        self.session = {
            'grow_id': '',
            'password': '',
            'token': '',
            'uid': '',
            'world': '',
            'items': [],
            'players': set(),
        }
        
        # Modification rules
        self.drop_rules = []
        self.modify_rules = {}
        self.inject_queue = []
        
        # Stats
        self.stats = defaultdict(int)
        
        # UI state
        self.ui_mode = 'full'  # full, minimal, silent
    
    def start(self):
        """Start MITM proxy."""
        print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════╗{RESET}")
        print(f"{BOLD}{CYAN}║   PITER INTERCEPTOR — Full MITM Proxy   ║{RESET}")
        print(f"{BOLD}{CYAN}╚══════════════════════════════════════════╝{RESET}")
        print(f"\n{YELLOW}[*] Listening on 0.0.0.0:{PROXY_PORT}{RESET}")
        print(f"{YELLOW}[*] Forwarding to {PITER_IP}:{PITER_PORT}{RESET}")
        print(f"{YELLOW}[*] Run: sudo pfctl -e && echo 'rdr pass proto udp from any to any port 17091 -> 127.0.0.1 port {PROXY_PORT}' | sudo pfctl -f -{RESET}")
        print(f"{YELLOW}[*] Then open Growtopia and login{RESET}")
        print(f"\n  {BOLD}Commands (type while running):{RESET}")
        print(f"  d <num>     - Drop packet #<num>")
        print(f"  m <num> <data> - Modify packet #<num>")  
        print(f"  i <data>    - Inject packet")
        print(f"  s           - Show session info")
        print(f"  w           - Show world/players")
        print(f"  q           - Quit")
        print()
        
        # Start admin thread for user commands
        admin_thread = threading.Thread(target=self._admin_loop, daemon=True)
        admin_thread.start()
        
        try:
            self._main_loop()
        except KeyboardInterrupt:
            self._cleanup()
    
    def _main_loop(self):
        """Main proxy loop - intercept + forward."""
        # Create listening socket for redirected traffic
        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_sock.bind(('0.0.0.0', PROXY_PORT))
        
        # Create socket for forwarding to real server
        forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        forward_sock.settimeout(0.1)
        
        # Map of (remote_addr) → last source port (for response routing)
        client_map = {}
        
        print(f"  {GREEN}[READY] Waiting for GT client to connect...{RESET}\n")
        
        while self.running:
            try:
                data, addr = listen_sock.recvfrom(65535)
            except:
                continue
            
            self.packet_count += 1
            pkt_num = self.packet_count
            
            # Determine direction
            if addr[0] == PITER_IP:
                direction = "← SERVER"
                color = CYAN
            else:
                direction = "→ CLIENT"
                color = YELLOW
            
            # Extract readable info
            info = self._analyze_packet(data, direction)
            
            # Check drop rules
            should_drop = self._check_drop_rules(pkt_num, data)
            
            # Check modify rules
            original_data = data
            data = self._apply_modify_rules(pkt_num, data)
            was_modified = data != original_data
            
            # Log
            if self.ui_mode != 'silent':
                self._log_packet(pkt_num, direction, len(data), info, should_drop, was_modified, color)
            
            # Update session state
            self._update_session(info)
            
            # Forward to real server (if not dropping)
            if not should_drop:
                if direction == "→ CLIENT":
                    # Forward client → server
                    forward_sock.sendto(data, (PITER_IP, PITER_PORT))
                    
                    # Store client addr for response routing
                    client_map[addr] = True
                    
                    # Get server response
                    try:
                        resp, srv_addr = forward_sock.recvfrom(65535)
                        if resp:
                            # Also intercept server response
                            resp_info = self._analyze_packet(resp, "← SERVER")
                            self.packet_count += 1
                            
                            if self.ui_mode != 'silent':
                                self._log_packet(self.packet_count, "← SERVER", len(resp), resp_info, False, False, CYAN)
                            
                            self._update_session(resp_info)
                            
                            # Send back to client
                            listen_sock.sendto(resp, addr)
                    except socket.timeout:
                        pass
            
            # Process injection queue
            if self.inject_queue:
                inject_data = self.inject_queue.pop(0)
                forward_sock.sendto(inject_data, (PITER_IP, PITER_PORT))
                print(f"  {RED}[INJECT] Sent {len(inject_data)}B to server{RESET}")
    
    def _analyze_packet(self, data: bytes, direction: str) -> dict[str, object]:
        """Extract meaningful info from packet."""
        info: dict[str, object] = {'raw_size': len(data)}
        
        if len(data) < 4:
            info['type'] = 'TOO_SMALL'
            return info
        
        # Try to decode as text
        try:
            text = data.decode('utf-8', errors='replace')
            
            # Login fields
            for field in ['requestedName', 'tankIDName', 'tankIDPass', '_token']:
                if field in text:
                    for line in text.split('\n'):
                        if field in line:
                            key, val = line.split('|', 1) if '|' in line else (field, '?')
                            info[field] = val.strip()
            
            # Actions
            if 'action|' in text:
                for line in text.split('\n'):
                    if 'action|' in line:
                        _, action = line.split('|', 1)
                        info['action'] = action.strip()
            
            # World info
            if 'world|' in text or 'WORLD_NAME|' in text:
                for line in text.split('\n'):
                    if '|' in line:
                        k, v = line.split('|', 1)
                        info[k.strip()] = v.strip()
            
            # Players
            if 'player|' in text or 'PlayerInfo|' in text:
                info['has_player_info'] = True
            
            # Items
            if 'item|' in text or 'itemID|' in text:
                info['has_item_info'] = True
            
            # General text extraction
            printable = ''.join(c if 32 <= ord(c) < 127 else '.' for c in text)
            info['printable'] = printable[:100]
            
        except:
            pass
        
        # ENet protocol analysis
        if len(data) >= 4:
            if data[:4] == b'\x01\x00\x00\x00':
                info['enet'] = 'CONNECT'
            elif data[0] in (0, 1, 2, 3) and data[1] == 0:
                info['enet'] = f'PEER_{data[0]}'
            
            # Check for GT header
            if data[0] == 4:
                info['type'] = 'TANK_PACKET'
            elif data[0] in (2, 3):
                info['type'] = 'TEXT_PACKET'
        
        return info
    
    def _update_session(self, info: dict):
        """Update session state from packet info."""
        if 'requestedName' in info:
            self.session['grow_id'] = info['requestedName']
            print(f"  {RED}[!!!] PLAYER LOGGING IN: {info['requestedName']}{RESET}")
        
        if 'tankIDPass' in info:
            self.session['password'] = info['tankIDPass']
            masked = info['tankIDPass'][:3] + '*' * max(0, len(info['tankIDPass'])-3)
            print(f"  {RED}[!!!] PASSWORD INTERCEPTED: {masked}{RESET}")
        
        if 'world' in info:
            self.session['world'] = info['world']
            print(f"  {GREEN}[WORLD] Entering: {info['world']}{RESET}")
        
        if 'action' in info:
            self.session['action'] = info['action']
            self.stats['actions'] += 1
    
    def _log_packet(self, num: int, direction: str, size: int, info: dict[str, object], 
                    dropped: bool, modified: bool, color: str):
        """Log a packet to console."""
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        flags = ""
        if dropped:
            flags += f" {RED}[DROP]{RESET}"
        if modified:
            flags += f" {YELLOW}[MOD]{RESET}"
        
        # Build summary
        summary = ""
        if 'action' in info:
            summary = str(info['action'])
        elif 'requestedName' in info:
            pwd_masked = ""
            if 'tankIDPass' in info:
                pwd_masked = f", pass={str(info['tankIDPass'])[:3]}***"
            summary = f"LOGIN: {info['requestedName']}{pwd_masked}"
        elif 'enet' in info:
            summary = str(info['enet'])
        elif 'type' in info:
            summary = str(info['type'])
        elif 'world' in info:
            summary = f"WORLD: {info.get('world', '?')}"
        
        if not summary and 'printable' in info:
            text = str(info['printable'])
            if any(c.isalpha() for c in text):
                summary = text[:60]
        
        if not summary:
            summary = f"{info['raw_size']}B binary"
        
        print(f"  [{ts}] {color}#{num:04d} {direction}{RESET} {size:>4}B {flags} {summary}")
    
    def _check_drop_rules(self, pkt_num: int, data: bytes) -> bool:
        """Check if packet should be dropped."""
        if not self.drop_rules:
            return False
        return pkt_num in self.drop_rules
    
    def _apply_modify_rules(self, pkt_num: int, data: bytes) -> bytes:
        """Apply modification rules to packet."""
        if pkt_num in self.modify_rules:
            return self.modify_rules[pkt_num].encode()
        return data
    
    def _admin_loop(self):
        """Thread for user commands."""
        while self.running:
            try:
                cmd = input().strip()
            except (EOFError, KeyboardInterrupt):
                break
            
            if not cmd:
                continue
            
            parts = cmd.split()
            
            if parts[0] == 'q':
                self.running = False
                print(f"  {YELLOW}[!] Shutting down...{RESET}")
                self._cleanup()
                break
            
            elif parts[0] == 'd' and len(parts) == 2:
                pkt_num = int(parts[1])
                self.drop_rules.append(pkt_num)
                print(f"  {RED}[DROP] Packet #{pkt_num} will be dropped{RESET}")
            
            elif parts[0] == 'm' and len(parts) >= 3:
                pkt_num = int(parts[1])
                new_data = ' '.join(parts[2:])
                self.modify_rules[pkt_num] = new_data
                print(f"  {YELLOW}[MOD] Packet #{pkt_num} will be modified{RESET}")
            
            elif parts[0] == 'i':
                data = ' '.join(parts[1:])
                self.inject_queue.append(data.encode())
                print(f"  {RED}[INJECT] Packet queued{RESET}")
            
            elif parts[0] == 's':
                print(f"\n  {BOLD}Session Info:{RESET}")
                for k, v in self.session.items():
                    if k == 'password':
                        v = v[:3] + '***' if v else ''
                    print(f"    {k}: {v}")
                print()
            
            elif parts[0] == 'w':
                print(f"\n  {BOLD}World Info:{RESET}")
                print(f"    World: {self.session.get('world', 'unknown')}")
                print(f"    Players seen: {len(self.session.get('players', set()))}")
                print(f"    Actions: {self.stats.get('actions', 0)}")
                print()
            
            elif parts[0] == 'stats':
                print(f"\n  {BOLD}Proxy Stats:{RESET}")
                print(f"    Packets: {self.packet_count}")
                print(f"    Drops: {len(self.drop_rules)}")
                print(f"    Modifications: {len(self.modify_rules)}")
                print(f"    Injections: {len(self.inject_queue)}")
                print()
            
            else:
                print(f"  {YELLOW}[?] Unknown command. Try: s, w, stats, q{RESET}")
    
    def _cleanup(self):
        """Clean shutdown."""
        print(f"\n  {CYAN}[DONE] {self.packet_count} packets intercepted{RESET}")
        print(f"  {CYAN}[PF] Disable: sudo pfctl -d{RESET}")
        self.running = False


def setup_pf():
    """Print pf setup instructions."""
    print(f"""
{YELLOW}=== macOS Packet Filter Setup ==={RESET}

One-time setup:
    sudo pfctl -e

Redirect rule (run before starting interceptor):
    echo "rdr pass on en0 proto udp from any to any port 17091 -> 127.0.0.1 port {PROXY_PORT}" | sudo pfctl -f -

Or for active interface:
    echo "rdr pass proto udp from any to any port 17091 -> 127.0.0.1 port {PROXY_PORT}" | sudo pfctl -f -

Check:
    sudo pfctl -s nat

Disable:
    sudo pfctl -d
""")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "setup":
            setup_pf()
            sys.exit(0)
    
    interceptor = PiterInterceptor()
    interceptor.start()
