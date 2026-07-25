#!/usr/bin/env python3
"""
Piter Interceptor v4 — Auto MITM Proxy
======================================
Self-contained MITM for Growtopia on macOS / Linux.
NO pf, NO DNS override needed — just run and open GT.

HOW IT WORKS:
  Binds to 0.0.0.0:17091 directly. Your GT client must be DNS-redirected
  to this machine (or localhost). Pair with /etc/hosts:
    127.0.0.1 www.growtopia1.com
    103.129.148.178 logingtps.preman.my.id  (loginurl — keep real)

  For local machine usage, use the auto-mode that detects if GT connects.

MODES:
  python3 piter_intercept.py local   — for same machine as GT (default)
  python3 piter_intercept.py remote  — for remote MITM
  
REQUIRES: Python 3.7+, root/sudo only.
"""

import socket
import struct
import sys
import time
import select
import threading
import os
import subprocess
import re
from datetime import datetime
from collections import defaultdict

PITER_IP = "103.129.148.178"
PITER_PORT = 17091

# ──── ANSI ────
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
BOLD = '\033[1m'
RESET = '\033[0m'
MAGENTA = '\033[95m'


class PiterInterceptor:
    """Full MITM proxy — intercept, view, modify, drop, inject."""
    
    def __init__(self, mode='local'):
        self.mode = mode
        self.running = True
        self.packet_count = 0
        self.listen_sock = None
        self.client_addr = None
        
        self.session = {
            'grow_id': '',
            'password': '',
            'token': '',
            'uid': '',
            'world': '',
            'players': set(),
            'actions': [],
            'last_activity': 0,
        }
        
        self.drop_rules = set()
        self.modify_rules = {}
        self.inject_queue = []
        self.stored_packets = []
        self.stats = defaultdict(int)
    
    def start(self):
        print(f"\n{BOLD}{CYAN}{'═'*50}{RESET}")
        print(f"{BOLD}{CYAN}  PITER INTERCEPTOR v4 — Auto MITM{RESET}")
        print(f"{BOLD}{CYAN}{'═'*50}{RESET}")
        print(f"\n  {YELLOW}Mode:{RESET} {self.mode}")
        print(f"  {YELLOW}Listen:{RESET} 0.0.0.0:{PITER_PORT}")
        print(f"  {YELLOW}Target:{RESET} {PITER_IP}:{PITER_PORT}")
        print()
        
        if self.mode == 'local':
            print(f"  {GREEN}[SETUP] Make sure /etc/hosts has:{RESET}")
            print(f"    127.0.0.1 www.growtopia1.com")
            print(f"    (Keep logingtps.preman.my.id → {PITER_IP})")
            print()
        
        print(f"  {BOLD}Commands:{RESET}")
        print(f"  s          — Session (GrowID, password, world)")
        print(f"  w          — World info + players")
        print(f"  d <N>      — Drop packet #N")
        print(f"  m <N> <T>  — Modify packet #N content")
        print(f"  i <TEXT>   — Inject action packet")
        print(f"  x <TEXT>   — Inject ENET raw packet")
        print(f"  p <N>      — Replay packet #N")
        print(f"  stats      — Proxy statistics")
        print(f"  q          — Quit")
        print()
        
        # Start admin thread
        admin_thread = threading.Thread(target=self._admin_loop, daemon=True)
        admin_thread.start()
        
        self._main_loop()
    
    def _main_loop(self):
        """Main MITM loop."""
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.listen_sock.bind(('0.0.0.0', PITER_PORT))
        except PermissionError:
            print(f"  {RED}[!] Need root to bind port 17091.{RESET}")
            print(f"  {RED}[!] Run: sudo python3 piter_intercept.py local{RESET}")
            self.running = False
            return
        except OSError as e:
            print(f"  {RED}[!] Can't bind port 17091: {e}{RESET}")
            print(f"  {RED}[!] Port might be in use. Kill GT first.{RESET}")
            self.running = False
            return
        
        forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        forward_sock.settimeout(0.5)
        
        stored_packets = []  # For replay
        pending_responses = {}  # client_addr → server response
        
        print(f"  {GREEN}[READY] Waiting for GT client... (open Growtopia now){RESET}")
        print(f"  {YELLOW}         Login URL still uses real server: {PITER_IP}:443{RESET}")
        print()
        
        while self.running:
            try:
                data, addr = self.listen_sock.recvfrom(65535)
            except (OSError, socket.timeout):
                continue
            
            self.packet_count += 1
            pkt_num = self.packet_count
            self.session['last_activity'] = time.time()
            
            # First packet from client → store as client addr
            if self.client_addr is None and addr[0] != PITER_IP:
                self.client_addr = addr
                print(f"  {GREEN}[CONNECTED] GT client detected: {addr[0]}:{addr[1]}{RESET}\n")
            
            # Direction
            if addr[0] == PITER_IP:
                direction = "←"
                is_from_server = True
            else:
                direction = "→"
                is_from_server = False
            
            # Analyze
            info = self._analyze(data)
            info['size'] = len(data)
            info['pkt_num'] = pkt_num
            
            # Store for replay
            stored_packets.append(data)
            
            # Check drop
            should_drop = pkt_num in self.drop_rules or info.get('drop_trigger', False)
            
            # Check modify
            original = data
            if pkt_num in self.modify_rules:
                new_text = self.modify_rules[pkt_num]
                data = new_text.encode() if isinstance(new_text, str) else new_text
                was_modified = True
            else:
                was_modified = False
            
            # Log
            self._log(pkt_num, direction, info, should_drop, was_modified)
            
            # Update session
            self._update_session(info)
            
            # If from GT client and not dropped → forward to Piter
            if not is_from_server and not should_drop:
                try:
                    forward_sock.sendto(data, (PITER_IP, PITER_PORT))
                    
                    # Get server response
                    try:
                        resp, _ = forward_sock.recvfrom(65535)
                        if resp:
                            self.packet_count += 1
                            resp_info = self._analyze(resp)
                            resp_info['size'] = len(resp)
                            self._log(self.packet_count, "←", resp_info, False, False)
                            self._update_session(resp_info)
                            stored_packets.append(resp)
                            
                            # Send back to GT client
                            self.listen_sock.sendto(resp, addr)
                    except socket.timeout:
                        pass
                    
                except Exception as e:
                    print(f"  {RED}[ERR] Forward failed: {e}{RESET}")
            
            # If from Piter server → send back to GT client directly
            elif is_from_server and not should_drop:
                if self.client_addr:
                    self.listen_sock.sendto(data, self.client_addr)
            
            # Process injection queue
            if self.inject_queue and self.client_addr:
                inj = self.inject_queue.pop(0)
                print(f"  {MAGENTA}[INJECT] {inj[:80]}{RESET}")
                forward_sock.sendto(inj.encode() if isinstance(inj, str) else inj, 
                                   (PITER_IP, PITER_PORT))
    
    def _analyze(self, data: bytes) -> dict:
        """Extract all readable info from packet."""
        info = {'raw': data}
        
        if len(data) < 4:
            info['type'] = 'tiny'
            return info
        
        # ENet header
        if data[:4] == b'\x01\x00\x00\x00':
            info['enet'] = 'CONNECT'
            info['type'] = 'handshake'
        elif len(data) >= 4 and data[1] == 0 and data[2] == 0 and data[3] == 0:
            if data[0] == 0:
                info['enet'] = 'VERIFY'
            else:
                info['enet'] = f'PEER{data[0]}'
        
        # Try text decode
        try:
            text = data.decode('utf-8', errors='ignore')
            
            # Login fields (pipe-delimited)
            for field in ['requestedName', 'tankIDName', 'tankIDPass',
                          'password', 'growId', '_token', 'ltoken',
                          'country', 'mac', 'game_version', 'platformID']:
                if field in text:
                    idx = text.find(field)
                    end = text.find('\n', idx) if '\n' in text[idx:] else len(text)
                    line = text[idx:end]
                    if '|' in line:
                        _, val = line.split('|', 1)
                    else:
                        val = line
                    info[field] = val.strip()[:100]
            
            # Actions
            if 'action|' in text:
                idx = text.find('action|')
                end = text.find('\n', idx) if '\n' in text[idx:] else len(text)
                line = text[idx:end]
                if '|' in line:
                    info['action'] = line.split('|', 1)[1].strip()[:80]
            
            # Messages
            if 'msg|' in text:
                idx = text.find('msg|')
                end = text.find('\n', idx) if '\n' in text[idx:] else len(text)
                line = text[idx:end]
                if '|' in line:
                    info['message'] = line.split('|', 1)[1].strip()[:80]
            
            # World name
            for key in ['world', 'WORLD_NAME', 'worldName', 'name']:
                if key + '|' in text:
                    idx = text.find(key + '|')
                    end = text.find('\n', idx) if '\n' in text[idx:] else len(text)
                    line = text[idx:end]
                    if '|' in line:
                        info['world'] = line.split('|', 1)[1].strip()[:80]
            
            # Player info
            if 'PlayerInfo' in text or 'playerInfo' in text or 'netID|' in text:
                info['has_players'] = True
            
            # Items
            if 'itemID' in text or 'item|' in text or 'inventory' in text.lower():
                info['has_items'] = True
            
            # Extract all pipe fields
            all_fields = {}
            for line in text.split('\n'):
                if '|' in line:
                    key, _, val = line.partition('|')
                    all_fields[key.strip()] = val.strip()
            if all_fields:
                info['fields'] = all_fields
            
            # Readable text
            printable = text[:200].replace('\n', '↵').replace('\r', '')
            printable = ''.join(c if 32 <= ord(c) < 127 or c == '↵' else '.' for c in printable)
            info['text'] = printable[:200]
            
        except:
            pass
        
        # GT packet type
        if len(data) >= 4 and data[0] == 4:
            info['gt_type'] = 'TANK'
        elif len(data) >= 1 and data[0] in (2, 3):
            info['gt_type'] = 'GAME_DATA'
        
        # Hex
        info['hex'] = data[:32].hex()
        
        return info
    
    def _log(self, num: int, direction: str, info: dict, drop: bool, mod: bool):
        """Log packet to console."""
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        size = info.get('size', 0)
        
        color = CYAN if direction == '←' else YELLOW
        if drop:
            color = RED
        elif mod:
            color = MAGENTA
        
        # Build summary
        parts = []
        
        if 'requestedName' in info:
            pw = info.get('tankIDPass', '?')
            if pw and len(pw) > 3:
                pw = pw[:3] + '***'
            parts.append(f"LOGIN: {info['requestedName']}")
        elif 'action' in info:
            parts.append(f"ACTION: {info['action'][:50]}")
        elif 'world' in info:
            parts.append(f"WORLD: {info['world']}")
        elif 'message' in info:
            parts.append(f"MSG: {info['message'][:50]}")
        elif 'enet' in info:
            parts.append(info['enet'])
        elif 'fields' in info and info['fields']:
            keys = list(info['fields'].keys())[:3]
            parts.append(f"FIELDS: {keys}")
        elif 'text' in info:
            text = info['text']
            if any(c.isalpha() for c in text[:10]):
                parts.append(f"TEXT: {text[:60]}")
            else:
                parts.append(f"{size}B binary")
        else:
            parts.append(f"{size}B")
        
        summary = ' | '.join(parts) if parts else f"{size}B"
        
        flags = ''
        if drop:
            flags = f'{RED}[DROP]{RESET} '
        if mod:
            flags += f'{MAGENTA}[MOD]{RESET} '
        
        print(f"  [{ts}] {color}#{num:04d} {direction}{RESET} {size:>4}B {flags}{summary}")
    
    def _update_session(self, info: dict):
        """Update session state from packet."""
        if 'requestedName' in info:
            self.session['grow_id'] = info['requestedName']
            print(f"  {RED}{BOLD}[!!!] PLAYER: {info['requestedName']}{RESET}")
        
        if 'tankIDPass' in info:
            pw = info['tankIDPass']
            self.session['password'] = pw
            masked = pw[:3] + '*' * max(0, len(pw) - 3) if pw else '(empty)'
            print(f"  {RED}{BOLD}[!!!] PASSWORD: {masked}{RESET}")
        
        if 'token' in info or '_token' in info:
            tok = info.get('token') or info.get('_token')
            self.session['token'] = tok
        
        if 'world' in info:
            self.session['world'] = info['world']
            print(f"  {GREEN}[WORLD] → {info['world']}{RESET}")
        
        if 'action' in info:
            self.session['actions'].append(info['action'])
            if 'enter_game' in info['action']:
                print(f"  {GREEN}[GAME] Player entered world!{RESET}")
            elif 'quit' in info['action'] or 'disconnect' in info['action']:
                print(f"  {YELLOW}[GAME] Player left{RESET}")
        
        if info.get('has_players'):
            fields = info.get('fields', {})
            for k, v in fields.items():
                if 'name' in k.lower() or 'player' in k.lower():
                    self.session['players'].add(v)
    
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
            op = parts[0].lower()
            
            if op == 'q':
                self.running = False
                self._cleanup()
                break
            
            elif op == 's':
                self._show_session()
            
            elif op == 'w':
                self._show_world()
            
            elif op == 'd':
                if len(parts) >= 2:
                    try:
                        n = int(parts[1])
                        self.drop_rules.add(n)
                        print(f"  {RED}[DROP] Packet #{n} will be dropped{RESET}")
                    except:
                        print(f"  {YELLOW}[?] Usage: d <packet_num>{RESET}")
                else:
                    print(f"  {YELLOW}[?] Usage: d <packet_num>{RESET}")
            
            elif op == 'm':
                if len(parts) >= 3:
                    try:
                        n = int(parts[1])
                        text = ' '.join(parts[2:])
                        self.modify_rules[n] = text
                        print(f"  {MAGENTA}[MOD] Packet #{n} → \"{text[:60]}\"{RESET}")
                    except:
                        print(f"  {YELLOW}[?] Usage: m <packet_num> <new_text>{RESET}")
                else:
                    print(f"  {YELLOW}[?] Usage: m <packet_num> <new_text>{RESET}")
            
            elif op == 'i':
                if len(parts) >= 2:
                    text = ' '.join(parts[1:])
                    self.inject_queue.append(f"action|{text}\n")
                    print(f"  {MAGENTA}[INJECT] Queued: action|{text}{RESET}")
                else:
                    print(f"  {YELLOW}[?] Usage: i <action_text>{RESET}")
            
            elif op == 'x':
                if len(parts) >= 2:
                    text = ' '.join(parts[1:])
                    self.inject_queue.append(f"{text}\n")
                    print(f"  {MAGENTA}[INJECT] Queued raw: {text}{RESET}")
                else:
                    print(f"  {YELLOW}[?] Usage: x <raw_data>{RESET}")
            
            elif op == 'p':
                if len(parts) >= 2:
                    try:
                        n = int(parts[1])
                        if 0 <= n < len(self.stored_packets):
                            data = self.stored_packets[n]
                            self.inject_queue.append(data)
                            print(f"  {MAGENTA}[REPLAY] Replaying packet #{n}{RESET}")
                        else:
                            print(f"  {YELLOW}[?] Packet #{n} not in buffer{RESET}")
                    except:
                        pass
                else:
                    print(f"  {YELLOW}[?] Usage: p <packet_num>{RESET}")
            
            elif op == 'stats':
                print(f"\n  {BOLD}Proxy Stats:{RESET}")
                print(f"    Packets: {self.packet_count}")
                print(f"    Drops: {len(self.drop_rules)} pending")
                print(f"    Mods: {len(self.modify_rules)} pending")
                print(f"    Injections: {len(self.inject_queue)} queued")
                print(f"    Session: {self.session['grow_id'] or '(waiting)'}")
                print()
            
            elif op == 'h':
                print(f"\n  {BOLD}Commands:{RESET}")
                print(f"  s | w | stats | q")
                print(f"  d <N>           — Drop packet N")
                print(f"  m <N> <TEXT>    — Replace packet N with TEXT")
                print(f"  i <ACTION>      — Inject action|ACTION")
                print(f"  x <RAW>         — Inject raw data")
                print(f"  p <N>           — Replay saved packet N")
                print()
            
            else:
                print(f"  {YELLOW}[?] Unknown. Type 'h' for help.{RESET}")
    
    def _show_session(self):
        print(f"\n  {BOLD}{'═'*40}{RESET}")
        print(f"  {BOLD}  Session Info{RESET}")
        print(f"  {'═'*40}")
        for k, v in self.session.items():
            if k == 'password' and v:
                v = v[:3] + '*' * max(0, len(v) - 3)
            elif k == 'actions':
                v = v[-5:] if v else '[]'
            elif k == 'players':
                v = list(v)[:10]
            print(f"  {k:>15}: {v}")
        print()
    
    def _show_world(self):
        players = self.session.get('players', set())
        print(f"\n  {BOLD}{'═'*40}{RESET}")
        print(f"  {BOLD}  World Info{RESET}")
        print(f"  {'═'*40}")
        print(f"  World:     {self.session.get('world', 'unknown')}")
        print(f"  Players:   {len(players)}")
        if players:
            for i, p in enumerate(list(players)[:20], 1):
                print(f"    {i}. {p}")
        print(f"  Actions:   {len(self.session.get('actions', []))}")
        if self.session['actions']:
            for a in self.session['actions'][-10:]:
                print(f"    → {a}")
        print()
    
    def _cleanup(self):
        print(f"\n  {CYAN}{'═'*40}{RESET}")
        print(f"  {CYAN}  Session Summary{RESET}")
        print(f"  {CYAN}{'═'*40}{RESET}")
        print(f"  Packets:   {self.packet_count}")
        print(f"  GrowID:    {self.session['grow_id'] or '(none)'}")
        print(f"  World:     {self.session['world'] or '(none)'}")
        print(f"  Players:   {len(self.session['players'])}")
        print(f"  Actions:   {len(self.session['actions'])}")
        print()
        self.running = False


def detect_interface():
    """Auto-detect active network interface on macOS."""
    try:
        out = subprocess.check_output(['route', '-n', 'get', 'default'], 
                                       stderr=subprocess.DEVNULL, timeout=3).decode()
        for line in out.split('\n'):
            m = re.search(r'interface:\s+(\S+)', line)
            if m:
                return m.group(1)
    except:
        pass
    return 'en0'


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else 'local'
    
    if mode == 'local':
        # Auto-detect interface and show /etc/hosts instruction
        iface = detect_interface()
        print(f"\n  {YELLOW}Detected interface:{RESET} {iface}")
        
    interceptor = PiterInterceptor(mode=mode)
    interceptor.start()
