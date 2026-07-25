#!/usr/bin/env python3
"""
Piter Cheat Engine — Frida-based Growtopia Hook
================================================
Phase 1: Hook ENet send/recv, capture GrowID, password, tokens.
Works on Mac (Frida v7+).

Usage:
  pip3 install frida-tools
  python3 piter_cheat.py          # auto-attach to Growtopia
  python3 piter_cheat.py --debug  # verbose mode

Requirements:
  - Growtopia running (logged in)
  - Frida installed
  - Root/sudo (for task_for_pid)
"""

import sys
import time
import frida
import subprocess
import json
from datetime import datetime


# ──── Cheat Engine ────
class PiterCheat:
    def __init__(self, debug=False):
        self.debug = debug
        self.session = None
        self.script = None
        self.packets = []
        self.exfiltrated = []
        self.player_info = {
            'grow_id': '',
            'password': '',
            'token': '',
            'uid': '',
            'world': '',
            'net_id': 0
        }
        self.packet_count = 0
        self.start_time = time.time()

    def find_growtopia(self):
        """Find the Growtopia process PID."""
        try:
            result = subprocess.run(
                ['pgrep', '-fl', 'Growtopia'],
                capture_output=True, text=True
            )
            lines = [l for l in result.stdout.strip().split('\n') if l]
            if not lines:
                return None

            # Filter: prefer the main process (largest PID usually)
            pids = []
            for line in lines:
                parts = line.split()
                pid = int(parts[0])
                name = ' '.join(parts[1:])
                pids.append((pid, name))
            
            if len(pids) > 1:
                pids.sort(key=lambda x: x[0], reverse=True)
                if self.debug:
                    print(f"[*] Multiple GT processes, using PID {pids[0][0]} (largest)")
            
            return pids[0][0]
        except Exception as e:
            print(f"[!] Can't find Growtopia: {e}")
            return None

    def exfiltrate(self, data):
        """Log exfiltrated data for dashboard."""
        self.exfiltrated.append(data)
        if 'grow_id' in data and not self.player_info['grow_id']:
            self.player_info['grow_id'] = data['grow_id']
        if 'password' in data and not self.player_info['password']:
            self.player_info['password'] = data['password']
        if 'token' in data:
            self.player_info['token'] = data['token']
        if 'world' in data:
            self.player_info['world'] = data['world']

    def print_dashboard(self):
        """Show live dashboard."""
        elapsed = int(time.time() - self.start_time)
        print(f"\n  PITER CHEAT — {elapsed}s | packets: {self.packet_count}")
        if self.player_info['grow_id']:
            print(f"  GrowID: {self.player_info['grow_id']}")
        if self.player_info['password']:
            print(f"  Password: {self.player_info['password']}")
        if self.player_info['world']:
            print(f"  World: {self.player_info['world']}")
        print()

    def on_message(self, message, data):
        """Handle messages from Frida agent."""
        if message['type'] == 'send':
            payload = message.get('payload', {})
            msg_type = payload.get('type', 'unknown')

            if msg_type == 'loaded':
                print(f"[!] Piter Frida Agent v8 loaded")
                if 'pid' in payload:
                    print(f"[*] Target PID: {payload['pid']}, arch: {payload.get('arch', '?')}")

            elif msg_type == 'ready' or msg_type == 'debug':
                if msg_type == 'ready':
                    results = payload.get('results', {})
                    
                    if self.debug and 'modules' in results:
                        print(f"\n  [DEBUG] System modules:")
                        for m in results['modules']:
                            print(f"    {m['name']}: {m['path']}")

                    if self.debug and 'hooks' in results:
                        print(f"\n  [DEBUG] Hook attempts:")
                        for name, info in results['hooks'].items():
                            if isinstance(info, dict):
                                status = 'OK' if info.get('ok') else f"FAIL ({info.get('flag', '?')})"
                            else:
                                status = 'OK' if info else 'FAIL'
                            print(f"    {name}: {status}")

                    send_ok = payload.get('sendHooked', False)
                    recv_ok = payload.get('recvHooked', False)
                    status = f"send: {'OK' if send_ok else 'FAIL'}, recv: {'OK' if recv_ok else 'FAIL'}"
                    print(f"\n[+] Agent ready. Hooks: {status}")

                elif msg_type == 'debug' and self.debug:
                    print(f"  [DEBUG] {payload.get('msg', '')}")

            elif msg_type == 'connected':
                fd = payload.get('fd')
                port = payload.get('port')
                print(f"[+] Socket detected: fd={fd}, port={port}")

            elif msg_type == 'packet':
                self.packet_count += 1
                dir_ = payload.get('dir', '?')
                size = payload.get('size', 0)
                info = payload.get('info', '')
                hex_ = payload.get('hex', '')
                fields = payload.get('fields', {})

                # Color and print
                color = '\033[92m' if dir_ == '→' else '\033[94m'
                reset = '\033[0m'
                ts = datetime.now().strftime("%H:%M:%S")
                
                print(f"  [{ts}] {color}{self.packet_count:04d} {dir_}{reset} {size:>4}B  {info[:80]}")

                # Capture credentials
                if 'tankIDName' in fields:
                    grow_id = fields['tankIDName']
                    password = fields.get('tankIDPass', '')
                    print(f"    [!!!] CAPTURED: GrowID={grow_id}, Password={password}")
                    self.exfiltrate({'grow_id': grow_id, 'password': password})

                if 'user' in fields:
                    print(f"    [USER] {fields['user']}")

                if 'world' in fields:
                    world = fields['world']
                    print(f"    [WORLD] {world}")
                    self.exfiltrate({'world': world})

                if 'netID' in fields:
                    print(f"    [NETID] {fields['netID']}")

                self.packets.append(payload)

            elif msg_type == 'error':
                print(f"  [!] Agent error: {payload.get('msg', payload)}")

        elif message['type'] == 'error':
            print(f"\n[!!!] Frida error: {message.get('description', message)}")

    def run(self):
        """Attach to Growtopia and inject agent."""
        pid = self.find_growtopia()
        if not pid:
            print("[!] Growtopia not running. Start it first, login, then run this.")
            print("[*] Quick start: open Growtopia → login → run: sudo python3 piter_cheat.py")
            sys.exit(1)

        print(f"[*] Attached to Growtopia (PID: {pid})")

        try:
            self.session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            print(f"[!] Process {pid} not found. Restart Growtopia then retry.")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Attachment failed: {e}")
            print("[*] Try: sudo python3 piter_cheat.py")
            sys.exit(1)

        # Load agent
        try:
            with open('piter_agent.js', 'r') as f:
                agent_code = f.read()
        except FileNotFoundError:
            import os
            script_dir = os.path.dirname(os.path.abspath(__file__))
            with open(os.path.join(script_dir, 'piter_agent.js'), 'r') as f:
                agent_code = f.read()

        self.script = self.session.create_script(agent_code)
        self.script.on('message', self.on_message)
        self.script.load()

        # Init hooks
        print("[+] Agent injected. Waiting for hooks...")
        self.script.exports.init()

        print(f"\n  Type /help for commands")
        print(f"  {'─'*50}")

        # Interactive loop
        try:
            self.interactive_loop()
        except KeyboardInterrupt:
            print("\n[*] Detaching...")
            self.session.detach()
            print("[*] Done.")

    def interactive_loop(self):
        """Simple command interface."""
        while True:
            time.sleep(0.5)

# ──── MAIN ────
if __name__ == "__main__":
    debug = '--debug' in sys.argv or '-d' in sys.argv
    
    print("")
    print("  ╔══════════════════════════════════════════╗")
    print("  ║     PITER CHEAT ENGINE — Phase 1         ║")
    print("  ║     Frida-based Growtopia Hook            ║")
    print("  ╚══════════════════════════════════════════╝")
    print("")

    cheat = PiterCheat(debug=debug)
    cheat.run()
