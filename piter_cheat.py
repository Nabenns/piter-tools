#!/usr/bin/env python3
"""
Piter Cheat Engine — Frida Controller (Phase 1)
=================================================
Attaches to Growtopia process via Frida, injects piter_agent.js.
Provides CLI dashboard with live packet monitoring and command interface.

USAGE:
  python3 piter_cheat.py              # Auto-attach to Growtopia
  python3 piter_cheat.py --pid 1234   # Attach to specific PID
  
REQUIRES: pip3 install frida-tools

COMMANDS (in-app):
  /help        Show commands
  /state       Show player state (growID, world, gems)
  /packets     Show recent packets
  /scan <str>  Scan memory for string
  /watch       Continuous packet monitor (Ctrl+C to exit)
  /hook        Hook status
  /quit        Exit
"""

import frida
import sys
import time
import json
import threading
import os
from datetime import datetime

# ──── Colors ────
class C:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

BANNER = f"""
{C.MAGENTA}{C.BOLD}╔══════════════════════════════════════════╗
║     PITER CHEAT ENGINE — Phase 1         ║
║     Frida-based Growtopia Hook            ║
╚══════════════════════════════════════════╝{C.RESET}
"""

AGENT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'piter_agent.js')

# ──── Frida Controller ────
class PiterCheat:
    def __init__(self, pid=None):
        self.pid = pid
        self.session = None
        self.script = None
        self.running = False
        self.state = {}
        self.packets = []
        
    def attach(self):
        """Attach to Growtopia process."""
        if self.pid:
            try:
                self.session = frida.attach(self.pid)
                print(f"{C.GREEN}[*] Attached to PID {self.pid}{C.RESET}")
            except frida.ProcessNotFoundError:
                print(f"{C.RED}[!] PID {self.pid} not found{C.RESET}")
                sys.exit(1)
        else:
            # Auto-find Growtopia
            try:
                device = frida.get_local_device()
                processes = device.enumerate_processes()
                
                gt_procs = [p for p in processes if 'growtopia' in p.name.lower()]
                
                if not gt_procs:
                    print(f"{C.RED}[!] Growtopia not running. Start it first.{C.RESET}")
                    sys.exit(1)
                
                if len(gt_procs) == 1:
                    self.pid = gt_procs[0].pid
                else:
                    # Multiple — use the one with highest memory
                    gt_procs.sort(key=lambda x: x.parameters.get('rss', 0), reverse=True)
                    self.pid = gt_procs[0].pid
                    print(f"{C.YELLOW}[*] Multiple GT processes, using PID {self.pid} (largest){C.RESET}")
                
                self.session = frida.attach(self.pid)
                print(f"{C.GREEN}[*] Attached to Growtopia (PID: {self.pid}){C.RESET}")
            except Exception as e:
                print(f"{C.RED}[!] Failed: {e}{C.RESET}")
                print(f"{C.YELLOW}[*] Try: python3 piter_cheat.py --pid <PID>{C.RESET}")
                sys.exit(1)
        
        return True
    
    def load_agent(self):
        """Load and inject the Frida agent script."""
        if not os.path.exists(AGENT_PATH):
            print(f"{C.RED}[!] Agent not found: {AGENT_PATH}{C.RESET}")
            return False
        
        with open(AGENT_PATH) as f:
            source = f.read()
        
        self.script = self.session.create_script(source)
        
        # Message handler
        self.script.on('message', self._on_message)
        self.script.load()
        
        print(f"{C.GREEN}[+] Agent injected. Waiting for hooks...{C.RESET}")
        return True
    
    def _on_message(self, message, data):
        """Handle messages from Frida agent."""
        if message['type'] == 'error':
            print(f"{C.RED}[!] Agent error: {message.get('description', message)}{C.RESET}")
            return
        
        if message['type'] == 'send':
            payload = message.get('payload', {})
            event = payload.get('event', '')
            
            if event == 'ready':
                ok = payload.get('hooksOk', False)
                status = f"{C.GREEN}OK{C.RESET}" if ok else f"{C.RED}FAILED{C.RESET}"
                print(f"{C.GREEN}[+] Agent ready. Hooks: {status}{C.RESET}")
                if ok:
                    print(f"{C.GREEN}[+] All hooks active — monitoring packets...{C.RESET}")
            
            elif event == 'packet_out':
                ptype = payload.get('type', '?')
                summary = payload.get('summary', '')
                size = payload.get('size', 0)
                
                # Color by type
                if 'LOGIN' in ptype:
                    color = C.YELLOW + C.BOLD
                elif 'GAME_ACTION' in ptype:
                    color = C.CYAN
                elif 'TILE' in ptype:
                    color = C.MAGENTA
                else:
                    color = C.DIM
                
                ts = datetime.now().strftime('%H:%M:%S')
                print(f"  {color}[{ts}] → {C.RESET}{color}{size:>4}B {ptype:>15s}{C.RESET} {summary}")
                
                if 'LOGIN' in ptype:
                    print(f"  {C.YELLOW}{C.BOLD}[!!!] LOGIN INTERCEPTED! Run /state for details{C.RESET}")
            
            elif event == 'packet_in':
                ptype = payload.get('type', '?')
                summary = payload.get('summary', '')
                size = payload.get('size', 0)
                
                ts = datetime.now().strftime('%H:%M:%S')
                
                if 'WORLD' in ptype:
                    color = C.GREEN + C.BOLD
                else:
                    color = C.BLUE
                
                if summary:
                    print(f"  {color}[{ts}] ← {C.RESET}{color}{size:>4}B {ptype:>15s}{C.RESET} {summary}")
            
            elif event == 'state':
                self.state = payload.get('data', {})
            
            elif event == 'scan_result':
                results = payload.get('data', [])
                print(f"\n{C.BOLD}  Memory scan results:{C.RESET}")
                for r in results[:10]:
                    addr = r.get('address', '?')
                    val = r.get('value', '?')[:80]
                    print(f"  {C.CYAN}{addr}{C.RESET}: {val}")
            
            elif event == 'packets':
                pkts = payload.get('data', [])
                self.packets = pkts
                self._show_packets(pkts)
            
            elif event == 'hook_stats':
                print(f"\n{C.BOLD}  Hook Status:{C.RESET}")
                print(f"  Hooks active: {payload.get('hooks', False)}")
                print(f"  Packets: {payload.get('packets', 0)}")
                print(f"  GrowID: {payload.get('growId', '?')}")
                print(f"  World: {payload.get('world', '?')}")
            
            elif event == 'error':
                print(f"{C.RED}[!] {payload.get('msg', 'Error')}{C.RESET}")
    
    def _show_packets(self, pkts):
        """Display recent packets."""
        if not pkts:
            print("  No packets yet.")
            return
        
        print(f"\n{C.BOLD}  Recent Packets ({len(pkts)}):{C.RESET}")
        print(f"  {'─'*70}")
        
        for i, p in enumerate(pkts[:15]):
            d = p.get('dir', '?')
            t = p.get('type', '?')
            s = p.get('size', 0)
            summary = p.get('summary', '')[:60]
            hex_str = p.get('hex', '')[:40]
            
            arrow = '→' if d == 'OUT' else '←'
            color = C.GREEN if d == 'OUT' else C.BLUE
            
            print(f"  {C.DIM}{i+1:02d}{C.RESET} {color}{arrow}{C.RESET} {s:>4}B {t:>15s} {C.DIM}{summary}{C.RESET}")
            if hex_str:
                print(f"      {C.DIM}{hex_str}{C.RESET}")
    
    def cmd_state(self):
        """Show player state."""
        self.script.exports.send_command({'cmd': 'state'})
        time.sleep(0.2)
        
        if self.state:
            print(f"\n{C.BOLD}  Player State:{C.RESET}")
            for k, v in self.state.items():
                print(f"  {k}: {C.CYAN}{v}{C.RESET}")
        else:
            self.script.exports.send_command({'cmd': 'hook_stats'})
    
    def cmd_packets(self, count=10):
        """Show recent packets."""
        self.script.exports.send_command({'cmd': 'packets', 'count': count})
    
    def cmd_scan(self, term):
        """Scan memory for string."""
        print(f"{C.YELLOW}[*] Scanning for '{term}'...{C.RESET}")
        self.script.exports.send_command({'cmd': 'scan', 'term': term})
    
    def cmd_hook(self):
        """Show hook stats."""
        self.script.exports.send_command({'cmd': 'hook_stats'})
    
    def cmd_watch(self):
        """Continuous packet watch mode."""
        print(f"\n{C.BOLD}  Watch Mode — Ctrl+C to stop{C.RESET}")
        print(f"  {'─'*70}")
        
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print(f"\n{C.YELLOW}[*] Watch stopped.{C.RESET}")
    
    def cmd_inject(self, data_hex):
        """Inject raw packet."""
        print(f"{C.RED}[!] Injection not yet safe — could crash client{C.RESET}")
        # self.script.exports.send_command({'cmd': 'inject', 'data': data_hex})
    
    def run(self):
        """Main loop — CLI command interface."""
        self.running = True
        
        print(f"\n{C.GREEN}  Type /help for commands{C.RESET}")
        
        while self.running:
            try:
                cmd = input(f"\n{C.MAGENTA}piter>{C.RESET} ").strip()
                
                if not cmd:
                    continue
                
                if cmd == '/help':
                    print(f"""
{C.BOLD}  Piter Cheat — Commands{C.RESET}
  {C.GREEN}/state{C.RESET}      Show player state (growID, world, gems)
  {C.GREEN}/packets [N]{C.RESET} Show last N packets (default: 10)
  {C.GREEN}/scan <str>{C.RESET}  Scan Growtopia memory for string
  {C.GREEN}/watch{C.RESET}       Continuous packet monitor
  {C.GREEN}/hook{C.RESET}        Show hook status
  {C.GREEN}/quit{C.RESET}        Exit
""")
                
                elif cmd.startswith('/state'):
                    self.cmd_state()
                
                elif cmd.startswith('/packets'):
                    parts = cmd.split()
                    count = int(parts[1]) if len(parts) > 1 else 10
                    self.cmd_packets(count)
                    time.sleep(0.3)
                
                elif cmd.startswith('/scan'):
                    parts = cmd.split()
                    if len(parts) < 2:
                        print(f"{C.RED}[!] Usage: /scan <search_term>{C.RESET}")
                    else:
                        term = ' '.join(parts[1:])
                        self.cmd_scan(term)
                        time.sleep(0.5)
                
                elif cmd == '/watch':
                    self.cmd_watch()
                
                elif cmd == '/hook':
                    self.cmd_hook()
                    time.sleep(0.3)
                
                elif cmd.startswith('/inject'):
                    parts = cmd.split()
                    if len(parts) < 2:
                        print(f"{C.RED}[!] Usage: /inject <hex_data>{C.RESET}")
                    else:
                        self.cmd_inject(parts[1])
                
                elif cmd == '/quit':
                    self.running = False
                    print(f"{C.YELLOW}[*] Detaching...{C.RESET}")
                
                else:
                    print(f"{C.RED}[?] Unknown: {cmd}. Type /help{C.RESET}")
            
            except KeyboardInterrupt:
                self.running = False
            except Exception as e:
                print(f"{C.RED}[!] Error: {e}{C.RESET}")
    
    def detach(self):
        """Cleanup."""
        if self.script:
            try:
                self.script.unload()
            except:
                pass
        if self.session:
            try:
                self.session.detach()
            except:
                pass
        print(f"{C.YELLOW}[*] Detached.{C.RESET}")


# ──── Install Check ────
def check_frida():
    try:
        import frida
        return True
    except ImportError:
        return False


def main():
    print(BANNER)
    
    # Parse args
    import argparse
    parser = argparse.ArgumentParser(description='Piter Cheat Engine — Frida Controller')
    parser.add_argument('--pid', type=int, help='Growtopia PID')
    args = parser.parse_args()
    
    if not check_frida():
        print(f"{C.RED}[!] Frida not installed.{C.RESET}")
        print(f"{C.YELLOW}[*] Install: pip3 install frida-tools{C.RESET}")
        sys.exit(1)
    
    cheat = PiterCheat(pid=args.pid)
    
    try:
        cheat.attach()
        cheat.load_agent()
        
        # Small delay for hooks to initialize
        time.sleep(1)
        
        cheat.run()
    except Exception as e:
        print(f"{C.RED}[!] Fatal: {e}{C.RESET}")
    finally:
        cheat.detach()


if __name__ == '__main__':
    main()
