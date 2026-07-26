#!/usr/bin/env python3
"""
Piter Cheat Engine v11 — UDP sendto/recvfrom hook
Test: sudo python3 piter_cheat_v11.py
"""
import sys, time, threading, json, signal
import frida

DEBUG = '--debug' in sys.argv

class PiterCheat:
    def __init__(self):
        self.session = None
        self.script = None
        self.running = True
        self.packets = []

    def on_message(self, msg, data):
        if msg['type'] == 'log':
            print(msg['payload'])
        elif msg['type'] == 'send':
            payload = msg.get('payload', '')
            if isinstance(payload, dict) and payload.get('type') == 'packet':
                print(f"\n{'='*60}")
                print(f"[{payload['dir']}] #{payload['num']} | {payload['size']} bytes")
                print(f"HEX: {payload['hex']}")
                print(f"{'='*60}")
                self.packets.append(payload)
            else:
                print(f"[agent] {payload}")

    def attach(self, pid=None):
        try:
            if pid:
                self.session = frida.attach(pid)
            else:
                self.session = frida.attach('Growtopia')
            print(f"[+] Attached to Growtopia (PID: {self.session._impl.pid})")

            with open('/Users/dangshafinaismirajarlaputri/N/gtps/piter-tools/piter_agent_v11.js') as f:
                agent_code = f.read()

            self.script = self.session.create_script(agent_code)
            self.script.on('message', self.on_message)
            self.script.load()
            print("[+] Agent v11 injected — hooking sendto/recvfrom")
            print("[*] Buka Growtopia & connect ke server...")

            signal.signal(signal.SIGINT, lambda s, f: self.stop())
            while self.running:
                time.sleep(1)

        except frida.ProcessNotFoundError:
            print("[!] Growtopia not running. Start it first.")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error: {e}")
            self.stop()

    def stop(self):
        self.running = False
        if self.script:
            try:
                self.script.unload()
            except: pass
        if self.session:
            try:
                self.session.detach()
            except: pass
        print(f"\n[*] Stopped. {len(self.packets)} packets captured.")

if __name__ == '__main__':
    pid = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else None
    cheat = PiterCheat()
    cheat.attach(pid)
