#!/usr/bin/env python3
"""
Mac Hermes Bridge — MCP Server
===============================
Bikin Python MCP server di Mac yang nge-forward command dari VPS ke Mac.
Ini biar gw bisa execute command di Mac lo langsung tanpa browser/RemoteTTYs.

Di Mac lo, jalanin ini:
  python3 mac_bridge.py
  
Lalu dari VPS, gw bisa:
  curl -X POST http://<MAC_IP>:9999/exec -H "X-API-Key: piter_hermes_2024" -d "cd ~/N/gtps && git pull"

Atau kalo Mac gak reachable langsung, pake mode reverse:
  python3 mac_bridge.py --reverse wss://103.253.213.178:8080/ws/agent --token piter-mac-1785004473-nbfzz3rXLtYnfvuY
"""

import asyncio
import subprocess
import json
import sys
import os
import signal
import hashlib
import base64
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

API_KEY = "piter_hermes_2024"
PORT = 9999

# ──── HTTP Server (direct mode) ────

class MacBridgeHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        parsed = urlparse(self.path)
        
        # Auth check
        api_key = self.headers.get('X-API-Key', '')
        if not self._verify(api_key):
            self.send_error(403, "Forbidden")
            return
        
        # Read body
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        
        if parsed.path == '/exec':
            cmd = body.decode('utf-8').strip()
            if not cmd:
                self._json_response({"error": "No command"})
                return
            
            try:
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True,
                    timeout=30, cwd=os.path.expanduser('~')
                )
                self._json_response({
                    "ok": True,
                    "stdout": result.stdout[-5000:],
                    "stderr": result.stderr[-2000:],
                    "exit_code": result.returncode
                })
            except subprocess.TimeoutExpired:
                self._json_response({"error": "Command timed out after 30s"})
            except Exception as e:
                self._json_response({"error": str(e)})
        
        elif parsed.path == '/health':
            self._json_response({"ok": True, "hostname": os.uname().nodename})
        
        elif parsed.path == '/upload':
            # Save file sent from VPS
            filepath = self.headers.get('X-File-Path', '/tmp/vps_upload')
            os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
            with open(filepath, 'wb') as f:
                f.write(body)
            self._json_response({"ok": True, "path": filepath, "size": len(body)})
        
        elif parsed.path == '/download':
            filepath = body.decode('utf-8').strip()
            if os.path.isfile(filepath):
                with open(filepath, 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('X-File-Size', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            else:
                self._json_response({"error": "File not found"})
        
        else:
            self._json_response({"error": "Unknown path"})
    
    def _verify(self, key):
        return hashlib.sha256((key + "salt_piter").encode()).hexdigest() == \
               hashlib.sha256((API_KEY + "salt_piter").encode()).hexdigest()
    
    def _json_response(self, data):
        resp = json.dumps(data).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)
    
    def log_message(self, format, *args):
        pass  # silent


# ──── WebSocket Client (reverse relay mode) ────

async def reverse_relay_mode(relay_url, token):
    """Connect to RemoteTTYs relay as agent, accept exec commands."""
    try:
        import websockets
    except ImportError:
        print("[!] Install: pip3 install websockets")
        return
    
    headers = {"X-Token": token}
    
    while True:
        try:
            async with websockets.connect(relay_url, extra_headers=headers) as ws:
                print(f"[+] Connected to {relay_url}")
                
                # Send hello
                hello = {
                    "type": "agent.hello",
                    "name": "MacBridge",
                    "os": "darwin",
                    "fingerprint": hashlib.sha256(token.encode()).hexdigest(),
                    "identityKey": base64.b64encode(os.urandom(32)).decode(),
                    "capabilities": ["clipboard"]
                }
                await ws.send(json.dumps(hello))
                
                # Handle pty.create by spawning shell command
                async for msg in ws:
                    data = json.loads(msg)
                    
                    if data.get("type") == "pty.create":
                        session_id = data["sessionId"]
                        shell = data.get("shell", "/bin/zsh")
                        cwd = data.get("cwd", os.path.expanduser("~"))
                        
                        # Create subprocess
                        proc = await asyncio.create_subprocess_shell(
                            f"cd {cwd}; exec {shell}",
                            stdin=asyncio.subprocess.PIPE,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.STDOUT
                        )
                        
                        # Send pty.created (with dummy encryption)
                        created = {
                            "type": "pty.created",
                            "sessionId": session_id,
                            "pid": proc.pid,
                            "publicKey": base64.b64encode(os.urandom(65)).decode(),
                            "signature": base64.b64encode(os.urandom(64)).decode()
                        }
                        await ws.send(json.dumps(created))
                        
                        # Read stdout and forward
                        async def forward_output():
                            while True:
                                line = await proc.stdout.readline()
                                if not line:
                                    break
                                pty_data = {
                                    "type": "pty.data",
                                    "sessionId": session_id,
                                    "payload": base64.b64encode(line).decode()
                                }
                                await ws.send(json.dumps(pty_data))
                        
                        asyncio.create_task(forward_output())
                    
                    elif data.get("type") == "pty.data":
                        # Execute command from browser
                        session_id = data["sessionId"]
                        decoded = base64.b64decode(data["payload"]).decode()
                        proc.stdin.write(decoded.encode())
                        await proc.stdin.drain()
                    
                    elif data.get("type") == "pty.close":
                        proc.terminate()
        
        except Exception as e:
            print(f"[!] Disconnected: {e}, reconnecting in 3s...")
            await asyncio.sleep(3)


# ──── Main ────

def main():
    parser = argparse.ArgumentParser(description="Mac Hermes Bridge")
    parser.add_argument("--reverse", help="Relay URL for reverse mode (wss://...)")
    parser.add_argument("--token", help="Agent token for reverse mode")
    parser.add_argument("--port", type=int, default=PORT, help="HTTP port (direct mode)")
    args = parser.parse_args()
    
    if args.reverse:
        print(f"[*] Reverse relay mode: {args.reverse}")
        asyncio.run(reverse_relay_mode(args.reverse, args.token or ""))
    else:
        print(f"[*] Direct mode: HTTP on port {args.port}")
        print(f"[*] API Key: {API_KEY}")
        print(f"[*] Test: curl http://localhost:{args.port}/health")
        server = HTTPServer(('0.0.0.0', args.port), MacBridgeHandler)
        signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Stopped.")


if __name__ == "__main__":
    main()
