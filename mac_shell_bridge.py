#!/usr/bin/env python3
"""
Mac Shell Bridge — HTTP daemon untuk remote execution
=====================================================
Running di Mac, expose local port 9999.
Dipasangkan dengan bore tunnel (bore.pub) untuk akses dari VPS.

USAGE:
  python3 mac_shell_bridge.py          # Start daemon di port 9999
  bore local 9999 --to bore.pub        # Buka tunnel (di terminal terpisah)

API:
  GET  /health              → {"ok": true, "hostname": "...", "user": "..."}
  POST /exec  {"cmd":"..."} → {"ok": true, "stdout": "...", "stderr": "...", "code": 0}
"""

import http.server
import json
import subprocess
import sys
import os
import platform
import socket

PORT = 9999
ALLOWED_IPS = None  # None = allow all (bore tunnels through public internet)


class ShellHandler(http.server.BaseHTTPRequestHandler):
    """Handle /health and /exec endpoints."""
    
    def log_message(self, format, *args):
        """Silent logging."""
        pass
    
    def _send_json(self, data, status=200):
        """Send JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def do_GET(self):
        if self.path == "/health":
            self._send_json({
                "ok": True,
                "hostname": socket.gethostname(),
                "user": os.environ.get("USER", "unknown"),
                "platform": platform.platform(),
                "python": sys.version.split()[0],
                "cwd": os.getcwd(),
            })
        else:
            self._send_json({"ok": False, "error": "Not found"}, 404)
    
    def do_POST(self):
        if self.path != "/exec":
            self._send_json({"ok": False, "error": "Not found"}, 404)
            return
        
        # Read request body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        
        try:
            req = json.loads(body)
        except json.JSONDecodeError:
            self._send_json({"ok": False, "error": "Invalid JSON"}, 400)
            return
        
        cmd = req.get("cmd", "")
        timeout = req.get("timeout", 30)
        workdir = req.get("cwd")
        
        if not cmd:
            self._send_json({"ok": False, "error": "Missing 'cmd' field"}, 400)
            return
        
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=workdir,
                env={**os.environ, "PYTHONUNBUFFERED": "1"},
            )
            
            self._send_json({
                "ok": True,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "code": result.returncode,
                "cmd": cmd,
            })
        except subprocess.TimeoutExpired:
            self._send_json({
                "ok": False,
                "error": f"Command timed out after {timeout}s",
                "cmd": cmd,
            }, 408)
        except Exception as e:
            self._send_json({
                "ok": False,
                "error": str(e),
                "cmd": cmd,
            }, 500)


def main():
    server = http.server.HTTPServer(("0.0.0.0", PORT), ShellHandler)
    print(f"mac_shell_bridge v1.0 — http://0.0.0.0:{PORT}")
    print(f"  /health  → GET")
    print(f"  /exec    → POST {{\"cmd\": \"...\"}}")
    print(f"")
    print(f"  Connect via bore: bore local {PORT} --to bore.pub")
    print(f"")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
