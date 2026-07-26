#!/usr/bin/env python3
"""
Mac Reverse Shell Bridge
========================
Runs on Mac. Sends terminal output back to Hermes VPS.
Keeps a persistent HTTP listener on port 9999.

Hermes VPS calls: curl http://bore.pub:PORT/exec -d '{"cmd":"whoami"}'
"""

import http.server
import json
import subprocess
import os
import sys
import time
import platform
import shlex
import signal
import socket


HOST = "0.0.0.0"
PORT = 9999


class BridgeHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler: /health for status, /exec for command execution."""
    
    def log_message(self, format, *args):
        pass  # silent logging
    
    def _send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)
    
    def do_GET(self):
        if self.path == "/health" or self.path == "/":
            self._send_json({
                "ok": True,
                "hostname": platform.node(),
                "user": os.environ.get("USER", "unknown"),
                "platform": platform.platform(),
                "python": platform.python_version(),
                "cwd": os.getcwd(),
                "pid": os.getpid(),
                "uptime": int(time.time())
            })
        else:
            self._send_json({"error": "not found"}, 404)
    
    def do_POST(self):
        if self.path == "/exec":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            
            try:
                data = json.loads(body)
                cmd = data.get("cmd", "")
                timeout = int(data.get("timeout", 30))
                workdir = data.get("cwd", os.getcwd())
                env_extra = data.get("env", {})
            except json.JSONDecodeError:
                self._send_json({"error": "invalid JSON"}, 400)
                return
            
            if not cmd:
                self._send_json({"error": "no cmd provided"}, 400)
                return
            
            # Execute
            start = time.time()
            env = os.environ.copy()
            env.update(env_extra)
            
            try:
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=workdir,
                    env=env,
                    executable="/bin/zsh"
                )
                elapsed = time.time() - start
                
                self._send_json({
                    "ok": True,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "exit_code": result.returncode,
                    "elapsed": round(elapsed, 3),
                    "cmd": cmd
                })
            except subprocess.TimeoutExpired:
                self._send_json({
                    "ok": False,
                    "error": f"timeout after {timeout}s",
                    "cmd": cmd
                }, 408)
            except Exception as e:
                self._send_json({
                    "ok": False,
                    "error": str(e),
                    "cmd": cmd
                }, 500)
        
        elif self.path == "/upload":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            
            try:
                data = json.loads(body)
                filepath = data.get("path", "")
                content = data.get("content", "")
                
                if not filepath:
                    self._send_json({"error": "no path"}, 400)
                    return
                
                # Expand ~ and relative paths
                filepath = os.path.expanduser(filepath)
                if not os.path.isabs(filepath):
                    filepath = os.path.join(os.getcwd(), filepath)
                
                # Create directories if needed
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                
                with open(filepath, "w") as f:
                    f.write(content)
                
                self._send_json({
                    "ok": True,
                    "path": filepath,
                    "size": len(content)
                })
            except Exception as e:
                self._send_json({"ok": False, "error": str(e)}, 500)
        
        elif self.path == "/read":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            
            try:
                data = json.loads(body)
                filepath = data.get("path", "")
                
                if not filepath:
                    self._send_json({"error": "no path"}, 400)
                    return
                
                filepath = os.path.expanduser(filepath)
                
                with open(filepath, "r") as f:
                    content = f.read()
                
                self._send_json({
                    "ok": True,
                    "path": filepath,
                    "content": content,
                    "size": len(content)
                })
            except FileNotFoundError:
                self._send_json({"ok": False, "error": "file not found"}, 404)
            except Exception as e:
                self._send_json({"ok": False, "error": str(e)}, 500)
        
        else:
            self._send_json({"error": "not found"}, 404)
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


def main():
    print(f"\n  Mac Reverse Shell Bridge")
    print(f"  {'─'*40}")
    print(f"  Host: {HOST}:{PORT}")
    print(f"  Endpoints:")
    print(f"    GET  /health  → status check")
    print(f"    POST /exec    → execute command")
    print(f"    POST /upload  → write file")
    print(f"    POST /read    → read file")
    print(f"  {'─'*40}\n")
    
    import socketserver
    class ReuseServer(socketserver.TCPServer):
        allow_reuse_address = True
    
    server = http.server.HTTPServer((HOST, PORT), BridgeHandler, bind_and_activate=True)
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Graceful shutdown
    def shutdown(sig, frame):
        print("\n[*] Shutting down...")
        server.shutdown()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        shutdown(None, None)


if __name__ == "__main__":
    main()
