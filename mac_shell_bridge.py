#!/usr/bin/env python3
"""
Mac Shell Bridge — HTTP-to-shell proxy for Hermes MCP.
Run on Mac: python3 mac_shell_bridge.py
Then MCP on VPS hits http://<bore-url>/exec
"""
import http.server, subprocess, json, sys, os, base64, argparse

PORT = 9999

class ShellHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.respond({"ok": True, "hostname": os.uname().nodename, "whoami": os.getlogin()})
            return
        self.error(404)
    
    def do_POST(self):
        if self.path != '/exec':
            self.error(404)
            return
        
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8')
        data = json.loads(body) if body else {}
        
        cmd = data.get('cmd', data.get('command', ''))
        timeout = data.get('timeout', 30)
        workdir = data.get('cwd') or os.path.expanduser('~')
        
        if not cmd:
            self.respond({"ok": False, "error": "No command provided"})
            return
        
        try:
            result = subprocess.run(
                ['/bin/zsh', '-c', cmd],
                capture_output=True, text=True,
                timeout=timeout, cwd=workdir
            )
            self.respond({
                "ok": True,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.returncode
            })
        except subprocess.TimeoutExpired:
            self.respond({"ok": False, "error": f"Timeout ({timeout}s)"})
        except Exception as e:
            self.respond({"ok": False, "error": str(e)})
    
    def respond(self, data):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def error(self, code):
        self.send_response(code)
        self.end_headers()
    
    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {args}", flush=True)

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('-p', '--port', type=int, default=PORT)
    args = p.parse_args()
    
    server = http.server.HTTPServer(('127.0.0.1', args.port), ShellHandler)
    print(f"Mac Shell Bridge ready on 127.0.0.1:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
