#!/usr/bin/env python3
"""
Hermes → Mac MCP Bridge
========================
MCP stdio tool buat execute command di Mac Nabhan via RemoteTTYs relay.
Dipasang sebagai MCP server di Hermes.

Setup:
  hermes mcp add mac-bridge -- python3 /root/piter-tools/mac_mcp.py

Tools:
  - mac_exec(command)   → execute command di Mac, return stdout/stderr
  - mac_health()        → check koneksi Mac
  - mac_file_put(path, content) → tulis file di Mac
  - mac_file_get(path)  → baca file dari Mac
  - mac_git_pull(dir)   → git pull di direktori project di Mac
"""

import asyncio
import json
import sys
import time
import urllib.request
import urllib.error
import websockets
import os
import base64
import hashlib

# ──── Config ────
RELAY_URL = "ws://localhost:8080/ws/agent"
RELAY_TOKEN = "piter-mac-1785004473-nbfzz3rXLtYnfvuY"
SERVER_KEY = "AVFTUHFSoVgslo5PiaLPj75pjagBK9hycwa6tktISHg="  # relay Ed25519 pubkey
AGENT_ID = None  # will be discovered

# HTTP fallback (if mac_bridge.py is running with reverse tunnel exposing port)
MAC_BRIDGE_URL = None  # set when bridged, e.g. "http://mac-nabhan.local:9999"

# ──── MCP Protocol ────

def mcp_response(id, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": id}
    if result is not None:
        msg["result"] = result
    if error is not None:
        msg["error"] = error
    return json.dumps(msg)

def mcp_notification(method, params=None):
    return json.dumps({"jsonrpc": "2.0", "method": method, "params": params or {}})

# ──── Mac command execution via relay (async WebSocket) ────

async def mac_exec_via_relay(command, timeout=30):
    """Execute command on Mac via RemoteTTYs relay WebSocket agent connection."""
    try:
        ws = await asyncio.wait_for(
            websockets.connect(
                RELAY_URL, 
                extra_headers={"X-Token": RELAY_TOKEN}
            ),
            timeout=5
        )
        
        # Wait for server challenge
        challenge = await asyncio.wait_for(ws.recv(), timeout=5)
        challenge_data = json.loads(challenge)
        
        # Send agent hello
        await ws.send(json.dumps({
            "type": "agent.hello",
            "name": "Hermes-MCP",
            "os": "linux",
            "fingerprint": hashlib.sha256(f"hermes-mcp-{time.time()}".encode()).hexdigest(),
            "identityKey": base64.b64encode(os.urandom(32)).decode(),
            "capabilities": []
        }))
        
        # Create PTY
        session_id = f"mcp-{int(time.time()*1000)}"
        await ws.send(json.dumps({
            "type": "pty.create",
            "sessionId": session_id,
            "shell": "/bin/zsh",
            "cwd": "/Users/dangshafinaismirajarlaputri",
            "publicKey": base64.b64encode(os.urandom(65)).decode()
        }))
        
        created = await asyncio.wait_for(ws.recv(), timeout=5)
        
        # Send the command
        full_cmd = f"{command}; echo '===HERMES_EXIT==='; exit\n"
        await ws.send(json.dumps({
            "type": "pty.data",
            "sessionId": session_id,
            "payload": base64.b64encode(full_cmd.encode()).decode()
        }))
        
        # Read all output
        output = []
        exit_code = -1
        try:
            while True:
                raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
                msg = json.loads(raw)
                
                if msg.get("type") == "pty.data":
                    decoded = base64.b64decode(msg["payload"]).decode('utf-8', errors='replace')
                    if "===HERMES_EXIT===" in decoded:
                        decoded = decoded.replace("===HERMES_EXIT===", "")
                        output.append(decoded)
                        exit_code = 0
                        break
                    output.append(decoded)
                    
                elif msg.get("type") == "pty.exited":
                    exit_code = msg.get("exitCode", 0)
                    break
                    
                elif msg.get("type") == "pty.error":
                    return {"ok": False, "error": msg.get("error", "Unknown")}
                
        except asyncio.TimeoutError:
            # Timeout reading but we have output
            pass
        
        await ws.close()
        
        result = "".join(output).strip()
        return {
            "ok": True,
            "stdout": result[-10000:] if result else "",
            "exit_code": exit_code
        }
    
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ──── Sync wrapper untuk MCP tools ────

def mac_exec(command, timeout=30):
    """Execute shell command on Nabhan's Mac. Returns dict with stdout, stderr, exit_code."""
    try:
        result = asyncio.run(mac_exec_via_relay(command, timeout))
        return result
    except Exception as e:
        return {"ok": False, "error": str(e)}

def mac_health():
    """Check Mac bridge connectivity."""
    return mac_exec("echo 'HERMES_ALIVE' && uname -a && whoami && pwd")

def mac_git_pull(repo_path="~/N/gtps/piter-tools"):
    """Pull latest code on Mac."""
    cmd = f"cd {repo_path} && git stash 2>/dev/null; git pull --rebase 2>&1"
    return mac_exec(cmd)

def mac_file_read(path):
    """Read file from Mac."""
    cmd = f"if [ -f '{path}' ]; then cat '{path}' 2>&1; else echo 'FILE_NOT_FOUND'; fi"
    return mac_exec(cmd)

def mac_file_write(path, content):
    """Write file to Mac (via base64)."""
    b64 = base64.b64encode(content.encode()).decode()
    cmd = f"echo '{b64}' | base64 -d > '{path}' && echo 'WRITTEN:' && wc -c '{path}'"
    return mac_exec(cmd)

# ──── MCP Server ────

def handle_mcp():
    """Run as MCP stdio server."""
    
    tools = {
        "mac_exec": {
            "description": "Execute a shell command on Nabhan's Mac",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Shell command to execute"},
                    "timeout": {"type": "integer", "default": 30, "description": "Timeout in seconds"}
                },
                "required": ["command"]
            }
        },
        "mac_health": {
            "description": "Check Mac connectivity and basic info (uname, whoami, pwd)",
            "inputSchema": {"type": "object", "properties": {}}
        },
        "mac_git_pull": {
            "description": "Git pull latest code on Mac for a project directory",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "default": "~/N/gtps/piter-tools", "description": "Path to git repo"}
                }
            }
        },
        "mac_file_read": {
            "description": "Read a file from Mac",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute path to file"}
                },
                "required": ["path"]
            }
        },
        "mac_file_write": {
            "description": "Write content to a file on Mac",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute path to file"},
                    "content": {"type": "string", "description": "Content to write"}
                },
                "required": ["path", "content"]
            }
        }
    }
    
    # Process stdin/stdout MCP protocol
    for line in sys.stdin:
        try:
            msg = json.loads(line.strip())
        except json.JSONDecodeError:
            continue
        
        msg_id = msg.get("id")
        method = msg.get("method")
        params = msg.get("params", {})
        
        if method == "initialize":
            resp = mcp_response(msg_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mac-bridge", "version": "1.0"}
            })
            sys.stdout.write(resp + "\n")
            sys.stdout.flush()
        
        elif method == "tools/list":
            resp = mcp_response(msg_id, {
                "tools": [
                    {"name": name, **info}
                    for name, info in tools.items()
                ]
            })
            sys.stdout.write(resp + "\n")
            sys.stdout.flush()
        
        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})
            
            if tool_name == "mac_exec":
                result = mac_exec(tool_args["command"], tool_args.get("timeout", 30))
            elif tool_name == "mac_health":
                result = mac_health()
            elif tool_name == "mac_git_pull":
                result = mac_git_pull(tool_args.get("path", "~/N/gtps/piter-tools"))
            elif tool_name == "mac_file_read":
                result = mac_file_read(tool_args["path"])
            elif tool_name == "mac_file_write":
                result = mac_file_write(tool_args["path"], tool_args["content"])
            else:
                result = {"ok": False, "error": f"Unknown tool: {tool_name}"}
            
            resp = mcp_response(msg_id, {
                "content": [{"type": "text", "text": json.dumps(result, indent=2)}]
            })
            sys.stdout.write(resp + "\n")
            sys.stdout.flush()
        
        elif method == "notifications/initialized":
            pass  # no response needed
        
        else:
            resp = mcp_response(msg_id, error={
                "code": -32601,
                "message": f"Unknown method: {method}"
            })
            sys.stdout.write(resp + "\n")
            sys.stdout.flush()


# ──── Standalone CLI mode ────

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        print("Testing Mac bridge...")
        result = mac_health()
        print(json.dumps(result, indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] == "serve":
        # HTTP mode
        from http.server import HTTPServer, BaseHTTPRequestHandler
        
        class H(BaseHTTPRequestHandler):
            def do_POST(s):
                if s.path == "/exec":
                    body = json.loads(s.rfile.read(int(s.headers["Content-Length"])))
                    cmd = body.get("command", "")
                    result = mac_exec(cmd, body.get("timeout", 30))
                    resp = json.dumps(result).encode()
                    s.send_response(200 if result.get("ok") else 500)
                    s.send_header("Content-Type", "application/json")
                    s.send_header("Content-Length", str(len(resp)))
                    s.end_headers()
                    s.wfile.write(resp)
            def log_message(s, *a): pass
        
        print(f"[*] HTTP bridge on :8081")
        HTTPServer(("0.0.0.0", 8081), H).serve_forever()
    else:
        # MCP stdio mode
        handle_mcp()
