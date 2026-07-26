#!/usr/bin/env python3
"""
Hermes → Mac MCP Bridge v2.0
=============================
MCP stdio tool buat execute command di Mac Nabhan via HTTP bridge + bore tunnel.

Tools:
  mac_exec(command, timeout=30)  → execute command di Mac
  mac_health()                   → check koneksi Mac
  mac_file_put(path, content)    → tulis file di Mac
  mac_file_get(path)             → baca file dari Mac
  mac_git_pull(path)             → git pull di Mac
"""

import json
import sys
import urllib.request
import urllib.error

# ──── Config ────
BRIDGE_URLS = [
    "http://bore.pub:1657",     # bore tunnel (current)
]

def _detect_bridge():
    for url in BRIDGE_URLS:
        try:
            req = urllib.request.Request(f"{url}/health", method="GET")
            resp = urllib.request.urlopen(req, timeout=3)
            data = json.loads(resp.read())
            if data.get("ok"):
                return url
        except:
            continue
    return None

def _call(endpoint, method="GET", body=None, timeout=30):
    bridge = _detect_bridge()
    if not bridge:
        return False, {"error": "no bridge available"}
    
    try:
        data_bytes = json.dumps(body).encode() if body else None
        req = urllib.request.Request(
            f"{bridge}{endpoint}",
            data=data_bytes,
            headers={"Content-Type": "application/json"} if data_bytes else {},
            method=method
        )
        resp = urllib.request.urlopen(req, timeout=timeout)
        return True, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try: return False, json.loads(e.read())
        except: return False, {"error": f"HTTP {e.code}"}
    except Exception as e:
        return False, {"error": str(e)}

def mac_health():
    ok, data = _call("/health")
    data["bridge_url"] = _detect_bridge()
    return data

def mac_exec(command, timeout=30, cwd=None):
    body = {"cmd": command, "timeout": timeout}
    if cwd: body["cwd"] = cwd
    ok, data = _call("/exec", "POST", body, timeout=timeout+5)
    return data

def mac_file_put(path, content):
    ok, data = _call("/upload", "POST", {"path": path, "content": content})
    return data

def mac_file_get(path):
    ok, data = _call("/read", "POST", {"path": path})
    return data

def mac_git_pull(path="~/N/gtps/piter-tools"):
    return mac_exec(f"cd {path} && git pull --rebase 2>&1")

# ──── MCP stdio ────

TOOLS = {
    "mac_health": mac_health,
    "mac_exec": mac_exec,
    "mac_file_put": mac_file_put,
    "mac_file_get": mac_file_get,
    "mac_git_pull": mac_git_pull,
}

TOOL_SCHEMAS = [
    {"name": "mac_health", "description": "Check Mac connectivity and basic info", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "mac_exec", "description": "Execute a shell command on Nabhan's Mac", "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}, "timeout": {"type": "integer", "default": 30}, "cwd": {"type": "string"}}, "required": ["command"]}},
    {"name": "mac_file_put", "description": "Write content to a file on Mac", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]}},
    {"name": "mac_file_get", "description": "Read a file from Mac", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "mac_git_pull", "description": "Git pull latest code on Mac", "inputSchema": {"type": "object", "properties": {"path": {"type": "string", "default": "~/N/gtps/piter-tools"}}}},
]

def handle(msg):
    mid = msg.get("id")
    method = msg.get("method", "")
    params = msg.get("params", {})
    
    if method == "initialize":
        return {"jsonrpc":"2.0","id":mid,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"mac-bridge","version":"2.0"}}}
    elif method == "tools/list":
        return {"jsonrpc":"2.0","id":mid,"result":{"tools": TOOL_SCHEMAS}}
    elif method == "tools/call":
        name = params.get("name","")
        args = params.get("arguments",{})
        if name not in TOOLS:
            return {"jsonrpc":"2.0","id":mid,"error":{"code":-32601,"message":f"Unknown tool: {name}"}}
        try:
            result = TOOLS[name](**args)
            return {"jsonrpc":"2.0","id":mid,"result":{"content":[{"type":"text","text":json.dumps(result,indent=2)}]}}
        except Exception as e:
            return {"jsonrpc":"2.0","id":mid,"error":{"code":-32000,"message":str(e)}}
    elif method == "notifications/initialized":
        return None
    else:
        return {"jsonrpc":"2.0","id":mid,"error":{"code":-32601,"message":f"Unknown: {method}"}}

if __name__ == "__main__":
    for line in sys.stdin:
        line = line.strip()
        if not line: continue
        try:
            msg = json.loads(line)
            resp = handle(msg)
            if resp:
                print(json.dumps(resp), flush=True)
        except:
            continue
