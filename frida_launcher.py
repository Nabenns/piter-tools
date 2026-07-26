#!/usr/bin/env python3
"""
Frida launcher — fully detached, no TTY needed.
Run: python3 frida_launcher.py
Output goes to /tmp/piter_frida.log
"""
import subprocess, os, sys

LOG = '/tmp/piter_frida.log'
CHEAT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'piter_cheat_v12.py')

with open(LOG, 'w') as f:
    f.write(f"[LAUNCHER] Starting Frida cheat v12\nPID={os.getpid()}\n")
    f.flush()

# Fully detach from terminal
os.setsid()

try:
    result = subprocess.run(
        ['sudo', '-n', 'python3', CHEAT, '22782'],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=300
    )
    with open(LOG, 'a') as f:
        f.write(result.stdout)
        f.write(f"\n[EXIT] code={result.returncode}\n")
except subprocess.TimeoutExpired:
    with open(LOG, 'a') as f:
        f.write("[TIMEOUT] 5 minutes\n")
except Exception as e:
    with open(LOG, 'a') as f:
        f.write(f"[CRASH] {e}\n")
