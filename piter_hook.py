#!/usr/bin/env python3
"""
Piter Hook — Direct Memory Scanner for Growtopia
=================================================
Attaches to Growtopia process (PID you specify) and scans
all readable memory regions for GrowID, password, token, world, etc.

USAGE:
  python3 piter_hook.py                    # Auto-find GT process
  python3 piter_hook.py <PID>              # Specific PID
  python3 piter_hook.py scan               # Just list candidates
  python3 piter_hook.py dump > out.txt     # Dump all found strings

More reliable than MITM — reads actual memory, can't be bypassed.
"""

import sys
import os
import re
import struct
import ctypes
import ctypes.util
from ctypes import (
    c_int, c_uint, c_uint32, c_uint64, c_void_p, c_char_p,
    c_size_t, c_bool, Structure, POINTER, byref, sizeof
)
from datetime import datetime


# ──── Mach VM Constants ────
VM_PROT_READ = 0x01
VM_PROT_WRITE = 0x02
VM_PROT_EXECUTE = 0x04

MACH_PORT_NULL = 0
MACH_MSG_TYPE_COPY_SEND = 19

# task_for_pid constants
TASK_FOR_PID = 0x002


class vm_region_basic_info_data_64_t(Structure):
    """Mach VM region info."""
    _fields_ = [
        ("protection", c_uint32),
        ("max_protection", c_uint32),
        ("inheritance", c_uint32),
        ("shared", c_uint32),
        ("reserved", c_uint32),
        ("offset", c_uint64),
        ("behavior", c_uint32),
        ("user_wired_count", c_uint32),
    ]


# ──── Mach API Bindings ────
libc = ctypes.CDLL(ctypes.util.find_library("c"))

# Mach kernel interface
try:
    mach = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
except:
    mach = libc

mach.mach_task_self.restype = c_uint32
mach.mach_task_self.argtypes = []

mach.task_for_pid.restype = c_int
mach.task_for_pid.argtypes = [c_uint32, c_int, POINTER(c_uint32)]

mach.mach_vm_region.restype = c_int
mach.mach_vm_region.argtypes = [
    c_uint32, POINTER(c_uint64), POINTER(c_uint64),
    c_int, POINTER(vm_region_basic_info_data_64_t),
    POINTER(c_uint32), POINTER(c_uint32)
]

mach.mach_vm_read_overwrite.restype = c_int
mach.mach_vm_read_overwrite.argtypes = [
    c_uint32, c_uint64, c_uint64,
    c_void_p, POINTER(c_uint64)
]

mach.vm_deallocate.restype = c_int
mach.vm_deallocate.argtypes = [c_uint32, c_void_p, c_size_t]


TARGET_PROCESS = "Growtopia"

# Patterns to search for
PATTERNS = {
    "grow_id": [
        rb'tankIDName\x00([^\x00]{1,64})',
        rb'growId\x00([^\x00]{1,64})',
        rb'"growId"\s*:\s*"([^"]+)"',
    ],
    "password": [
        rb'tankIDPass\x00([^\x00]{1,64})',
        rb'password\x00([^\x00]{1,64})',
        rb'"password"\s*:\s*"([^"]+)"',
    ],
    "token": [
        rb'_token\x00([^\x00]{1,256})',
        rb'"token"\s*:\s*"([^"]+)"',
    ],
    "world": [
        rb'world\x00([^\x00]{1,64})',
        rb'currentWorld\x00([^\x00]{1,64})',
    ],
}


def find_growtopia_pid():
    """Find Growtopia process PID."""
    try:
        out = os.popen("ps aux | grep -i Growtopia | grep -v grep").read()
        lines = out.strip().split('\n')
        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                pid = int(parts[1])
                name = parts[-1] if len(parts) > 10 else ''
                if 'Growtopia' in name or 'Growtopia' in line:
                    return pid
    except:
        pass
    return None


def task_for_pid(target_pid):
    """Get task port for PID."""
    task = c_uint32(0)
    ret = mach.task_for_pid(mach.mach_task_self(), target_pid, byref(task))
    if ret != 0:
        return None
    return task.value


def scan_region(task, addr, size):
    """Read and scan a memory region, return found matches."""
    if size == 0 or size > 256 * 1024 * 1024:
        return []
    
    data = (ctypes.c_char * size)()
    data_out = c_uint64(0)
    
    ret = mach.mach_vm_read_overwrite(
        task, addr, size,
        ctypes.cast(data, c_void_p), byref(data_out)
    )
    
    if ret != 0 or data_out.value == 0:
        return []
    
    raw = bytes(data[:data_out.value])
    results = []
    
    for category, regexes in PATTERNS.items():
        for regex in regexes:
            for match in re.finditer(regex, raw):
                value = match.group(1)
                try:
                    text = value.decode('utf-8', errors='replace')
                    if text.isprintable() and len(text) > 1:
                        results.append((category, text, addr + match.start(1)))
                except:
                    pass
    
    return results


def scan_memory(task):
    """Scan all readable memory regions."""
    results = []
    address = c_uint64(0)
    size = c_uint64(0)
    info = vm_region_basic_info_data_64_t()
    info_count = c_uint32(sizeof(info) // 4)
    object_name = c_uint32(0)
    
    region_count = 0
    
    print("  Scanning memory regions...")
    
    while True:
        ret = mach.mach_vm_region(
            task, byref(address), byref(size),
            0, byref(info), byref(info_count), byref(object_name)
        )
        
        if ret != 0:
            break
        
        region_count += 1
        
        # Only scan readable regions, skip execute-only
        if info.protection & VM_PROT_READ and not (info.protection & VM_PROT_EXECUTE):
            if 0 < size.value <= 256 * 1024 * 1024:
                found = scan_region(task, address.value, size.value)
                if found:
                    results.extend(found)
        
        address = c_uint64(address.value + size.value)
        
        if address.value == 0 or size.value == 0:
            break
    
    print(f"  Scanned {region_count} regions")
    return results


def auto_mode():
    """Auto-find GT process and scan."""
    pid = find_growtopia_pid()
    
    if pid is None:
        print("[!] Growtopia not running.")
        print("[!] Start Growtopia first, login, then run this.")
        
        # Fallback: let user specify
        print("\n[*] Looking for Growtopia in ps output...")
        os.system("ps aux | grep -i growto | grep -v grep || true")
        print()
        pid_str = input("[?] Enter PID manually: ").strip()
        try:
            pid = int(pid_str)
        except:
            print("[!] Invalid PID.")
            sys.exit(1)
    
    print(f"\n[*] Attaching to Growtopia (PID: {pid})...")
    
    task = task_for_pid(pid)
    if task is None:
        print("\n[!] Cannot access Growtopia memory.")
        print("\n  Reason: System Integrity Protection (SIP) is ON.")
        print("\n  Fix: Disable SIP debug restrictions")
        print("    1. Reboot → hold Cmd+R (Recovery)")
        print("    2. Utilities → Terminal")
        print("    3. csrutil enable --without debug")
        print("    4. Reboot")
        print("    5. Run this script again")
        print("\n  Or use the MITM interceptor instead:")
        print("    sudo python3 piter_intercept.py")
        sys.exit(1)
    
    print(f"  Task port: {task}")
    print(f"  Scanning memory...")
    print()
    
    results = scan_memory(task)
    
    if not results:
        print("\n  [-] No matches found in memory.")
        print("  [*] Ensure you're logged in to the server.")
        print("  [*] The GrowID/password should be in memory during gameplay.")
        return
    
    print(f"\n  [RESULT] Found {len(results)} matches:")
    print(f"  {'─'*50}")
    
    # Deduplicate and organize
    seen = set()
    organized = {"grow_id": [], "password": [], "token": [], "world": []}
    
    for category, value, addr in results:
        key = (category, value)
        if key not in seen:
            seen.add(key)
            organized[category].append((value, addr))
    
    for cat, items in organized.items():
        if items:
            print(f"\n  [{cat.upper()}]")
            for value, addr in items:
                # Mask passwords partially
                if cat == "password":
                    masked = value[:2] + '*' * max(0, len(value) - 2)
                    print(f"    0x{addr:016x} → {masked}")
                else:
                    print(f"    0x{addr:016x} → {value}")
    
    # Summary
    print(f"\n  [SUMMARY]")
    for cat in ["grow_id", "password", "token", "world"]:
        if organized[cat]:
            val = organized[cat][0][0]
            if cat == "password":
                val = val[:2] + '*' * max(0, len(val) - 2)
            print(f"    {cat}: {val}")


def scan_mode():
    """Just list candidate processes."""
    print("\n[*] Looking for Growtopia processes...")
    os.system("ps aux | grep -i grow | grep -v grep || echo '  No GT process found'")
    
    print("\n[*] Looking for any Mach-O GUI apps...")
    os.system("ps aux | grep -E 'MacOS/' | head -20 || echo '  None'")
    
    print("\n[*] To scan a specific PID:")
    print("  python3 piter_hook.py <PID>")


def dump_mode():
    """Dump all found strings from memory (for piping to file)."""
    pid = find_growtopia_pid()
    if pid is None:
        print("[!] Growtopia not running.")
        sys.exit(1)
    
    task = task_for_pid(pid)
    if task is None:
        print("[!] Cannot access memory (SIP enabled).")
        sys.exit(1)
    
    results = scan_memory(task)
    
    seen = set()
    for category, value, addr in results:
        key = (category, value)
        if key not in seen:
            seen.add(key)
            print(f"{category}\t0x{addr:016x}\t{value}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg == "scan":
            scan_mode()
        elif arg == "dump":
            dump_mode()
        else:
            try:
                pid = int(arg)
                print(f"[*] Attaching to PID: {pid}")
                task = task_for_pid(pid)
                if task is None:
                    print("[!] Cannot access memory.")
                    sys.exit(1)
                results = scan_memory(task)
                for category, value, addr in results:
                    print(f"{category}\t0x{addr:016x}\t{value}")
            except ValueError:
                print(f"[!] Unknown argument: {arg}")
                print("Usage: piter_hook.py [scan|dump|<PID>]")
    else:
        auto_mode()
