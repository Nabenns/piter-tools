#!/usr/bin/env python3
"""
Piter Hook v2 — macOS Memory Scanner for Growtopia
===================================================
Directly attach to Growtopia process and dump readable strings,
memory maps, and search for credentials.
Uses mach_vm_* APIs (needs SIP debug exemption).

Pure Python + ctypes, no external deps.
"""

import ctypes
import ctypes.util
import sys
import struct
import os
import re
from typing import Optional

# ──── Mach / Darwin Constants ────
libc = ctypes.CDLL(ctypes.util.find_library('c'))
libkern = ctypes.CDLL(ctypes.util.find_library('System'))

VM_PROT_READ = 0x01
VM_PROT_WRITE = 0x02
VM_PROT_EXECUTE = 0x04

MACH_PORT_NULL = 0
MACH_MSG_TYPE_COPY_SEND = 19

# ──── Data types ────
mach_port_t = ctypes.c_uint32
vm_address_t = ctypes.c_ulonglong
vm_size_t = ctypes.c_ulonglong
vm_offset_t = ctypes.c_ulonglong
natural_t = ctypes.c_uint32
kern_return_t = ctypes.c_int
boolean_t = ctypes.c_uint
thread_act_t = ctypes.c_uint32


class task_basic_info(ctypes.Structure):
    _fields_ = [
        ("suspend_count", ctypes.c_uint32),
        ("virtual_size", ctypes.c_ulonglong),
        ("resident_size", ctypes.c_ulonglong),
        ("user_time_sec", ctypes.c_uint32),
        ("user_time_usec", ctypes.c_uint32),
        ("system_time_sec", ctypes.c_uint32),
        ("system_time_usec", ctypes.c_uint32),
        ("policy", ctypes.c_uint32),
    ]


# ──── Libc / Mach API Setup ────
TASK_FOR_PID_FN = libc.task_for_pid
TASK_FOR_PID_FN.argtypes = [mach_port_t, ctypes.c_int, ctypes.POINTER(mach_port_t)]
TASK_FOR_PID_FN.restype = kern_return_t

MACH_VM_REGION = libkern.mach_vm_region
MACH_VM_REGION.argtypes = [
    mach_port_t, ctypes.POINTER(vm_address_t), ctypes.POINTER(vm_size_t),
    natural_t, ctypes.POINTER(ctypes.c_uint32), ctypes.c_int,
    ctypes.POINTER(ctypes.c_char * 256)
]
MACH_VM_REGION.restype = kern_return_t

MACH_VM_READ = libkern.mach_vm_read_overwrite
MACH_VM_READ.argtypes = [
    mach_port_t, vm_address_t, vm_size_t,
    vm_address_t, ctypes.POINTER(vm_size_t)
]
MACH_VM_READ.restype = kern_return_t

MACH_VM_DEALLOCATE = libkern.mach_vm_deallocate
MACH_VM_DEALLOCATE.argtypes = [mach_port_t, vm_address_t, vm_size_t]
MACH_VM_DEALLOCATE.restype = kern_return_t

MACH_TASK_BASIC_INFO_COUNT = ctypes.sizeof(task_basic_info) // ctypes.sizeof(natural_t)
MACH_TASK_BASIC_INFO = libc.task_info
MACH_TASK_BASIC_INFO.argtypes = [mach_port_t, natural_t, ctypes.c_void_p, ctypes.POINTER(natural_t)]
MACH_TASK_BASIC_INFO.restype = kern_return_t


def task_for_pid(target_pid: int) -> Optional[int]:
    """Get task port for a given PID."""
    task = mach_port_t(0)
    ret = TASK_FOR_PID_FN(mach_port_t(MACH_PORT_NULL), target_pid, ctypes.byref(task))
    if ret != 0:
        return None
    return task.value


def get_task_info(task: int) -> Optional[task_basic_info]:
    """Get basic task info (memory size, etc)."""
    info = task_basic_info()
    count = natural_t(MACH_TASK_BASIC_INFO_COUNT)
    ret = MACH_TASK_BASIC_INFO(task, 20, ctypes.byref(info), ctypes.byref(count))
    if ret != 0:
        return None
    return info


def read_memory(task: int, address: int, size: int) -> Optional[bytes]:
    """Read raw memory from task at address."""
    if size == 0:
        return b""
    
    buf = ctypes.create_string_buffer(size)
    out_size = vm_size_t(0)
    
    ret = MACH_VM_READ(task, address, size,
                       ctypes.cast(buf, vm_address_t),
                       ctypes.byref(out_size))
    
    if ret != 0:
        return None
    
    return buf.raw[:out_size.value]


# ──── String Scanner ────
def is_ascii_printable(data: bytes) -> bool:
    """Check if data is mostly printable ASCII."""
    printable = sum(1 for b in data if 0x20 <= b < 0x7F)
    return printable > len(data) * 0.7


def scan_region(task: int, address: int, size: int,
                search_terms: list[bytes] = None) -> list[dict]:
    """Scan a memory region for interesting strings.
    
    Returns list of {offset, length, data}
    """
    CHUNK = 0x10000  # 64KB chunks
    
    results = []
    full_data = b""
    
    # Read the region in chunks
    for offset in range(0, min(size, 50 * 1024 * 1024), CHUNK):  # Max 50MB
        chunk = min(CHUNK, size - offset)
        data = read_memory(task, address + offset, chunk)
        if data:
            full_data += data
    
    if not full_data:
        return results
    
    # Find printable strings (min 4 chars)
    current = b""
    start_offset = 0
    
    for i, byte in enumerate(full_data):
        if 0x20 <= byte < 0x7F or byte in (0x09, 0x0A, 0x0D):  # tab, lf, cr
            if not current:
                start_offset = i
            current += bytes([byte])
        else:
            if len(current) >= 4:
                text = current.decode('ascii', errors='replace')
                results.append({
                    'offset': address + start_offset,
                    'length': len(current),
                    'data': text,
                })
            current = b""
    
    # Don't forget the last string
    if len(current) >= 4:
        text = current.decode('ascii', errors='replace')
        results.append({
            'offset': address + start_offset,
            'length': len(current),
            'data': text,
        })
    
    return results


def find_growid_credentials(strings: list[dict]) -> list[dict]:
    """Find GrowID-related strings from scanned data."""
    findings = []
    
    for s in strings:
        text = s['data']
        
        # Match GrowID patterns
        for pattern, label in [
            (r'requestedName\|(\w+)', 'requestedName'),
            (r'tankIDName\|(\w+)', 'tankIDName'),
            (r'tankIDPass\|(\w+)', 'tankIDPass'),
            (r'growId=(\w+)', 'growId'),
            (r'password=(\w+)', 'password'),
            (r'_token=(\d+)', 'token'),
            (r'token=([\w/=+]+)', 'token'),
            (r'prod=(\w+)', 'product'),
            (r'world\|(\w+)', 'world'),
            (r'onSuperMainStart', 'GAME_START'),
            (r'onSendToServer\|', 'GAME_ACTION'),
        ]:
            match = re.search(pattern, text.encode('ascii', errors='replace') if isinstance(text, str) else text)
            if match:
                findings.append({
                    'offset': s['offset'],
                    'label': label,
                    'value': match.group(1) if match.lastindex else 'TRIGGER',
                    'context': text[:100],
                })
    
    return findings


def find_domains_urls(strings: list[dict]) -> list[dict]:
    """Find URLs and domains in scanned strings."""
    findings = []
    url_pattern = re.compile(
        r'(https?://[\w.-]+(?:\.\w+)+(?:/\S*)?)'
        r'|([\w-]+\.(?:com|net|org|id|io|app|gg|xyz|my|id|tk|ml|ga|cf|gq))',
        re.IGNORECASE
    )
    
    for s in strings:
        matches = url_pattern.findall(s['data'])
        for match in matches:
            url = match[0] or match[1] or match[2]
            if url and len(url) > 4:
                findings.append({
                    'offset': s['offset'],
                    'url': url,
                    'context': s['data'][:100],
                })
    
    return findings


# ──── Main ────
def main():
    if len(sys.argv) < 2:
        print("[*] Usage: sudo python3 piter_hook.py <PID>")
        print("[*] Find PID: ps aux | grep Growtopia")
        
        # Auto-detect
        import subprocess
        try:
            out = subprocess.check_output(
                "ps aux | grep -i [g]rowtopia | awk '{print $2}'",
                shell=True, stderr=subprocess.DEVNULL
            ).decode().strip()
            if out:
                pid = int(out.split()[0])
                print(f"[*] Auto-detected Growtopia PID: {pid}")
            else:
                print("[!] Growtopia not found. Start Growtopia first and login.")
                sys.exit(1)
        except:
            print("[!] Growtopia not found. Start Growtopia first and login.")
            sys.exit(1)
    else:
        pid = int(sys.argv[1])
    
    print(f"\n[*] Attaching to Growtopia (PID: {pid})...")
    
    task = task_for_pid(pid)
    if task is None:
        print("[!] task_for_pid failed. SIP might be blocking debug access.")
        print("[!] Fix: boot into Recovery (Cmd+R), run 'csrutil enable --without debug', reboot.")
        print("[!] Or use piter_intercept.py instead (no SIP needed).")
        sys.exit(1)
    
    print(f"  Task port: {task}")
    
    info = get_task_info(task)
    if info:
        print(f"  Virtual size: {info.virtual_size / 1024 / 1024:.0f} MB")
        print(f"  Resident size: {info.resident_size / 1024 / 1024:.0f} MB")
    
    print(f"\n  Scanning memory...")
    
    # Scan all readable memory regions
    address = vm_address_t(0)
    size = vm_size_t(0)
    region_count = 0
    
    all_strings = []
    
    MAX_REGIONS = 5000
    MAX_TOTAL = 2 * 1024 * 1024 * 1024  # 2GB max
    
    while region_count < MAX_REGIONS and address.value < MAX_TOTAL:
        addr_before = address.value
        info_count = ctypes.c_uint32(0)
        object_name = ctypes.create_string_buffer(256)
        
        ret = MACH_VM_REGION(task, ctypes.byref(address), ctypes.byref(size),
                            1, ctypes.byref(info_count), 0,
                            object_name)
        
        if ret != 0:
            break
        
        # Only scan readable regions
        if (info_count.value & VM_PROT_READ) and size.value > 0:
            region_count += 1
            
            # Skip tiny regions
            if size.value < 128:
                address.value += size.value
                continue
            
            # Read and scan
            strings = scan_region(task, address.value, min(size.value, 10 * 1024 * 1024))
            
            if strings:
                all_strings.extend(strings)
            
            if region_count % 200 == 0:
                print(f"  Scanned {region_count} regions, {len(all_strings)} strings found...", end='\r')
        
        address.value += size.value
    
    print(f"\n  Scanned {region_count} regions")
    print(f"  Found {len(all_strings)} readable strings\n")
    
    if not all_strings:
        print("  [-] No strings found. Possible causes:")
        print("      - Growtopia needs to be logged in to the server")
        print("      - SIP might still be blocking reads (test: sudo csrutil status)")
        print("      - Memory might be encrypted/protected")
        return
    
    # Search for credentials
    creds = find_growid_credentials(all_strings)
    
    if creds:
        print(f"  [!!!] FOUND {len(creds)} GTPS-related strings:\n")
        for c in creds:
            print(f"    [{c['label']}] {c['value']}")
            print(f"      offset: 0x{c['offset']:x}")
            print(f"      context: {c['context']}")
            print()
    else:
        print("  [-] No GTPS credentials found in memory.")
        print("  [*] Try different search patterns:")
    
    # Search for URLs
    urls = find_domains_urls(all_strings)
    if urls:
        print(f"\n  [*] Found {len(urls)} URLs/domains:")
        for u in urls[:10]:
            print(f"    {u['url']}")
    
    # Show some random strings for debugging
    print(f"\n  [*] Sample readable strings ({min(20, len(all_strings))} of {len(all_strings)}):")
    for s in all_strings[:20]:
        text = s['data'][:80].replace('\n', '\\n').replace('\t', '\\t')
        print(f"    0x{s['offset']:x}: {text}")


if __name__ == "__main__":
    main()
