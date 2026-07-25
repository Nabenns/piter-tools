#!/usr/bin/env python3
"""
Piter Hook — Process-Level Game Hook
=====================================
Attach langsung ke process Growtopia (PID atau by name).
Baca memory, intercept function call, inject command.

Mac-only. Pake Mach kernel API via ctypes.
Requires: SIP disabled (for task_for_pid on Apple-signed bins)
          OR com.apple.security.cs.debugger entitlement
          OR run as root + codesign the Python binary

USAGE:
  sudo python3 piter_hook.py              # Auto-find Growtopia process
  sudo python3 piter_hook.py -p 22782     # Attach to specific PID
  sudo python3 piter_hook.py --inject     # Inject command into game

COMMANDS (interactive):
  mem <pattern>   - Search memory for string/hex pattern
  growid          - Find GrowID in memory
  pass            - Find password/token in memory  
  world           - Find world name
  inject <cmd>    - Inject command via function hook
  dump <addr> <n> - Dump N bytes from address
  write <addr> <hex> - Write hex to memory address
  players         - List online players (from memory)
  items           - List inventory items (from memory)
  help            - This help
"""

import ctypes
import ctypes.util
import struct
import sys
import os
import signal
import re
import time
from ctypes import (
    c_uint32, c_uint64, c_int, c_void_p, c_char_p, c_size_t,
    byref, POINTER, Structure, addressof, cast, string_at
)
from typing import Optional

# ──── Mach Kernel Types (from <mach/mach_types.h>) ────

class mach_header_64(Structure):
    _fields_ = [
        ("magic", c_uint32),
        ("cputype", c_uint32),
        ("cpusubtype", c_uint32),
        ("filetype", c_uint32),
        ("ncmds", c_uint32),
        ("sizeofcmds", c_uint32),
        ("flags", c_uint32),
        ("reserved", c_uint32),
    ]

# ──── Mach VM Types ────

VM_PROT_READ = 1
VM_PROT_WRITE = 2
VM_PROT_EXECUTE = 4

# mach_vm_address_t = uint64
# mach_vm_size_t = uint64
# vm_region_basic_info_data_64_t

class vm_region_basic_info_64(Structure):
    _fields_ = [
        ("protection", c_uint32),
        ("max_protection", c_uint32),
        ("inheritance", c_uint32),
        ("shared", c_uint32),
        ("reserved", c_uint32),
        ("offset", c_uint64),
        ("behavior", c_uint32),
        ("user_wired_count", c_uint16),
    ]

VM_REGION_BASIC_INFO_64 = 9
VM_REGION_BASIC_INFO_COUNT_64 = ctypes.sizeof(vm_region_basic_info_64) // 4

# ──── Mach port types ────
mach_port_t = c_uint32
mach_port_name_t = c_uint32
mach_task_self = c_uint32

# ──── Load libSystem (contains Mach APIs) ────
libc = ctypes.CDLL(ctypes.util.find_library("System"))

# task_for_pid
libc.task_for_pid.argtypes = [mach_port_t, c_int, POINTER(mach_port_t)]
libc.task_for_pid.restype = c_int

# mach_task_self()
libc.mach_task_self.argtypes = []
libc.mach_task_self.restype = mach_port_t

# mach_vm_read_overwrite
libc.mach_vm_read_overwrite.argtypes = [
    mach_port_t, c_uint64, c_uint64, c_uint64, 
    POINTER(c_uint64), POINTER(c_uint32)
]
libc.mach_vm_read_overwrite.restype = c_int

# mach_vm_write
libc.mach_vm_write.argtypes = [
    mach_port_t, c_uint64, c_void_p, c_uint32
]
libc.mach_vm_write.restype = c_int

# mach_vm_region
libc.mach_vm_region.argtypes = [
    mach_port_t, POINTER(c_uint64), POINTER(c_uint64),
    c_uint32, POINTER(vm_region_basic_info_64),
    POINTER(c_uint32), POINTER(c_uint32)
]
libc.mach_vm_region.restype = c_int

# mach_vm_protect
libc.mach_vm_protect.argtypes = [
    mach_port_t, c_uint64, c_uint64, c_int, c_uint32
]
libc.mach_vm_protect.restype = c_int

# mach_port_deallocate
libc.mach_port_deallocate.argtypes = [mach_port_t, mach_port_t]
libc.mach_port_deallocate.restype = c_int


class MachException(Exception):
    pass

def kern_check(ret: int, msg: str = ""):
    if ret != 0:
        raise MachException(f"{msg}: KERN error {ret} (0x{ret:x})")

# ──── Process Management ────

def find_process(name: str = "Growtopia") -> Optional[int]:
    """Find PID of Growtopia process."""
    try:
        output = os.popen("ps aux | grep -i growtopia | grep -v grep").read()
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                try:
                    pid = int(parts[1])
                    cmd = ' '.join(parts[10:]) if len(parts) > 10 else parts[-1]
                    if 'growtopia' in cmd.lower():
                        return pid
                except ValueError:
                    continue
    except:
        pass
    return None


def task_for_pid(pid: int) -> int:
    """Get task port for a PID."""
    task = mach_port_t()
    ret = libc.task_for_pid(mach_task_self(), pid, byref(task))
    kern_check(ret, f"task_for_pid({pid})")
    return task.value


def release_task(task: int):
    """Release a task port."""
    libc.mach_port_deallocate(mach_task_self(), task)


# ──── Memory Operations ────

def vm_read(task: int, address: int, size: int) -> bytes:
    """Read memory from a task. Max 4096 bytes per call."""
    if size > 4096:
        # Split into chunks
        result = b""
        for offset in range(0, size, 4096):
            chunk = min(4096, size - offset)
            result += vm_read(task, address + offset, chunk)
        return result
    
    buf = ctypes.create_string_buffer(size)
    out_size = c_uint64()
    
    ret = libc.mach_vm_read_overwrite(
        task,
        c_uint64(address),
        c_uint64(size),
        c_uint64(addressof(buf)),
        byref(out_size),
        None
    )
    kern_check(ret, f"vm_read(0x{address:x}, {size})")
    
    return buf.raw[:out_size.value]


def vm_write(task: int, address: int, data: bytes):
    """Write memory to a task."""
    buf = ctypes.create_string_buffer(data, len(data))
    ret = libc.mach_vm_write(
        task,
        c_uint64(address),
        cast(buf, c_void_p),
        c_uint32(len(data))
    )
    kern_check(ret, f"vm_write(0x{address:x}, {len(data)}B)")


def vm_protect(task: int, address: int, size: int, prot: int):
    """Change memory protection."""
    ret = libc.mach_vm_protect(
        task,
        c_uint64(address),
        c_uint64(size),
        c_int(0),  # set_maximum = False
        c_uint32(prot)
    )
    kern_check(ret, f"vm_protect(0x{address:x}, {size}, prot={prot})")


def enumerate_regions(task: int) -> list[dict]:
    """Enumerate all memory regions of a task."""
    regions = []
    address = c_uint64(0)
    size = c_uint64(0)
    info = vm_region_basic_info_64()
    info_count = c_uint32(VM_REGION_BASIC_INFO_COUNT_64)
    obj_name = c_uint32(0)
    
    while True:
        ret = libc.mach_vm_region(
            task,
            byref(address),
            byref(size),
            c_uint32(VM_REGION_BASIC_INFO_64),
            byref(info),
            byref(info_count),
            byref(obj_name)
        )
        
        if ret != 0:
            break
        
        addr = address.value
        sz = size.value
        
        region = {
            'start': addr,
            'end': addr + sz,
            'size': sz,
            'prot': info.protection,
            'max_prot': info.max_protection,
            'r': bool(info.protection & VM_PROT_READ),
            'w': bool(info.protection & VM_PROT_WRITE),
            'x': bool(info.protection & VM_PROT_EXECUTE),
        }
        regions.append(region)
        
        address = c_uint64(addr + sz)
    
    return regions


# ──── Memory Search ────

def search_strings(task: int, pattern: bytes) -> list[int]:
    """Search for a byte pattern in readable memory regions."""
    results = []
    regions = enumerate_regions(task)
    
    print(f"  Searching {len(regions)} regions for: {pattern[:50]}...")
    
    for i, region in enumerate(regions):
        if not region['r']:
            continue
        if region['size'] > 512 * 1024 * 1024:  # Skip huge regions
            continue
        
        try:
            for offset in range(0, region['size'], 4096):
                chunk_size = min(4096, region['size'] - offset)
                data = vm_read(task, region['start'] + offset, chunk_size)
                
                pos = data.find(pattern)
                while pos != -1:
                    addr = region['start'] + offset + pos
                    results.append(addr)
                    pos = data.find(pattern, pos + 1)
        except MachException:
            # Skip unreadable region
            continue
        except Exception:
            continue
    
    return results


def search_string(task: int, text: str) -> list[int]:
    """Search for a text string in task memory."""
    return search_strings(task, text.encode('utf-8'))


def dump_strings(task: int, min_len: int = 4) -> list[tuple[int, str]]:
    """Dump all ASCII strings from readable memory (limited scan)."""
    results = []
    regions = enumerate_regions(task)
    
    # Only scan writable regions (where the interesting data is)
    writable = [r for r in regions if r['w'] and r['size'] < 64 * 1024 * 1024]
    
    for region in writable[:20]:  # Limit to first 20 writable regions
        try:
            for offset in range(0, region['size'], 4096):
                chunk_size = min(4096, region['size'] - offset)
                data = vm_read(task, region['start'] + offset, chunk_size)
                
                current = ""
                current_start = 0
                
                for i, byte in enumerate(data):
                    if 32 <= byte < 127:
                        if not current:
                            current_start = region['start'] + offset + i
                        current += chr(byte)
                    else:
                        if len(current) >= min_len:
                            results.append((current_start, current))
                        current = ""
                
                if len(current) >= min_len:
                    results.append((current_start, current))
        except:
            continue
    
    return results


# ──── Growtopia-Specific Memory Layout ────

KNOWN_PATTERNS = {
    'growid': [
        b'"growId":"', b'growId|', b'requestedName|',
        b'tankIDName', b'"tankIDName"', b'ltoken',
    ],
    'password': [
        b'tankIDPass', b'"tankIDPass"', b'"password":"',
        b'password|', b'pass|',
    ],
    'token': [
        b'_token=', b'ltoken=', b'"ltoken"',
    ],
    'meta': [
        b'meta|', b'"meta"', b'gameVersion',
        b'game_version', b'"game_version"',
    ],
    'world': [
        b'world|', b'"world"', b'currentWorld',
        b'onSuperMainStart', b'OnSendToServer',
    ],
    'player_list': [
        b'players|', b'"players"', b'"playerList"',
        b'netAvatar', b'OnConsoleMessage',
    ],
}


class PiterHook:
    """Main hook engine for Growtopia process."""
    
    def __init__(self, pid: Optional[int] = None):
        if pid is None:
            pid = find_process()
            if pid is None:
                print("[!] Growtopia process not found.")
                print("[!] Open Growtopia first, then run: sudo python3 piter_hook.py")
                sys.exit(1)
        
        self.pid = pid
        self.task = None
        self.hits = {}  # category → list of (address, context_data)
        print(f"[*] Attached to PID: {pid}")
    
    def attach(self):
        """Get task port for the process."""
        try:
            self.task = task_for_pid(self.pid)
            print(f"[*] Task port: 0x{self.task:x}")
        except MachException as e:
            print(f"[!] {e}")
            print("[!] SIP must be disabled for task_for_pid on Apple-signed apps.")
            print("[!] Or: run `sudo nvram boot-args=\"amfi_get_out_of_my_way=1\"` and reboot.")
            print("[!] Or: codesign the Python binary with get-task-allow entitlement.")
            sys.exit(1)
    
    def detach(self):
        """Release task port."""
        if self.task:
            release_task(self.task)
            self.task = None
    
    def scan(self):
        """Full scan: find GrowID, password, tokens, world."""
        print("\n[*] Scanning process memory...\n")
        
        for category, patterns in KNOWN_PATTERNS.items():
            for pattern in patterns:
                addrs = search_strings(self.task, pattern)
                if addrs:
                    self.hits[category] = addrs
                    break  # Found one pattern, skip others
        
        self._print_results()
    
    def _print_results(self):
        """Format and display scan results."""
        print("  ───────────────────────────────────────────────")
        
        for category in ['growid', 'password', 'token', 'world']:
            if category in self.hits:
                addrs = self.hits[category]
                print(f"  [{category.upper()}] {len(addrs)} matches:")
                for addr in addrs[:5]:  # Show first 5
                    try:
                        data = vm_read(self.task, addr, 128)
                        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
                        print(f"    0x{addr:016x}: {printable[:100]}")
                    except:
                        print(f"    0x{addr:016x}: <unreadable>")
                if len(addrs) > 5:
                    print(f"    ... and {len(addrs) - 5} more")
                print()
            else:
                print(f"  [{category.upper()}] not found in memory\n")
    
    def find_growid(self) -> Optional[str]:
        """Extract GrowID from memory."""
        patterns = [b'"growId":"', b'growId|', b'requestedName|', b'tankIDName|']
        
        for pattern in patterns:
            addrs = search_strings(self.task, pattern)
            for addr in addrs:
                try:
                    data = vm_read(self.task, addr + len(pattern), 64)
                    # Extract up to first non-alphanumeric
                    growid = ""
                    for b in data:
                        if chr(b).isalnum() or chr(b) in '_-.':
                            growid += chr(b)
                        else:
                            break
                    if len(growid) >= 2:
                        return growid
                except:
                    continue
        
        return None
    
    def find_password(self) -> Optional[str]:
        """Extract password from memory."""
        patterns = [b'"password":"', b'tankIDPass|', b'"tankIDPass":"', b'pass|']
        
        for pattern in patterns:
            addrs = search_strings(self.task, pattern)
            for addr in addrs:
                try:
                    data = vm_read(self.task, addr + len(pattern), 64)
                    password = ""
                    for b in data:
                        if 32 <= b < 127 and b not in (ord('"'), ord('|'), ord('&'), ord('\n'), ord('\r')):
                            password += chr(b)
                        else:
                            break
                    if len(password) >= 2:
                        return password
                except:
                    continue
        
        return None
    
    def find_token(self) -> Optional[str]:
        """Extract auth token from memory."""
        addrs = search_strings(self.task, b'_token=') + search_strings(self.task, b'ltoken=')
        for addr in addrs:
            try:
                data = vm_read(self.task, addr, 128)
                # Find the full token
                text = data.decode('utf-8', errors='replace')
                if '_token=' in text:
                    start = text.index('_token=') + 7
                    tok = text[start:start+50].split('&')[0].split('"')[0].split("'")[0]
                    if len(tok) > 5:
                        return tok
            except:
                continue
        return None
    
    def find_world(self) -> Optional[str]:
        """Extract world name from memory."""
        addrs = search_strings(self.task, b'currentWorld|') + search_strings(self.task, b'"world":')
        for addr in addrs:
            try:
                data = vm_read(self.task, addr + 13, 32)
                world = data.decode('utf-8', errors='replace').split('|')[0].split('"')[0]
                if world and all(c.isprintable() for c in world):
                    return world
            except:
                continue
        return None
    
    def dump_interesting(self):
        """Dump all interesting strings from writable memory."""
        strings = dump_strings(self.task, min_len=4)
        
        keywords = [
            'growid', 'password', 'tankID', 'token', 'world',
            'action|', 'onConsole', 'onSuper', 'inventory',
            'item', 'player', 'discord', 'admin', 'owner'
        ]
        
        print("\n  [INTERESTING STRINGS IN MEMORY]")
        print("  ───────────────────────────────────────────────")
        
        for addr, text in strings:
            lower = text.lower()
            if any(kw in lower for kw in keywords):
                print(f"    0x{addr:016x}: {text[:100]}")
        
        # Also show recent strings (near the end of memory — likely heap)
        if strings:
            recent = strings[-10:]
            print(f"\n  [RECENT MEMORY STRINGS (last 10)]")
            print("  ───────────────────────────────────────────────")
            for addr, text in recent:
                print(f"    0x{addr:016x}: {text[:100]}")
    
    def read_addr(self, address_str: str, size: int = 64):
        """Read memory at address and display."""
        try:
            if address_str.startswith('0x'):
                addr = int(address_str, 16)
            else:
                addr = int(address_str)
        except ValueError:
            print(f"  [!] Invalid address: {address_str}")
            return
        
        try:
            data = vm_read(self.task, addr, size)
            print(f"\n  0x{addr:016x} ({size}B):")
            
            # Hex dump
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_str = ' '.join(f'{b:02x}' for b in chunk)
                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                print(f"  {addr+i:016x}  {hex_str:<48s}  |{ascii_str}|")
        except Exception as e:
            print(f"  [!] Read failed: {e}")
    
    def write_addr(self, address_str: str, hex_data: str):
        """Write hex bytes to memory address."""
        try:
            if address_str.startswith('0x'):
                addr = int(address_str, 16)
            else:
                addr = int(address_str)
        except ValueError:
            print(f"  [!] Invalid address: {address_str}")
            return
        
        try:
            data = bytes.fromhex(hex_data.replace(' ', ''))
            vm_write(self.task, addr, data)
            print(f"  [+] Wrote {len(data)} bytes to 0x{addr:016x}")
        except Exception as e:
            print(f"  [!] Write failed: {e}")


# ──── Interactive shell ────

def print_banner():
    print("""
  ╔══════════════════════════════════════════╗
  ║     PITER HOOK — Process Memory Hook    ║
  ║        Attach: Growtopia memory          ║
  ╚══════════════════════════════════════════╝
""")


def print_help():
    print("""
  Commands:
    scan            - Full memory scan (GrowID, password, tokens)
    growid          - Find GrowID in memory
    pass            - Find password in memory
    token           - Find auth token
    world           - Find world name
    strings         - Dump interesting strings from memory
    read <addr> [n] - Read N bytes from memory address
    write <addr> <hex> - Write hex to memory address
    regions         - Show writable memory regions
    info            - Process info
    help            - This help
    q/quit/exit     - Exit
""")


def interactive(hook: PiterHook):
    """Interactive command loop."""
    print_banner()
    
    # Auto-scan on start
    print("[*] Auto-scanning for login credentials...")
    growid = hook.find_growid()
    password = hook.find_password()
    token = hook.find_token()
    world = hook.find_world()
    
    found = False
    if growid:
        print(f"\n  [!!!] GROWID: {growid}")
        found = True
    if password:
        print(f"  [!!!] PASSWORD: {password}")
        found = True
    if token:
        print(f"  [!!!] TOKEN: {token[:40]}...")
        found = True
    if world:
        print(f"  [!!!] WORLD: {world}")
        found = True
    
    if not found:
        print("\n  [!] No credentials found in memory.")
        print("  [*] Try logging in from Growtopia first, then run 'scan'")
    
    print_help()
    
    while True:
        try:
            raw = input("\n  hook> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Detaching...")
            break
        
        if not raw:
            continue
        
        parts = raw.split(maxsplit=2)
        cmd = parts[0].lower()
        
        if cmd in ('q', 'quit', 'exit'):
            break
        
        elif cmd == 'help':
            print_help()
        
        elif cmd == 'scan':
            hook.scan()
        
        elif cmd == 'growid':
            result = hook.find_growid()
            if result:
                print(f"  [!!!] GROWID: {result}")
            else:
                print("  [-] GrowID not found")
        
        elif cmd == 'pass':
            result = hook.find_password()
            if result:
                print(f"  [!!!] PASSWORD: {result}")
            else:
                print("  [-] Password not found")
        
        elif cmd == 'token':
            result = hook.find_token()
            if result:
                print(f"  [!!!] TOKEN: {result}")
            else:
                print("  [-] Token not found")
        
        elif cmd == 'world':
            result = hook.find_world()
            if result:
                print(f"  [!!!] WORLD: {result}")
            else:
                print("  [-] World not found")
        
        elif cmd == 'strings':
            hook.dump_interesting()
        
        elif cmd == 'read':
            if len(parts) < 2:
                print("  Usage: read <addr> [size]")
                continue
            addr = parts[1]
            size = int(parts[2]) if len(parts) > 2 else 64
            hook.read_addr(addr, size)
        
        elif cmd == 'write':
            if len(parts) < 3:
                print("  Usage: write <addr> <hex>")
                continue
            hook.write_addr(parts[1], parts[2])
        
        elif cmd == 'regions':
            regions = enumerate_regions(hook.task)
            writable = [r for r in regions if r['w'] and r['size'] < 512*1024*1024]
            print(f"\n  [MEMORY REGIONS] Total: {len(regions)}, Writable: {len(writable)}")
            print("  ───────────────────────────────────────────────")
            for r in writable[:15]:
                perms = f"{'R' if r['r'] else '-'}{'W' if r['w'] else '-'}{'X' if r['x'] else '-'}"
                size_kb = r['size'] / 1024
                if size_kb > 1024:
                    size_str = f"{size_kb/1024:.1f}MB"
                else:
                    size_str = f"{size_kb:.0f}KB"
                print(f"    0x{r['start']:016x} - 0x{r['end']:016x}  [{perms}] {size_str}")
        
        elif cmd == 'info':
            print(f"  PID: {hook.pid}")
            print(f"  Task: 0x{hook.task:x}" if hook.task else "  Task: <not attached>")
        
        else:
            print(f"  [?] Unknown: {cmd}. Type 'help' for commands.")
    
    hook.detach()
    print("[*] Done.")


# ──── CLI Entry Point ────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Piter Hook — Process Memory Hook for Growtopia")
    parser.add_argument('-p', '--pid', type=int, help='Target PID')
    parser.add_argument('--scan', action='store_true', help='Quick scan and exit')
    parser.add_argument('--growid', action='store_true', help='Find GrowID and exit')
    parser.add_argument('--pass', dest='find_pass', action='store_true', help='Find password and exit')
    parser.add_argument('--dump', type=str, help='Dump memory address (hex or decimal)')
    
    args = parser.parse_args()
    
    hook = PiterHook(pid=args.pid)
    
    try:
        hook.attach()
    except SystemExit:
        return
    
    if args.scan:
        hook.scan()
        hook.detach()
        return
    
    if args.growid:
        result = hook.find_growid()
        if result:
            print(f"GROWID: {result}")
        hook.detach()
        return
    
    if args.find_pass:
        result = hook.find_password()
        if result:
            print(f"PASSWORD: {result}")
        hook.detach()
        return
    
    if args.dump:
        hook.read_addr(args.dump, 256)
        hook.detach()
        return
    
    interactive(hook)


if __name__ == "__main__":
    main()
