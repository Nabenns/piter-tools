#!/bin/bash
# Piter Server — Mac Setup Script
# Run this on your Mac to intercept Growtopia traffic

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SNIFF_SCRIPT="$SCRIPT_DIR/piter_sniff.py"

echo "========================================="
echo "  Piter Server — GTPS Packet Interceptor"
echo "========================================="
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "[!] Python 3 not found. Install from python.org or brew install python3"
    exit 1
fi

if [ ! -f "$SNIFF_SCRIPT" ]; then
    echo "[!] piter_sniff.py not found. Put it in the same directory as this script."
    exit 1
fi

echo "[1] Testing connection to Piter server..."
python3 -c "
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)
try:
    sock.sendto(b'test', ('103.129.148.178', 17091))
    print('  UDP 17091: reachable')
except Exception as e:
    print(f'  UDP 17091: {e}')
" 2>&1

echo ""
echo "[2] Setup options:"
echo ""
echo "  OPTION A: Sniff mode (passive — just watch)"
echo "    sudo python3 piter_sniff.py sniff"
echo "    → Watches ALL UDP traffic on port 17091"
echo ""
echo "  OPTION B: Proxy mode (intercept + modify)"
echo "    Step 1: sudo python3 piter_sniff.py proxy"
echo "    Step 2: Redirect GT traffic to proxy:"
echo "      sudo pfctl -e"
echo "      echo 'rdr pass on lo0 proto udp from any to any port 17091 -> 127.0.0.1 port 17091' | sudo pfctl -f -"
echo "    Step 3: Run Growtopia and login"
echo ""
echo "  OPTION C: Forge login (test GrowID/password combos)"
echo "    python3 piter_sniff.py forge <GrowID> <password>"
echo "    → Sends ENet login packet directly to server"
echo ""
echo "  OPTION D: Brute force (enumerate existing accounts)"
echo "    python3 piter_sniff.py brute growids.txt"
echo "    → Tests each GrowID against server"

echo ""
echo "[3] Suggested first test: OPTION A — sniff while you play"
echo "    sudo python3 piter_sniff.py sniff"
echo "    (Open another terminal, start Growtopia, login as nabenns)"
echo ""
echo "This will show you all ENet packets between your client and Piter."