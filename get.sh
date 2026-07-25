#!/bin/bash
# Mac: Quick curl-to-file alternative if git fails
set -e
echo "=== Downloading Piter Tools ==="
curl -fsSL -o piter_sniff.py    "https://raw.githubusercontent.com/Nabenns/piter-tools/master/piter_sniff.py"
curl -fsSL -o piter_tcpdump.py  "https://raw.githubusercontent.com/Nabenns/piter-tools/master/piter_tcpdump.py"
curl -fsSL -o piter_setup.sh    "https://raw.githubusercontent.com/Nabenns/piter-tools/master/piter_setup.sh"
chmod +x piter_sniff.py piter_tcpdump.py piter_setup.sh
echo "[√] Downloaded. Run: sudo python3 piter_tcpdump.py sniff"