/**
 * Piter Agent v11 — macOS arm64, UDP-focused for Growtopia ENet
 * =================================================================
 * Hook sendto() and recvfrom() filtered by socket fd tracking.
 * No guessing — libSystem functions guaranteed to exist on arm64.
 */
'use strict';

const PITER_IP = '103.129.148.178';
const PITER_PORT = 17091;
let gtFd = -1;
let packetCount = 0;

function hexstr(arr, maxLen) {
    maxLen = maxLen || 64;
    const bytes = new Uint8Array(arr.slice(0, Math.min(arr.byteLength, maxLen)));
    return Array.from(bytes).map(b => ('0' + b.toString(16)).slice(-2)).join(' ');
}

// ──── Safe hook ────
function tryHook(moduleName, funcName, callbacks) {
    try {
        const addr = Module.findExportByName(moduleName, funcName);
        if (!addr) { send(`[-] ${funcName}: not found`); return false; }
        Interceptor.attach(addr, callbacks);
        send(`[+] Hooked ${funcName} @ ${addr}`);
        return true;
    } catch (e) { send(`[!] ${funcName}: ${e.message}`); return false; }
}

// ──── Port extraction from sockaddr ────
function getPort(sa) {
    if (sa.isNull()) return 0;
    try {
        if (sa.readU8() !== 2) return 0; // AF_INET
        return ((sa.add(2).readU8() & 0xFF) << 8) | (sa.add(3).readU8() & 0xFF);
    } catch(e) { return 0; }
}

function getIP(sa) {
    if (sa.isNull()) return '';
    try {
        if (sa.readU8() !== 2) return '';
        const b = sa.add(4).readByteArray(4);
        const u = new Uint8Array(b);
        return u[0] + '.' + u[1] + '.' + u[2] + '.' + u[3];
    } catch(e) { return ''; }
}

// ──── Hook sendto() ────
tryHook(null, 'sendto', {
    onEnter(args) {
        const fd = args[0].toInt32();
        const port = getPort(args[4]);
        const ip = getIP(args[4]);

        if (port === PITER_PORT && ip === PITER_IP) {
            gtFd = fd;
            const buf = args[1];
            const len = args[2].toInt32();
            if (len < 4 || len > 65536) return;

            try {
                const data = buf.readByteArray(len);
                packetCount++;
                send({
                    type: 'packet',
                    dir: 'SEND',
                    num: packetCount,
                    size: len,
                    hex: hexstr(data),
                    ts: Date.now()
                });
            } catch(e) {}
        }
    }
});

// ──── Hook recvfrom() ────
tryHook(null, 'recvfrom', {
    onEnter(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
    },
    onLeave(retval) {
        if (this.fd !== gtFd || gtFd === -1) return;
        const n = retval.toInt32();
        if (n < 4 || n > 65536) return;

        try {
            const data = this.buf.readByteArray(n);
            packetCount++;
            send({
                type: 'packet',
                dir: 'RECV',
                num: packetCount,
                size: n,
                hex: hexstr(data),
                ts: Date.now()
            });
        } catch(e) {}
    }
});

// ──── Scan modules ────
const modules = Process.enumerateModules();
const relevant = [];
const targets = ['libSystem', 'CFNetwork', 'Network', 'CoreFoundation'];
for (const m of modules) {
    for (const t of targets) {
        if (m.name.toLowerCase().includes(t.toLowerCase())) { relevant.push(m.name); break; }
    }
}
send(`[MODULES] ${relevant.join(', ')}`);

send(`[READY] Agent v11 active — PID: ${Process.id} | GT fd: ${gtFd} | Packets: ${packetCount}`);
send('[WAIT] Connect to server in Growtopia...');

// ──── Status command ────
rpc.exports = {
    status: function() {
        return JSON.stringify({ fd: gtFd, packets: packetCount });
    }
};
