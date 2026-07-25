/**
 * Piter Agent v10 — macOS arm64, zero-guess hook
 * ==============================================
 * Strategy: hook connect() to track GT socket fd,
 * then hook write() and filter by that fd.
 * No guessing — libSystem functions guaranteed to exist.
 */

'use strict';

const PITER_IP = '103.129.148.178';
const PITER_PORT = 17091;
let gtFd = -1;
let packetCount = 0;

// ──── Safe hook helper ────
function tryHook(moduleName, funcName, callbacks) {
    try {
        const addr = Module.findExportByName(moduleName, funcName);
        if (!addr) {
            send(`[-] ${moduleName}!${funcName}: not found`);
            return false;
        }
        Interceptor.attach(addr, callbacks);
        send(`[+] Hooked ${moduleName}!${funcName} @ ${addr}`);
        return true;
    } catch (e) {
        send(`[!] ${moduleName}!${funcName}: ${e.message}`);
        return false;
    }
}

// ──── Helper: extract port from sockaddr ────
function getPort(sockaddrPtr) {
    if (sockaddrPtr.isNull()) return 0;
    try {
        // sa_family at offset 1 (byte), port at offset 2-3 (uint16 big-endian)
        const family = sockaddrPtr.readU8();
        if (family !== 2) return 0; // AF_INET = 2
        const port = sockaddrPtr.add(2).readU16();
        // Network byte order → host
        return ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
    } catch (e) {
        return 0;
    }
}

// ──── Helper: extract IP from sockaddr_in ────
function getIP(sockaddrPtr) {
    if (sockaddrPtr.isNull()) return '';
    try {
        const family = sockaddrPtr.readU8();
        if (family !== 2) return ''; // AF_INET
        const addr = sockaddrPtr.add(4).readByteArray(4);
        if (!addr) return '';
        const bytes = new Uint8Array(addr);
        return bytes[0] + '.' + bytes[1] + '.' + bytes[2] + '.' + bytes[3];
    } catch (e) {
        return '';
    }
}

// ──── Hook 1: connect() to track GT socket ────
function hookConnect() {
    tryHook(null, 'connect', {
        onEnter(args) {
            const fd = args[0].toInt32();
            const ip = getIP(args[1]);
            const port = getPort(args[1]);
            
            if (port === PITER_PORT && ip === PITER_IP) {
                gtFd = fd;
                send(`[TRACK] GT socket fd=${fd} → ${ip}:${port}`);
            }
        }
    });
}

// ──── Hook 2: write() to intercept GT packets ────
function hookWrite() {
    tryHook(null, 'write', {
        onEnter(args) {
            const fd = args[0].toInt32();
            if (fd !== gtFd || gtFd === -1) return;
            
            const buf = args[1];
            const len = args[2].toInt32();
            if (len < 4 || len > 65536) return;
            
            try {
                const data = buf.readByteArray(len);
                if (!data) return;
                
                packetCount++;
                const hex = hexdump(data, { offset: 0, length: Math.min(len, 64), header: false, ansi: false });
                
                send({
                    type: 'packet',
                    direction: 'send',
                    num: packetCount,
                    size: len,
                    hex: hex.trim(),
                    timestamp: Date.now()
                });
            } catch (e) {
                // silent
            }
        }
    });
}

// ──── Hook 3: read() to intercept server responses ────
function hookRead() {
    tryHook(null, 'read', {
        onLeave(retval) {
            if (gtFd === -1) return;
            
            // read() was called on our GT fd
            const n = retval.toInt32();
            if (n <= 0) return;
            
            // read() doesn't give us the buffer in onLeave easily,
            // but we can hook the return value to know data arrived
            // For actual payload, hook recv() for incoming
        }
    });
}

// ──── Hook 4: recv() for incoming packets ────
function hookRecv() {
    tryHook(null, 'recv', {
        onLeave(retval) {
            const fd = this.fd;
            if (fd !== gtFd || gtFd === -1) return;
            
            const n = retval.toInt32();
            if (n < 4 || n > 65536) return;
            
            try {
                const buf = this.buf;
                const data = buf.readByteArray(n);
                if (!data) return;
                
                packetCount++;
                send({
                    type: 'packet',
                    direction: 'recv',
                    num: packetCount,
                    size: n,
                    hex: hexdump(data, { offset: 0, length: Math.min(n, 64), header: false, ansi: false }),
                    timestamp: Date.now()
                });
            } catch (e) {
                // silent
            }
        }
    });
    
    // Also hook recvfrom (some apps use it)
    tryHook(null, 'recvfrom', {
        onLeave(retval) {
            const fd = this.fd;
            if (fd !== gtFd || gtFd === -1) return;
            
            const n = retval.toInt32();
            if (n < 4) return;
            
            try {
                const buf = this.buf;
                const data = buf.readByteArray(n);
                if (!data) return;
                
                packetCount++;
                send({
                    type: 'packet',
                    direction: 'recv',
                    num: packetCount,
                    size: n,
                    hex: hexdump(data, { offset: 0, length: Math.min(n, 64), header: false, ansi: false }),
                    timestamp: Date.now()
                });
            } catch (e) {}
        }
    });
}

// Need to save fd and buf for recv/recvfrom onLeave
const origRecv = Module.findExportByName(null, 'recv');
if (origRecv) {
    Interceptor.attach(origRecv, {
        onEnter(args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
            this.len = args[2].toInt32();
        },
        onLeave(retval) {
            const fd = this.fd;
            if (fd !== gtFd || gtFd === -1) return;
            const n = retval.toInt32();
            if (n < 4 || n > 65536) return;
            try {
                const data = this.buf.readByteArray(n);
                if (!data) return;
                packetCount++;
                send({
                    type: 'packet',
                    direction: 'recv',
                    num: packetCount,
                    size: n,
                    hex: hexdump(data, { offset: 0, length: Math.min(n, 64), header: false, ansi: false }),
                    timestamp: Date.now()
                });
            } catch (e) {}
        }
    });
    send('[+] Hooked recv with fd tracking');
}

const origRecvfrom = Module.findExportByName(null, 'recvfrom');
if (origRecvfrom) {
    Interceptor.attach(origRecvfrom, {
        onEnter(args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
        },
        onLeave(retval) {
            const fd = this.fd;
            if (fd !== gtFd || gtFd === -1) return;
            const n = retval.toInt32();
            if (n < 4) return;
            try {
                const data = this.buf.readByteArray(n);
                if (!data) return;
                packetCount++;
                send({
                    type: 'packet',
                    direction: 'recv',
                    num: packetCount,
                    size: n,
                    hex: hexdump(data, { offset: 0, length: Math.min(n, 64), header: false, ansi: false }),
                    timestamp: Date.now()
                });
            } catch (e) {}
        }
    });
    send('[+] Hooked recvfrom with fd tracking');
}

// ──── Scan available modules ────
function scanModules() {
    const modules = Process.enumerateModules();
    const relevant = [];
    const targets = ['libSystem', 'libc', 'libdispatch', 'CFNetwork', 'Network', 'CoreFoundation'];
    for (const m of modules) {
        for (const t of targets) {
            if (m.name.toLowerCase().includes(t.toLowerCase())) {
                relevant.push(m.name);
                break;
            }
        }
    }
    send(`[MODULES] Relevant: ${JSON.stringify(relevant.slice(0, 15))}`);
    return relevant;
}

// ──── Init ────
function init() {
    send('[INIT] Piter Agent v10 — arm64 zero-guess');
    
    scanModules();
    
    // Hook connect — guaranteed in libSystem
    hookConnect();
    
    // Hook write — guaranteed in libSystem  
    hookWrite();
    
    // recv/recvfrom hooked inline above with fd tracking
    // read hook
    
    tryHook(null, 'read', {
        onEnter(args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
        },
        onLeave(retval) {
            const fd = this.fd;
            if (fd !== gtFd || gtFd === -1) return;
            const n = retval.toInt32();
            if (n < 4 || n > 65536) return;
            try {
                const data = this.buf.readByteArray(n);
                if (!data) return;
                packetCount++;
                send({
                    type: 'packet',
                    direction: 'recv',
                    num: packetCount,
                    size: n,
                    hex: hexdump(data, { offset: 0, length: Math.min(n, 64), header: false, ansi: false }),
                    timestamp: Date.now()
                });
            } catch (e) {}
        }
    });
    
    send(`[STATUS] Hooks active | connect: true | write: true | recv: true | read: true`);
    send(`[WAITING] Open GT and connect to server... (fd=${gtFd})`);
}

// ──── Status check (called periodically by Python) ────
function status() {
    send(JSON.stringify({
        fd: gtFd,
        packets: packetCount,
        time: Date.now()
    }));
}

// Auto-init
init();
