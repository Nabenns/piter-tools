/*
 * Piter Agent v8 — libSystem + CFSocket + socket fd monitoring
 * Growtopia on Mac uses CFSocket backed by libSystem write/read.
 * We enumerate ALL loaded modules, find libSystem, hook everything.
 */

let send_count = 0, recv_count = 0;
let pending = {};  // fd → callback tracking

function hex(buf, n) {
    const a = new Uint8Array(buf); let s = '';
    for (let i = 0; i < Math.min(a.length, n || 32); i++)
        s += a[i].toString(16).padStart(2, '0');
    return s;
}

function decodeText(buf) {
    const a = new Uint8Array(buf); let s = '', alphas = 0;
    for (let i = 0; i < Math.min(a.length, 200); i++) {
        const c = a[i];
        if (c === 0) break;
        s += (c >= 32 && c < 127) ? String.fromCharCode(c) : '.';
        if (c >= 65 && c <= 122) alphas++;
    }
    return alphas >= 2 ? s : '';
}

function extractFields(buf) {
    const t = decodeText(buf); const f = {};
    if (!t) return f;
    for (const line of t.split('\n')) {
        const i = line.indexOf('|');
        if (i > 0) f[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    }
    return f;
}

function emitPacket(dir, size, data) {
    const fields = extractFields(data);
    const text = decodeText(data);
    let info = 'ENET';
    if (fields.tankIDName) {
        info = `LOGIN ${fields.tankIDName}/${(fields.tankIDPass||'').slice(0,2)}***`;
    } else if (fields.action) {
        info = `ACT ${fields.action}`;
    } else if (fields.onSuperMainStart) {
        info = 'GAME_ENTER';
    } else if (fields.world) {
        info = `WORLD ${fields.world}`;
    } else if (text) {
        info = text.slice(0, 60);
    }
    send({type:'packet', dir, size, info, hex:hex(data,40), fields});
    if (dir === '→') send_count++; else recv_count++;
}

// Step 0: Enumerate all available export functions
function enumerateExports() {
    const mods = Process.enumerateModules();
    const result = [];
    for (const m of mods) {
        if (m.name.includes('System') || m.name.includes('network') || m.name.includes('CFNetwork') || m.name.includes('Socket')) {
            result.push({name: m.name, path: m.path, base: m.base.toString()});
        }
    }
    return result;
}

// Step 1: Find libSystem and hook write/read
function hookLibSystem() {
    const libSystem = Process.findModuleByName('libSystem.B.dylib');
    const libSystemPath = libSystem ? libSystem.path : null;
    
    send({ type: 'debug', msg: 'libSystem: ' + (libSystemPath || 'NOT FOUND') });
    
    // Try write
    const writePtr = Module.findExportByName(libSystemPath, 'write');
    if (writePtr && !writePtr.isNull()) {
        Interceptor.attach(writePtr, {
            onEnter(args) {
                const fd = args[0].toInt32();
                const buf = args[1];
                const count = args[2].toInt32();
                if (!buf || count < 4 || count > 65536) return;
                const data = Memory.readByteArray(buf, Math.min(count, 4096));
                if (!data) return;
                const a = new Uint8Array(data);
                if (a[0]===0 && a[1]===0 && a[2]===0 && a[3]===0) return;
                emitPacket('→', count, data);
            }
        });
        return { flag: 'write', ok: true };
    }
    return { flag: 'write', ok: false };
}

function hookLibSystemRecv() {
    const libSystem = Process.findModuleByName('libSystem.B.dylib');
    const libSystemPath = libSystem ? libSystem.path : null;
    
    // Try recv
    const recvPtr = Module.findExportByName(libSystemPath, 'recv');
    if (recvPtr && !recvPtr.isNull()) {
        Interceptor.attach(recvPtr, {
            onEnter(args) { this.buf = args[1]; },
            onLeave(retval) {
                const count = retval.toInt32();
                if (count < 4 || count > 65536 || !this.buf) return;
                const data = Memory.readByteArray(this.buf, Math.min(count, 4096));
                if (!data) return;
                emitPacket('←', count, data);
            }
        });
        return { flag: 'recv', ok: true };
    }

    // Try read
    const readPtr = Module.findExportByName(libSystemPath, 'read');
    if (readPtr && !readPtr.isNull()) {
        Interceptor.attach(readPtr, {
            onEnter(args) { this.buf = args[1]; },
            onLeave(retval) {
                const count = retval.toInt32();
                if (count < 4 || count > 65536 || !this.buf) return;
                const data = Memory.readByteArray(this.buf, Math.min(count, 4096));
                if (!data) return;
                emitPacket('←', count, data);
            }
        });
        return { flag: 'read', ok: true };
    }
    return { flag: 'recv/read', ok: false };
}

// Step 2: Hook sendto/recvfrom
function hookSendto() {
    const ptr = Module.findExportByName(null, 'sendto');
    if (!ptr || ptr.isNull()) return { flag: 'sendto', ok: false };
    Interceptor.attach(ptr, {
        onEnter(args) {
            const buf = args[1];
            const count = args[2].toInt32();
            if (!buf || count < 4 || count > 65536) return;
            const data = Memory.readByteArray(buf, Math.min(count, 4096));
            if (!data) return;
            emitPacket('→', count, data);
        }
    });
    return { flag: 'sendto', ok: true };
}

function hookRecvfrom() {
    const ptr = Module.findExportByName(null, 'recvfrom');
    if (!ptr || ptr.isNull()) return { flag: 'recvfrom', ok: false };
    Interceptor.attach(ptr, {
        onEnter(args) { this.buf = args[1]; },
        onLeave(retval) {
            const count = retval.toInt32();
            if (count < 4 || count > 65536 || !this.buf) return;
            const data = Memory.readByteArray(this.buf, Math.min(count, 4096));
            if (!data) return;
            emitPacket('←', count, data);
        }
    });
    return { flag: 'recvfrom', ok: true };
}

// Step 3: Hook connect() to find the socket fd, then hook write() with fd filter
function hookConnect() {
    const ptr = Module.findExportByName(null, 'connect');
    if (!ptr || ptr.isNull()) return false;
    
    Interceptor.attach(ptr, {
        onEnter(args) {
            // args[0] = fd, args[1] = sockaddr
            this.fd = args[0].toInt32();
        },
        onLeave(retval) {
            if (retval.toInt32() !== 0) return;
            const fd = this.fd;
            if (fd < 3) return;
            // Read sockaddr to get port
            try {
                const sa = this.context.rdi; // args[1]
                if (sa) {
                    const family = Memory.readUShort(sa.add(1)); // sa_family (offset 1 in sockaddr)
                    const port = ((Memory.readU8(sa.add(2)) << 8) | Memory.readU8(sa.add(3)));
                    send({ type: 'debug', msg: `connect fd=${fd} port=${port}` });
                    if (port === 17091) {
                        pending[fd] = { port: 17091, time: Date.now() };
                        send({ type: 'connected', fd, port: 17091 });
                    }
                }
            } catch(e) {}
        }
    });
    return true;
}

// Step 4: Hook write() with FD tracking — only intercept known GT socket
function hookWriteFiltered() {
    const libSystem = Process.findModuleByName('libSystem.B.dylib');
    const libSystemPath = libSystem ? libSystem.path : null;
    const writePtr = Module.findExportByName(libSystemPath, 'write');
    if (!writePtr || writePtr.isNull()) return false;
    
    Interceptor.attach(writePtr, {
        onEnter(args) {
            const fd = args[0].toInt32();
            const buf = args[1];
            const count = args[2].toInt32();
            if (!buf || count < 4 || count > 65536) return;
            // Filter: only known GT socket fd
            if (pending[fd] && pending[fd].port === 17091) {
                const data = Memory.readByteArray(buf, Math.min(count, 4096));
                if (!data) return;
                emitPacket('→', count, data);
            }
        }
    });
    return true;
}

rpc.exports = {
    init() {
        send_count = 0; recv_count = 0;
        pending = {};
        
        const results = { modules: enumerateExports(), hooks: {} };

        // Hook connect to find GT socket
        results.hooks.connect = hookConnect();

        // Hook libc send
        results.hooks.libsend = hookLibSystem();
        if (!results.hooks.libsend.ok) results.hooks.sendto = hookSendto();

        // Hook libc recv
        results.hooks.librecv = hookLibSystemRecv();
        if (!results.hooks.librecv.ok) results.hooks.recvfrom = hookRecvfrom();

        // Hook write with fd filter (bonus - if connect worked)
        if (results.hooks.connect) {
            try { hookWriteFiltered(); results.hooks.writeFiltered = true; } catch(e) {}
        }

        // Hook CFSocketSendData as last resort
        try {
            const cfPtr = Module.findExportByName(null, 'CFSocketSendData');
            if (cfPtr && !cfPtr.isNull()) {
                Interceptor.attach(cfPtr, {
                    onEnter(args) {
                        const dataPtr = args[1];
                        if (!dataPtr) return;
                        const lenPtr = Memory.readPointer(dataPtr);
                        if (!lenPtr) return;
                        const len = Memory.readUInt(lenPtr);
                        if (len < 4 || len > 65536) return;
                        const bufPtr = dataPtr.add(Process.pointerSize);
                        const data = Memory.readByteArray(bufPtr, Math.min(len, 4096));
                        if (!data) return;
                        emitPacket('→', len, data);
                    }
                });
                results.hooks.CFSocket = true;
            }
        } catch(e) {}

        send({ type: 'ready',
            sendHooked: results.hooks.libsend.ok || results.hooks.sendto.ok,
            recvHooked: results.hooks.librecv.ok || results.hooks.recvfrom.ok,
            results
        });
        return results;
    },

    stats() { return { send_count, recv_count }; }
};

send({ type: 'loaded', pid: Process.id, arch: Process.arch });
