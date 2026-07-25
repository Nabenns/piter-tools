/*
 * Piter Agent v9 — Network.framework nw_connection hook
 * Growtopia Mac (arm64) uses Network.framework (nw_connection_send, nw_connection_receive).
 * This is the correct layer — bypasses libSystem entirely.
 */

let send_count = 0, recv_count = 0;

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
        info = 'LOGIN ' + fields.tankIDName + '/' + (fields.tankIDPass||'').slice(0,2) + '***';
    } else if (fields.action) {
        info = 'ACT ' + fields.action;
    } else if (fields.onSuperMainStart) {
        info = 'GAME_ENTER';
    } else if (fields.world) {
        info = 'WORLD ' + fields.world;
    } else if (text) {
        info = text.slice(0, 60);
    }
    send({type:'packet', dir, size, info, hex:hex(data,40), fields});
    if (dir === '→') send_count++; else recv_count++;
}

// ── Safe Interceptor.attach wrapper ──
function safeAttach(name, ptr, callbacks) {
    if (!ptr || ptr.isNull()) {
        send({type:'debug', msg: 'SKIP ' + name + ': null ptr'});
        return false;
    }
    try {
        Interceptor.attach(ptr, callbacks);
        send({type:'debug', msg: 'HOOKED ' + name});
        return true;
    } catch(e) {
        send({type:'debug', msg: 'FAIL ' + name + ': ' + e.message});
        return false;
    }
}

// ── Method 1: nw_connection_send (Network.framework) ──
function hookNwConnectionSend() {
    const ptr = Module.findExportByName('/System/Library/Frameworks/Network.framework/Network', 'nw_connection_send');
    if (!ptr || ptr.isNull()) {
        // Try without full path as fallback
        const p2 = Module.findExportByName('Network', 'nw_connection_send');
        if (p2 && !p2.isNull()) return safeAttach('nw_connection_send', p2, {
            onEnter(args) {
                // args[0] = nw_connection_t, args[1] = dispatch_data_t
                const dd = args[1];
                if (!dd || dd.isNull()) return;
                // dispatch_data_get_size + dispatch_data_create_map
                const getSize = Module.findExportByName('/usr/lib/system/libdispatch.dylib', 'dispatch_data_get_size');
                const createMap = Module.findExportByName('/usr/lib/system/libdispatch.dylib', 'dispatch_data_create_map');
                if (!getSize || getSize.isNull() || !createMap || createMap.isNull()) return;
                const size = new NativeFunction(getSize, 'size_t', ['pointer'])(dd);
                if (size < 4 || size > 65536) return;
                const map = new NativeFunction(createMap, 'pointer', ['pointer', 'pointer', 'pointer'])(dd, ptr(0), ptr(0));
                if (!map || map.isNull()) return;
                const buf = map.add(16); // dispatch_data_s: data ptr at offset 16
                const data = Memory.readByteArray(buf, Math.min(size, 4096));
                if (!data) return;
                emitPacket('→', size, data);
            }
        });
        return safeAttach('nw_connection_send', ptr);
    }
    return safeAttach('nw_connection_send', ptr, {
        onEnter(args) {
            const dd = args[1];
            if (!dd || dd.isNull()) return;
            const sizePtr = dd.add(Process.pointerSize); // dispatch_data_t: length at +8
            const size = Memory.readULong(sizePtr);
            if (size < 4 || size > 65536) return;
            const bufPtr = dd.add(Process.pointerSize * 2);
            const data = Memory.readByteArray(bufPtr, Math.min(size, 4096));
            if (!data) return;
            emitPacket('→', size, data);
        }
    });
}

// ── Method 2: nw_connection_receive (Network.framework) ──
function hookNwConnectionReceive() {
    const ptr = Module.findExportByName('/System/Library/Frameworks/Network.framework/Network', 'nw_connection_receive');
    if (!ptr || ptr.isNull()) {
        const p2 = Module.findExportByName('Network', 'nw_connection_receive');
        if (p2 && !p2.isNull()) return safeAttach('nw_connection_receive', p2, {
            onEnter(args) {
                this.completionHandler = args[1]; // nw_connection_receive_completion_t block
            },
            onLeave(retval) {}
        });
        return false;
    }
    return safeAttach('nw_connection_receive', ptr, {
        onEnter(args) {
            this.completionHandler = args[1];
        },
        onLeave(retval) {}
    });
}

// ── Method 3: CFWriteStreamWrite (CoreFoundation) ──
function hookCFWriteStreamWrite() {
    const ptr = Module.findExportByName('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation', 'CFWriteStreamWrite');
    if (!ptr || ptr.isNull()) return false;
    return safeAttach('CFWriteStreamWrite', ptr, {
        onEnter(args) {
            const buf = args[1];
            const count = args[2].toInt32();
            if (!buf || count < 4 || count > 65536) return;
            const data = Memory.readByteArray(buf, Math.min(count, 4096));
            if (!data) return;
            emitPacket('→', count, data);
        }
    });
}

// ── Method 4: CFReadStreamRead ──
function hookCFReadStreamRead() {
    const ptr = Module.findExportByName('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation', 'CFReadStreamRead');
    if (!ptr || ptr.isNull()) return false;
    return safeAttach('CFReadStreamRead', ptr, {
        onEnter(args) { this.buf = args[1]; },
        onLeave(retval) {
            const count = retval.toInt32();
            if (count < 4 || count > 65536 || !this.buf) return;
            const data = Memory.readByteArray(this.buf, Math.min(count, 4096));
            if (!data) return;
            emitPacket('←', count, data);
        }
    });
}

// ── Method 5: Last resort — socket write/read via syscall ──
function hookSyscallWrite() {
    // syscall(4, fd, buf, count) = write
    const libSystem = Module.findExportByName(null, 'syscall');
    if (!libSystem || libSystem.isNull()) return false;
    return safeAttach('syscall(write)', libSystem, {
        onEnter(args) {
            const num = args[0].toInt32();
            if (num !== 4) return; // 4 = SYS_write on arm64
            const buf = args[2];
            const count = args[3].toInt32();
            if (!buf || count < 4 || count > 65536) return;
            const data = Memory.readByteArray(buf, Math.min(count, 4096));
            if (!data) return;
            const a = new Uint8Array(data);
            if (a[0]===0 && a[1]===0 && a[2]===0 && a[3]===0) return;
            emitPacket('→', count, data);
        }
    });
}

function hookSyscallRead() {
    const libSystem = Module.findExportByName(null, 'syscall');
    if (!libSystem || libSystem.isNull()) return false;
    return safeAttach('syscall(read)', libSystem, {
        onEnter(args) {
            const num = args[0].toInt32();
            if (num !== 3) return; // 3 = SYS_read on arm64
            this.buf = args[2];
        },
        onLeave(retval) {
            const count = retval.toInt32();
            if (count < 4 || count > 65536 || !this.buf) return;
            const data = Memory.readByteArray(this.buf, Math.min(count, 4096));
            if (!data) return;
            emitPacket('←', count, data);
        }
    });
}

// ── Main init ──
rpc.exports = {
    init() {
        send_count = 0; recv_count = 0;
        const results = {};
        
        // Enumerate available modules for debug
        const mods = Process.enumerateModules();
        const netMods = [];
        for (const m of mods) {
            if (m.name.toLowerCase().includes('network') || 
                m.name.toLowerCase().includes('system') ||
                m.name.toLowerCase().includes('corefoundation') ||
                m.name.toLowerCase().includes('dispatch')) {
                netMods.push(m.name);
            }
        }
        send({type:'debug', msg:'Relevant modules: ' + JSON.stringify(netMods.slice(0,10))});
        
        // Try all hook methods — one will work
        results.nw_send = hookNwConnectionSend();
        results.nw_recv = hookNwConnectionReceive();
        results.cf_write = hookCFWriteStreamWrite();
        results.cf_read = hookCFReadStreamRead();
        
        // If nothing worked, fall back to raw syscalls
        if (!results.nw_send && !results.cf_write) {
            results.syscall_write = hookSyscallWrite();
            results.syscall_read = hookSyscallRead();
        }
        
        const sendOk = results.nw_send || results.cf_write || results.syscall_write;
        const recvOk = results.nw_recv || results.cf_read || results.syscall_read;
        
        send({
            type:'ready',
            sendHooked: sendOk,
            recvHooked: recvOk,
            results
        });
        
        return results;
    },
    
    stats() { return { send_count, recv_count }; }
};

send({ type: 'loaded', pid: Process.id, arch: Process.arch });
