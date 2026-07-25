/**
 * Piter Cheat Engine — Frida Agent (v6)
 * =======================================
 * Injected into Growtopia process via Frida.
 * Hooks ENet, tank protocol, and game packets.
 * macOS focused — `sendto`, `sendmsg`, `write` fallback.
 */
'use strict';

// ──── State ────
const state = {
    growId: '',
    password: '',
    token: '',
    worldName: '',
    netId: 0,
    players: [],
    inventory: [],
    gems: 0,
    level: 0,
    posX: 0,
    posY: 0,
    hooksActive: false,
    packetLog: [],
    maxPacketLog: 200
};

// ──── Pattern Scanner ────
function scanPattern(pattern, moduleName) {
    try {
        const mod = Process.findModuleByName(moduleName || 'Growtopia');
        if (!mod) return [];
        const results = [];
        const patternStr = pattern.replace(/\s/g, '');
        const bytes = [];
        for (let i = 0; i < patternStr.length; i += 2) {
            const b = patternStr.substr(i, 2);
            bytes.push(b === '??' ? null : parseInt(b, 16));
        }
        const base = mod.base;
        const size = mod.size;
        const buf = base.readByteArray(size);
        for (let i = 0; i <= size - bytes.length; i++) {
            let matched = true;
            for (let j = 0; j < bytes.length; j++) {
                if (bytes[j] !== null && (buf[i + j] & 0xFF) !== bytes[j]) {
                    matched = false;
                    break;
                }
            }
            if (matched) results.push(base.add(i));
        }
        return results;
    } catch (e) {
        return [];
    }
}

// ──── String Scanner ────
function scanStrings(term, maxResults) {
    try {
        const mod = Process.findModuleByName('Growtopia');
        if (!mod) return [];
        const results = [];
        Memory.scan(mod.base, mod.size, term, {
            onMatch(address) {
                try {
                    const str = address.readCString();
                    if (str && str.length > 2 && str.length < 256) {
                        results.push({ address: address, value: str });
                    }
                } catch (e) {}
            },
            onComplete() {}
        });
        return results.slice(0, maxResults || 50);
    } catch (e) {
        return [];
    }
}

// ──── ENet Send/Recv Hooks ────
function hookEnetSend() {
    const methods = ['sendto', 'sendmsg', 'send', 'write'];
    let hooked = false;
    const errors = [];

    for (let i = 0; i < methods.length; i++) {
        const name = methods[i];
        let addr = Module.findExportByName(null, name);

        if (!addr) addr = Module.findExportByName('libsystem_c.dylib', name);
        if (!addr) addr = Module.findExportByName('libSystem.B.dylib', name);
        if (!addr) addr = Module.findExportByName('/usr/lib/libSystem.B.dylib', name);

        if (addr) {
            try {
                // Capture `name` in closure so it stays correct
                const fnName = name;
                Interceptor.attach(addr, {
                    onEnter(args) {
                        const buf = args[1];
                        let len = 0;
                        try { len = args[2].toInt32(); } catch(e) {}
                        if (len > 0 && len < 65536) {
                            try {
                                const data = Memory.readByteArray(buf, len);
                                if (data) handleOutboundPacket(data);
                            } catch(e) {}
                        }
                    }
                });
                hooked = true;
                send({ status: 'hook_ok', fn: name });
                break;
            } catch (e) {
                errors.push(name + ': ' + e.message);
            }
        } else {
            errors.push(name + ': not found');
        }
    }

    if (!hooked) {
        send({ status: 'hook_failed', errors: errors });
        // Fallback: hook raw write() without socket filtering
        tryWriteFallback();
    }

    return hooked;
}

function tryWriteFallback() {
    const writePtr = Module.findExportByName(null, 'write');
    if (!writePtr) {
        send({ status: 'hook_failed', info: 'no write() either' });
        return;
    }

    Interceptor.attach(writePtr, {
        onEnter(args) {
            const buf = args[1];
            let len = 0;
            try { len = args[2].toInt32(); } catch(e) {}
            if (len > 3 && len < 65536) {
                try {
                    const data = Memory.readByteArray(buf, len);
                    // Quick heuristic: does it look like an ENet packet?
                    const peek = new Uint8Array(data);
                    if (peek[0] === 0x01 || peek[0] === 0x04 || peek[0] === 0x02) {
                        handleOutboundPacket(data);
                    } else {
                        // Check for pipe-delimited tank data
                        for (let i = 0; i < Math.min(len, 100); i++) {
                            if (peek[i] === 0x7c) { // '|' character
                                handleOutboundPacket(data);
                                break;
                            }
                        }
                    }
                } catch(e) {}
            }
        }
    });
    send({ status: 'hook_ok', fn: 'write(fallback)' });
}

function hookEnetRecv() {
    let hooked = false;
    const methods = ['recvfrom', 'recv', 'recvmsg', 'read'];

    for (let i = 0; i < methods.length; i++) {
        const name = methods[i];
        let addr = Module.findExportByName(null, name);

        if (!addr) addr = Module.findExportByName('libsystem_c.dylib', name);
        if (!addr) addr = Module.findExportByName('libSystem.B.dylib', name);

        if (addr) {
            try {
                Interceptor.attach(addr, {
                    onEnter(args) {
                        this.buf = args[1];
                    },
                    onLeave(retval) {
                        const ret = retval.toInt32();
                        if (ret > 0 && ret < 65536) {
                            try {
                                const data = Memory.readByteArray(this.buf, ret);
                                if (data) handleInboundPacket(data);
                            } catch(e) {}
                        }
                    }
                });
                hooked = true;
                send({ status: 'hook_ok', fn: name + '(recv)' });
                break;
            } catch (e) {}
        }
    }

    if (!hooked) {
        send({ status: 'hook_warn', info: 'no recv hook — outbound only' });
    }

    return hooked;
}

// ──── Packet Handlers ────
function handleOutboundPacket(data) {
    try {
        const arr = new Uint8Array(data);
        if (arr.length < 4) return;

        const hex = Array.from(arr.slice(0, 32)).map(b => b.toString(16).padStart(2, '0')).join('');
        let ptype = 'DATA';
        let summary = '';

        if (arr[0] === 0x01 && arr[1] === 0x00 && arr[2] === 0x00 && arr[3] === 0x00) {
            ptype = 'ENET_CONNECT';
        } else {
            // Try to decode as text
            const text = String.fromCharCode.apply(null, arr.filter(b => b >= 32 && b < 127));

            // Look for tank fields
            const tankMatch = text.match(/requestedName\|([^\n]+)/);
            if (tankMatch) state.growId = tankMatch[1];

            const passMatch = text.match(/tankIDPass\|([^\n]+)/);
            if (passMatch) state.password = passMatch[1];

            const tokenMatch = text.match(/_token=([^\n&]+)/);
            if (tokenMatch) state.token = tokenMatch[1];

            if (tankMatch || passMatch) {
                ptype = 'ENET_LOGIN';
                summary = 'GROWID: ' + state.growId + ' | PASS: ' + (state.password ? state.password.substring(0,3)+'***' : '?');
            } else if (text.includes('action|')) {
                ptype = 'GAME_ACTION';
                summary = text.substring(0, 80);
                if (text.includes('enter_game')) summary = 'action|enter_game (JOINED)';
            } else if (text.includes('tileChange')) {
                ptype = 'TILE_CHANGE';
                summary = text.substring(0, 80);
            } else if (text.length > 2) {
                summary = text.substring(0, 60);
            }
        }

        // Log
        state.packetLog.unshift({
            dir: 'OUT',
            type: ptype,
            size: arr.length,
            hex: hex,
            summary: summary,
            time: Date.now()
        });
        if (state.packetLog.length > state.maxPacketLog) state.packetLog.pop();

        send({
            event: 'packet_out',
            type: ptype,
            size: arr.length,
            summary: summary
        });

    } catch (e) {}
}

function handleInboundPacket(data) {
    try {
        const arr = new Uint8Array(data);
        if (arr.length < 4) return;

        const text = String.fromCharCode.apply(null, arr.filter(b => b >= 32 && b < 127));
        let ptype = 'SERVER';
        let summary = '';

        if (text.includes('OnSuperMainStart')) {
            ptype = 'WORLD_JOIN';
            const nameMatch = text.match(/OnSuperMainStart[^\n]*/);
            if (nameMatch) {
                const parts = nameMatch[0].split('|');
                if (parts.length > 1) state.worldName = parts[1] || '';
                for (const part of parts) {
                    if (part.includes('base_uid')) state.netId = parseInt(part.split('=')[1]) || 0;
                    if (part.includes('credits')) state.gems = parseInt(part.split('=')[1]) || 0;
                }
            }
            summary = 'WORLD: ' + state.worldName + ' | GEMS: ' + state.gems + ' | NETID: ' + state.netId;
        } else if (text.includes('action|')) {
            ptype = 'GAME_ACTION';
            summary = text.substring(0, 100);
        } else if (text.includes('add_player')) {
            ptype = 'PLAYER_JOIN';
            summary = text.substring(0, 100);
        } else if (text.includes('remove_player')) {
            ptype = 'PLAYER_LEAVE';
            summary = text.substring(0, 100);
        } else if (text.length > 2) {
            summary = text.substring(0, 60);
        }

        const hex = Array.from(arr.slice(0, 32)).map(b => b.toString(16).padStart(2, '0')).join('');

        state.packetLog.unshift({
            dir: 'IN',
            type: ptype,
            size: arr.length,
            hex: hex,
            summary: summary,
            time: Date.now()
        });
        if (state.packetLog.length > state.maxPacketLog) state.packetLog.pop();

        send({
            event: 'packet_in',
            type: ptype,
            size: arr.length,
            summary: summary
        });

    } catch (e) {}
}

// ──── Commands ────
function scanMemory(searchTerm) {
    return scanStrings(searchTerm, 50);
}

function getState() {
    return {
        growId: state.growId,
        password: state.password ? state.password.substring(0,3) + '***' : '',
        worldName: state.worldName,
        netId: state.netId,
        gems: state.gems,
        packetCount: state.packetLog.length,
        hooksActive: state.hooksActive
    };
}

function getPackets(count) {
    return state.packetLog.slice(0, count || 20);
}

function injectPacket(dataHex) {
    try {
        console.log('[!] Packet injection not yet implemented safely');
    } catch (e) {
        console.log('[!] Inject error: ' + e);
    }
}

// ──── Message Handler ────
recv('command', function(msg) {
    try {
        switch (msg.cmd) {
            case 'scan':
                send({ event: 'scan_result', data: scanMemory(msg.term) });
                break;

            case 'state':
                send({ event: 'state', data: getState() });
                break;

            case 'packets':
                send({ event: 'packets', data: getPackets(msg.count) });
                break;

            case 'inject':
                injectPacket(msg.data);
                send({ event: 'injected', success: true });
                break;

            case 'hook_stats':
                send({
                    event: 'hook_stats',
                    hooks: state.hooksActive,
                    packets: state.packetLog.length,
                    growId: state.growId,
                    world: state.worldName
                });
                break;

            default:
                send({ event: 'error', msg: 'Unknown command: ' + msg.cmd });
        }
    } catch (e) {
        send({ event: 'error', msg: String(e) });
    }
});

// ──── Init ────
console.log('[!] Piter Frida Agent v6 loaded');
console.log('[!] Hooking ENet send/recv...');

setTimeout(() => {
    const okSend = hookEnetSend();
    const okRecv = hookEnetRecv();
    state.hooksActive = okSend || okRecv;
    send({ event: 'ready', hooksOk: state.hooksActive, sendHook: okSend, recvHook: okRecv });
}, 500);

// Keep alive
setInterval(() => {}, 30000);
