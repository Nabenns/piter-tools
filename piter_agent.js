/**
 * Piter Cheat Engine — Frida Agent (Phase 1)
 * ============================================
 * Injected into Growtopia process via Frida.
 * Hooks ENet, tank protocol, and game packets.
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
        
        let matchStart = 0;
        for (let i = 0; i <= size - bytes.length; i++) {
            let matched = true;
            for (let j = 0; j < bytes.length; j++) {
                if (bytes[j] !== null && (buf[i + j] & 0xFF) !== bytes[j]) {
                    matched = false;
                    break;
                }
            }
            if (matched) {
                results.push(base.add(i));
            }
        }
        return results;
    } catch (e) {
        console.log('[!] Pattern scan error: ' + e);
        return [];
    }
}

// ──── String Scanner ────
function scanStrings(term, maxResults) {
    try {
        const mod = Process.findModuleByName('Growtopia');
        if (!mod) return [];
        
        const results = [];
        const base = mod.base;
        const size = mod.size;
        
        Memory.scan(base, size, term, {
            onMatch(address) {
                try {
                    let str = address.readCString();
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

// ──── ENet Send Hook ────
function hookEnetSend() {
    try {
        // Look for ENet send function signature
        // enet_peer_send(ENetPeer*, enet_uint8 channelID, ENetPacket*)
        // Pattern: push channel count, call send, etc.
        
        const enetModule = Process.findModuleByName('Growtopia');
        if (!enetModule) {
            console.log('[!] Growtopia module not found');
            return false;
        }
        
        // Try to find ENet send by scanning for common patterns
        // We'll hook sendto() as fallback — intercept all UDP writes
        const sendtoPtr = Module.findExportByName(null, 'sendto');
        if (sendtoPtr) {
            Interceptor.attach(sendtoPtr, {
                onEnter(args) {
                    this.sockfd = args[0].toInt32();
                    this.buf = args[1];
                    this.len = args[2].toInt32();
                    this.flags = args[3].toInt32();
                    this.addr = args[4];
                    this.addrlen = args[5].toInt32();
                },
                onLeave(retval) {
                    try {
                        // Check if this is UDP to port 17091
                        if (this.addrlen >= 8) {
                            const family = this.addr.readU16();
                            if (family === 2) { // AF_INET
                                const port = ((this.addr.add(2).readU8() << 8) | this.addr.add(3).readU8());
                                if (port === htons(17091) || port === 17091 || port === 43847) {
                                    // Game packet! Parse it.
                                    const data = this.buf.readByteArray(Math.min(this.len, 512));
                                    handleOutboundPacket(data);
                                }
                            }
                        }
                    } catch (e) {}
                }
            });
            console.log('[+] sendto() hooked');
        }
        
        // Hook recvfrom for inbound
        const recvfromPtr = Module.findExportByName(null, 'recvfrom');
        if (recvfromPtr) {
            Interceptor.attach(recvfromPtr, {
                onLeave(retval) {
                    if (retval.toInt32() <= 0) return;
                    try {
                        if (this.addr && this.addrlen >= 8) {
                            const family = this.addr.readU16();
                            if (family === 2) {
                                const port = ((this.addr.add(2).readU8() << 8) | this.addr.add(3).readU8());
                                if (port === htons(17091) || port === 17091 || port === 43847) {
                                    const len = retval.toInt32();
                                    const data = this.buf.readByteArray(Math.min(len, 2048));
                                    handleInboundPacket(data);
                                }
                            }
                        }
                    } catch (e) {}
                }
            });
            console.log('[+] recvfrom() hooked');
        }
        
        state.hooksActive = true;
        return true;
    } catch (e) {
        console.log('[!] Hook error: ' + e);
        return false;
    }
}

// ──── Packet Handlers ────
function handleOutboundPacket(data) {
    try {
        const arr = new Uint8Array(data);
        const hex = Array.from(arr.slice(0, 32)).map(b => b.toString(16).padStart(2, '0')).join('');
        
        // Detect packet type
        let ptype = 'UNKNOWN';
        let summary = '';
        
        if (arr[0] === 0x01 && arr[1] === 0x00 && arr[2] === 0x00 && arr[3] === 0x00) {
            ptype = 'ENET_CONNECT';
        } else if (arr[0] === 0x04 || arr[1] === 0x00) {
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
                summary = `GROWID: ${state.growId} | PASS: ${state.password ? state.password.substring(0,3)+'***' : '?'}`;
            } else if (text.includes('action|')) {
                ptype = 'GAME_ACTION';
                summary = text.substring(0, 80);
                
                const actionMatch = text.match(/action\|([^\n]+)/);
                if (actionMatch) {
                    const action = actionMatch[1];
                    if (action === 'enter_game') summary = 'action|enter_game (JOINED)';
                }
            } else if (text.includes('tileChange')) {
                ptype = 'TILE_CHANGE';
                summary = text.substring(0, 80);
            }
        }
        
        // Check for GameUpdatePacket (type 4)
        if (arr[0] === 0x04 && arr.length > 4) {
            ptype = 'GAME_UPDATE';
            try {
                // Parse 4-byte header
                const netId = (arr[4] | (arr[5] << 8) | (arr[6] << 16) | (arr[7] << 24)) >>> 0;
                const itemId = (arr[8] | (arr[9] << 8)) & 0xFFFF;
                const x = (arr[10] | (arr[11] << 8)) & 0xFFFF;
                const y = (arr[12] | (arr[13] << 8)) & 0xFFFF;
                summary = `item=${itemId} pos=(${x},${y})`;
            } catch (e) {}
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
        
        // Send to Python controller
        send({
            event: 'packet_out',
            type: ptype,
            size: arr.length,
            summary: summary
        });
        
    } catch (e) {
        console.log('[!] Outbound handler error: ' + e);
    }
}

function handleInboundPacket(data) {
    try {
        const arr = new Uint8Array(data);
        
        // Look for text data
        const text = String.fromCharCode.apply(null, arr.filter(b => b >= 32 && b < 127));
        
        let ptype = 'SERVER';
        let summary = '';
        
        if (text.includes('OnSuperMainStart')) {
            ptype = 'WORLD_JOIN';
            summary = 'ENTERED WORLD';
            
            // Parse world name
            const nameMatch = text.match(/OnSuperMainStart[^\n]*/);
            if (nameMatch) {
                const parts = nameMatch[0].split('|');
                if (parts.length > 1) {
                    state.worldName = parts[1] || '';
                    // Extract more fields
                    for (const part of parts) {
                        if (part.includes('base_uid')) state.netId = parseInt(part.split('=')[1]) || 0;
                        if (part.includes('credits')) state.gems = parseInt(part.split('=')[1]) || 0;
                    }
                }
            }
            summary = `WORLD: ${state.worldName} | GEMS: ${state.gems} | NETID: ${state.netId}`;
            
        } else if (text.includes('action|')) {
            ptype = 'GAME_ACTION';
            summary = text.substring(0, 100);
        } else if (text.includes('add_player')) {
            ptype = 'PLAYER_JOIN';
            summary = text.substring(0, 100);
        } else if (text.includes('remove_player')) {
            ptype = 'PLAYER_LEAVE';
            summary = text.substring(0, 100);
        }
        
        // Hex
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
        
    } catch (e) {
        console.log('[!] Inbound handler error: ' + e);
    }
}

// ──── Command Handlers ────

// Memory scanner
function scanMemory(searchTerm) {
    return scanStrings(searchTerm, 50);
}

// Get current state
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

// Get recent packets
function getPackets(count) {
    return state.packetLog.slice(0, count || 20);
}

// Inject packet (placeholder — needs proper ENet packet building)
function injectPacket(dataHex) {
    try {
        // WARNING: Could crash the client if malformed
        console.log('[!] Packet injection not yet implemented safely');
        // TODO: Build proper ENet packet and call enet_peer_send
    } catch (e) {
        console.log('[!] Inject error: ' + e);
    }
}

// ──── Message Handler ────
recv('command', function(msg) {
    try {
        switch (msg.cmd) {
            case 'scan':
                const results = scanMemory(msg.term);
                send({ event: 'scan_result', data: results });
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
console.log('[!] Piter Frida Agent loaded');
console.log('[!] Hooking ENet send/recv...');

setTimeout(() => {
    const ok = hookEnetSend();
    send({ event: 'ready', hooksOk: ok, module: 'Growtopia' });
}, 500);

// Keep alive
setInterval(() => {}, 30000);
