"""
Piter Tools — Tank Protocol Decoder
====================================
Decodes Growtopia/GTPS tank protocol packets (pipe-delimited key-value).
Handles encrypted GameUpdatePacket format.
"""

import struct
import zlib
import base64
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class TankPacket:
    """Decoded tank protocol packet."""
    packet_type: int = 0
    net_id: int = 0
    flags: int = 0
    data_size: int = 0
    value: int = 0
    x: int = 0
    y: int = 0
    unk1: int = 0
    unk2: int = 0
    unk3: int = 0
    raw_data: bytes = b""
    extra_data: bytes = b""
    
    @property
    def is_game_update(self) -> bool:
        return self.packet_type == 4
    
    @property
    def is_tank_packet(self) -> bool:
        return self.packet_type == 0
    
    @property
    def is_hello(self) -> bool:
        return self.packet_type == 1
    
    @property
    def is_disconnect(self) -> bool:
        return self.packet_type == 10


@dataclass 
class GameUpdatePacket:
    """Decoded GameUpdatePacket (type 4)."""
    packet_type: int = 0
    item_type: int = 0
    tile_type: int = 0
    tile_style: int = 0
    col1: int = 0
    col2: int = 0
    col3: int = 0
    raw: bytes = b""


@dataclass
class TankField:
    """Named field from tank protocol."""
    key: str
    value: str
    original: str


# ──── Packet Type Constants ────
PACKET_HELLO = 1
PACKET_STR = 2  
PACKET_ACTION = 3
PACKET_TANK = 0  # tank packet
PACKET_GAME_UPDATE = 4

PACKET_CALL_FUNCTION = 1
PACKET_UPDATE_STATUS = 2
PACKET_TILE_CHANGE_REQUEST = 3
PACKET_SEND_MAP_DATA = 4
PACKET_SEND_TILE_UPDATE_DATA = 5
PACKET_SEND_TILE_UPDATE_DATA_MULTIPLE = 6
PACKET_TILE_ACTIVATE_REQUEST = 7
PACKET_TILE_APPLY_DAMAGE = 8
PACKET_SEND_INVENTORY_STATE = 9
PACKET_ITEM_ACTIVATE_REQUEST = 10
PACKET_ITEM_ACTIVATE_OBJECT_REQUEST = 11
PACKET_SEND_TILE_TREE_STATE = 12
PACKET_MODIFY_ITEM_INVENTORY = 13
PACKET_ITEM_CHANGE_OBJECT = 14
PACKET_SEND_LOCK = 15
PACKET_SEND_ITEM_DATABASE_DATA = 16
PACKET_SEND_PARTICLE_EFFECT = 17
PACKET_SET_ICON_STATE = 18
PACKET_ITEM_EFFECT = 19
PACKET_SET_CHARACTER_STATE = 20
PACKET_PING_REPLY = 21
PACKET_PING_REQUEST = 22
PACKET_GOT_PUNCHED = 23
PACKET_APP_CHECK_RESPONSE = 24
PACKET_APP_INTEGRITY_FAIL = 25
PACKET_DISCONNECT = 26
PACKET_BATTLE_JOIN = 27
PACKET_BATTLE_EVENT = 28
PACKET_USE_DOOR = 29
PACKET_SEND_PARENTAL = 30
PACKET_GONE_FISHIN = 31
PACKET_STEAM = 32
PACKET_PET_BATTLE = 33
PACKET_NPC = 34
PACKET_SPECIAL = 35
PACKET_SEND_PARTICLE_EFFECT_V2 = 36
PACKET_GAME_ACTIVE_ARROW_TO_ITEM = 37
PACKET_GAME_SELECT_TILE_INDEX = 38

GAME_UPDATE_TYPES = {
    -1: "UNKNOWN",
    0: "NONE",
    1: "DOOR",
    2: "LOCK",
    3: "SIGN",
    4: "SEED",
    5: "TREE",
    6: "PORTAL",
    7: "MAIN_DOOR",
    8: "BEDROCK",
    9: "FIST",
    10: "WRENCH",
    11: "WEATHER_MACHINE",
    12: "PASSWORD_DOOR",
    13: "DONATION_BOX",
    14: "TOMBSTONE",
    15: "TRAVEL_PASSED",
    16: "TABLE",
    17: "DOOR2",
    18: "DISPLAY_BLOCK",
}

PACKET_TYPE_NAMES = {
    0: "TANK",
    1: "HELLO",
    2: "STR",
    3: "ACTION",
    4: "GAME_UPDATE",
    10: "DISCONNECT",
    21: "PING_REPLY",
    22: "PING_REQUEST",
    26: "DISCONNECT",
}

GT_PACKET_FLAG = 4


def parse_tank_fields(data: bytes) -> dict[str, str]:
    """Parse pipe-delimited tank fields from raw bytes.
    
    Format: key1|val1\nkey2|val2\n...
    """
    if b'|' not in data:
        return {}
    
    fields = {}
    try:
        text = data.decode('utf-8', errors='replace')
        for line in text.split('\n'):
            line = line.strip()
            if '|' in line:
                key, _, val = line.partition('|')
                fields[key.strip()] = val.strip()
    except:
        pass
    
    return fields


def parse_raw_packet(data: bytes) -> Optional[TankPacket]:
    """Parse a raw tank packet header (4-byte type + 56-byte header + data)."""
    if len(data) < 4:
        return None
    
    # Check for GT packet flag (0x04 prefix)
    if len(data) == 1 and data[0] == GT_PACKET_FLAG:
        return None  # Just a flag byte
    
    if len(data) >= 4 and data[0] == GT_PACKET_FLAG:
        # GT packet: 4 bytes header
        try:
            header = struct.unpack_from("<I", data, 0)[0]
            packet_type = data[0]
        except:
            packet_type = 0
    else:
        packet_type = data[0] if data else 0
    
    pkt = TankPacket(packet_type=packet_type)
    
    # For standard tank packets (4+ bytes)
    if len(data) >= 58:  # 2B type + 56B tank header
        try:
            raw_header = struct.unpack_from("<I", data, 0)[0]
            pkt.packet_type = raw_header & 0xFF
            
            full_header = struct.unpack_from("<QIIIIIIII", data, 0)
            pkt.net_id = full_header[1] if len(full_header) > 1 else 0
            pkt.flags = full_header[2] if len(full_header) > 2 else 0
            pkt.data_size = full_header[3] if len(full_header) > 3 else 0
            pkt.value = full_header[4] if len(full_header) > 4 else 0
            pkt.x = full_header[5] if len(full_header) > 5 else 0
            pkt.y = full_header[6] if len(full_header) > 6 else 0
            pkt.unk1 = full_header[7] if len(full_header) > 7 else 0
            pkt.unk2 = full_header[8] if len(full_header) > 8 else 0
            pkt.unk3 = full_header[9] if len(full_header) > 9 else 0
        except:
            pass
        
        # Data starts after header (60 bytes: 4 type + 56 header)
        header_size = 60
        if pkt.packet_type == PACKET_GAME_UPDATE:
            header_size = 56  # GameUpdate has smaller header
        
        if len(data) > header_size:
            pkt.raw_data = data[header_size:]
    
    # For small packets, just store the data
    elif len(data) > 4:
        pkt.raw_data = data[4:]
    
    return pkt


def parse_game_update(pkt: TankPacket) -> Optional[GameUpdatePacket]:
    """Parse a GameUpdatePacket from tank packet data."""
    if not pkt.is_game_update:
        return None
    
    gu = GameUpdatePacket()
    
    try:
        if len(pkt.raw_data) >= 44:
            raw = struct.unpack_from("<HHHHHHH", pkt.raw_data, 0)
            gu.packet_type = raw[0]
            gu.item_type = raw[1]
            gu.tile_type = raw[2]
            gu.tile_style = raw[3]
            gu.col1 = raw[4]
            gu.col2 = raw[5]
            gu.col3 = raw[6]
        gu.raw = pkt.raw_data
    except:
        pass
    
    return gu


def decode_text_packet(data: bytes) -> str:
    """Try to decode text from packet data, stripping null bytes and control chars."""
    if not data:
        return ""
    
    # Try plain ASCII
    try:
        text = data.decode('ascii', errors='ignore')
        clean = ''.join(c for c in text if c.isprintable() or c in '\n\t')
        if len(clean) > 3:
            return clean
    except:
        pass
    
    # Try raw binary to hex
    return data.hex()


def describe_packet(pkt: TankPacket) -> str:
    """Return human-readable description of a tank packet."""
    ptype = PACKET_TYPE_NAMES.get(pkt.packet_type, f"TYPE_{pkt.packet_type}")
    
    parts = [f"[{ptype}]"]
    
    if pkt.is_game_update:
        gu = parse_game_update(pkt)
        if gu:
            item_name = GAME_UPDATE_TYPES.get(gu.item_type, f"ITEM_{gu.item_type}")
            parts.append(f"item={item_name} pos=({gu.tile_type},{gu.tile_style})")
    elif pkt.raw_data:
        # Try to read as text
        text = decode_text_packet(pkt.raw_data)
        if text and not text.startswith('0'):
            # Check for tank fields
            fields = parse_tank_fields(pkt.raw_data)
            if fields:
                keys = list(fields.keys())[:5]
                parts.append(f"fields={keys}")
            elif len(text) > 200:
                parts.append(f"data={text[:200]}...")
            else:
                parts.append(f"data={text}")
    
    if pkt.x or pkt.y:
        parts.append(f"pos=({pkt.x},{pkt.y})")
    
    return ' '.join(parts)


def find_text_packets(packets: list[TankPacket]) -> list[tuple[int, TankPacket]]:
    """Find packets containing readable text data (like actions, chat)."""
    results = []
    for i, pkt in enumerate(packets):
        if pkt.raw_data and len(pkt.raw_data) > 2:
            text = decode_text_packet(pkt.raw_data)
            if text and any(c.isalpha() for c in text[:10]):
                results.append((i, pkt))
    return results


def find_login_packets(packets: list[TankPacket]) -> list[tuple[int, dict]]:
    """Find login/auth packets containing tankIDName fields."""
    results = []
    for i, pkt in enumerate(packets):
        fields = parse_tank_fields(pkt.raw_data)
        if 'tankIDName' in fields or 'requestedName' in fields:
            results.append((i, fields))
    return results
