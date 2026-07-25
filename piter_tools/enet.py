"""
Piter Tools — GTPS ENet Protocol Engine
========================================
ENet protocol header parser for Growtopia Private Server traffic.
Handles CONNECT, VERIFY, reliable/unreliable packets, and fragmentation.
"""

import struct
import enum
from dataclasses import dataclass, field
from typing import Optional

# ──── ENet Protocol Commands ────
class ENetCommand(enum.IntEnum):
    NONE = 0
    ACKNOWLEDGE = 1
    CONNECT = 2
    VERIFY_CONNECT = 3
    DISCONNECT = 4
    PING = 5
    SEND_RELIABLE = 6
    SEND_UNRELIABLE = 7
    SEND_FRAGMENT = 8
    SEND_UNSEQUENCED = 9
    BANDWIDTH_LIMIT = 10
    THROTTLE_CONFIGURE = 11
    SEND_UNRELIABLE_FRAGMENT = 12

ENET_COMMAND_NAMES = {
    0: "NONE", 1: "ACK", 2: "CONNECT", 3: "VERIFY_CONNECT",
    4: "DISCONNECT", 5: "PING", 6: "SEND_RELIABLE",
    7: "SEND_UNRELIABLE", 8: "SEND_FRAGMENT",
    9: "SEND_UNSEQUENCED", 10: "BANDWIDTH_LIMIT",
    11: "THROTTLE_CONFIGURE", 12: "SEND_UNRELIABLE_FRAGMENT"
}

# ENet packet flags
ENET_PACKET_FLAG_RELIABLE = 0x01
ENET_PACKET_FLAG_UNSEQUENCED = 0x02
ENET_PACKET_FLAG_NO_ALLOCATE = 0x04
ENET_PACKET_FLAG_UNRELIABLE_FRAGMENT = 0x08
ENET_PACKET_FLAG_SENT = 0x100

PROTOCOL_MINIMUM_MTU = 576
PROTOCOL_MAXIMUM_MTU = 4096
ENET_HOST_ANY = 0
ENET_HOST_BROADCAST = 0xFFFFFFFF
ENET_PORT_ANY = 0


@dataclass
class ENetProtocolHeader:
    """ENet protocol header (first 4 bytes of UDP payload)."""
    peer_id: int = 0
    flags: int = 0
    command: ENetCommand = ENetCommand.NONE
    
    @property
    def is_connect(self) -> bool:
        return self.flags == 0 and self.peer_id == 0
    
    @property
    def is_reliable(self) -> bool:
        return bool(self.flags & ENET_PACKET_FLAG_RELIABLE)
    
    @property
    def is_unsequenced(self) -> bool:
        return bool(self.flags & ENET_PACKET_FLAG_UNSEQUENCED)
    
    @property
    def command_name(self) -> str:
        return ENET_COMMAND_NAMES.get(self.command.value, f"CMD_{self.command.value}")


@dataclass
class ENetConnect:
    """ENet CONNECT packet."""
    outgoing_peer_id: int = 0
    window_size: int = 0
    channel_count: int = 0
    incoming_bandwidth: int = 0
    outgoing_bandwidth: int = 0
    packet_throttle_interval: int = 0
    packet_throttle_acceleration: int = 0
    packet_throttle_deceleration: int = 0
    connect_id: int = 0
    data: bytes = b""
    
    HEADER_SIZE = 48


@dataclass
class ENetAcknowledge:
    """ENet ACKNOWLEDGE packet."""
    received_reliable_sequence_number: int = 0
    received_sent_time: int = 0


@dataclass
class ENetProtocol:
    """Fully parsed ENet protocol command."""
    header: ENetProtocolHeader
    channel_id: int = 0
    reliable_sequence_number: int = 0
    connect: Optional[ENetConnect] = None
    acknowledge: Optional[ENetAcknowledge] = None
    send_reliable: Optional[bytes] = None
    payload: bytes = b""


def parse_enet(data: bytes) -> Optional[ENetProtocol]:
    """Parse ENet protocol header and command from raw UDP payload.
    
    Returns ENetProtocol on success, None on failure.
    """
    if len(data) < 4:
        return None
    
    # Parse protocol header (first 4 bytes)
    # On little-endian: byte0=peerID, byte1=flags, byte2-3 vary
    raw = struct.unpack("<I", data[:4])[0]
    
    # Check for special CONNECT sequence
    if data[0] == 0x01 and data[1:4] == b'\x00\x00\x00':
        return _parse_connect(data)
    
    # Standard header
    header = ENetProtocolHeader()
    header.peer_id = data[0]
    header.flags = data[1]
    
    # Determine command from flags
    if data[1] == 0x00 and data[2] == 0x00:
        # Potentially a simple ACK or VERIFY
        pass
    
    proto = ENetProtocol(header=header, payload=data)
    
    # If we have more data, try to parse command
    if len(data) > 4:
        _parse_command(proto, data[4:])
    
    return proto


def _parse_connect(data: bytes) -> ENetProtocol:
    """Parse CONNECT packet."""
    header = ENetProtocolHeader(peer_id=0, flags=0)
    proto = ENetProtocol(header=header)
    
    if len(data) >= 4 + ENetConnect.HEADER_SIZE:
        raw = struct.unpack_from("<IIIIIIIIIIII", data, 0)
        connect = ENetConnect(
            outgoing_peer_id=raw[1],
            window_size=raw[2],
            channel_count=raw[3],
            incoming_bandwidth=raw[4],
            outgoing_bandwidth=raw[5],
            packet_throttle_interval=raw[6],
            packet_throttle_acceleration=raw[7],
            packet_throttle_deceleration=raw[8],
            connect_id=raw[9],
            data=data[4 + ENetConnect.HEADER_SIZE:]
        )
        proto.connect = connect
        proto.payload = data
    else:
        proto.payload = data
    
    return proto


def _parse_command(proto: ENetProtocol, data: bytes):
    """Parse ENet command after protocol header."""
    if len(data) < 3:
        return
    
    # Command format in ENet (little-endian):
    # byte 0: command type
    # byte 1: channel_id
    # byte 2-3: reliable_sequence_number (if reliable)
    
    cmd_byte = data[0]
    
    try:
        proto.header.command = ENetCommand(cmd_byte)
    except ValueError:
        proto.header.command = ENetCommand.NONE
    
    if len(data) >= 2:
        proto.channel_id = data[1]
    
    if proto.header.is_reliable and len(data) >= 4:
        proto.reliable_sequence_number = struct.unpack_from("<H", data, 2)[0]
    
    # Extract payload based on command
    offset = 1  # command byte
    
    if proto.header.is_reliable:
        offset += 3  # channel_id(1) + seq(2)
    else:
        offset += 1  # channel_id(1)
    
    if offset < len(data):
        payload = data[offset:]
        
        if proto.header.command == ENetCommand.SEND_RELIABLE:
            proto.send_reliable = payload
            proto.payload = payload


def build_header(proto: ENetProtocol) -> bytes:
    """Build ENet header bytes from protocol struct."""
    return struct.pack("<I", proto.header.peer_id | (proto.header.flags << 8) | (proto.header.command << 16))


class ENetStreamParser:
    """Stateful ENet stream parser. Feeds raw bytes, yields parsed packets."""
    
    def __init__(self):
        self.buffer = b""
        self.packets_parsed = 0
    
    def feed(self, data: bytes) -> list[ENetProtocol]:
        """Feed raw bytes, return list of parsed ENetProtocol packets."""
        self.buffer += data
        results = []
        
        while len(self.buffer) >= 4:
            proto = parse_enet(self.buffer)
            if proto is None:
                self.buffer = self.buffer[1:]  # Skip one byte, try again
                continue
            
            # Calculate consumed length (rough estimate)
            consumed = 4  # header
            
            if proto.connect:
                consumed = 4 + ENetConnect.HEADER_SIZE + len(proto.connect.data)
            elif proto.send_reliable:
                consumed = 4 + 3 + len(proto.send_reliable)  # header + cmd/channel/seq + payload
            
            consumed = min(consumed, len(self.buffer))
            if consumed > len(self.buffer):
                break  # Need more data
            
            self.buffer = self.buffer[consumed:]
            self.packets_parsed += 1
            results.append(proto)
        
        return results
