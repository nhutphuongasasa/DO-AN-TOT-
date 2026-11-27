"""Bounded QUIC v1 long-header Initial packet parser (RFC 9000)."""
from __future__ import annotations

from dataclasses import dataclass


class QUICParseError(ValueError):
    pass

@dataclass(frozen=True, slots=True)
class QUICInitialHeader:
    version: int
    dcid: bytes
    scid: bytes
    token: bytes
    packet_length: int
    packet_number_offset: int
    packet_end: int
    first_byte: int


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data): raise QUICParseError("TRUNCATED_VARINT")
    size = 1 << (data[offset] >> 6)
    if offset + size > len(data): raise QUICParseError("TRUNCATED_VARINT")
    value = int.from_bytes(data[offset:offset+size], "big") & ((1 << (size*8-2))-1)
    return value, offset + size


def parse_initial_header(datagram: bytes) -> QUICInitialHeader:
    data = bytes(datagram)
    if len(data) < 7: raise QUICParseError("SHORT_LONG_HEADER")
    first = data[0]
    if first & 0x80 == 0 or first & 0x40 == 0: raise QUICParseError("NOT_QUIC_LONG_HEADER")
    version = int.from_bytes(data[1:5], "big")
    if version != 1: raise QUICParseError("UNSUPPORTED_QUIC_VERSION")
    # QUIC v1 long-header packet type 00 is Initial.
    if ((first >> 4) & 0x03) != 0: raise QUICParseError("NOT_INITIAL_PACKET")
    pos = 5
    dlen = data[pos]; pos += 1
    if dlen > 20 or pos+dlen+1 > len(data): raise QUICParseError("INVALID_DCID_LENGTH")
    dcid = data[pos:pos+dlen]; pos += dlen
    slen = data[pos]; pos += 1
    if slen > 20 or pos+slen > len(data): raise QUICParseError("INVALID_SCID_LENGTH")
    scid = data[pos:pos+slen]; pos += slen
    token_len, pos = read_varint(data, pos)
    if token_len > len(data)-pos: raise QUICParseError("TRUNCATED_TOKEN")
    token = data[pos:pos+token_len]; pos += token_len
    length, pos = read_varint(data, pos)
    if length < 17 or length > len(data)-pos: raise QUICParseError("INVALID_INITIAL_LENGTH")
    return QUICInitialHeader(version, dcid, scid, token, length, pos, pos+length, first)
