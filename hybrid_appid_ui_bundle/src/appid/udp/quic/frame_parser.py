"""Parser for QUIC v1 frames needed by Initial packets."""
from __future__ import annotations

from dataclasses import dataclass

from appid.udp.quic.header import QUICParseError, read_varint


@dataclass(frozen=True, slots=True)
class CryptoFrame:
    offset: int
    data: bytes

@dataclass(frozen=True, slots=True)
class ParsedFrames:
    crypto_frames: tuple[CryptoFrame, ...]
    frame_types: tuple[int, ...]


def parse_frames(payload: bytes) -> ParsedFrames:
    data=bytes(payload); pos=0; cryptos=[]; types=[]
    def vi():
        nonlocal pos
        v,pos=read_varint(data,pos); return v
    while pos < len(data):
        typ=vi(); types.append(typ)
        if typ == 0:  # PADDING (may be repeated)
            while pos < len(data) and data[pos] == 0: pos += 1
        elif typ == 1:  # PING
            pass
        elif typ in (2,3):  # ACK / ACK_ECN
            largest=vi(); delay=vi(); ranges=vi(); first=vi()
            if ranges > 256: raise QUICParseError("ACK_RANGE_LIMIT")
            for _ in range(ranges): vi(); vi()
            if typ == 3: vi(); vi(); vi()
        elif typ in (0x1c, 0x1d):  # CONNECTION_CLOSE / APPLICATION_CLOSE
            vi()  # error_code
            if typ == 0x1c: vi()  # triggering_frame_type
            reason_len=vi()
            if reason_len > len(data)-pos: raise QUICParseError("TRUNCATED_CONNECTION_CLOSE_REASON")
            pos += reason_len
        elif typ == 6:  # CRYPTO
            offset=vi(); length=vi()
            if length > len(data)-pos: raise QUICParseError("TRUNCATED_CRYPTO_FRAME")
            cryptos.append(CryptoFrame(offset, data[pos:pos+length])); pos += length
        else:
            raise QUICParseError(f"UNSUPPORTED_INITIAL_FRAME_0x{typ:x}")
    return ParsedFrames(tuple(cryptos), tuple(types))
