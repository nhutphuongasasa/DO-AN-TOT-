"""Conservative structural identification of common UDP protocols.

Port numbers are used only as a consistency check after a payload has passed
protocol-specific structural validation. This module identifies transport
protocols, not end-user applications such as TikTok or Spotify.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class UDPProtocol(str, Enum):
    DNS = "DNS"
    DHCP = "DHCP"
    NTP = "NTP"
    STUN = "STUN"
    QUIC_INITIAL_CANDIDATE = "QUIC_INITIAL_CANDIDATE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class UDPProtocolResult:
    protocol: UDPProtocol
    confidence: float
    reason_code: str
    evidence: tuple[str, ...] = ()


class UDPProtocolIdentifier:
    """Classify a UDP datagram using bounded, conservative wire checks."""

    STUN_COOKIE = b"\x21\x12\xa4\x42"
    DHCP_COOKIE = b"\x63\x82\x53\x63"

    def identify(self, payload: bytes, *, src_port: int, dst_port: int) -> UDPProtocolResult:
        data = bytes(payload)
        if not 0 <= src_port <= 65535 or not 0 <= dst_port <= 65535:
            raise ValueError("UDP ports must be between 0 and 65535")
        if not data:
            return self._unknown("EMPTY_PAYLOAD")

        # DNS: 12-byte header, legal opcode/rcode envelope, and at least one
        # question/answer/authority/additional record. DNS parser performs the
        # detailed name/RR validation in the main pipeline.
        if len(data) >= 12 and (src_port == 53 or dst_port == 53):
            flags = int.from_bytes(data[2:4], "big")
            qd, an, ns, ar = (int.from_bytes(data[i:i + 2], "big") for i in (4, 6, 8, 10))
            opcode = (flags >> 11) & 0xF
            if opcode <= 5 and qd + an + ns + ar > 0:
                return UDPProtocolResult(UDPProtocol.DNS, 0.90, "DNS_HEADER_AND_PORT",
                                         (f"udp_ports={src_port},{dst_port}", f"dns_counts={qd},{an},{ns},{ar}"))

        # DHCPv4: BOOTP fixed header, client/server ports and magic cookie.
        if len(data) >= 240 and {src_port, dst_port} == {67, 68}:
            if data[236:240] == self.DHCP_COOKIE and data[0] in (1, 2):
                return UDPProtocolResult(UDPProtocol.DHCP, 0.99, "DHCP_BOOTP_COOKIE",
                                         ("bootp_op_valid", "dhcp_magic_cookie"))

        # NTP: version 1..4, client/server/broadcast mode, minimum 48-byte header.
        if len(data) >= 48 and (src_port == 123 or dst_port == 123):
            first = data[0]
            version, mode = (first >> 3) & 0x7, first & 0x7
            if 1 <= version <= 4 and mode in (3, 4, 5):
                return UDPProtocolResult(UDPProtocol.NTP, 0.95, "NTP_HEADER_AND_PORT",
                                         (f"ntp_version={version}", f"ntp_mode={mode}"))

        # STUN: top two type bits are zero, length is 4-byte aligned and
        # exactly matches the payload after the 20-byte header, cookie matches.
        if len(data) >= 20 and (data[0] & 0xC0) == 0 and data[4:8] == self.STUN_COOKIE:
            msg_len = int.from_bytes(data[2:4], "big")
            if msg_len % 4 == 0 and msg_len == len(data) - 20:
                return UDPProtocolResult(UDPProtocol.STUN, 0.99, "STUN_COOKIE_AND_LENGTH",
                                         (f"stun_message_length={msg_len}",))

        # QUIC long header: fixed bit set, non-zero version, Initial packet
        # type bits (v1/v2 mapping is refined in P0.7.3), and DCID/SCID lengths
        # bounded by the datagram. This is only a candidate, not validated QUIC.
        if len(data) >= 7 and (data[0] & 0xC0) == 0xC0:
            version = int.from_bytes(data[1:5], "big")
            dcid_len = data[5]
            dcid_end = 6 + dcid_len
            if version == 1 and dcid_len <= 20 and dcid_end < len(data):
                scid_len = data[dcid_end]
                scid_end = dcid_end + 1 + scid_len
                packet_type = (data[0] >> 4) & 0x3
                if scid_len <= 20 and scid_end < len(data) and packet_type == 0:
                    return UDPProtocolResult(
                        UDPProtocol.QUIC_INITIAL_CANDIDATE, 0.70,
                        "QUIC_LONG_HEADER_INITIAL_CANDIDATE",
                        (f"quic_version=0x{version:08x}", f"dcid_length={dcid_len}",
                         f"scid_length={scid_len}"),
                    )

        return self._unknown("NO_VALIDATED_UDP_SIGNATURE")

    @staticmethod
    def _unknown(reason: str) -> UDPProtocolResult:
        return UDPProtocolResult(UDPProtocol.UNKNOWN, 0.0, reason)
