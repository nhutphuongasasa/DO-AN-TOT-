"""Convert Scapy packets into the project's normalized PacketRecord model."""
from __future__ import annotations

from appid.domain.models import PacketRecord, TransportProtocol


def _packet_length(raw_packet) -> int:
    """Return original packet length when capture metadata exposes it.

    Offline Scapy PcapReader packets expose the PCAP record's original length
    as ``wirelen`` even when the saved packet bytes were truncated by snaplen.
    Live packets may not expose that attribute, so fall back to captured length.
    """
    captured_length = len(raw_packet)
    wire_length = getattr(raw_packet, "wirelen", None)
    if wire_length is None:
        return captured_length
    try:
        wire_length = int(wire_length)
    except (TypeError, ValueError):
        return captured_length
    return wire_length if wire_length > 0 else captured_length


def parse_packet(raw_packet, *, session_id: str, packet_index: int) -> PacketRecord | None:
    """Parse supported IPv4/IPv6 TCP/UDP packets; return None if unsupported."""
    from scapy.all import IP, TCP, UDP, IPv6

    if IP in raw_packet:
        src_ip, dst_ip = raw_packet[IP].src, raw_packet[IP].dst
    elif IPv6 in raw_packet:
        src_ip, dst_ip = raw_packet[IPv6].src, raw_packet[IPv6].dst
    else:
        return None

    if TCP in raw_packet:
        transport = TransportProtocol.TCP
        src_port, dst_port = int(raw_packet[TCP].sport), int(raw_packet[TCP].dport)
        tcp_flags = int(raw_packet[TCP].flags)
    elif UDP in raw_packet:
        transport = TransportProtocol.UDP
        src_port, dst_port = int(raw_packet[UDP].sport), int(raw_packet[UDP].dport)
        tcp_flags = None
    else:
        return None

    return PacketRecord(
        session_id=session_id,
        packet_index=packet_index,
        timestamp=float(raw_packet.time),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        transport=transport,
        packet_length=_packet_length(raw_packet),
        tcp_flags=tcp_flags,
    )
