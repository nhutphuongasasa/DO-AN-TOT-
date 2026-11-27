"""Canonical bidirectional Flow identity and explicit direction resolution.

This module implements only the FIXED identity contract. It deliberately does
not infer client/server roles, allocate Flow IDs, or manage Flow lifecycle.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import TYPE_CHECKING

from appid.domain.models import Direction, TransportProtocol

if TYPE_CHECKING:
    from appid.domain.models import PacketRecord


@dataclass(frozen=True, slots=True)
class Endpoint:
    """An IP endpoint identified by a canonical IP address and transport port."""

    ip: str
    port: int

    def __post_init__(self) -> None:
        try:
            address = ipaddress.ip_address(self.ip)
        except ValueError as exc:
            raise ValueError(f"ip must be a valid IPv4 or IPv6 address: {self.ip!r}") from exc
        if not isinstance(self.port, int) or isinstance(self.port, bool) or not 0 <= self.port <= 65535:
            raise ValueError("port must be an integer between 0 and 65535")
        object.__setattr__(self, "ip", str(address))

    def sort_key(self) -> tuple[int, bytes, int]:
        """Return a stable ordering key independent of packet direction."""
        address = ipaddress.ip_address(self.ip)
        return address.version, address.packed, self.port


@dataclass(frozen=True, slots=True)
class FlowKey:
    """Session-scoped, normalized bidirectional connection identity."""

    session_id: str
    protocol: TransportProtocol
    endpoint_a: Endpoint
    endpoint_b: Endpoint

    def __post_init__(self) -> None:
        if not self.session_id:
            raise ValueError("session_id must not be empty")
        if not isinstance(self.protocol, TransportProtocol):
            raise TypeError("protocol must be a TransportProtocol")
        if not isinstance(self.endpoint_a, Endpoint) or not isinstance(self.endpoint_b, Endpoint):
            raise TypeError("endpoint_a and endpoint_b must be Endpoint instances")
        if self.endpoint_b.sort_key() < self.endpoint_a.sort_key():
            original_a, original_b = self.endpoint_a, self.endpoint_b
            object.__setattr__(self, "endpoint_a", original_b)
            object.__setattr__(self, "endpoint_b", original_a)

    @classmethod
    def from_packet(cls, packet: PacketRecord) -> FlowKey:
        """Build a canonical key from packet metadata; role is not inferred."""
        if packet.src_port is None or packet.dst_port is None:
            raise ValueError("Flow identity requires both source and destination ports")
        return cls(
            session_id=packet.session_id,
            protocol=packet.transport,
            endpoint_a=Endpoint(packet.src_ip, packet.src_port),
            endpoint_b=Endpoint(packet.dst_ip, packet.dst_port),
        )


def normalize_flow_key(packet: PacketRecord) -> FlowKey:
    """Return the same FlowKey for either packet direction of a connection."""
    return FlowKey.from_packet(packet)


def resolve_direction(packet: PacketRecord, client_endpoint: Endpoint | None) -> Direction:
    """Resolve packet direction only when the client endpoint is explicitly known.

    No first-packet, port-number, or source/destination heuristic is applied.
    """
    if client_endpoint is None or packet.src_port is None or packet.dst_port is None:
        return Direction.UNKNOWN

    source = Endpoint(packet.src_ip, packet.src_port)
    destination = Endpoint(packet.dst_ip, packet.dst_port)
    if source == client_endpoint and destination != client_endpoint:
        return Direction.FORWARD
    if destination == client_endpoint and source != client_endpoint:
        return Direction.BACKWARD
    return Direction.UNKNOWN
