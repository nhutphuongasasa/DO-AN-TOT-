"""Bounded UDP pseudo-flow tracking (no TCP-style stream reassembly).

A UDP flow is a session-scoped bidirectional 5-tuple observed over time. UDP
has no transport connection handshake or sequence space; this tracker records
datagrams and byte counts and expires idle pseudo-flows using a configurable
idle timeout.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from appid.domain.models import Direction, PacketRecord, TransportProtocol
from appid.flow.identity import Endpoint, FlowKey, normalize_flow_key


class UDPFlowStatus(str, Enum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    CLOSED = "CLOSED"


@dataclass(slots=True)
class UDPFlowState:
    session_id: str
    flow_id: str
    key: FlowKey
    client_endpoint: Endpoint | None
    first_seen: float
    last_seen: float
    status: UDPFlowStatus = UDPFlowStatus.ACTIVE
    datagrams_forward: int = 0
    datagrams_backward: int = 0
    datagrams_unknown: int = 0
    bytes_forward: int = 0
    bytes_backward: int = 0
    bytes_unknown: int = 0

    @property
    def datagrams_total(self) -> int:
        return self.datagrams_forward + self.datagrams_backward + self.datagrams_unknown

    @property
    def bytes_total(self) -> int:
        return self.bytes_forward + self.bytes_backward + self.bytes_unknown

    def observe(self, packet: PacketRecord, direction: Direction) -> None:
        if self.status is not UDPFlowStatus.ACTIVE:
            raise ValueError("cannot append a datagram to an inactive UDP Flow")
        self.first_seen = min(self.first_seen, packet.timestamp)
        self.last_seen = max(self.last_seen, packet.timestamp)
        if direction is Direction.FORWARD:
            self.datagrams_forward += 1
            self.bytes_forward += packet.packet_length
        elif direction is Direction.BACKWARD:
            self.datagrams_backward += 1
            self.bytes_backward += packet.packet_length
        else:
            self.datagrams_unknown += 1
            self.bytes_unknown += packet.packet_length


class UDPFlowTracker:
    """Track UDP pseudo-flows with bounded state and explicit LAN role policy.

    Client direction is known only when exactly one endpoint belongs to one of
    the configured LAN subnets. Otherwise packet counters go to UNKNOWN; no
    source-port or first-packet heuristic is used.
    """

    def __init__(
        self,
        *,
        lan_subnets: Iterable[str | ipaddress.IPv4Network | ipaddress.IPv6Network],
        idle_timeout: float = 60.0,
        max_flows: int = 10000,
    ) -> None:
        if idle_timeout <= 0:
            raise ValueError("idle_timeout must be > 0")
        if max_flows < 1:
            raise ValueError("max_flows must be >= 1")
        self._lan_networks = tuple(ipaddress.ip_network(item, strict=False) for item in lan_subnets)
        self.idle_timeout = float(idle_timeout)
        self.max_flows = int(max_flows)
        self._active: dict[FlowKey, UDPFlowState] = {}
        self._all: dict[str, UDPFlowState] = {}
        self._next_id: dict[str, int] = {}
        self._closed_sessions: set[str] = set()

    @property
    def active_flows(self) -> tuple[UDPFlowState, ...]:
        return tuple(self._active.values())

    @property
    def flows(self) -> tuple[UDPFlowState, ...]:
        return tuple(self._all.values())

    def _client_endpoint(self, packet: PacketRecord) -> Endpoint | None:
        source = Endpoint(packet.src_ip, packet.src_port)  # validated by PacketRecord/Endpoint
        destination = Endpoint(packet.dst_ip, packet.dst_port)
        source_ip, destination_ip = ipaddress.ip_address(source.ip), ipaddress.ip_address(destination.ip)
        source_lan = any(source_ip.version == net.version and source_ip in net for net in self._lan_networks)
        destination_lan = any(destination_ip.version == net.version and destination_ip in net for net in self._lan_networks)
        if source_lan != destination_lan:
            return source if source_lan else destination
        return None

    def _direction(self, packet: PacketRecord, client: Endpoint | None) -> Direction:
        if client is None:
            return Direction.UNKNOWN
        source = Endpoint(packet.src_ip, packet.src_port)
        destination = Endpoint(packet.dst_ip, packet.dst_port)
        if source == client and destination != client:
            return Direction.FORWARD
        if destination == client and source != client:
            return Direction.BACKWARD
        return Direction.UNKNOWN

    def add_packet(self, packet: PacketRecord) -> UDPFlowState:
        if packet.transport is not TransportProtocol.UDP:
            raise ValueError("UDPFlowTracker accepts UDP packets only")
        if packet.src_port is None or packet.dst_port is None:
            raise ValueError("UDP Flow requires source and destination ports")
        if packet.session_id in self._closed_sessions:
            raise ValueError(f"capture session {packet.session_id!r} is already closed")

        self.cleanup(packet.timestamp)
        key = normalize_flow_key(packet)
        flow = self._active.get(key)
        if flow is None:
            if len(self._active) >= self.max_flows:
                raise RuntimeError("UDP Flow capacity reached; cleanup or increase max_flows")
            sequence = self._next_id.get(packet.session_id, 0) + 1
            self._next_id[packet.session_id] = sequence
            flow_id = f"{packet.session_id}:udp-{sequence:06d}"
            client = self._client_endpoint(packet)
            flow = UDPFlowState(
                session_id=packet.session_id,
                flow_id=flow_id,
                key=key,
                client_endpoint=client,
                first_seen=packet.timestamp,
                last_seen=packet.timestamp,
            )
            self._active[key] = flow
            self._all[flow_id] = flow
        flow.observe(packet, self._direction(packet, flow.client_endpoint))
        return flow

    def cleanup(self, now: float) -> tuple[UDPFlowState, ...]:
        """Expire flows idle for at least idle_timeout; return newly expired flows."""
        expired: list[UDPFlowState] = []
        for key, flow in tuple(self._active.items()):
            if now - flow.last_seen >= self.idle_timeout:
                flow.status = UDPFlowStatus.EXPIRED
                del self._active[key]
                expired.append(flow)
        return tuple(expired)

    def close_flow(self, flow_id: str) -> UDPFlowState:
        flow = self._all.get(flow_id)
        if flow is None or flow.status is not UDPFlowStatus.ACTIVE:
            raise KeyError(flow_id)
        flow.status = UDPFlowStatus.CLOSED
        self._active.pop(flow.key, None)
        return flow

    def close_session(self, session_id: str) -> tuple[UDPFlowState, ...]:
        if session_id in self._closed_sessions:
            return ()
        closed: list[UDPFlowState] = []
        for flow in self._active.values():
            if flow.session_id == session_id:
                flow.status = UDPFlowStatus.CLOSED
                closed.append(flow)
        self._active = {key: flow for key, flow in self._active.items() if flow.session_id != session_id}
        self._closed_sessions.add(session_id)
        return tuple(closed)
