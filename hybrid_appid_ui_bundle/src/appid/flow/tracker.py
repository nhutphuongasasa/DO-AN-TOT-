"""Session-scoped stateful bidirectional Flow tracking.

No idle timeout is applied. Callers explicitly close a Flow or capture session
until TCP/UDP lifecycle timeout values are specified by the project.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum

from appid.domain.models import Direction, IdentificationResult, PacketRecord
from appid.flow.identity import Endpoint, FlowKey, normalize_flow_key, resolve_direction
from appid.network.interfaces import discover_interface_subnets


class FlowStatus(str, Enum):
    ACTIVE = "ACTIVE"
    CLOSED = "CLOSED"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True, slots=True)
class PacketSequenceRecord:
    """Packet metadata retained for deterministic chronological reconstruction."""

    packet_index: int
    timestamp: float
    direction: Direction
    packet_length: int
    src_endpoint: Endpoint
    dst_endpoint: Endpoint


@dataclass(slots=True)
class FlowState:
    session_id: str
    flow_id: str
    key: FlowKey
    client_endpoint: Endpoint | None
    remote_endpoint: Endpoint | None
    first_seen: float
    last_seen: float
    status: FlowStatus = FlowStatus.ACTIVE
    packets: list[PacketSequenceRecord] = field(default_factory=list)
    packets_forward: int = 0
    packets_backward: int = 0
    packets_unknown: int = 0
    bytes_forward: int = 0
    bytes_backward: int = 0
    bytes_unknown: int = 0
    identification_result: IdentificationResult | None = None
    quic_connection_id: str | None = None
    application_protocol: str | None = None

    @property
    def ordered_packets(self) -> tuple[PacketSequenceRecord, ...]:
        return tuple(sorted(self.packets, key=lambda packet: (packet.timestamp, packet.packet_index)))

    def add_packet(self, packet: PacketRecord, direction: Direction) -> None:
        if self.status is not FlowStatus.ACTIVE:
            raise ValueError("cannot append a packet to a closed Flow")
        if packet.session_id != self.session_id:
            raise ValueError("packet session_id does not match Flow session")
        if packet.src_port is None or packet.dst_port is None:
            raise ValueError("Flow packet requires source and destination ports")

        observation = PacketSequenceRecord(
            packet_index=packet.packet_index,
            timestamp=packet.timestamp,
            direction=direction,
            packet_length=packet.packet_length,
            src_endpoint=Endpoint(packet.src_ip, packet.src_port),
            dst_endpoint=Endpoint(packet.dst_ip, packet.dst_port),
        )
        self.packets.append(observation)
        self.first_seen = min(self.first_seen, packet.timestamp)
        self.last_seen = max(self.last_seen, packet.timestamp)
        if direction is Direction.FORWARD:
            self.packets_forward += 1
            self.bytes_forward += packet.packet_length
        elif direction is Direction.BACKWARD:
            self.packets_backward += 1
            self.bytes_backward += packet.packet_length
        else:
            self.packets_unknown += 1
            self.bytes_unknown += packet.packet_length


class FlowTracker:
    """Track active Flows and retain finalized records for downstream consumers.

    LAN/client role is inferred only when exactly one endpoint IP belongs to a
    subnet discovered from an active host interface (or an explicit subnet
    snapshot supplied by the caller). Ambiguous and non-LAN tuples stay UNKNOWN.
    """

    def __init__(
        self,
        *,
        lan_subnets: Iterable[str | ipaddress.IPv4Network | ipaddress.IPv6Network] | None = None,
        interface_allowlist: Iterable[str] | None = None,
        interface_denylist: Iterable[str] = (),
    ) -> None:
        if lan_subnets is None:
            self.interface_subnets = discover_interface_subnets(
                interface_allowlist=interface_allowlist,
                interface_denylist=interface_denylist,
            )
            networks = [item.network for item in self.interface_subnets]
        else:
            networks = [ipaddress.ip_network(value, strict=False) for value in lan_subnets]
            self.interface_subnets = ()
        self._lan_networks = tuple(networks)
        self._active_by_key: dict[FlowKey, FlowState] = {}
        self._flows_by_id: dict[str, FlowState] = {}
        self._next_id_by_session: dict[str, int] = {}
        self._closed_sessions: set[str] = set()

    @property
    def flows(self) -> tuple[FlowState, ...]:
        return tuple(self._flows_by_id.values())

    @property
    def active_flows(self) -> tuple[FlowState, ...]:
        return tuple(self._active_by_key.values())

    def _client_endpoint_for(self, packet: PacketRecord) -> tuple[Endpoint | None, Endpoint | None]:
        if packet.src_port is None or packet.dst_port is None:
            return None, None
        source = Endpoint(packet.src_ip, packet.src_port)
        destination = Endpoint(packet.dst_ip, packet.dst_port)
        source_is_lan = self._is_lan_ip(source.ip)
        destination_is_lan = self._is_lan_ip(destination.ip)
        if source_is_lan and not destination_is_lan:
            return source, destination
        if destination_is_lan and not source_is_lan:
            return destination, source
        return None, None

    def _is_lan_ip(self, address: str) -> bool:
        ip = ipaddress.ip_address(address)
        return any(ip.version == network.version and ip in network for network in self._lan_networks)

    def add_packet(self, packet: PacketRecord) -> FlowState:
        if packet.session_id in self._closed_sessions:
            raise ValueError(f"capture session {packet.session_id!r} is already closed")
        key = normalize_flow_key(packet)
        flow = self._active_by_key.get(key)
        if flow is None:
            client_endpoint, remote_endpoint = self._client_endpoint_for(packet)
            next_id = self._next_id_by_session.get(packet.session_id, 0) + 1
            self._next_id_by_session[packet.session_id] = next_id
            flow_id = f"{packet.session_id}:flow-{next_id:06d}"
            flow = FlowState(
                session_id=packet.session_id,
                flow_id=flow_id,
                key=key,
                client_endpoint=client_endpoint,
                remote_endpoint=remote_endpoint,
                first_seen=packet.timestamp,
                last_seen=packet.timestamp,
            )
            self._active_by_key[key] = flow
            self._flows_by_id[flow_id] = flow

        direction = resolve_direction(packet, flow.client_endpoint)
        flow.add_packet(packet, direction)
        return flow

    def expire_udp_flows(self, now: float, *, idle_timeout: float = 60.0) -> tuple[FlowState, ...]:
        """Expire idle UDP pseudo-flows without applying TCP timeout policy."""
        if idle_timeout <= 0:
            raise ValueError("idle_timeout must be > 0")
        expired: list[FlowState] = []
        for key, flow in tuple(self._active_by_key.items()):
            if key.protocol.value == "UDP" and now - flow.last_seen >= idle_timeout:
                flow.status = FlowStatus.EXPIRED
                self._active_by_key.pop(key, None)
                expired.append(flow)
        return tuple(expired)

    def close_flow(self, flow_id: str) -> FlowState:
        try:
            flow = self._flows_by_id[flow_id]
        except KeyError as exc:
            raise KeyError(f"unknown Flow ID: {flow_id}") from exc
        if flow.status is FlowStatus.ACTIVE:
            flow.status = FlowStatus.CLOSED
            self._active_by_key.pop(flow.key, None)
        return flow

    def close_session(self, session_id: str) -> tuple[FlowState, ...]:
        if not session_id:
            raise ValueError("session_id must not be empty")
        closed: list[FlowState] = []
        for flow in tuple(self._active_by_key.values()):
            if flow.session_id == session_id:
                closed.append(self.close_flow(flow.flow_id))
        self._closed_sessions.add(session_id)
        return tuple(closed)

    def get_flow(self, flow_id: str) -> FlowState:
        try:
            return self._flows_by_id[flow_id]
        except KeyError as exc:
            raise KeyError(f"unknown Flow ID: {flow_id}") from exc

    def get_active_flow(self, key: FlowKey) -> FlowState | None:
        return self._active_by_key.get(key)
