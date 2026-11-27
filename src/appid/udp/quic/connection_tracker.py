"""Bounded QUIC v1 connection/CID tracking across UDP 5-tuples.

Only authenticated Initial packets contribute connection-ID mappings. UDP Flow
identity remains independent: a QUIC connection may reference multiple flows.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from appid.udp.quic.connection import QUICInitialConnection, QUICInitialResult
from appid.udp.quic.header import QUICParseError, parse_initial_header


@dataclass(slots=True)
class QUICConnectionState:
    connection_id: str
    original_dcid: bytes
    parser: QUICInitialConnection
    flow_ids: set[str] = field(default_factory=set)
    cids: set[bytes] = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0
    sni: str | None = None
    ech_detected: bool = False


class QUICConnectionTracker:
    def __init__(self, *, max_connections: int = 4096, max_cids_per_connection: int = 8,
                 idle_timeout: float = 120.0, max_crypto_bytes: int = 1_048_576) -> None:
        if max_connections < 1 or max_cids_per_connection < 2 or idle_timeout <= 0:
            raise ValueError("invalid QUIC tracker limits")
        self.max_connections = max_connections
        self.max_cids_per_connection = max_cids_per_connection
        self.idle_timeout = idle_timeout
        self.max_crypto_bytes = max_crypto_bytes
        self._connections: dict[str, QUICConnectionState] = {}
        self._cid_to_connection: dict[bytes, str] = {}
        self._next_id = 0
        self.capacity_evictions = 0

    @property
    def connections(self) -> tuple[QUICConnectionState, ...]:
        return tuple(self._connections.values())

    def _expire(self, now: float) -> None:
        for cid, connection_id in tuple(self._cid_to_connection.items()):
            state = self._connections.get(connection_id)
            if state is None or now - state.last_seen >= self.idle_timeout:
                self._cid_to_connection.pop(cid, None)
        for connection_id, state in tuple(self._connections.items()):
            if now - state.last_seen >= self.idle_timeout:
                self._remove(connection_id)

    def _remove(self, connection_id: str) -> None:
        state = self._connections.pop(connection_id, None)
        if state:
            for cid in state.cids:
                if self._cid_to_connection.get(cid) == connection_id:
                    self._cid_to_connection.pop(cid, None)

    def process(self, datagram: bytes, *, flow_id: str, timestamp: float) -> tuple[QUICConnectionState | None, QUICInitialResult]:
        self._expire(timestamp)
        try:
            header = parse_initial_header(datagram)
        except QUICParseError as exc:
            return None, QUICInitialResult("REJECTED", reason_code=str(exc))
        connection_id = self._cid_to_connection.get(header.dcid)
        state = self._connections.get(connection_id) if connection_id else None
        if state is None:
            # A new connection is established only by an authenticated client Initial.
            self._next_id += 1
            candidate_id = f"quic-{self._next_id:06d}"
            parser = QUICInitialConnection(max_crypto_bytes=self.max_crypto_bytes)
            result = parser.process_datagram(datagram)
            if result.status != "DECRYPTED" or result.sender_role != "client":
                return None, result
            if len(self._connections) >= self.max_connections:
                oldest = min(self._connections.values(), key=lambda item: item.last_seen)
                self._remove(oldest.connection_id)
                self.capacity_evictions += 1
            state = QUICConnectionState(candidate_id, header.dcid, parser,
                                        first_seen=timestamp, last_seen=timestamp)
            self._connections[candidate_id] = state
            connection_id = candidate_id
        else:
            result = state.parser.process_datagram(datagram)
            if result.status != "DECRYPTED":
                return state, result
        state.last_seen = max(state.last_seen, timestamp)
        state.flow_ids.add(flow_id)
        if result.sni:
            state.sni = result.sni
        state.ech_detected = state.ech_detected or result.ech_detected
        for cid in (result.dcid, result.scid):
            if not cid or cid in state.cids:
                continue
            if len(state.cids) >= self.max_cids_per_connection:
                continue
            owner = self._cid_to_connection.get(cid)
            if owner is None or owner == state.connection_id:
                state.cids.add(cid)
                self._cid_to_connection[cid] = state.connection_id
        return state, result
