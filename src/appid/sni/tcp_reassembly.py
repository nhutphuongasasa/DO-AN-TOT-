"""Bounded, per-Flow/per-direction TCP byte-stream reassembly (P0.6.2).

The caller supplies normalized TCP metadata and payload bytes. This module does
not parse Scapy packets, infer client/server roles, or perform TLS parsing.
For mid-stream captures without a SYN, the first payload observed anchors the
stream; bytes sent before capture began cannot be reconstructed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from appid.domain.models import Direction


class ReassemblyStatus(str, Enum):
    DATA = "DATA"
    BUFFERED = "BUFFERED"
    DUPLICATE = "DUPLICATE"
    CONTROL = "CONTROL"
    BUFFER_LIMIT = "BUFFER_LIMIT"
    STREAM_LIMIT = "STREAM_LIMIT"
    CLOSED = "CLOSED"


@dataclass(frozen=True, slots=True)
class ReassemblyResult:
    flow_id: str
    direction: Direction
    data: bytes = b""
    status: ReassemblyStatus = ReassemblyStatus.CONTROL
    buffered_bytes: int = 0
    stream_closed: bool = False


@dataclass(slots=True)
class _Stream:
    expected_seq: int | None = None
    pending: dict[int, int] = field(default_factory=dict)
    last_seen: float = 0.0
    closed: bool = False
    syn_seen: bool = False


class TCPReassembler:
    """Reassemble TCP payloads with first-seen overlap handling and hard bounds.

    Streams are keyed by (Flow ID, direction), so opposite directions never
    share sequence space or buffers. Sequence arithmetic is unwrapped around
    the current expected sequence and supports the TCP 32-bit wrap boundary.
    """

    SEQ_MOD = 1 << 32
    SEQ_HALF = 1 << 31

    def __init__(self, *, idle_timeout: float = 60.0,
                 max_streams: int = 4096, max_buffered_bytes_per_stream: int = 256 * 1024,
                 max_buffered_bytes_total: int = 16 * 1024 * 1024,
                 max_gap_bytes: int = 256 * 1024, max_segment_payload: int = 65535) -> None:
        if idle_timeout <= 0 or min(max_streams, max_buffered_bytes_per_stream,
                                    max_buffered_bytes_total, max_gap_bytes,
                                    max_segment_payload) <= 0:
            raise ValueError("TCP reassembly limits must be positive")
        if max_buffered_bytes_per_stream > max_buffered_bytes_total:
            raise ValueError("per-stream buffer limit cannot exceed total buffer limit")
        self.idle_timeout = float(idle_timeout)
        self.max_streams = max_streams
        self.max_buffered_bytes_per_stream = max_buffered_bytes_per_stream
        self.max_buffered_bytes_total = max_buffered_bytes_total
        self.max_gap_bytes = max_gap_bytes
        self.max_segment_payload = max_segment_payload
        self._streams: dict[tuple[str, Direction], _Stream] = {}
        self._buffered_total = 0

    @property
    def stream_count(self) -> int:
        return len(self._streams)

    @property
    def buffered_bytes(self) -> int:
        return self._buffered_total

    def push(self, flow_id: str, direction: Direction, sequence_number: int,
             payload: bytes | bytearray | memoryview = b"", *, timestamp: float,
             syn: bool = False, fin: bool = False, rst: bool = False) -> ReassemblyResult:
        if not flow_id:
            raise ValueError("flow_id must not be empty")
        if direction not in (Direction.FORWARD, Direction.BACKWARD):
            raise ValueError("direction must be FORWARD or BACKWARD")
        if not isinstance(sequence_number, int) or not 0 <= sequence_number < self.SEQ_MOD:
            raise ValueError("sequence_number must be an unsigned 32-bit integer")
        try:
            data = bytes(payload)
        except (TypeError, ValueError) as exc:
            raise TypeError("payload must be bytes-like") from exc
        if len(data) > self.max_segment_payload:
            raise ValueError("segment payload exceeds max_segment_payload")

        key = (flow_id, direction)
        stream = self._streams.get(key)
        if stream is None:
            if len(self._streams) >= self.max_streams:
                # Do not evict an active stream silently: that could corrupt a
                # ClientHello. Caller can run cleanup() and retry the segment.
                return ReassemblyResult(flow_id, direction, status=ReassemblyStatus.STREAM_LIMIT)
            stream = _Stream(last_seen=timestamp)
            self._streams[key] = stream

        if stream.closed:
            return ReassemblyResult(flow_id, direction, status=ReassemblyStatus.CLOSED,
                                    stream_closed=True)
        stream.last_seen = max(stream.last_seen, timestamp)

        if rst:
            self._drop_stream(key)
            return ReassemblyResult(flow_id, direction, status=ReassemblyStatus.CLOSED,
                                    stream_closed=True)

        if syn and stream.expected_seq is None:
            stream.expected_seq = (sequence_number + 1) % self.SEQ_MOD
            stream.syn_seen = True
        payload_seq = (sequence_number + (1 if syn else 0)) % self.SEQ_MOD
        if data and stream.expected_seq is None:
            # Mid-stream capture: the first observed payload becomes the anchor.
            stream.expected_seq = payload_seq

        emitted = b""
        status = ReassemblyStatus.CONTROL
        if data:
            assert stream.expected_seq is not None
            absolute_start = self._unwrap(payload_seq, stream.expected_seq)
            expected = stream.expected_seq
            end = absolute_start + len(data)
            if end <= expected:
                status = ReassemblyStatus.DUPLICATE
            else:
                trim = max(0, expected - absolute_start)
                absolute_start += trim
                data = data[trim:]
                for offset, byte in enumerate(data):
                    position = absolute_start + offset
                    # First-seen byte wins for ambiguous overlapping segments.
                    if position not in stream.pending:
                        stream.pending[position] = byte
                        self._buffered_total += 1
                if self._over_limit(stream, expected):
                    self._drop_stream(key)
                    return ReassemblyResult(flow_id, direction,
                                            status=ReassemblyStatus.BUFFER_LIMIT,
                                            stream_closed=True)
                contiguous = bytearray()
                while stream.expected_seq in stream.pending:
                    contiguous.append(stream.pending.pop(stream.expected_seq))
                    stream.expected_seq += 1
                    self._buffered_total -= 1
                emitted = bytes(contiguous)
                if emitted:
                    status = ReassemblyStatus.DATA
                elif stream.pending:
                    status = ReassemblyStatus.BUFFERED
                else:
                    status = ReassemblyStatus.DUPLICATE

        if fin:
            # Surface directional close and release any gap-buffered bytes. A
            # full connection teardown state machine is intentionally out of scope.
            stream.closed = True
            self._buffered_total -= len(stream.pending)
            stream.pending.clear()
            status = ReassemblyStatus.CLOSED if not emitted else status
        return ReassemblyResult(flow_id, direction, emitted, status,
                                len(stream.pending), stream.closed)

    def cleanup(self, now: float) -> int:
        """Remove idle directional streams; return the number removed."""
        expired = [key for key, stream in self._streams.items()
                   if now - stream.last_seen >= self.idle_timeout]
        for key in expired:
            self._drop_stream(key)
        return len(expired)

    def close_flow(self, flow_id: str) -> int:
        """Remove both directional buffers for a Flow ID."""
        keys = [key for key in self._streams if key[0] == flow_id]
        for key in keys:
            self._drop_stream(key)
        return len(keys)

    def _over_limit(self, stream: _Stream, expected: int) -> bool:
        if len(stream.pending) > self.max_buffered_bytes_per_stream:
            return True
        if self._buffered_total > self.max_buffered_bytes_total:
            return True
        if stream.pending and max(stream.pending) - expected > self.max_gap_bytes:
            return True
        return False

    @staticmethod
    def _unwrap(sequence: int, reference: int) -> int:
        """Map a 32-bit sequence number to the nearest absolute sequence space."""
        reference_low = reference % TCPReassembler.SEQ_MOD
        delta = (sequence - reference_low + TCPReassembler.SEQ_HALF) % TCPReassembler.SEQ_MOD
        delta -= TCPReassembler.SEQ_HALF
        return reference + delta

    def _drop_stream(self, key: tuple[str, Direction]) -> None:
        stream = self._streams.pop(key, None)
        if stream is not None:
            self._buffered_total -= len(stream.pending)
