"""Foundational domain models aligned with the project module contracts.

Only decisions marked FIXED in the specification are encoded here. In
particular, this module does not guess client/server roles, flow timeouts,
DNS/SNI mapping policies, or ML parameters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TransportProtocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    OTHER = "OTHER"


class Direction(str, Enum):
    FORWARD = "FORWARD"
    BACKWARD = "BACKWARD"
    UNKNOWN = "UNKNOWN"


class IdentificationStatus(str, Enum):
    CLASSIFIED = "CLASSIFIED"
    UNKNOWN = "UNKNOWN"


class IdentificationMethod(str, Enum):
    DNS = "dns"
    SNI = "sni"
    HYBRID_DNS_SNI = "hybrid_dns_sni"
    HYBRID_DNS_QUIC_SNI = "hybrid_dns_quic_sni"
    BURST_FUSION = "burst_fusion"


@dataclass(frozen=True, slots=True)
class PacketRecord:
    """Normalized packet metadata shared by capture and protocol parsers.

    `packet_length` is the original packet length in bytes when the capture
    source exposes it (for example, Scapy's PCAP `wirelen`). If that metadata
    is unavailable, it falls back to the captured packet representation length.
    """

    session_id: str
    packet_index: int
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    transport: TransportProtocol
    packet_length: int
    tcp_flags: int | None = None

    def __post_init__(self) -> None:
        if not self.session_id:
            raise ValueError("session_id must not be empty")
        if self.packet_index < 0:
            raise ValueError("packet_index must be >= 0")
        if self.packet_length < 0:
            raise ValueError("packet_length must be >= 0")
        if self.src_port is not None and not 0 <= self.src_port <= 65535:
            raise ValueError("src_port must be between 0 and 65535")
        if self.dst_port is not None and not 0 <= self.dst_port <= 65535:
            raise ValueError("dst_port must be between 0 and 65535")
        if self.transport is not TransportProtocol.TCP and self.tcp_flags is not None:
            raise ValueError("tcp_flags is only valid for TCP packets")


@dataclass(frozen=True, slots=True)
class Evidence:
    """Evidence attached to a rule-based or ML identification result."""

    source: str
    value: str
    packet_indexes: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class IdentificationResult:
    """Common logical result returned by DNS, SNI or ML classification."""

    session_id: str
    flow_id: str
    status: IdentificationStatus
    application: str | None
    method: IdentificationMethod | None
    reason_code: str
    evidence: tuple[Evidence, ...] = ()
    confidence: float | None = None
    model_versions: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.session_id:
            raise ValueError("session_id must not be empty")
        if not self.flow_id:
            raise ValueError("flow_id must not be empty")
        if not self.reason_code:
            raise ValueError("reason_code must not be empty")

        if self.status is IdentificationStatus.CLASSIFIED:
            if not self.application:
                raise ValueError("CLASSIFIED result requires an application")
            if self.method is None:
                raise ValueError("CLASSIFIED result requires an identification method")
        elif self.status is IdentificationStatus.UNKNOWN:
            if self.application is not None:
                raise ValueError("UNKNOWN result must not contain an application")

        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
