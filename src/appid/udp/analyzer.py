"""UDP protocol analysis and QUIC Initial inspection for the shared pipeline."""
from __future__ import annotations

from dataclasses import dataclass

from appid.udp.protocol_identifier import UDPProtocol, UDPProtocolIdentifier
from appid.udp.quic.connection_tracker import QUICConnectionTracker


@dataclass(frozen=True, slots=True)
class UDPAnalysis:
    protocol: UDPProtocol
    reason_code: str
    connection_id: str | None = None
    hostname: str | None = None
    application_id: str | None = None
    ech_detected: bool = False
    decrypt_status: str | None = None
    rule_ids: tuple[str, ...] = ()


class UDPAnalyzer:
    def __init__(self, *, domain_identifier, max_connections: int = 4096,
                 idle_timeout: float = 120.0, max_crypto_bytes: int = 1_048_576,
                 enable_quic: bool = True) -> None:
        self.protocol_identifier = UDPProtocolIdentifier()
        self.quic_tracker = QUICConnectionTracker(max_connections=max_connections,
            idle_timeout=idle_timeout, max_crypto_bytes=max_crypto_bytes)
        self.domain_identifier = domain_identifier
        self.enable_quic = bool(enable_quic)

    def analyze(self, payload: bytes, *, src_port: int, dst_port: int,
                flow_id: str, timestamp: float) -> UDPAnalysis:
        identified = self.protocol_identifier.identify(payload, src_port=src_port, dst_port=dst_port)
        if identified.protocol is not UDPProtocol.QUIC_INITIAL_CANDIDATE:
            return UDPAnalysis(identified.protocol, identified.reason_code)
        if not self.enable_quic:
            return UDPAnalysis(identified.protocol, "QUIC_ANALYSIS_DISABLED")
        connection, result = self.quic_tracker.process(payload, flow_id=flow_id, timestamp=timestamp)
        if result.status != "DECRYPTED":
            return UDPAnalysis(identified.protocol, result.reason_code or "QUIC_INITIAL_REJECTED",
                               connection.connection_id if connection else None,
                               decrypt_status=result.status)
        app_id = None
        if result.sni:
            match = self.domain_identifier.identify(result.sni)
            app_id = match.application_id
        return UDPAnalysis(identified.protocol, result.reason_code,
            connection.connection_id if connection else None, result.sni, app_id,
            result.ech_detected, result.status, match.rule_ids if result.sni and app_id else ())
