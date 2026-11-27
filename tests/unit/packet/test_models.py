import pytest

from appid.domain.models import (
    Direction,
    IdentificationMethod,
    IdentificationResult,
    IdentificationStatus,
    PacketRecord,
    TransportProtocol,
)


def make_packet(**overrides):
    values = {
        "session_id": "session-001",
        "packet_index": 0,
        "timestamp": 1000.25,
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
        "src_port": 51000,
        "dst_port": 443,
        "transport": TransportProtocol.TCP,
        "packet_length": 128,
        "tcp_flags": 0x02,
    }
    values.update(overrides)
    return PacketRecord(**values)


def test_packet_record_accepts_valid_tcp_packet():
    packet = make_packet()
    assert packet.transport is TransportProtocol.TCP
    assert packet.tcp_flags == 0x02


def test_packet_record_rejects_negative_packet_index():
    with pytest.raises(ValueError, match="packet_index"):
        make_packet(packet_index=-1)


def test_packet_record_rejects_tcp_flags_for_udp():
    with pytest.raises(ValueError, match="tcp_flags"):
        make_packet(transport=TransportProtocol.UDP, tcp_flags=0)


def test_direction_contract_has_unknown_state():
    assert Direction.UNKNOWN.value == "UNKNOWN"


def test_classified_result_requires_application_and_method():
    result = IdentificationResult(
        session_id="session-001",
        flow_id="flow-001",
        status=IdentificationStatus.CLASSIFIED,
        application="example-app",
        method=IdentificationMethod.DNS,
        reason_code="DNS_MAPPING_MATCH",
    )
    assert result.application == "example-app"


def test_unknown_result_must_not_claim_application():
    with pytest.raises(ValueError, match="UNKNOWN result"):
        IdentificationResult(
            session_id="session-001",
            flow_id="flow-001",
            status=IdentificationStatus.UNKNOWN,
            application="example-app",
            method=None,
            reason_code="INSUFFICIENT_EVIDENCE",
        )
