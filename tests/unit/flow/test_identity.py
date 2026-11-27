import pytest

from appid.domain.models import Direction, PacketRecord, TransportProtocol
from appid.flow.identity import Endpoint, normalize_flow_key, resolve_direction


def packet(**overrides):
    values = {
        "session_id": "capture-a",
        "packet_index": 0,
        "timestamp": 100.0,
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
        "src_port": 51000,
        "dst_port": 443,
        "transport": TransportProtocol.TCP,
        "packet_length": 128,
    }
    values.update(overrides)
    return PacketRecord(**values)


def test_reverse_tcp_packets_have_same_flow_key():
    forward = normalize_flow_key(packet())
    backward = normalize_flow_key(packet(
        src_ip="198.51.100.20", dst_ip="192.0.2.10", src_port=443, dst_port=51000
    ))
    assert forward == backward
    assert forward.endpoint_a.sort_key() <= forward.endpoint_b.sort_key()


def test_reverse_udp_packets_have_same_flow_key():
    forward = normalize_flow_key(packet(transport=TransportProtocol.UDP, tcp_flags=None))
    backward = normalize_flow_key(packet(
        src_ip="198.51.100.20", dst_ip="192.0.2.10", src_port=443, dst_port=51000,
        transport=TransportProtocol.UDP, tcp_flags=None,
    ))
    assert forward == backward


def test_protocol_is_part_of_flow_identity():
    tcp_key = normalize_flow_key(packet())
    udp_key = normalize_flow_key(packet(transport=TransportProtocol.UDP, tcp_flags=None))
    assert tcp_key != udp_key


def test_ip_and_port_are_part_of_flow_identity():
    baseline = normalize_flow_key(packet())
    assert baseline != normalize_flow_key(packet(src_ip="192.0.2.11"))
    assert baseline != normalize_flow_key(packet(src_port=51001))
    assert baseline != normalize_flow_key(packet(dst_ip="198.51.100.21"))
    assert baseline != normalize_flow_key(packet(dst_port=8443))


def test_session_is_part_of_flow_identity():
    assert normalize_flow_key(packet()) != normalize_flow_key(packet(session_id="capture-b"))


def test_direction_is_forward_and_backward_only_with_explicit_client():
    client = Endpoint("192.0.2.10", 51000)
    assert resolve_direction(packet(), client) is Direction.FORWARD
    assert resolve_direction(packet(
        src_ip="198.51.100.20", dst_ip="192.0.2.10", src_port=443, dst_port=51000
    ), client) is Direction.BACKWARD


def test_direction_is_unknown_without_client_role():
    assert resolve_direction(packet(), None) is Direction.UNKNOWN


def test_direction_is_unknown_when_client_endpoint_is_not_in_packet():
    assert resolve_direction(packet(), Endpoint("203.0.113.5", 12345)) is Direction.UNKNOWN


def test_direction_is_unknown_for_ambiguous_same_endpoint_packet():
    same = packet(dst_ip="192.0.2.10", dst_port=51000)
    assert resolve_direction(same, Endpoint("192.0.2.10", 51000)) is Direction.UNKNOWN


def test_flow_key_requires_both_ports():
    with pytest.raises(ValueError, match="both source and destination ports"):
        normalize_flow_key(packet(src_port=None))


def test_endpoint_normalizes_ip_and_validates_port():
    assert Endpoint("2001:0db8::1", 443).ip == "2001:db8::1"
    with pytest.raises(ValueError, match="port"):
        Endpoint("192.0.2.1", 65536)
    with pytest.raises(ValueError, match="valid IPv4 or IPv6"):
        Endpoint("not-an-ip", 443)
