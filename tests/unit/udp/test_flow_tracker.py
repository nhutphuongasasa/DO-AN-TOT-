import pytest

from appid.domain.models import PacketRecord, TransportProtocol
from appid.udp import UDPFlowStatus, UDPFlowTracker


def packet(index=1, *, src="192.168.1.10", dst="8.8.8.8", sport=53000, dport=53,
           timestamp=1.0, length=80, session="s"):
    return PacketRecord(session_id=session, packet_index=index, timestamp=timestamp,
                        src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
                        transport=TransportProtocol.UDP, packet_length=length)


def test_tracks_bidirectional_datagrams_and_bytes():
    tracker = UDPFlowTracker(lan_subnets=["192.168.1.0/24"])
    first = tracker.add_packet(packet())
    second = tracker.add_packet(packet(2, src="8.8.8.8", dst="192.168.1.10",
                                       sport=53, dport=53000, timestamp=2, length=120))
    assert first is second
    assert first.datagrams_forward == 1
    assert first.datagrams_backward == 1
    assert first.bytes_forward == 80
    assert first.bytes_backward == 120
    assert first.datagrams_total == 2
    assert first.bytes_total == 200


def test_canonical_flow_key_is_bidirectional_and_session_scoped():
    tracker = UDPFlowTracker(lan_subnets=["192.168.1.0/24"])
    a = tracker.add_packet(packet())
    b = tracker.add_packet(packet(2, src="8.8.8.8", dst="192.168.1.10", sport=53, dport=53000))
    c = tracker.add_packet(packet(3, session="another"))
    assert a is b
    assert c is not a
    assert a.flow_id != c.flow_id


def test_ambiguous_non_lan_direction_is_unknown():
    tracker = UDPFlowTracker(lan_subnets=["192.168.1.0/24"])
    flow = tracker.add_packet(packet(src="10.0.0.1", dst="8.8.8.8"))
    assert flow.client_endpoint is None
    assert flow.datagrams_unknown == 1


def test_idle_timeout_expires_flow_and_allows_tuple_reuse():
    tracker = UDPFlowTracker(lan_subnets=["192.168.1.0/24"], idle_timeout=10)
    old = tracker.add_packet(packet(timestamp=1))
    expired = tracker.cleanup(11)
    assert expired == (old,)
    assert old.status is UDPFlowStatus.EXPIRED
    new = tracker.add_packet(packet(2, timestamp=12))
    assert new is not old
    assert new.flow_id != old.flow_id


def test_capacity_is_bounded_and_cleanup_frees_slot():
    tracker = UDPFlowTracker(lan_subnets=["192.168.1.0/24"], max_flows=1, idle_timeout=5)
    tracker.add_packet(packet())
    with pytest.raises(RuntimeError, match="capacity"):
        tracker.add_packet(packet(2, sport=53001))
    tracker.cleanup(6)
    assert len(tracker.active_flows) == 0
    tracker.add_packet(packet(3, sport=53001, timestamp=7))
    assert len(tracker.active_flows) == 1


def test_rejects_tcp_packets_and_invalid_configuration():
    tracker = UDPFlowTracker(lan_subnets=["192.168.1.0/24"])
    tcp = PacketRecord("s", 1, 1.0, "192.168.1.10", "8.8.8.8", 1234, 443,
                       TransportProtocol.TCP, 100, tcp_flags=2)
    with pytest.raises(ValueError, match="UDP packets only"):
        tracker.add_packet(tcp)
    with pytest.raises(ValueError):
        UDPFlowTracker(lan_subnets=[], idle_timeout=0)
    with pytest.raises(ValueError):
        UDPFlowTracker(lan_subnets=[], max_flows=0)


def test_close_flow_and_session_prevent_further_tracking():
    tracker = UDPFlowTracker(lan_subnets=["192.168.1.0/24"])
    flow = tracker.add_packet(packet())
    tracker.close_flow(flow.flow_id)
    assert flow.status is UDPFlowStatus.CLOSED
    session_flows = tracker.close_session("s")
    assert session_flows == ()
    with pytest.raises(ValueError, match="already closed"):
        tracker.add_packet(packet(2))
