import socket
from types import SimpleNamespace

import pytest

from appid.domain.models import Direction, PacketRecord, TransportProtocol
from appid.flow.identity import Endpoint, normalize_flow_key
from appid.flow.tracker import FlowStatus, FlowTracker
from appid.network.interfaces import discover_interface_subnets


def packet(**overrides):
    values = {
        "session_id": "capture-a",
        "packet_index": 0,
        "timestamp": 100.0,
        "src_ip": "192.168.1.10",
        "dst_ip": "203.0.113.20",
        "src_port": 51000,
        "dst_port": 443,
        "transport": TransportProtocol.TCP,
        "packet_length": 128,
    }
    values.update(overrides)
    return PacketRecord(**values)


def test_bidirectional_packets_share_flow_and_have_correct_direction():
    tracker = FlowTracker(lan_subnets=["192.168.1.0/24"])
    first = tracker.add_packet(packet(packet_index=4))
    second = tracker.add_packet(packet(
        packet_index=5, timestamp=101.0, src_ip="203.0.113.20", dst_ip="192.168.1.10",
        src_port=443, dst_port=51000, packet_length=64,
    ))
    assert first is second
    assert second.flow_id == "capture-a:flow-000001"
    assert [p.direction for p in second.ordered_packets] == [Direction.FORWARD, Direction.BACKWARD]
    assert second.packets_forward == 1
    assert second.packets_backward == 1
    assert second.bytes_forward == 128
    assert second.bytes_backward == 64


def test_server_first_packet_does_not_reverse_direction():
    tracker = FlowTracker(lan_subnets=["192.168.1.0/24"])
    flow = tracker.add_packet(packet(
        src_ip="203.0.113.20", dst_ip="192.168.1.10", src_port=443, dst_port=51000,
    ))
    assert flow.client_endpoint == Endpoint("192.168.1.10", 51000)
    assert flow.ordered_packets[0].direction is Direction.BACKWARD


def test_ambiguous_both_lan_or_neither_lan_is_unknown():
    tracker = FlowTracker(lan_subnets=["192.168.1.0/24"])
    both_lan = tracker.add_packet(packet(dst_ip="192.168.1.11", dst_port=51001))
    outside = tracker.add_packet(packet(
        session_id="capture-b", src_ip="198.51.100.10", dst_ip="203.0.113.20",
    ))
    assert both_lan.client_endpoint is None
    assert both_lan.ordered_packets[0].direction is Direction.UNKNOWN
    assert outside.client_endpoint is None
    assert outside.ordered_packets[0].direction is Direction.UNKNOWN


def test_unknown_can_be_resolved_as_unknown_for_unavailable_subnet_snapshot():
    tracker = FlowTracker(lan_subnets=[])
    flow = tracker.add_packet(packet())
    assert flow.ordered_packets[0].direction is Direction.UNKNOWN
    assert flow.packets_unknown == 1


def test_packets_are_sorted_by_timestamp_then_packet_index():
    tracker = FlowTracker(lan_subnets=["192.168.1.0/24"])
    flow = tracker.add_packet(packet(packet_index=8, timestamp=102.0))
    tracker.add_packet(packet(packet_index=4, timestamp=101.0))
    tracker.add_packet(packet(packet_index=3, timestamp=101.0))
    assert [(p.timestamp, p.packet_index) for p in flow.ordered_packets] == [
        (101.0, 3), (101.0, 4), (102.0, 8)
    ]
    assert flow.first_seen == 101.0
    assert flow.last_seen == 102.0


def test_tuple_reuse_after_explicit_close_gets_new_flow_id():
    tracker = FlowTracker(lan_subnets=["192.168.1.0/24"])
    old_flow = tracker.add_packet(packet())
    tracker.close_flow(old_flow.flow_id)
    new_flow = tracker.add_packet(packet(packet_index=1, timestamp=200.0))
    assert old_flow.status is FlowStatus.CLOSED
    assert new_flow.flow_id != old_flow.flow_id
    assert new_flow.flow_id == "capture-a:flow-000002"
    assert len(tracker.flows) == 2


def test_flow_is_not_closed_by_elapsed_time_without_timeout_policy():
    tracker = FlowTracker(lan_subnets=["192.168.1.0/24"])
    flow = tracker.add_packet(packet(timestamp=1.0))
    same = tracker.add_packet(packet(packet_index=1, timestamp=10_000_000.0))
    assert same is flow
    assert flow.status is FlowStatus.ACTIVE


def test_close_session_closes_active_flows_and_rejects_more_packets():
    tracker = FlowTracker(lan_subnets=["192.168.1.0/24"])
    flow_a = tracker.add_packet(packet())
    flow_b = tracker.add_packet(packet(dst_port=8443))
    closed = tracker.close_session("capture-a")
    assert set(item.flow_id for item in closed) == {flow_a.flow_id, flow_b.flow_id}
    assert all(item.status is FlowStatus.CLOSED for item in closed)
    with pytest.raises(ValueError, match="already closed"):
        tracker.add_packet(packet(packet_index=1))


def test_flow_ids_are_session_scoped_and_session_tuple_identity_isolated():
    tracker = FlowTracker(lan_subnets=["192.168.1.0/24"])
    flow_a = tracker.add_packet(packet())
    flow_b = tracker.add_packet(packet(session_id="capture-b"))
    assert flow_a.flow_id == "capture-a:flow-000001"
    assert flow_b.flow_id == "capture-b:flow-000001"
    assert flow_a.key != flow_b.key


def test_duplicate_packets_are_not_silently_deduplicated():
    tracker = FlowTracker(lan_subnets=["192.168.1.0/24"])
    flow = tracker.add_packet(packet(packet_index=7))
    tracker.add_packet(packet(packet_index=7))
    assert len(flow.packets) == 2


def test_tracker_requires_both_ports_for_flow_identity():
    tracker = FlowTracker(lan_subnets=["192.168.1.0/24"])
    with pytest.raises(ValueError, match="both source and destination ports"):
        tracker.add_packet(packet(src_port=None))


def test_interface_subnet_discovery_filters_down_loopback_and_denied_interfaces(monkeypatch):
    import appid.network.interfaces as network

    def addr(ip, mask, family=socket.AF_INET):
        return SimpleNamespace(family=family, address=ip, netmask=mask)

    monkeypatch.setattr(network.psutil, "net_if_addrs", lambda: {
        "eth0": [addr("192.168.1.10", "255.255.255.0")],
        "lo": [addr("127.0.0.1", "255.0.0.0")],
        "down0": [addr("10.0.0.2", "255.255.255.0")],
        "wlan0": [addr("10.10.0.4", "255.255.0.0")],
    })
    monkeypatch.setattr(network.psutil, "net_if_stats", lambda: {
        "eth0": SimpleNamespace(isup=True),
        "lo": SimpleNamespace(isup=True),
        "down0": SimpleNamespace(isup=False),
        "wlan0": SimpleNamespace(isup=True),
    })
    found = discover_interface_subnets(interface_denylist=["wlan0"])
    assert [(item.interface, str(item.network)) for item in found] == [
        ("eth0", "192.168.1.0/24")
    ]


def test_auto_discovered_subnets_are_used_by_tracker(monkeypatch):
    import ipaddress

    import appid.flow.tracker as tracker_module
    from appid.network.interfaces import InterfaceSubnet

    monkeypatch.setattr(
        tracker_module,
        "discover_interface_subnets",
        lambda **kwargs: (InterfaceSubnet("eth0", ipaddress.ip_network("192.168.1.0/24")),),
    )
    tracker = FlowTracker()
    flow = tracker.add_packet(packet())
    assert flow.client_endpoint == Endpoint("192.168.1.10", 51000)


def test_flow_key_remains_the_p02_canonical_identity():
    tracker = FlowTracker(lan_subnets=["192.168.1.0/24"])
    flow = tracker.add_packet(packet())
    assert flow.key == normalize_flow_key(packet())


def test_udp_idle_expiry_is_separate_from_tcp_lifecycle():
    from appid.domain.models import PacketRecord, TransportProtocol
    from appid.flow.tracker import FlowStatus

    tracker = FlowTracker(lan_subnets=["192.168.1.0/24"])
    udp = PacketRecord("s", 0, 1.0, "192.168.1.10", "203.0.113.10", 50000, 443,
                       TransportProtocol.UDP, 100)
    tcp = PacketRecord("s", 1, 1.0, "192.168.1.10", "203.0.113.11", 50001, 443,
                       TransportProtocol.TCP, 100)
    udp_flow = tracker.add_packet(udp)
    tcp_flow = tracker.add_packet(tcp)
    expired = tracker.expire_udp_flows(61.0, idle_timeout=60.0)
    assert expired == (udp_flow,)
    assert udp_flow.status is FlowStatus.EXPIRED
    assert tcp_flow.status is FlowStatus.ACTIVE
    assert tracker.get_active_flow(udp_flow.key) is None
    assert tracker.get_active_flow(tcp_flow.key) is tcp_flow
