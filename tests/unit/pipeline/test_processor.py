import ipaddress
from dataclasses import replace

from appid.domain.models import PacketRecord, TransportProtocol
from appid.pipeline import processor as processor_module
from appid.pipeline.processor import PacketProcessor


class RawPacket:
    def __init__(self, timestamp=1.0):
        self.time = timestamp


def make_record(raw_packet, *, session_id, packet_index):
    return PacketRecord(
        session_id=session_id,
        packet_index=packet_index,
        timestamp=raw_packet.time,
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
        src_port=50000,
        dst_port=443,
        transport=TransportProtocol.TCP,
        packet_length=100,
    )


def test_processor_tracks_parsed_packet_and_retains_capture_timestamp(monkeypatch):
    monkeypatch.setattr(processor_module, "parse_packet", make_record)
    processor = PacketProcessor(session_id="s1", lan_network="192.168.1.0/24")
    flow = processor.process(RawPacket(timestamp=1234.5))
    assert flow is not None
    assert flow.flow_id == "s1:flow-000001"
    assert flow.packets[0].timestamp == 1234.5
    assert flow.packets[0].packet_index == 0
    assert processor.stats.tracked_packets == 1
    processor.close()


def test_processor_skips_packet_outside_selected_subnet(monkeypatch):
    def outside_record(raw_packet, *, session_id, packet_index):
        record = make_record(raw_packet, session_id=session_id, packet_index=packet_index)
        return replace(record, src_ip="10.0.0.1")

    monkeypatch.setattr(processor_module, "parse_packet", outside_record)
    processor = PacketProcessor(session_id="s2", lan_network="192.168.1.0/24")
    assert processor.process(RawPacket()) is None
    assert processor.stats.outside_lan_packets == 1
    assert processor.stats.tracked_packets == 0
    processor.close()


def test_processor_counts_parser_errors_without_stopping(monkeypatch):
    calls = iter([ValueError("bad packet"), None])

    def parser(*args, **kwargs):
        value = next(calls)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(processor_module, "parse_packet", parser)
    processor = PacketProcessor(session_id="s3", lan_network=ipaddress.ip_network("192.168.1.0/24"))
    assert processor.process(RawPacket()) is None
    assert processor.process(RawPacket()) is None
    assert processor.stats.parse_errors == 1
    assert processor.stats.unsupported_packets == 1
    processor.close()


def test_processor_expires_udp_flow_without_expiring_tcp(monkeypatch):
    from appid.domain.models import TransportProtocol

    records = iter([
        PacketRecord("s4", 0, 1.0, "192.168.1.10", "203.0.113.10", 50000, 443,
                     TransportProtocol.UDP, 80),
        PacketRecord("s4", 1, 62.0, "192.168.1.10", "203.0.113.10", 50000, 443,
                     TransportProtocol.UDP, 80),
    ])
    monkeypatch.setattr(processor_module, "parse_packet", lambda *a, **k: next(records))
    processor = PacketProcessor(session_id="s4", lan_network="192.168.1.0/24")
    first = processor.process(RawPacket(timestamp=1.0))
    second = processor.process(RawPacket(timestamp=62.0))
    assert first.flow_id != second.flow_id
    assert first.status.value == "EXPIRED"
    assert processor.stats.udp_flows_expired == 1
    processor.close()


def test_processor_bounds_active_udp_flow_count(monkeypatch):
    from appid.domain.models import TransportProtocol

    records = iter([
        PacketRecord("s5", 0, 1.0, "192.168.1.10", "203.0.113.10", 50000, 443,
                     TransportProtocol.UDP, 80),
        PacketRecord("s5", 1, 1.1, "192.168.1.10", "203.0.113.10", 50000, 443,
                     TransportProtocol.UDP, 90),
        PacketRecord("s5", 2, 2.0, "192.168.1.10", "203.0.113.11", 50001, 443,
                     TransportProtocol.UDP, 80),
    ])
    monkeypatch.setattr(processor_module, "parse_packet", lambda *a, **k: next(records))
    processor = PacketProcessor(session_id="s5", lan_network="192.168.1.0/24",
                                max_active_udp_flows=1)
    first = processor.process(RawPacket(timestamp=1.0))
    processor.process(RawPacket(timestamp=1.1))
    second = processor.process(RawPacket(timestamp=2.0))
    assert first.status.value == "CLOSED"
    assert second.status.value == "ACTIVE"
    assert processor.stats.udp_flow_capacity_evictions == 1
    assert processor.stats.burst_flows_finalized == 1
    assert processor.stats.bursts_created == 1
    processor.close()


def test_processor_exposes_ml_candidate_gate_after_shared_processing(monkeypatch):
    from appid.ml import CandidateReason, CandidateState

    monkeypatch.setattr(processor_module, "parse_packet", make_record)
    processor = PacketProcessor(session_id="s6", lan_network="192.168.1.0/24")
    flow = processor.process(RawPacket(timestamp=1234.5))
    assert flow is not None
    decision = processor.evaluate_ml_candidate(flow)
    assert decision.state is CandidateState.PENDING
    assert decision.reason is CandidateReason.OBSERVATION_POLICY_UNCONFIGURED
    processor.close()



class FakeTCP:
    def __init__(self, sequence, flags=0, payload=b""):
        self.seq = sequence
        self.flags = flags
        self.payload = payload


class RawTCPPacket:
    def __init__(self, tcp):
        self.tcp = tcp

    def getlayer(self, name):
        return self.tcp if name == "TCP" else None


def _forward_flow(processor, timestamp):
    record = PacketRecord(
        session_id=processor.session_id, packet_index=0, timestamp=timestamp,
        src_ip="192.168.1.10", dst_ip="8.8.8.8", src_port=50000, dst_port=443,
        transport=TransportProtocol.TCP, packet_length=100,
    )
    return processor.tracker.add_packet(record), record


def test_sni_idle_timer_refreshes_for_buffered_out_of_order_segment():
    processor = PacketProcessor(session_id="sni-buffer", lan_network="192.168.1.0/24")
    flow, record = _forward_flow(processor, 1.0)

    # Establish the TCP sequence space, then retain a partial TLS header.
    processor._try_sni_identification(
        RawTCPPacket(FakeTCP(100, flags=0x02)), flow, record
    )
    record = replace(record, packet_index=1, timestamp=2.0)
    processor._try_sni_identification(
        RawTCPPacket(FakeTCP(101, payload=b"\x16\x03\x03")), flow, record
    )
    assert processor._sni_stream_last_seen[flow.flow_id] == 2.0

    # This segment is buffered behind a gap and emits no bytes yet.
    record = replace(record, packet_index=2, timestamp=50.0)
    processor._try_sni_identification(
        RawTCPPacket(FakeTCP(110, payload=b"later")), flow, record
    )
    assert processor._sni_stream_last_seen[flow.flow_id] == 50.0
    assert flow.flow_id in processor._sni_stream_data
    processor.close()


def test_sni_unsupported_record_is_not_counted_as_malformed_tls():
    processor = PacketProcessor(session_id="sni-unsupported", lan_network="192.168.1.0/24")
    flow, record = _forward_flow(processor, 1.0)
    processor._try_sni_identification(
        RawTCPPacket(FakeTCP(100, payload=b"\x17\x03\x03\x00\x00")),
        flow, record,
    )
    assert processor.stats.sni_unsupported_records == 1
    assert processor.stats.sni_parse_errors == 0
    processor.close()


def test_dns_identified_flow_skips_sni_and_udp_stages(monkeypatch):
    from types import SimpleNamespace

    record = PacketRecord(
        session_id="dns-first", packet_index=0, timestamp=10.0,
        src_ip="192.168.1.10", dst_ip="203.0.113.20", src_port=51000,
        dst_port=443, transport=TransportProtocol.TCP, packet_length=100,
    )
    monkeypatch.setattr(processor_module, "parse_packet", lambda *a, **k: record)
    processor = PacketProcessor(session_id="dns-first", lan_network="192.168.1.0/24")
    processor.dns_identifier.identify = lambda **kwargs: SimpleNamespace(
        status="DNS_IDENTIFIED", application_id="chatgpt",
        matched_domains=("chatgpt.com",), destination_ip="203.0.113.20",
        client_ip="192.168.1.10", rule_ids=("chatgpt-chatgpt-com",),
        expires_at=100.0, reason_code="DNS_CLIENT_IP_DOMAIN_MATCH",
    )
    later_stages = []
    monkeypatch.setattr(processor, "_try_sni_identification",
                        lambda *args: later_stages.append("sni"))
    monkeypatch.setattr(processor, "_try_udp_identification",
                        lambda *args: later_stages.append("udp"))

    flow = processor.process(RawPacket(timestamp=10.0))

    assert flow.identification_result.application == "chatgpt"
    assert flow.identification_result.method.value == "dns"
    assert later_stages == []
    assert processor.stats.dns_identified_flows == 1
    processor.close()
