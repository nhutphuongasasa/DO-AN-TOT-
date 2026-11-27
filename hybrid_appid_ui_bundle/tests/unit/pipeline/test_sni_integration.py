from types import SimpleNamespace

from appid.domain.models import (
    IdentificationMethod,
    IdentificationResult,
    IdentificationStatus,
    PacketRecord,
    TransportProtocol,
)
from appid.pipeline import processor as processor_module
from appid.pipeline.processor import PacketProcessor


def _u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def _client_hello(host: str) -> bytes:
    name = host.encode("ascii")
    sni_entry = b"\x00" + _u16(len(name)) + name
    sni_list = _u16(len(sni_entry)) + sni_entry
    extension = _u16(0) + _u16(len(sni_list)) + sni_list
    body = (b"\x03\x03" + bytes(range(32)) + b"\x00" + _u16(2)
            + b"\x13\x01" + b"\x01\x00" + _u16(len(extension)) + extension)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + _u16(len(handshake)) + handshake


class FakePacket:
    def __init__(self, seq: int, payload: bytes = b"", flags=0x18):
        self.time = float(seq)
        self.tcp = SimpleNamespace(seq=seq, payload=SimpleNamespace(__bytes__=lambda self: payload),
                                   flags=flags)
        self.tcp.payload = payload

    def getlayer(self, name):
        return self.tcp if name == "TCP" else None


def _record(raw, *, session_id, packet_index):
    return PacketRecord(session_id=session_id, packet_index=packet_index,
        timestamp=raw.time, src_ip="192.168.1.10", dst_ip="203.0.113.20",
        src_port=51000, dst_port=443, transport=TransportProtocol.TCP,
        packet_length=40 + len(raw.tcp.payload), tcp_flags=raw.tcp.flags)


def test_live_pipeline_identifies_sni_after_tcp_segmentation(monkeypatch):
    monkeypatch.setattr(processor_module, "parse_packet", _record)
    processor = PacketProcessor(session_id="sni-test", lan_network="192.168.1.0/24")
    hello = _client_hello("chatgpt.com")
    processor.process(FakePacket(100, flags=0x02))
    split = len(hello) // 2
    processor.process(FakePacket(101 + split, hello[split:]))
    flow = processor.process(FakePacket(101, hello[:split]))

    assert flow is not None
    assert flow.identification_result is not None
    assert flow.identification_result.application == "chatgpt"
    assert flow.identification_result.method is IdentificationMethod.SNI
    assert any(item.source == "tls_sni" and item.value == "chatgpt.com"
               for item in flow.identification_result.evidence)
    assert processor.stats.sni_identified_flows == 1
    processor.close()


def test_sni_identification_uses_only_the_approved_application_domain_rules(monkeypatch):
    monkeypatch.setattr(processor_module, "parse_packet", _record)
    processor = PacketProcessor(session_id="sni-other", lan_network="192.168.1.0/24")
    hello = _client_hello("generic-example.net")
    processor.process(FakePacket(200, flags=0x02))
    flow = processor.process(FakePacket(201, hello))

    assert flow is not None
    assert flow.identification_result is None
    assert processor.stats.sni_unmapped_hostnames == 1
    processor.close()


def test_dns_identification_is_preserved_when_sni_result_is_attempted():
    processor = PacketProcessor(session_id="hybrid-test", lan_network="192.168.1.0/24")
    record = PacketRecord(session_id="hybrid-test", packet_index=0, timestamp=1.0,
        src_ip="192.168.1.10", dst_ip="203.0.113.20", src_port=51000,
        dst_port=443, transport=TransportProtocol.TCP, packet_length=100)
    flow = processor.tracker.add_packet(record)
    flow.identification_result = IdentificationResult(
        session_id=flow.session_id, flow_id=flow.flow_id,
        status=IdentificationStatus.CLASSIFIED, application="chatgpt",
        method=IdentificationMethod.DNS, reason_code="DNS_CLIENT_IP_DOMAIN_MATCH")

    processor._apply_sni_result(flow, "chatgpt.com", "chatgpt", ("chatgpt-chatgpt-com",))

    assert flow.identification_result.method is IdentificationMethod.DNS
    assert flow.identification_result.application == "chatgpt"
    assert flow.identification_result.reason_code == "DNS_CLIENT_IP_DOMAIN_MATCH"
    processor.close()


def test_dns_precedence_prevents_conflicting_sni_from_overwriting_result():
    processor = PacketProcessor(session_id="conflict-test", lan_network="192.168.1.0/24")
    record = PacketRecord(session_id="conflict-test", packet_index=0, timestamp=1.0,
        src_ip="192.168.1.10", dst_ip="203.0.113.20", src_port=51000,
        dst_port=443, transport=TransportProtocol.TCP, packet_length=100)
    flow = processor.tracker.add_packet(record)
    flow.identification_result = IdentificationResult(
        session_id=flow.session_id, flow_id=flow.flow_id,
        status=IdentificationStatus.CLASSIFIED, application="facebook",
        method=IdentificationMethod.DNS, reason_code="DNS_CLIENT_IP_DOMAIN_MATCH")

    processor._apply_sni_result(flow, "chatgpt.com", "chatgpt", ("chatgpt-chatgpt-com",))

    assert flow.identification_result.application == "facebook"
    assert flow.identification_result.method is IdentificationMethod.DNS
    assert flow.identification_result.reason_code == "DNS_CLIENT_IP_DOMAIN_MATCH"
    processor.close()


def test_late_dns_identification_replaces_sni_and_then_early_exits():
    processor = PacketProcessor(session_id="hybrid-repeat", lan_network="192.168.1.0/24")
    record = PacketRecord(session_id="hybrid-repeat", packet_index=0, timestamp=1.0,
        src_ip="192.168.1.10", dst_ip="203.0.113.20", src_port=51000,
        dst_port=443, transport=TransportProtocol.TCP, packet_length=100)
    flow = processor.tracker.add_packet(record)
    processor._apply_sni_result(flow, "chatgpt.com", "chatgpt", ("chatgpt-chatgpt-com",))
    processor.dns_identifier.identify = lambda **kwargs: SimpleNamespace(
        status="DNS_IDENTIFIED", application_id="chatgpt", matched_domains=("chatgpt.com",),
        destination_ip="203.0.113.20", client_ip="192.168.1.10",
        rule_ids=("chatgpt-chatgpt-com",), expires_at=100.0,
        reason_code="DNS_CLIENT_IP_DOMAIN_MATCH")

    processor._try_dns_identification(flow)
    first_count = len(flow.identification_result.evidence)
    processor._try_dns_identification(flow)

    assert flow.identification_result.method is IdentificationMethod.DNS
    assert flow.identification_result.application == "chatgpt"
    assert len(flow.identification_result.evidence) >= first_count
    assert processor._try_dns_identification(flow) is True
    processor.close()
