
import appid.pipeline.processor as processor_module
from appid.dns.models import DNSAnswerRecord, DNSObservation
from appid.domain.models import PacketRecord, TransportProtocol
from appid.pipeline.processor import PacketProcessor


class Raw:
    def __init__(self, kind):
        self.kind = kind


class FakeDNSParser:
    def parse(self, raw_packet, **kwargs):
        if raw_packet.kind != "dns_response":
            return None
        return DNSObservation(
            session_id=kwargs["session_id"], packet_index=kwargs["packet_index"],
            observed_at=100.0, client_ip="192.168.1.10", resolver_ip="192.168.1.1",
            transaction_id=10, query_name="chat.example", query_type="A", response_code=0,
            answers=(DNSAnswerRecord("chat.example", "A", "203.0.113.8", 300),),
        )


def record(raw, *, session_id, packet_index):
    if raw.kind == "dns_response":
        return PacketRecord(session_id, packet_index, 100.0, "192.168.1.1", "192.168.1.10",
                            53, 53000, TransportProtocol.UDP, 100)
    return PacketRecord(session_id, packet_index, 101.0 + packet_index, "192.168.1.10",
                        "203.0.113.8", 51000, 443, TransportProtocol.TCP, 120)


def test_dns_cache_updates_and_identification_is_bound_to_flow(tmp_path, monkeypatch):
    monkeypatch.setattr(processor_module, "parse_packet", record)
    monkeypatch.setattr(processor_module, "DNSParser", FakeDNSParser)
    rules = tmp_path / "dns_mapping.yaml"
    rules.write_text(
        "version: 1\napplications:\n  - application_id: chatapp\n    domains:\n"
        "      - rule_id: chat-primary\n        domain: chat.example\n        match: exact\n",
        encoding="utf-8",
    )
    processor = PacketProcessor(session_id="s1", lan_network="192.168.1.0/24", dns_rules_path=rules)
    processor.process(Raw("dns_response"))
    flow = processor.process(Raw("app_packet"))
    assert flow.identification_result is not None
    assert flow.identification_result.application == "chatapp"
    assert flow.identification_result.method.value == "dns"
    assert processor.stats.dns_bindings_created == 1
    assert processor.stats.dns_identified_flows == 1
    bound_result = flow.identification_result
    processor.process(Raw("app_packet"))
    assert flow.identification_result is bound_result
    assert processor.stats.dns_identified_flows == 1


def test_dns_parser_failure_does_not_drop_valid_flow(monkeypatch):
    monkeypatch.setattr(processor_module, "parse_packet", record)

    class BrokenDNSParser:
        def parse(self, *args, **kwargs):
            raise RuntimeError("malformed DNS fixture")
        def close(self):
            pass

    monkeypatch.setattr(processor_module, "DNSParser", BrokenDNSParser)
    processor = PacketProcessor(session_id="s1", lan_network="192.168.1.0/24")
    flow = processor.process(Raw("app_packet"))
    assert flow is not None
    assert processor.stats.tracked_packets == 1
    assert processor.stats.dns_processing_errors == 1
