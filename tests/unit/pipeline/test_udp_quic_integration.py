from appid.appid.evidence_engine import EvidenceEngine
from appid.domain.models import (
    Evidence,
    IdentificationMethod,
    IdentificationResult,
    IdentificationStatus,
    TransportProtocol,
)
from appid.flow.identity import Endpoint, FlowKey
from appid.flow.tracker import FlowState


def flow():
    key = FlowKey("s", TransportProtocol.UDP, Endpoint("192.168.1.10", 50000),
                  Endpoint("203.0.113.8", 443))
    return FlowState("s", "s:flow-1", key, key.endpoint_a, key.endpoint_b, 1.0, 1.0)


def test_quic_sni_classifies_udp_flow_with_explicit_transport_evidence():
    target = flow()
    result = EvidenceEngine().apply_sni(flow=target, hostname="www.youtube.com",
        application="youtube", source="quic_tls_sni", rule_ids=("youtube-host",))
    assert result.application == "youtube"
    assert result.method is IdentificationMethod.SNI
    assert result.reason_code == "SNI_HOSTNAME_RULE_MATCH"
    assert result.metadata["sni_source"] == "quic_tls_sni"
    assert any(item.source == "quic_tls_sni" for item in result.evidence)


def test_dns_identification_is_authoritative_over_quic_sni():
    target = flow()
    target.identification_result = IdentificationResult("s", "s:flow-1",
        IdentificationStatus.CLASSIFIED, "youtube", IdentificationMethod.DNS,
        "DNS_CLIENT_IP_DOMAIN_MATCH", (Evidence("dns_domain", "www.youtube.com"),))
    result = EvidenceEngine().apply_sni(flow=target, hostname="www.youtube.com",
        application="youtube", source="quic_tls_sni")
    assert result is target.identification_result
    assert result.method is IdentificationMethod.DNS
    assert result.application == "youtube"
    assert result.reason_code == "DNS_CLIENT_IP_DOMAIN_MATCH"
    assert len(result.evidence) == 1

    target.identification_result = IdentificationResult("s", "s:flow-1",
        IdentificationStatus.CLASSIFIED, "facebook", IdentificationMethod.DNS,
        "DNS_CLIENT_IP_DOMAIN_MATCH", (Evidence("dns_domain", "www.facebook.com"),))
    conflict = EvidenceEngine().apply_sni(flow=target, hostname="www.youtube.com",
        application="youtube", source="quic_tls_sni")
    assert conflict.application == "facebook"
    assert conflict.method is IdentificationMethod.DNS
    assert conflict.reason_code == "DNS_CLIENT_IP_DOMAIN_MATCH"
    assert len(conflict.evidence) == 1


def test_packet_processor_invokes_quic_analyzer_for_udp_and_classifies_sni(monkeypatch):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from appid.domain.models import PacketRecord, TransportProtocol
    from appid.pipeline import processor as processor_module
    from appid.pipeline.processor import PacketProcessor
    from appid.udp.quic.crypto import derive_initial_keys, header_protection_mask, packet_nonce

    def vi(value):
        return bytes([value]) if value < 64 else (value | 0x4000).to_bytes(2, "big")

    hostname = b"www.youtube.com"
    sni_name = b"\x00" + len(hostname).to_bytes(2, "big") + hostname
    sni_list = len(sni_name).to_bytes(2, "big") + sni_name
    extension = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
    body = (b"\x03\x03" + b"R" * 32 + b"\x00" + b"\x00\x02\x13\x01" +
            b"\x01\x00" + len(extension).to_bytes(2, "big") + extension)
    hello = b"\x01" + len(body).to_bytes(3, "big") + body
    crypto_frame = b"\x06" + vi(0) + vi(len(hello)) + hello
    plaintext = crypto_frame + b"\x00" * 40
    dcid = bytes.fromhex("8394c8f03e515708")
    scid = bytes.fromhex("0102030405060708")
    keys = derive_initial_keys(dcid, is_client=True)
    pn = b"\x00"
    prefix = b"\xc0\x00\x00\x00\x01" + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + b"\x00"
    header = prefix + vi(len(pn) + len(plaintext) + 16)
    encrypted = AESGCM(keys.key).encrypt(packet_nonce(keys.iv, 0), plaintext, header + pn)
    packet = bytearray(header + pn + encrypted)
    offset = len(header)
    mask = header_protection_mask(keys.hp, bytes(packet[offset + 4:offset + 20]))
    packet[0] ^= mask[0] & 0x0F
    packet[offset] ^= mask[1]

    class UDP:
        sport, dport = 53000, 443
        payload = bytes(packet)

    class Raw:
        time = 10.0
        def getlayer(self, name):
            return UDP() if name == "UDP" else None
        def haslayer(self, name):
            return False

    raw = Raw()
    def parsed(_raw, *, session_id, packet_index):
        return PacketRecord(session_id, packet_index, 10.0, "192.168.1.10", "203.0.113.9",
            53000, 443, TransportProtocol.UDP, 100)
    monkeypatch.setattr(processor_module, "parse_packet", parsed)
    processor = PacketProcessor(session_id="udp-quic", lan_network="192.168.1.0/24")
    flow_state = processor.process(raw)
    assert flow_state is not None
    assert flow_state.identification_result is not None
    assert flow_state.identification_result.application == "youtube"
    assert flow_state.identification_result.metadata["application_protocol"] == "QUIC_INITIAL"
    assert processor.stats.quic_initial_candidates == 1
    assert processor.stats.quic_initial_decrypted == 1
    assert processor.stats.quic_sni_identified_flows == 1
    processor.close()


def test_repeated_quic_sni_does_not_duplicate_evidence():
    target = flow()
    engine = EvidenceEngine()
    first = engine.apply_sni(flow=target, hostname="www.youtube.com",
        application="youtube", source="quic_tls_sni")
    repeated = engine.apply_sni(flow=target, hostname="www.youtube.com",
        application="youtube", source="quic_tls_sni")
    assert repeated is first
    assert repeated.reason_code == "SNI_HOSTNAME_RULE_MATCH"
    assert len(repeated.evidence) == 1
