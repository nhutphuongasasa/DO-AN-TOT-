import pytest

scapy_dns = pytest.importorskip("scapy.layers.dns")
scapy_inet = pytest.importorskip("scapy.layers.inet")
DNS, DNSQR, DNSRR = scapy_dns.DNS, scapy_dns.DNSQR, scapy_dns.DNSRR
IP, UDP = scapy_inet.IP, scapy_inet.UDP
from appid.dns.parser import DNSParser


def test_query_response_correlation_and_answer_parse():
    parser = DNSParser()
    query = IP(src="192.168.1.10", dst="192.168.1.1")/UDP(sport=53000, dport=53)/DNS(id=42, qr=0, qd=DNSQR(qname="chat.example", qtype="A"))
    query.time = 100
    assert parser.parse(query, session_id="s", packet_index=0, lan_networks=()) is None
    response = IP(src="192.168.1.1", dst="192.168.1.10")/UDP(sport=53, dport=53000)/DNS(
        id=42, qr=1, rcode=0, qd=DNSQR(qname="chat.example", qtype="A"),
        an=DNSRR(rrname="chat.example", type="A", ttl=45, rdata="203.0.113.8"))
    response.time = 101
    observation = parser.parse(response, session_id="s", packet_index=1, lan_networks=())
    assert observation.client_ip == "192.168.1.10"
    assert observation.query_name == "chat.example"
    assert observation.answers[0].value == "203.0.113.8"
    assert observation.answers[0].ttl_seconds == 45


def test_response_without_query_requires_single_lan_destination():
    parser = DNSParser()
    response = IP(src="192.168.1.1", dst="192.168.1.10")/UDP(sport=53, dport=53000)/DNS(
        id=9, qr=1, rcode=0, qd=DNSQR(qname="x.example"),
        an=DNSRR(rrname="x.example", type="A", ttl=10, rdata="203.0.113.9"))
    response.time = 5
    result = parser.parse(response, session_id="s", packet_index=1, lan_networks=("192.168.1.0/24",))
    assert result.client_ip == "192.168.1.10"


def test_error_response_is_not_positive_observation():
    parser = DNSParser()
    response = IP(src="192.168.1.1", dst="192.168.1.10")/UDP(sport=53, dport=53000)/DNS(
        id=9, qr=1, rcode=3, qd=DNSQR(qname="missing.example"))
    response.time = 5
    assert parser.parse(response, session_id="s", packet_index=1, lan_networks=("192.168.1.0/24",)) is None


def test_response_without_query_accepts_string_lan_network():
    parser = DNSParser()
    response = IP(src="192.168.1.1", dst="192.168.1.10")/UDP(sport=53, dport=53000)/DNS(
        id=10, qr=1, rcode=0, qd=DNSQR(qname="x.example"),
        an=DNSRR(rrname="x.example", type="A", ttl=10, rdata="203.0.113.10"))
    response.time = 6
    result = parser.parse(response, session_id="s", packet_index=2, lan_networks=("192.168.1.0/24",))
    assert result is not None
    assert result.client_ip == "192.168.1.10"


def test_fallback_client_accepts_lan_router_dns_resolver():
    # Home routers commonly act as DNS resolvers and are themselves in the LAN.
    assert DNSParser._fallback_client(
        "192.168.1.10", "192.168.1.1", 53, ("192.168.1.0/24",)
    ) == "192.168.1.10"


def test_fallback_client_rejects_non_dns_source_port():
    assert DNSParser._fallback_client(
        "192.168.1.10", "192.168.1.1", 8443, ("192.168.1.0/24",)
    ) is None


def test_deserialized_response_parses_packetlist_cname_and_address_answers():
    """Regression: Scapy 2.8 dissects DNS answer sections as PacketListField lists."""
    parser = DNSParser()
    response = IP(src="192.168.1.1", dst="192.168.1.10")/UDP(sport=53, dport=53000)/DNS(
        id=77, qr=1, rcode=0, qd=DNSQR(qname="www.tiktok.com", qtype="A"),
        # Scapy 2.8 uses PacketListField for DNS answer sections.
        # Separate records must be supplied as a list, not a DNSRR payload chain.
        an=[
            DNSRR(rrname="www.tiktok.com", type="CNAME", ttl=120,
                  rdata="www.tiktok.com.edgesuite.net."),
            DNSRR(rrname="www.tiktok.com.edgesuite.net", type="A", ttl=90,
                  rdata="203.0.113.77"),
        ],
    )
    response.time = 10
    # Round-trip through bytes to exercise Scapy's real packet dissection path.
    wire_packet = IP(bytes(response))
    result = parser.parse(wire_packet, session_id="s", packet_index=77,
                          lan_networks=("192.168.1.0/24",))
    assert result is not None
    assert result.query_name == "www.tiktok.com"
    assert [(a.record_type, a.owner_name, a.value) for a in result.answers] == [
        ("CNAME", "www.tiktok.com", "www.tiktok.com.edgesuite.net"),
        ("A", "www.tiktok.com.edgesuite.net", "203.0.113.77"),
    ]


def test_empty_dns_question_section_is_ignored_without_exception():
    parser = DNSParser()
    response = IP(src="192.168.1.1", dst="192.168.1.10")/UDP(sport=53, dport=53000)/DNS(
        id=78, qr=1, rcode=0, qd=None,
        an=DNSRR(rrname="x.example", type="A", ttl=10, rdata="203.0.113.78"),
    )
    response.time = 11
    assert parser.parse(response, session_id="s", packet_index=78,
                         lan_networks=("192.168.1.0/24",)) is None

