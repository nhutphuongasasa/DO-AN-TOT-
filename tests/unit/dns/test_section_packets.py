"""Scapy-independent regression tests for DNS section flattening."""
from types import SimpleNamespace

from appid.dns.parser import DNSParser


class NoPayload:
    pass


def test_section_packets_keeps_dns_question_records():
    question = SimpleNamespace(qname=b"www.example.com.", qtype=1, payload=NoPayload())
    assert DNSParser._section_packets([question]) == [question]


def test_section_packets_flattens_answer_payload_chain_inside_list_item():
    address = SimpleNamespace(
        rrname=b"edge.example.com.", type=1, ttl=90,
        rdata="203.0.113.7", payload=NoPayload(),
    )
    cname = SimpleNamespace(
        rrname=b"www.example.com.", type=5, ttl=120,
        rdata=b"edge.example.com.", payload=address,
    )

    records = DNSParser._section_packets([cname])

    assert records == [cname, address]
