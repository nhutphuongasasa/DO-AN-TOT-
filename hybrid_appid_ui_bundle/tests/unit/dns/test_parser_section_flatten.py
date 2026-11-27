from appid.dns.parser import DNSParser


class _NoPayload:
    pass


class _FakeDNSRR:
    def __init__(self, name: bytes, rrtype: int, payload=None):
        self.rrname = name
        self.type = rrtype
        self.payload = payload if payload is not None else _NoPayload()


def test_packet_list_item_payload_chain_is_flattened():
    address = _FakeDNSRR(b"edge.example.", 1)
    cname = _FakeDNSRR(b"www.example.", 5, payload=address)
    assert DNSParser._section_packets([cname]) == [cname, address]


def test_payload_chain_is_not_duplicated_when_also_listed():
    address = _FakeDNSRR(b"edge.example.", 1)
    cname = _FakeDNSRR(b"www.example.", 5, payload=address)
    assert DNSParser._section_packets([cname, address]) == [cname, address]


def test_section_packet_flattening_ignores_non_dns_payload():
    class RawPayload:
        pass

    cname = _FakeDNSRR(b"www.example.", 5, payload=RawPayload())
    assert DNSParser._section_packets([cname]) == [cname]
