from appid.udp.protocol_identifier import UDPProtocol, UDPProtocolIdentifier


def test_dns_requires_header_structure_and_dns_port():
    ident = UDPProtocolIdentifier()
    dns = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x07example\x03com\x00\x00\x01\x00\x01"
    result = ident.identify(dns, src_port=53000, dst_port=53)
    assert result.protocol is UDPProtocol.DNS
    assert result.reason_code == "DNS_HEADER_AND_PORT"
    assert ident.identify(dns, src_port=53000, dst_port=53001).protocol is UDPProtocol.UNKNOWN


def test_dhcp_requires_cookie_and_valid_bootp_op():
    ident = UDPProtocolIdentifier()
    payload = bytearray(240)
    payload[0] = 1
    payload[236:240] = b"\x63\x82\x53\x63"
    assert ident.identify(payload, src_port=68, dst_port=67).protocol is UDPProtocol.DHCP
    payload[0] = 9
    assert ident.identify(payload, src_port=68, dst_port=67).protocol is UDPProtocol.UNKNOWN


def test_ntp_requires_header_version_mode_and_minimum_length():
    ident = UDPProtocolIdentifier()
    payload = bytes([(4 << 3) | 3]) + bytes(47)
    assert ident.identify(payload, src_port=50000, dst_port=123).protocol is UDPProtocol.NTP
    assert ident.identify(payload[:20], src_port=50000, dst_port=123).protocol is UDPProtocol.UNKNOWN
    assert ident.identify(payload, src_port=50000, dst_port=50001).protocol is UDPProtocol.UNKNOWN


def test_stun_requires_cookie_and_exact_aligned_length():
    ident = UDPProtocolIdentifier()
    payload = b"\x00\x01\x00\x00\x21\x12\xa4\x42" + bytes(12)
    assert ident.identify(payload, src_port=50000, dst_port=3478).protocol is UDPProtocol.STUN
    malformed = payload[:2] + b"\x00\x04" + payload[4:]
    assert ident.identify(malformed, src_port=50000, dst_port=3478).protocol is UDPProtocol.UNKNOWN


def test_quic_is_only_marked_as_candidate_after_long_header_checks():
    ident = UDPProtocolIdentifier()
    # Header form + fixed bit, v1 version, 1-byte DCID, 1-byte SCID.
    payload = bytes.fromhex("c00000000101aa01bb") + bytes(8)
    result = ident.identify(payload, src_port=50000, dst_port=443)
    assert result.protocol is UDPProtocol.QUIC_INITIAL_CANDIDATE
    assert result.confidence < 1.0
    assert ident.identify(bytes.fromhex("c00000000001aa01bb") + bytes(8),
                          src_port=50000, dst_port=443).protocol is UDPProtocol.UNKNOWN


def test_unknown_does_not_fall_back_to_port_only():
    ident = UDPProtocolIdentifier()
    for port in (53, 67, 68, 123, 3478, 443):
        assert ident.identify(b"arbitrary", src_port=50000, dst_port=port).protocol is UDPProtocol.UNKNOWN
    assert ident.identify(b"", src_port=1, dst_port=2).reason_code == "EMPTY_PAYLOAD"


def test_quic_v2_initial_is_not_mislabeled_as_v1_candidate():
    ident = UDPProtocolIdentifier()
    # QUIC v2 uses a different Initial type-bit mapping and is outside P0.7.3.
    payload = bytes.fromhex("d06b3343cf01aa01bb") + bytes(8)
    assert ident.identify(payload, src_port=50000, dst_port=443).protocol is UDPProtocol.UNKNOWN


def test_quic_disabled_keeps_protocol_candidate_without_decryption():
    from appid.udp.analyzer import UDPAnalyzer
    from appid.udp.protocol_identifier import UDPProtocol

    class NeverCalled:
        def identify(self, _hostname):
            raise AssertionError("domain mapping should not run when QUIC is disabled")

    analyzer = UDPAnalyzer(domain_identifier=NeverCalled(), enable_quic=False)
    # Structurally valid v1 Initial header envelope; encrypted body is not inspected.
    dcid, scid = b"12345678", b"abcdefgh"
    payload = (b"\xc0\x00\x00\x00\x01" + bytes([len(dcid)]) + dcid +
               bytes([len(scid)]) + scid + b"\x00\x40\x20" + b"\x00" * 32)
    result = analyzer.analyze(payload, src_port=50000, dst_port=443,
                              flow_id="s:flow-1", timestamp=1.0)
    assert result.protocol is UDPProtocol.QUIC_INITIAL_CANDIDATE
    assert result.reason_code == "QUIC_ANALYSIS_DISABLED"
    assert result.decrypt_status is None
