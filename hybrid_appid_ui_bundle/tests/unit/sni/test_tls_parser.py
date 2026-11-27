from appid.sni import SNIParseStatus, TLSClientHelloParser, normalize_server_name


def _u16(value):
    return value.to_bytes(2, "big")


def _extension(kind, data):
    return _u16(kind) + _u16(len(data)) + data


def _client_hello(extensions=b""):
    body = (b"\x03\x03" + bytes(range(32)) + b"\x00" + _u16(2) + b"\x13\x01"
            + b"\x01\x00")
    if extensions:
        body += _u16(len(extensions)) + extensions
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + _u16(len(handshake)) + handshake


def _sni(host="Example.COM."):
    name = host.encode("ascii")
    entry = b"\x00" + _u16(len(name)) + name
    return _u16(len(entry)) + entry


def test_extracts_and_normalizes_sni():
    result = TLSClientHelloParser().parse(_client_hello(_extension(0, _sni())))
    assert result.status is SNIParseStatus.PARSED
    assert result.server_name == "example.com"
    assert result.legacy_version == 0x0303
    assert result.cipher_suites == (0x1301,)


def test_no_sni_extension():
    result = TLSClientHelloParser().parse(_client_hello(_extension(11, b"\x00\x00")))
    assert result.status is SNIParseStatus.NO_SNI


def test_client_hello_without_extensions():
    assert TLSClientHelloParser().parse(_client_hello()).status is SNIParseStatus.NO_SNI


def test_truncated_record_is_incomplete():
    packet = _client_hello(_extension(0, _sni()))
    result = TLSClientHelloParser().parse(packet[:-3])
    assert result.status is SNIParseStatus.INCOMPLETE


def test_invalid_record_type_is_unsupported():
    assert TLSClientHelloParser().parse(b"\x17\x03\x03\x00\x00").status is SNIParseStatus.UNSUPPORTED


def test_malformed_sni_length_is_invalid():
    malformed_sni = b"\x00\x20\x00\x10example.com"
    result = TLSClientHelloParser().parse(_client_hello(_extension(0, malformed_sni)))
    assert result.status is SNIParseStatus.INVALID_TLS


def test_ech_extension_is_reported():
    result = TLSClientHelloParser().parse(_client_hello(_extension(0xFE0D, b"\x00")))
    assert result.status is SNIParseStatus.ECH_DETECTED


def test_hostname_normalization_and_validation():
    assert normalize_server_name("WWW.Example.COM.") == "www.example.com"
    assert normalize_server_name("bücher.example") == "xn--bcher-kva.example"
    for invalid in ("", "bad host", "-bad.example", "bad..example", "a\x00b"):
        try:
            normalize_server_name(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected invalid hostname: {invalid!r}")


def test_arbitrary_short_inputs_never_raise():
    parser = TLSClientHelloParser()
    for size in range(128):
        result = parser.parse(bytes(range(size)))
        assert isinstance(result.status, SNIParseStatus)


def test_nested_vector_length_overrun_is_invalid_not_incomplete():
    malformed = b"\x00\x10\x00\x0e\x00\x20x"
    result = TLSClientHelloParser().parse(_client_hello(_extension(0, malformed)))
    assert result.status is SNIParseStatus.INVALID_TLS


def test_tls13_client_hello_legacy_version_is_supported():
    # TLS 1.3 ClientHello still carries legacy_version 0x0303.
    result = TLSClientHelloParser().parse(_client_hello(_extension(0, _sni("api.example.net"))))
    assert result.status is SNIParseStatus.PARSED
    assert result.server_name == "api.example.net"
