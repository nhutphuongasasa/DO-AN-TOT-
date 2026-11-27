from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from appid.udp.quic import (
    CryptoStreamReassembler,
    QUICInitialConnection,
    QUICParseError,
    derive_initial_keys,
    parse_frames,
    parse_initial_header,
)
from appid.udp.quic.crypto import header_protection_mask, packet_nonce
from appid.udp.quic.header import read_varint

DCID = bytes.fromhex("8394c8f03e515708")
SCID = bytes.fromhex("0102030405060708")


def vi(value: int) -> bytes:
    if value < 64: return bytes([value])
    if value < 16384: return (value | 0x4000).to_bytes(2, "big")
    if value < 1 << 30: return (value | 0x80000000).to_bytes(4, "big")
    return (value | 0xC000000000000000).to_bytes(8, "big")


def client_hello(host: bytes = b"chatgpt.com") -> bytes:
    sni_name = b"\x00" + len(host).to_bytes(2, "big") + host
    sni = len(sni_name).to_bytes(2, "big") + sni_name
    ext = b"\x00\x00" + len(sni).to_bytes(2, "big") + sni
    body = (b"\x03\x03" + b"R" * 32 + b"\x00" + b"\x00\x02\x13\x01" +
            b"\x01\x00" + len(ext).to_bytes(2, "big") + ext)
    return b"\x01" + len(body).to_bytes(3, "big") + body


def make_initial(plaintext: bytes, *, dcid: bytes = DCID, scid: bytes = SCID,
                 packet_number: int = 0, is_client: bool = True, key_dcid: bytes | None = None) -> bytes:
    keys = derive_initial_keys(key_dcid if key_dcid is not None else dcid, is_client=is_client)
    pn = packet_number.to_bytes(1, "big")
    first = 0xC0  # long + fixed + Initial + one-byte PN
    prefix = (bytes([first]) + b"\x00\x00\x00\x01" + bytes([len(dcid)]) + dcid +
              bytes([len(scid)]) + scid + b"\x00")
    # Length includes packet number and AEAD ciphertext/tag.
    length = len(pn) + len(plaintext) + 16
    header = prefix + vi(length)
    aad = header + pn
    ciphertext = AESGCM(keys.key).encrypt(packet_nonce(keys.iv, packet_number), plaintext, aad)
    packet = bytearray(header + pn + ciphertext)
    pn_offset = len(header)
    mask = header_protection_mask(keys.hp, bytes(packet[pn_offset+4:pn_offset+20]))
    packet[0] ^= mask[0] & 0x0F
    packet[pn_offset] ^= mask[1]
    return bytes(packet)


def test_rfc9001_v1_client_initial_key_schedule_vector():
    keys = derive_initial_keys(DCID, is_client=True)
    assert keys.key.hex() == "1f369613dd76d5467730efcbe3b1a22d"
    assert keys.iv.hex() == "fa044b2f42a3fd3b46fb255c"
    assert keys.hp.hex() == "9f50449e04a0e810283a1e9933adedd2"


def test_header_parser_and_varint_boundaries():
    packet = make_initial(b"\x01" + b"\x00" * 40)
    header = parse_initial_header(packet)
    assert header.version == 1 and header.dcid == DCID and header.scid == SCID
    assert read_varint(b"\x40\x25", 0) == (37, 2)
    with pytest.raises(QUICParseError): parse_initial_header(b"\xc0\x00")


def test_decrypt_initial_and_extract_clienthello_sni():
    crypto = b"\x06" + vi(0) + vi(len(client_hello())) + client_hello()
    plaintext = crypto + b"\x00" * 40
    result = QUICInitialConnection().process_datagram(make_initial(plaintext))
    assert result.status == "DECRYPTED"
    assert result.sender_role == "client"
    assert result.sni == "chatgpt.com"
    assert result.reason_code == "SNI_EXTRACTED"


def test_server_initial_requires_original_dcid_context():
    crypto = b"\x06" + vi(0) + vi(len(client_hello(b"youtube.com"))) + client_hello(b"youtube.com")
    packet = make_initial(crypto + b"\x00" * 40, dcid=SCID, is_client=False, key_dcid=DCID)
    result = QUICInitialConnection(original_dcid=DCID).process_datagram(packet)
    assert result.status == "DECRYPTED" and result.sender_role == "server"


def test_authentication_failure_never_emits_sni():
    packet = bytearray(make_initial(b"\x01" + b"\x00" * 60))
    packet[-1] ^= 0x80
    result = QUICInitialConnection().process_datagram(bytes(packet))
    assert result.status == "REJECTED"
    assert result.sni is None
    assert result.reason_code == "INITIAL_AEAD_AUTHENTICATION_FAILED"


def test_frame_parser_crypto_and_ping():
    data = b"\x01\x06\x00\x03abc"
    frames = parse_frames(data)
    assert frames.frame_types == (1, 6)
    assert frames.crypto_frames[0].data == b"abc"


def test_crypto_reassembly_out_of_order_and_conflict():
    stream = CryptoStreamReassembler()
    assert stream.add(3, b"def") == b""
    assert stream.add(0, b"abc") == b"abcdef"
    with pytest.raises(ValueError): stream.add(1, b"ZZ")


def test_unknown_initial_frame_is_rejected():
    with pytest.raises(QUICParseError): parse_frames(b"\x1f")


def test_server_initial_without_original_dcid_is_not_mislearned():
    packet = make_initial(b"\x01" + b"\x00" * 60, dcid=SCID, is_client=False, key_dcid=DCID)
    conn = QUICInitialConnection()
    result = conn.process_datagram(packet)
    assert result.status == "REJECTED"
    assert result.reason_code == "INITIAL_AEAD_AUTHENTICATION_FAILED"
    assert conn.original_dcid is None


def test_connection_close_frame_is_parsed():
    # CONNECTION_CLOSE transport: error code 0, frame type 6, empty reason.
    frames = parse_frames(b"\x1c\x00\x06\x00")
    assert frames.frame_types == (0x1c,)


def test_clienthello_split_across_quic_initial_crypto_frames():
    hello = client_hello(b"spotify.com")
    connection = QUICInitialConnection()
    first_crypto = b"\x06" + vi(24) + vi(len(hello) - 24) + hello[24:]
    second_crypto = b"\x06" + vi(0) + vi(24) + hello[:24]
    first = make_initial(first_crypto + b"\x00" * 40, packet_number=0)
    second = make_initial(second_crypto + b"\x00" * 40, packet_number=1)
    assert connection.process_datagram(first).sni is None
    result = connection.process_datagram(second)
    assert result.status == "DECRYPTED"
    assert result.sni == "spotify.com"



def test_crypto_reassembly_same_offset_extension_preserves_existing_bytes():
    stream = CryptoStreamReassembler()
    assert stream.add(0, b"abcdef") == b"abcdef"
    assert stream.add(0, b"abc") == b"abcdef"
    assert stream.add(0, b"abcdefgh") == b"abcdefgh"
