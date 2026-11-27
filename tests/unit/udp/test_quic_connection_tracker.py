from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from appid.udp.quic.connection_tracker import QUICConnectionTracker
from appid.udp.quic.crypto import derive_initial_keys, header_protection_mask, packet_nonce

DCID = bytes.fromhex("8394c8f03e515708")
SCID = bytes.fromhex("0102030405060708")


def vi(value):
    if value < 64:
        return bytes([value])
    if value < 16384:
        return (value | 0x4000).to_bytes(2, "big")
    raise ValueError(value)


def initial(plaintext, *, dcid=DCID, scid=SCID, is_client=True, key_dcid=None):
    keys = derive_initial_keys(key_dcid or dcid, is_client=is_client)
    pn = b"\x00"
    first = 0xC0
    prefix = (bytes([first]) + b"\x00\x00\x00\x01" + bytes([len(dcid)]) + dcid
              + bytes([len(scid)]) + scid + b"\x00")
    header = prefix + vi(len(pn) + len(plaintext) + 16)
    ciphertext = AESGCM(keys.key).encrypt(packet_nonce(keys.iv, 0), plaintext, header + pn)
    packet = bytearray(header + pn + ciphertext)
    offset = len(header)
    mask = header_protection_mask(keys.hp, bytes(packet[offset + 4:offset + 20]))
    packet[0] ^= mask[0] & 0x0F
    packet[offset] ^= mask[1]
    return bytes(packet)


def test_authenticated_initial_creates_connection_and_indexes_cids():
    tracker = QUICConnectionTracker()
    packet = initial(b"\x01" + b"\x00" * 60)
    connection, result = tracker.process(packet, flow_id="s:flow-1", timestamp=1.0)
    assert result.status == "DECRYPTED"
    assert connection is not None
    assert connection.flow_ids == {"s:flow-1"}
    assert DCID in connection.cids and SCID in connection.cids


def test_server_initial_on_new_udp_tuple_links_to_existing_connection():
    tracker = QUICConnectionTracker()
    first = initial(b"\x01" + b"\x00" * 60)
    connection, result = tracker.process(first, flow_id="s:flow-1", timestamp=1.0)
    assert result.status == "DECRYPTED"
    # Server Initial uses the client's SCID as packet DCID and original DCID for keys.
    server = initial(b"\x01" + b"\x00" * 60, dcid=SCID,
                     scid=b"serverid", is_client=False, key_dcid=DCID)
    migrated, server_result = tracker.process(server, flow_id="s:flow-2", timestamp=2.0)
    assert server_result.status == "DECRYPTED"
    assert migrated is connection
    assert migrated.flow_ids == {"s:flow-1", "s:flow-2"}


def test_invalid_aead_does_not_create_connection_or_cid_mapping():
    tracker = QUICConnectionTracker()
    packet = bytearray(initial(b"\x01" + b"\x00" * 60))
    packet[-1] ^= 1
    connection, result = tracker.process(bytes(packet), flow_id="s:flow-1", timestamp=1.0)
    assert connection is None
    assert result.status == "REJECTED"
    assert tracker.connections == ()


def test_idle_cleanup_removes_connection_and_cids():
    tracker = QUICConnectionTracker(idle_timeout=5)
    connection, _ = tracker.process(initial(b"\x01" + b"\x00" * 60),
                                    flow_id="s:flow-1", timestamp=1.0)
    assert connection is not None
    tracker._expire(6.0)
    assert tracker.connections == ()
    assert tracker._cid_to_connection == {}


def test_connection_capacity_evicts_oldest_connection_and_cid_aliases():
    tracker = QUICConnectionTracker(max_connections=1)
    first, _ = tracker.process(initial(b"\x01" + b"\x00" * 60),
                               flow_id="s:flow-1", timestamp=1.0)
    dcid2 = bytes.fromhex("aabbccddeeff0011")
    scid2 = bytes.fromhex("1122334455667788")
    second_packet = initial(b"\x01" + b"\x00" * 60, dcid=dcid2, scid=scid2)
    second, result = tracker.process(second_packet, flow_id="s:flow-2", timestamp=2.0)
    assert result.status == "DECRYPTED"
    assert second is not None and second is not first
    assert tracker.capacity_evictions == 1
    assert DCID not in tracker._cid_to_connection
