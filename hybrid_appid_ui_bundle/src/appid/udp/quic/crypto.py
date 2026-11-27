"""RFC 9001 QUIC v1 Initial key schedule and packet protection."""
from __future__ import annotations

import hmac
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

@dataclass(frozen=True, slots=True)
class InitialKeys:
    key: bytes
    iv: bytes
    hp: bytes


def hkdf_expand_label(secret: bytes, label: str, length: int) -> bytes:
    full_label = b"tls13 " + label.encode("ascii")
    info = length.to_bytes(2, "big") + bytes([len(full_label)]) + full_label + b"\x00"
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(secret)


def derive_initial_keys(dcid: bytes, *, is_client: bool) -> InitialKeys:
    # HKDF-Extract(salt, DCID) is HMAC-SHA256(salt, DCID).
    initial = hmac.new(INITIAL_SALT_V1, bytes(dcid), "sha256").digest()
    side = hkdf_expand_label(initial, "client in" if is_client else "server in", 32)
    return InitialKeys(hkdf_expand_label(side, "quic key", 16),
                       hkdf_expand_label(side, "quic iv", 12),
                       hkdf_expand_label(side, "quic hp", 16))


def header_protection_mask(hp_key: bytes, sample: bytes) -> bytes:
    if len(sample) != 16: raise ValueError("QUIC header-protection sample must be 16 bytes")
    encryptor = Cipher(algorithms.AES(hp_key), modes.ECB()).encryptor()
    return encryptor.update(sample) + encryptor.finalize()


def packet_nonce(iv: bytes, packet_number: int) -> bytes:
    if len(iv) != 12 or packet_number < 0: raise ValueError("invalid QUIC nonce inputs")
    encoded = packet_number.to_bytes(12, "big")
    return bytes(a ^ b for a, b in zip(iv, encoded))


def reconstruct_packet_number(truncated: int, pn_nbits: int, largest_received: int | None) -> int:
    expected = 0 if largest_received is None else largest_received + 1
    window = 1 << pn_nbits; half = window // 2; mask = window - 1
    candidate = (expected & ~mask) | truncated
    if candidate + half <= expected and candidate < (1 << 62) - window: candidate += window
    elif candidate > expected + half and candidate >= window: candidate -= window
    return candidate


def decrypt_initial(datagram: bytes, header, *, original_dcid: bytes | None = None,
                    largest_received: int | dict[str, int | None] | None = None) -> tuple[bytes, int, str]:
    """Try both endpoint secrets. Returns (plaintext, packet_number, sender_role)."""
    from appid.udp.quic.header import QUICParseError
    raw = bytes(datagram[:header.packet_end])
    pn_offset = header.packet_number_offset
    if pn_offset + 4 + 16 > len(raw): raise QUICParseError("NO_HEADER_PROTECTION_SAMPLE")
    sample = raw[pn_offset+4:pn_offset+20]
    dcid_for_keys = original_dcid if original_dcid is not None else header.dcid
    for is_client in (True, False):
        role = "client" if is_client else "server"
        largest = largest_received.get(role) if isinstance(largest_received, dict) else largest_received
        keys = derive_initial_keys(dcid_for_keys, is_client=is_client)
        mask = header_protection_mask(keys.hp, sample)
        first = raw[0] ^ (mask[0] & 0x0f)
        if first & 0x0c:  # QUIC v1 reserved bits must be zero after unprotection.
            continue
        pn_len = (first & 0x03) + 1
        if pn_offset + pn_len > len(raw): continue
        pn_bytes = bytes(raw[pn_offset+i] ^ mask[i+1] for i in range(pn_len))
        truncated = int.from_bytes(pn_bytes, "big")
        pn = reconstruct_packet_number(truncated, pn_len*8, largest)
        aad = bytearray(raw[:pn_offset+pn_len]); aad[0] = first; aad[pn_offset:pn_offset+pn_len] = pn_bytes
        ciphertext = raw[pn_offset+pn_len:header.packet_end]
        try:
            plaintext = AESGCM(keys.key).decrypt(packet_nonce(keys.iv, pn), ciphertext, bytes(aad))
            return plaintext, pn, ("client" if is_client else "server")
        except InvalidTag:
            continue
    raise QUICParseError("INITIAL_AEAD_AUTHENTICATION_FAILED")
