# QUIC v1 Initial Parsing and SNI — P0.7.3

## 1. Scope and boundary

P0.7.3 implements QUIC v1 Initial packet parsing, Initial packet protection
removal, AEAD authentication/decryption, Initial-frame parsing, CRYPTO stream
reassembly and visible TLS ClientHello/SNI extraction. It is a standalone
connection-scoped component. It does not yet connect UDP Flow tracking or the
QUIC inspector to `PacketProcessor`, live NIC capture, or PCAP replay; that is
P0.7.4.

Supported version is exactly QUIC v1 (`0x00000001`). The parser inspects the
Initial packet at the start of a datagram and does not iterate subsequent
coalesced packets. QUIC v2, Version Negotiation, Retry processing, 0-RTT/1-RTT decryption, application data,
connection migration/CID management, ECH inner ClientHello recovery and full
QUIC connection state are out of scope.

## 2. Processing path

```text
UDP datagram
  -> QUIC v1 long-header / Initial parser
  -> original-DCID connection context
  -> RFC 9001 Initial secrets (HKDF-SHA256)
  -> AES header-protection removal
  -> packet-number reconstruction
  -> AES-128-GCM authentication and decryption
  -> Initial frame parser (PADDING, PING, ACK, ACK_ECN, CRYPTO,
     CONNECTION_CLOSE, APPLICATION_CLOSE)
  -> per-sender CRYPTO offset reassembly
  -> TLS ClientHello handshake parser
  -> existing TLSClientHelloParser via a synthetic TLS record envelope
  -> visible SNI / ECH metadata
```

QUIC carries TLS handshake messages directly in CRYPTO frames; it does not
carry TLS records inside those frames. The adapter creates a bounded synthetic
TLS handshake record only to reuse the existing ClientHello parser. Raw UDP
payload is never sent to the TCP reassembler.

## 3. Key schedule and packet protection

- Version salt: RFC 9001 QUIC v1 Initial salt.
- `initial_secret = HKDF-Extract(salt, initial_dcid)`.
- Expand `client in` / `server in`, then `quic key` (16 bytes), `quic iv`
  (12 bytes) and `quic hp` (16 bytes), all with TLS 1.3 HKDF-Expand-Label.
- Header protection uses AES-128-ECB over the 16-byte sample at
  `pn_offset + 4`; the first byte and packet-number bytes are unmasked.
- Nonce is the 12-byte IV XOR the reconstructed 64-bit packet number encoded
  as a 12-byte big-endian value.
- AES-128-GCM authenticates the unprotected header as AAD. No plaintext or SNI
  is accepted unless AEAD authentication succeeds.

The original DCID is learned only after a client Initial decrypts successfully.
A server Initial cannot be decrypted statelessly from its packet DCID: the
connection must be created with the original client Initial DCID (or have
already processed the client Initial). The inspector explicitly rejects a
server Initial when that context is absent rather than guessing.

## 4. Frame and CRYPTO stream policy

Frame parser supports the frame types permitted/expected in Initial packets:
PADDING, PING, ACK, ACK_ECN, CRYPTO, CONNECTION_CLOSE and
APPLICATION_CLOSE. Unsupported frame types are rejected with a reason code.
ACK range count is bounded. CRYPTO data is reassembled by offset separately
for client and server sender roles. Identical retransmissions are accepted;
conflicting overlaps, excessive offsets, excessive buffered bytes and more
than 4096 segments are rejected.

## 5. Module layout

- `src/appid/udp/quic/header.py`: QUIC varint and v1 Initial header parser.
- `src/appid/udp/quic/crypto.py`: RFC 9001 HKDF, header protection, nonce,
  packet-number reconstruction and AES-GCM decrypt.
- `src/appid/udp/quic/frame_parser.py`: bounded Initial-frame parser.
- `src/appid/udp/quic/crypto_reassembly.py`: bounded CRYPTO offset stream.
- `src/appid/udp/quic/connection.py`: connection context and SNI result.
- `src/appid/udp/quic/__init__.py`: public exports.

`cryptography>=42,<47` is a runtime dependency. Existing DNS and TCP modules
are not modified by the QUIC inspector.

## 6. API sketch

```python
from appid.udp.quic import QUICInitialConnection

connection = QUICInitialConnection()
result = connection.process_datagram(udp_payload)
if result.status == "DECRYPTED":
    print(result.sender_role, result.sni, result.ech_detected)
```

For a server Initial first observed in a capture, provide
`QUICInitialConnection(original_dcid=client_initial_dcid)`. Results expose
`DECRYPTED` or `REJECTED`, packet number, sender role, CIDs, frame types,
reason code, SNI and ECH indicator. This is evidence extraction, not mapping
to the six dataset application labels; SNI mapping and hybrid evidence fusion
remain later integration work.

## 7. Security and limitations

- AEAD tag validation is mandatory; invalid tags never emit SNI.
- Only QUIC v1 is accepted; unknown versions remain rejected.
- Header, token, length, varint, ACK range, CRYPTO offset, buffer and segment
  limits prevent unbounded parsing/reassembly.
- SNI is the visible outer ClientHello hostname. When ECH is detected, the
  encrypted inner hostname is not recovered; the outer name must not be
  represented as the true inner destination.
- Initial keys are public derivations from the Initial DCID, not user traffic
  secrets; this does not decrypt 0-RTT/1-RTT application data.
- No live UDP/QUIC traffic test is claimed in this milestone.
