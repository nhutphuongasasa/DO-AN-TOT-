# UDP Protocol Identification — P0.7.2

## Scope

P0.7.2 adds conservative per-datagram protocol identification. It identifies
transport/application protocols carried over UDP; it does **not** map a UDP
protocol directly to one of the six dataset application labels.

Supported signatures:

- DNS: minimum DNS header, plausible opcode and non-empty section counts,
  plus source or destination port 53. Full DNS name/RR validation remains the
  responsibility of `DNSParser`.
- DHCPv4: BOOTP request/reply op, DHCP magic cookie, minimum fixed header and
  UDP ports 67/68.
- NTP: minimum 48-byte header, version 1–4, supported mode and port 123.
- STUN: top type bits, magic cookie, aligned and exact message length.
- QUIC v1 Initial candidate: long-header/fixed bits, version exactly `0x00000001`,
  bounded connection-ID lengths and v1 Initial type bits. It remains a candidate
  until P0.7.3 validates packet protection and AEAD authentication.
- Otherwise `UNKNOWN`.

## Safety / false-positive policy

A port number alone never identifies a protocol. Malformed or ambiguous
payloads remain `UNKNOWN`. The QUIC result is named `QUIC_INITIAL_CANDIDATE` and has lower confidence;
it is only a structural hint. P0.7.3 separately parses QUIC v1 Initial and
validates it through header protection removal and AEAD authentication before
exposing TLS ClientHello/SNI. QUIC v2 is not accepted by the P0.7.3 parser.

## Interface

`UDPProtocolIdentifier.identify(payload, src_port=..., dst_port=...)` returns
`UDPProtocolResult(protocol, confidence, reason_code, evidence)`. The
identifier is stateless and bounded by the supplied datagram size. It does not
perform UDP stream reassembly (UDP has no byte stream) and does not mutate the
existing TCP/DNS/SNI pipeline.


## P0.7.3 follow-on

The standalone QUIC v1 Initial inspector is documented in
`docs/architecture/quic-v1-initial-parsing.md`. It is not yet wired into this
stateless UDP classifier or the shared live/PCAP pipeline; P0.7.4 owns that
integration.


## P0.7.4 integration update

This document describes the original standalone P0.7.2 classifier boundary.
P0.7.4 now calls the classifier from `UDPAnalyzer` in the shared
`PacketProcessor`; QUIC Initial candidates proceed to the authenticated QUIC
connection inspector. See `p0.7.4-hybrid-tcp-udp-pipeline.md` for the current
end-to-end contract and live-acceptance limitations.
