# P0.6.2 — TCP Reassembly Design

## Goal

Provide a bounded, transport-only TCP byte-stream reassembler that can feed a
complete TLS ClientHello to the existing P0.6.1 parser. The component is
independent of DNS and does not make application-identification decisions.

## Module contract

- Implementation: `src/appid/sni/tcp_reassembly.py`.
- Input: Flow ID, explicit `Direction`, 32-bit TCP sequence number, payload
  bytes, capture timestamp, and optional SYN/FIN/RST flags.
- Output: `ReassemblyResult`; `data` contains only newly contiguous bytes emitted
  by this call. Buffered out-of-order bytes are not emitted prematurely.
- Stream key: `(flow_id, direction)`. The two directions of a connection have
  separate sequence spaces and buffers.
- Integration contract: the future capture/pipeline adapter passes TCP payload
  and flags to this component, then passes emitted bytes to
  `TLSClientHelloParser`. This release does not wire that adapter into live
  capture and does not alter `PacketProcessor`.

## Sequence and overlap policy

- TCP sequence numbers are unwrapped around the next expected sequence and
  support the 32-bit wrap boundary.
- SYN consumes one sequence number; a SYN establishes the expected first
  payload sequence.
- If capture starts mid-connection and no SYN was observed, the first payload
  seen anchors the stream. Earlier missing bytes cannot be reconstructed; this
  limitation is explicit rather than guessed around.
- Out-of-order segments are buffered until the gap is filled.
- Retransmitted bytes already emitted are ignored.
- For overlapping buffered segments, first-seen bytes win. This deterministic
  policy avoids duplicating bytes or silently replacing previously accepted
  stream content.

## Resource and lifecycle limits

Defaults: 60-second idle timeout, 4,096 directional streams, 256 KiB buffered
per stream, 16 MiB total buffered, 256 KiB maximum sequence gap, and 65,535
bytes per input segment. Limits are configurable at construction. Exceeding a
buffer/gap limit drops that directional stream and releases its pending bytes.
`cleanup(now)` removes idle streams; `close_flow(flow_id)` removes both
directions for a Flow. RST removes the affected direction. When the stream cap
is reached, a new stream is rejected with `STREAM_LIMIT` rather than silently
evicting an active stream. FIN marks the direction closed and releases any
pending gap buffer. No background timer
is created; the caller must invoke cleanup periodically.

## Explicit non-goals / limitations

- No Scapy parsing or live capture integration in P0.6.2.
- No TLS parser invocation in the reassembler itself.
- No IP fragment reassembly, QUIC/UDP reassembly, TLS decryption, ECH recovery,
  or HTTP/3 support.
- No connection-level TCP state machine, congestion/window validation, or
  authoritative endpoint-role inference.
- FIN is surfaced as a directional close signal; this component is not a full
  TCP teardown implementation.
- Midstream capture cannot recover bytes that were transmitted before capture.

## Verification cases

Unit tests cover single/multiple segments, out-of-order arrival, retransmission,
first-seen overlap handling, Flow/direction isolation, sequence wraparound,
timeout/cleanup, buffer bounds, and RST cleanup. The unchanged TLS parser has
its existing unit tests run alongside these cases. Live traffic acceptance is
reserved for the later integration milestone.


## P0.6.3–P0.6.5 integration status update

The original P0.6.2 standalone component is now wired into the shared
`PacketProcessor`. Client-direction reassembled bytes are accumulated with a
64 KiB per-Flow cap and passed to `TLSClientHelloParser`; SNI mapping uses the
same approved domain rules as DNS. Live NIC capture and PCAP replay both use
this processor. See `tcp-sni-appid-integration.md` for the current end-to-end
contract, DNS/SNI precedence and remaining live acceptance requirements.
