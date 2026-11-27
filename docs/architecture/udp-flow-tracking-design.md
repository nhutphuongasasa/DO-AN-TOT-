# UDP Flow Tracking Design — P0.7.1

## Scope

P0.7.1 adds a UDP-specific, bounded pseudo-flow tracker. It is separate from
P0.6.2 TCP stream reassembly. UDP datagrams are counted, not concatenated into
a byte stream. This component does not parse QUIC, decrypt payloads, classify
applications, or change the existing generic `FlowTracker` pipeline.

## Identity and direction

- Identity is the existing session-scoped canonical bidirectional 5-tuple:
  session ID, UDP protocol, endpoint IP and port pairs.
- Forward/backward direction is assigned only when exactly one endpoint is
  inside a configured LAN subnet. Ambiguous and non-LAN pairs are UNKNOWN.
- No source-port heuristic or first-packet client inference is used.
- A UDP pseudo-flow is observational state, not a transport connection.

## State and limits

`UDPFlowState` retains first/last timestamp, lifecycle status, datagram counts
and packet-length byte totals for forward/backward/unknown directions.
`UDPFlowTracker` enforces configurable idle timeout and maximum active flow
count. `cleanup(now)` expires idle flows; `close_flow` and `close_session`
provide explicit lifecycle controls. Expired/closed entries remain in the
session history exposed by `flows`; the active map is bounded by `max_flows`.

## API

- `UDPFlowTracker(lan_subnets=..., idle_timeout=60.0, max_flows=10000)`
- `add_packet(PacketRecord) -> UDPFlowState` (UDP records only)
- `cleanup(now) -> tuple[UDPFlowState, ...]`
- `close_flow(flow_id)`
- `close_session(session_id)`
- Read-only snapshots: `active_flows`, `flows`

## Non-goals / next milestones

- UDP application/protocol classification is not part of P0.7.1.
- DNS remains handled by the existing DNS parser/cache path.
- QUIC Initial parsing and QUIC TLS ClientHello/SNI extraction require a
  separate P0.7.3 design; UDP payload must not be passed directly to the TLS
  TCP-stream parser.
- Live capture integration and unified TCP/UDP reporting are not added here.

## Acceptance tests

Tests cover bidirectional tuple reuse, session isolation, datagram/byte
accounting, ambiguous direction, idle expiration, bounded active-flow count,
explicit closure, and rejection of non-UDP packets.

## P0.7.3 relationship

P0.7.3 adds a separate QUIC v1 Initial inspector with its own connection-scoped
Original DCID, packet-number and CRYPTO stream state. It does not yet consume
`UDPFlowTracker` records or update its state from Flow lifecycle events. Mapping
UDP 5-tuples/CIDs to QUIC connection contexts and connecting the inspector to
live/PCAP capture are P0.7.4 responsibilities.
