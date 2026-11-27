# TCP SNI AppID Integration (P0.6.3–P0.6.5)

## Objective

Complete the TCP rule-first path by connecting the existing Flow Tracker,
TCP Reassembler, TLS ClientHello parser and approved application-domain rules
inside the shared live/PCAP `PacketProcessor`.

## Processing order

`Raw packet → PacketRecord → selected-LAN filter → DNS observation/cache →
Flow Tracker → DNS AppID attempt → client-direction TCP reassembly → TLS
ClientHello/SNI parser → SNI domain rule → Flow identification result`.

DNS observations are processed before Flow classification so a response can
populate the cache. DNS identification is authoritative and causes early exit. TCP SNI is evaluated
only when DNS is unresolved:

- DNS identifies the Flow: return the DNS result and skip TCP/TLS SNI.
- DNS is unresolved and SNI matches: result method is `sni` and processing exits.
- A valid DNS mapping arriving after an earlier SNI result replaces SNI.
- SNI is absent, ECH is detected, or the hostname is not mapped: do not invent
  an application label; the Flow remains unresolved for the next stage.

## Direction and reassembly

Only the `FORWARD` direction from the Flow's LAN-derived client endpoint is
inspected. No port-number heuristic is used. TCP sequence numbers and SYN/FIN/RST
flags are passed to the existing `TCPReassembler`, which handles segmentation,
out-of-order delivery, retransmission suppression, overlap policy and sequence
wraparound. Directional stream state is isolated by Flow ID.

The processor retains no packet payload in `FlowState`. For SNI parsing it keeps
only a temporary contiguous byte buffer per Flow, capped at 64 KiB, and removes
it after a terminal parse, Flow close or idle cleanup. The reassembler retains
its own configured per-stream/global bounds. A complete ClientHello is parsed
once per Flow; later application data is not repeatedly scanned as ClientHello.

## Domain policy

SNI reuses `ApplicationDomainRules` loaded from `config/dns_mapping.yaml`. This
keeps DNS and SNI labels aligned to the five explicit applications:
`chatgpt`, `facebook`, `spotify`, `tiktok`, `youtube`. The `other-web` dataset
label is deliberately not a suffix catch-all. Unmapped hostnames remain
unclassified for later ML/unknown policy.

## Counters

`PipelineStats` reports TCP payload packet count, parsed ClientHello count,
SNI-identified Flow count, unmapped hostname count, parse error count and ECH
count. Live capture and PCAP replay print the SNI counters in their summaries.

## Limitations / non-goals

- TLS is not decrypted; only visible outer SNI is used.
- ECH inner ClientHello is not recovered.
- QUIC/HTTP3 is not handled by this TCP integration. A separate standalone
  QUIC v1 Initial inspector was added in P0.7.3; shared UDP pipeline integration
  remains P0.7.4.
- A capture starting after ClientHello may not be able to identify by SNI.
- SNI rule matching is conservative and only as complete as the reviewed YAML.
- Real NIC capture and Scapy-backed packet tests must be run on the target laptop;
  the isolated build environment may not contain Scapy or root capture privileges.
