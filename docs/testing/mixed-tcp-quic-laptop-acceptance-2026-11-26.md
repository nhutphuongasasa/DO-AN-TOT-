# Mixed TCP + QUIC laptop acceptance — 2026-11-26

## Scope

Validate the shared `PacketProcessor` using a single PCAP created by merging the accepted TCP/TLS SNI capture and the live QUIC v1 capture. This verifies offline integration of the TCP and UDP/QUIC paths; it is not a long-running live-capture or resource benchmark.

## TCP/TLS SNI capture

- Interface: `wlp62s0`
- Captured packets: 2,423; dropped: 0
- PCAP: `p075-tcp-five-apps.pcap` (3,468,144 bytes)
- HTTP probes: ChatGPT, Facebook, TikTok, YouTube and Spotify all returned HTTP 200 with curl exit 0
- Expected SNI observed for all five applications
- Strict PacketProcessor verifier: all five AppIDs PASS
- Replay counters: raw/parsed/tracked 2,423; unsupported 0; parse errors 0; SNI errors 4

## QUIC v1 capture

- HTTP/3-only probes completed for three of five services. ChatGPT and TikTok probes did not complete in that run.
- QUIC Initial inspection and shared PacketProcessor replay nevertheless mapped SNI for all five target applications.
- QUIC-only PacketProcessor counters: 3,476 UDP datagrams; 31 Initial candidates; 28 decrypted; 3 rejected; 10 target SNI flows identified; 1 unmapped hostname; 1 ECH detection.
- Do not interpret SNI recognition as proof that all five HTTP/3 requests completed.

## Mixed PCAP replay

Command:

```bash
.venv/bin/python -m appid.capture.pcap \
  mixed-tcp-quic.pcap \
  --lan-subnet 192.168.128.0/21 \
  --session-id mixed-tcp-quic-acceptance \
  --burst-jsonl mixed-bursts.jsonl \
  --burst-tsv mixed-bursts.tsv
```

Results:

| Counter | Result |
|---|---:|
| Raw packets | 5,899 |
| Parsed packets | 5,899 |
| Tracked packets | 5,899 |
| Outside LAN | 0 |
| Unsupported | 0 |
| Parse errors | 0 |
| TCP ClientHello/SNI parsed | 23 |
| TCP/SNI target flows identified | 5 |
| TCP SNI unmapped | 18 |
| TCP SNI parser errors | 4 |
| UDP datagrams | 3,476 |
| QUIC Initial candidates | 31 |
| QUIC Initial decrypted | 28 |
| QUIC Initial rejected | 3 |
| QUIC SNI target flows identified | 10 |
| QUIC SNI unmapped | 1 |
| QUIC ECH detections | 1 |
| Total Flows | 39 |
| Bursts created | 484 |

Burst exports:

- `mixed-bursts.jsonl`: 484 lines / records
- `mixed-bursts.tsv`: 485 lines (one header + 484 records)
- The first JSONL records contain session/flow lineage, index, direction, start/end timestamps, duration, packet count, byte count and inter-Burst gap.

## Acceptance statement

**PASS for mixed offline TCP + QUIC pipeline integration on the laptop.** All 5,899 packets were parsed and tracked, with zero parse errors; five target TCP/SNI flows and ten target QUIC/SNI flows were identified; 484 Bursts were exported. Unmapped background traffic, four TCP SNI parse errors, three rejected QUIC Initial candidates and one ECH detection remain visible diagnostics and are not hidden by the PASS statement.

## Remaining validation

Run the live capture application itself on the laptop, then measure CPU/RAM and stability. The ML V2 models remain frozen; runtime model inference is deferred.
