# QUIC / HTTP/3 live traffic test — five target applications

## Purpose and scope

This test generates real HTTPS requests using aioquic while forcing HTTP/3 only.
The client advertises the HTTP/3 ALPN and QUIC v1 only; it has no curl dependency
and cannot silently fall back to HTTP/2 or HTTP/1.1 over TCP. It targets the five
Hybrid AppID labels and records the hostname expected in TLS SNI:

| AppID label | Probe hostname | Expected SNI |
|---|---|---|
| `chatgpt` | `https://chatgpt.com/` | `chatgpt.com` |
| `facebook` | `https://www.facebook.com/` | `www.facebook.com` |
| `tiktok` | `https://www.tiktok.com/` | `www.tiktok.com` |
| `youtube` | `https://www.youtube.com/` | `www.youtube.com` |
| `spotify` | `https://open.spotify.com/` | `open.spotify.com` |

The probe sends a small GET request to each service root. It does not log in,
play media, or access account data. A 3xx/4xx/5xx HTTP response can still mean
that HTTP/3 was negotiated; the important transport check is successful completion of the HTTP/3 response
stream over QUIC. Redirects are not followed, to avoid silently generating
traffic to unrelated hostnames.

## Requirements

- Linux with project dependencies installed using `./setup_linux.sh`; this
  installs `aioquic` in `.venv` and Scapy for PCAP inspection. No special curl
  build is required.
- Permission to capture on the selected interface (`sudo tcpdump` or equivalent).
- A network path that permits outbound UDP/443 and the target service's HTTP/3.
  A corporate proxy, VPN, firewall, captive portal, or service-side policy may
  prevent HTTP/3.

## 1. Start capture first

Find the interface used for the default route:

```bash
ip route get 1.1.1.1
```

Then capture UDP/443 on that interface. Replace `wlp62s0` if needed:

```bash
sudo tcpdump -ni wlp62s0 -s 0 -w quic-five-apps.pcap 'udp port 443'
```

Leave this running. Do not use a DNS-only capture filter. QUIC Initial packets
are UDP, usually on port 443.

## 2. Generate HTTP/3 traffic in a second terminal

From the project root:

```bash
./generate_quic_test_traffic.sh
```

Examples:

```bash
# Three requests per service, useful for observing Initial retransmission/retry behavior
./generate_quic_test_traffic.sh --rounds 3 --pause 1

# Test one service only
./generate_quic_test_traffic.sh --apps youtube

# Longer timeout and custom report location
./generate_quic_test_traffic.sh --timeout 35 --json-out results/quic-run.json
```

The generator uses aioquic directly and opens direct UDP connections; it does
not use HTTP proxy environment variables. It advertises only HTTP/3 ALPN and
QUIC v1, validates the server certificate, and has no TCP/HTTP2 fallback. A
request is marked PASS only after an HTTP/3 response stream completes. A server
may reject this lightweight client, or the network may block UDP/443; such a
request is reported as NO HTTP/3 rather than counted as a success.

Stop tcpdump with Ctrl+C after the generator finishes.

## 3. Inspect SNI with the P0.7.3 QUIC Initial inspector

Run from the project root:

```bash
.venv/bin/python scripts/inspect_quic_initial_pcap.py quic-five-apps.pcap
```

The script reads UDP datagrams, groups the two directions by endpoint pair,
uses the P0.7.3 QUIC v1 Initial decryption and CRYPTO reassembly code, extracts
visible TLS ClientHello SNI, then applies the existing conservative rules in
`config/dns_mapping.yaml`. It prints lines similar to:

```text
[SNI] chatgpt.com -> chatgpt (SNI_HOSTNAME_RULE_MATCH)
[SNI] www.facebook.com -> facebook (SNI_HOSTNAME_RULE_MATCH)
```

It writes `quic-pcap-inspection.json`. A hostname with no explicit mapping is
reported `UNMAPPED`; it is not forced into `other-web`.

Optional Wireshark/tshark cross-check (if the installed version decodes QUIC
Initial):

```bash
tshark -r quic-five-apps.pcap -Y 'tls.handshake.extensions_server_name' \
  -T fields -e ip.src -e ipv6.src -e tls.handshake.extensions_server_name
```

Compare hostname values, not packet counts: retransmissions and multiple
Initial packets can repeat observations. Some tshark versions expose the SNI
field under a QUIC/TLS dissection path differently; the P0.7.3 inspector JSON
is the project-native reference for this release.

## 4. How to judge the result

- **Generator PASS:** all requests reported HTTP version `3`. This confirms
  HTTP/3 was negotiated by curl for each probe. Inspect the JSON report for
  per-service status and remote IP.
- **Capture evidence:** the PCAP contains UDP/443 packets for the test interval.
- **QUIC Initial decrypt PASS:** the inspector reports a decrypted ClientHello
  and SNI. Authentication failure or missing original DCID is not an SNI.
- **SNI/AppID PASS:** extracted SNI maps to the expected application label via
  an explicit rule in `config/dns_mapping.yaml`.
- **PARTIAL:** a service did not negotiate HTTP/3, no ClientHello was captured,
  SNI was unavailable (for example ECH), or the hostname had no explicit rule.
  Record the exact reason; do not relabel it as a successful QUIC identification.

## Important P0.7.3 limitation

P0.7.3 provides a standalone QUIC v1 Initial inspector and the PCAP inspection
helper above. It is **not yet wired into the shared live `PacketProcessor`**.
Therefore the existing live capture summary will not yet report QUIC-derived
application IDs. Use the PCAP inspector for this phase. P0.7.4 is responsible
for connecting UDP Flow tracking, QUIC connection/CID state and SNI evidence
to the shared live/PCAP application-identification pipeline.

This test covers QUIC v1 Initial only. QUIC v2, 0-RTT/1-RTT decryption and ECH
inner ClientHello recovery are outside the current scope. If a service uses
ECH, the visible SNI may be absent or may not be the true service hostname.
