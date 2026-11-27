# DNS live diagnostics (P0.5.9)

The live test supports compact output by default and packet-level DNS diagnostics with
`--dns-debug`.

```bash
./run_dns_test.sh --interface wlp62s0 --duration 180 --dns-debug
```

Debug output is metadata-only. It does not log packet payloads. Useful event families:

- `[DNS][QUERY]`: query transaction, transport, endpoints, QNAME and QTYPE.
- `[DNS][RESPONSE]`: response transaction, correlation status and Answer count.
- `[DNS][ANSWER]` / `[DNS][ANSWER_SKIPPED]`: parsed or rejected RR metadata.
- `[DNS][CACHE_INSERT]`, `[DNS][CACHE_HIT]`, `[DNS][CACHE_MISS]`: cache decisions.
- `[DNS][IDENTIFY]`: identified application or unresolved reason.
- `[DNS][PARSER_ERROR]` / `[PIPELINE][DNS_PROCESSING_ERROR]`: exception type and packet index.

The summary includes parser diagnostic counters and processing exception counters. For a
useful five-application test, start capture first, then run `generate_dns_test_traffic.sh`
in a second terminal while capture is active. The generator must target a DNS server
reachable on the selected physical NIC (for example `DNS_SERVER=192.168.1.1`).

Debug logs can be large. Prefer a 60–180 second capture and save output when diagnosing:

```bash
./run_dns_test.sh --interface wlp62s0 --duration 180 --dns-debug 2>&1 | tee dns-debug.log
```
