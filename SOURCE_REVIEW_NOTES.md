# Source review notes — Hybrid AppID

## Scope
Reviewed the uploaded `hybrid_appid_source_review_final.zip` source snapshot.
No ML retraining or model tuning was performed. Existing ML datasets and model
outputs were retained as source evidence; the large raw training artefacts were
not required for this code review.

## Changes made

1. `src/appid/pipeline/processor.py`
   - Refresh the SNI stream idle timestamp for every accepted TCP segment,
     including out-of-order segments that are buffered but do not yet emit
     contiguous bytes. This prevents the processor's side-buffer from being
     expired while the TCP reassembler still considers the stream active.
   - Count unsupported TLS records separately from malformed TLS. A capture
     that starts midstream may encounter TLS application-data records before
     any ClientHello; these are not malformed TLS packets.

2. `src/appid/capture/live.py`
   - Include the new `sni_unsupported` counter in the capture summary.

3. `tests/unit/pipeline/test_processor.py`
   - Add regression coverage for buffered out-of-order TCP segments refreshing
     the SNI idle timer.
   - Add regression coverage ensuring unsupported TLS records do not inflate
     the malformed-TLS counter.

## Validation in this review environment
- `pytest -q -rs`: 185 passed, 3 skipped.
- `compileall -q src tests`: passed.
- Two skips are because Scapy is not installed in this review runtime
  (`test_pcap_burst_pipeline.py` and `test_dns_parser.py`).
- The live-NIC test is opt-in and was skipped as designed.
- Ruff was unavailable in this review runtime, so lint must be run in the
  project's `.venv` on the target machine.

## Important live-capture limitation
These changes improve SNI stream lifecycle handling and diagnostics. They do
not prove that a live capture will identify an application. A real-NIC test
with a controlled TLS ClientHello must still be performed on the target host.
ECH, midstream capture, DNS cache misses, and traffic that does not contain a
visible ClientHello can legitimately remain UNKNOWN.
