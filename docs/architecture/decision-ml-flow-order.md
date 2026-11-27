# Architecture Decision — ML Flow Order

**Status:** Accepted and implemented; DNS-first early exit verified in unit tests  
**Date:** 2026-11-24  
**Baseline:** P0.7.5.4

## Canonical runtime order

1. Packet Capture.
2. Packet Parsing & Flow Tracking.
3. DNS Parser + DNS Cache.
4. DNS Identification: identified → Application early exit; unresolved → continue.
5. TLS ClientHello/SNI: identified → Application early exit; unresolved → continue.
6. ML Candidate Selection / Admission Gate.
7. ML-specific Bidirectional Flow Reconstruction.
8. Burst Segmentation and Feature Extraction.
9. Branch A: Burst Statistics → CatBoost; Branch B: Burst Sequence → PyTorch 1D-CNN.
10. Late Fusion / Stacking.
11. Application Classification → Application label / `UNKNOWN`.

Candidate Selection is a gate, not a classifier. Inference happens only after reconstruction, Burst segmentation, and feature validation.

## Flow Tracker versus ML Reconstruction

Current FlowTracker already groups both directions under one canonical Flow ID, assigns client-relative direction, and retains packet metadata. ML Reconstruction reuses that FlowState to create a stable ML observation, validate ordering/direction coverage, and emit quality flags. It must not create a second Flow ID, regroup the 5-tuple, change direction semantics, reassemble TCP payload, or decrypt application data.

All derived objects preserve `session_id → flow_id → burst_index`. Both model branches consume the same observation and Burst set.

## Open decisions

Minimum packet count/duration, Flow-close/pending behavior, duplicate policy, Burst idle-gap threshold, direction-change boundary, Burst count, CatBoost feature schema, CNN tensor schema, fusion algorithm/calibration, and reject threshold remain OPEN. Do not invent defaults.

## Next increment: P1.0

Implement ML Candidate Gate + immutable Flow observation adapter. Reuse FlowTracker/FlowState. Add `ELIGIBLE`/`PENDING`/`REJECTED` states and reason codes. Define observation fields (`session_id`, `flow_id`, protocol, ordered packet metadata, direction coverage, quality flags). Test early exits, admission, deterministic ordering, direction preservation, one-way Flows, and malformed metadata. Do not implement Burst segmentation or models in P1.0.

**P1.0 implementation:** `src/appid/ml/candidate_gate.py` provides the gate, explicit policy, immutable observation and stable reason codes. `PacketProcessor.evaluate_ml_candidate()` exposes it without invoking inference. Unit tests cover early exit, policy admission/pending states, deterministic ordering, direction preservation, one-way Flows, duplicate-index uncertainty, and invalid timestamps.

**P1.0 Definition of Done:** stable observation contract, deterministic tests, no duplicate Flow identity, no DNS/SNI regression, and synchronized docs. P1.1 then implements Burst Segmentation only after boundary rules are decided.


## Runtime policy implementation — 2026-11-26

The shared `PacketProcessor` now enforces the accepted order:

- A valid DNS identification is authoritative and returns immediately. TCP/TLS SNI and UDP/QUIC analysis are skipped for that packet/Flow.
- If DNS is unresolved, TCP/TLS SNI (or UDP/QUIC v1 Initial SNI for UDP) may identify the Flow and then exits.
- Only Flows unresolved by DNS and SNI can proceed to ML Candidate Gate when finalized.
- A late-arriving valid DNS mapping replaces an earlier SNI result because DNS has the higher stage priority.

The previous agreement/conflict fusion behavior (`HYBRID_DNS_SNI`, SNI-preferred conflict) is superseded for runtime classification. The enum remains for compatibility with historical artifacts; new runtime results do not emit hybrid DNS/SNI outcomes.
