# Project status — 2026-11-27

## Overall

**Overall status: PARTIAL** Hybrid network AppID prototype with a shared live/PCAP pipeline and integrated optional CatBoost Flow V2 inference. ML runtime is implemented; prediction quality and operational acceptance remain open.

## Delivered and integrated

- Single-NIC live capture and PCAP replay through one `PacketProcessor`.
- Packet parsing, canonical bidirectional Flow tracking and UDP lifecycle.
- DNS parser/cache/domain identification with DNS-first early exit.
- TCP reassembly and TLS ClientHello/SNI identification.
- UDP protocol analysis and QUIC v1 Initial decrypt/CRYPTO/SNI path.
- Candidate Gate, immutable Flow observations, Burst segmentation and statistics.
- CatBoost Flow V2 loading, 70-feature Flow aggregation, ordered `predict_proba` inference and Flow result attachment.

## Confirmed evidence

- Prior user-run tests: `python -m compileall -q src/appid` and `PYTHONPATH="$PWD" pytest -q` → 195 passed, 1 skipped, 1 warning in 1.81s. Not rerun against this ZIP.
- One user-supplied live CatBoost run: 171 raw, 167 parsed, 164 tracked; 24 ML candidates evaluated, 23 admitted, 1 pending; 23 predictions, 0 inference errors; 24 Flows finalized; 108 Bursts.
- The live run confirms model load and inference execution only. It does not establish prediction accuracy.

## Not verified / remaining

- Ground-truth model evaluation and class-wise performance for current runtime.
- Model-enabled PCAP end-to-end acceptance.
- Structured Flow-level prediction export; live CLI does not display final predictions after close.
- Inference latency, CPU/RAM and long-duration resource profile.
- Confidence threshold / low-confidence UNKNOWN policy.
- TCP Flow idle expiration.

## Detailed documents

See [`PROJECT_COMPLETION_ASSESSMENT_2026-11-26.md`](PROJECT_COMPLETION_ASSESSMENT_2026-11-26.md) and [`PROJECT_HANDOVER.md`](PROJECT_HANDOVER.md).
