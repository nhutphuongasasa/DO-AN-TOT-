# P1.3 – Burst Statistics and Sequence Schema

## Purpose and boundaries

This phase adds deterministic, payload-free descriptive statistics over the
existing `Burst` objects. It does not alter Flow identity, packet direction,
Burst segmentation, Candidate Gate decisions, DNS/SNI behavior, or capture.

## Versioning

The first schema versions are:

- Burst statistics: `1.0`
- Flow statistics: `1.0`
- Burst sequence: `1.0`

Any incompatible field meaning/type change must increment the corresponding
major schema version. Additive optional fields may use a documented minor
revision policy in a later phase.

## Burst statistics fields

| Field | Meaning | Unit / type |
|---|---|---|
| `schema_version` | Statistics schema version | string |
| `session_id`, `flow_id` | Existing lineage identifiers | string |
| `burst_index` | Position assigned by BurstSegmenter | integer |
| `direction` | FORWARD, BACKWARD, or UNKNOWN | enum string |
| `start_ts`, `end_ts` | First/last packet timestamps | seconds, float |
| `duration_seconds` | `end_ts - start_ts`, never negative | seconds, float |
| `packet_count` | Number of packet observations | integer |
| `total_bytes` | Sum of packet observation lengths | bytes, integer |
| `packet_length_min/max/mean/median` | Packet length distribution | bytes |
| `packet_length_std_population` | Population standard deviation (ddof=0) | bytes |
| `iat_min/max/mean_seconds` | Adjacent packet timestamp differences | seconds |
| `iat_std_population_seconds` | Population standard deviation of IATs | seconds |
| `forward/backward/unknown_packet_count` | Packet counts by direction | integer |
| `forward/backward/unknown_bytes` | Bytes by direction | bytes, integer |
| `inter_burst_gap_seconds` | Gap from previous Burst end; absent for first Burst | seconds or null |

For a single-packet Burst, IAT statistics are `null` because no interval exists.
For an empty Burst, statistics are undefined and the API raises `ValueError`.
Population standard deviation is used consistently (`ddof=0`).

## Flow statistics fields

Flow aggregation requires at least one Burst and exactly one `(session_id,
flow_id)` lineage. Duplicate `burst_index` values are rejected. Counts and byte
totals are recomputed from packet observations rather than trusting cached
Burst totals. The result includes Burst count, packet count, total bytes, first
and last observed timestamps, duration, direction-specific Burst counts, and
min/max/mean of available inter-Burst gaps.

## Sequence schema

A sequence is ordered by `burst_index`; each element retains direction, packet
timestamps, packet lengths, packet count, byte total, duration and inter-Burst
gap. Packet observations are sorted by `(timestamp, packet_index)`. The sequence
contains no payload bytes and preserves the original session/Flow identifiers.

## Validation and missing values

- `UNKNOWN` remains an explicit direction; it is never coerced to FORWARD or
  BACKWARD.
- Timestamps must be finite. Negative packet lengths, negative gaps, invalid
  directions, inconsistent packet counts, inconsistent byte totals, duplicate
  Burst indexes, and mixed Flow lineage are rejected.
- A missing first-Burst gap and undefined single-packet IAT statistics are
  represented as `null`/`None`, not zero.
- All durations and gaps are expressed in seconds; packet lengths and totals
  are expressed in bytes.

## Public API

- `compute_burst_statistics(burst) -> BurstStatistics`
- `compute_flow_statistics(bursts) -> FlowStatistics`
- `build_burst_sequence(bursts) -> BurstSequence`

All result dataclasses expose `to_dict()` for serialization by downstream
Feature Extraction. These are statistics/schema APIs; the existing raw Burst
JSONL/TSV export remains backward-compatible and unchanged.
