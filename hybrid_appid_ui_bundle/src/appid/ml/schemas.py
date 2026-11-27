"""Versioned, payload-free schemas for Burst-derived ML inputs."""

BURST_STATISTICS_SCHEMA_VERSION = "1.0"
BURST_SEQUENCE_SCHEMA_VERSION = "1.0"
FLOW_STATISTICS_SCHEMA_VERSION = "1.0"

BURST_STATISTICS_FIELDS = (
    "schema_version", "session_id", "flow_id", "burst_index", "direction",
    "start_ts", "end_ts", "duration_seconds", "packet_count", "total_bytes",
    "packet_length_min", "packet_length_max", "packet_length_mean",
    "packet_length_median", "packet_length_std_population", "iat_min_seconds",
    "iat_max_seconds", "iat_mean_seconds", "iat_std_population_seconds",
    "forward_packet_count", "backward_packet_count", "unknown_packet_count",
    "forward_bytes", "backward_bytes", "unknown_bytes", "inter_burst_gap_seconds",
)

BURST_SEQUENCE_FIELDS = (
    "schema_version", "session_id", "flow_id", "sequence_length", "bursts",
)

FLOW_STATISTICS_FIELDS = (
    "schema_version", "session_id", "flow_id", "burst_count", "packet_count",
    "total_bytes", "start_ts", "end_ts", "duration_seconds",
    "forward_burst_count", "backward_burst_count", "unknown_burst_count",
    "inter_burst_gap_min_seconds", "inter_burst_gap_max_seconds",
    "inter_burst_gap_mean_seconds",
)
