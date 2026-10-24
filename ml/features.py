"""Feature extraction module for Edge AI traffic classification.

Provides:
    - WindowStats: Online, O(1)-per-packet statistical tracking across rolling windows.
    - extract_flow_features: Formats WindowStats tabular features with flow metadata.
    - extract_first_pkts_sequence: Extracts normalized (size, IAT) early packet sequence for CNN.
    - DeviceWindowCollector: Per-device traffic aggregation into 0.5s time-series bins (CNN/LSTM)
      and tabular window aggregates.

Strictly independent of packet capture libraries (no Scapy dependencies).
"""

from __future__ import annotations

import collections
import math
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

import numpy as np

if TYPE_CHECKING:
    from capture.flow_tracker import FlowState


class WindowStats:
    """Online statistical summary of packet arrivals within a temporal window.

    Maintains running sums and extrema in O(1) space and time per packet.
    Allows zero-copy window resets while preserving cross-window inter-arrival time (IAT).
    """

    def __init__(self) -> None:
        """Initialize online counters and running moments."""
        # Packet length statistics
        self.n: int = 0
        self.sum_bytes: int = 0
        self.sum_sq_bytes: float = 0.0
        self.min_bytes: Optional[int] = None
        self.max_bytes: int = 0

        # Directional packet & byte counts (forward = +1, backward = -1)
        self.n_fwd: int = 0
        self.bytes_fwd: int = 0
        self.n_bwd: int = 0
        self.bytes_bwd: int = 0

        # Window timestamps
        self.first_time: Optional[float] = None
        self.last_time: Optional[float] = None

        # Cross-window persistent timestamp (retained across window resets)
        self.prev_time: Optional[float] = None

        # Inter-arrival time (IAT) statistics in seconds
        self.n_iat: int = 0
        self.sum_iat: float = 0.0
        self.sum_sq_iat: float = 0.0
        self.min_iat: Optional[float] = None
        self.max_iat: float = 0.0

    def update(self, size: int, direction: int, timestamp: float) -> None:
        """Update online window statistics with a new packet in O(1) time.

        Args:
            size: Packet size in bytes (non-negative).
            direction: +1 for forward (client -> server), -1 for backward (server -> client).
            timestamp: Packet arrival epoch timestamp in seconds.
        """
        pkt_len = max(0, int(size))
        self.n += 1
        self.sum_bytes += pkt_len
        self.sum_sq_bytes += float(pkt_len * pkt_len)

        if self.min_bytes is None or pkt_len < self.min_bytes:
            self.min_bytes = pkt_len
        if pkt_len > self.max_bytes:
            self.max_bytes = pkt_len

        if direction > 0:
            self.n_fwd += 1
            self.bytes_fwd += pkt_len
        else:
            self.n_bwd += 1
            self.bytes_bwd += pkt_len

        # Track timestamps within current window
        if self.first_time is None:
            self.first_time = timestamp
        self.last_time = timestamp

        # Compute IAT if previous packet timestamp exists (preserves IAT across window reset)
        if self.prev_time is not None:
            iat = max(0.0, float(timestamp - self.prev_time))
            self.n_iat += 1
            self.sum_iat += iat
            self.sum_sq_iat += iat * iat
            if self.min_iat is None or iat < self.min_iat:
                self.min_iat = iat
            if iat > self.max_iat:
                self.max_iat = iat

        self.prev_time = timestamp

    def reset_for_next_window(self) -> None:
        """Reset current window metrics while retaining `prev_time` for continuity."""
        self.n = 0
        self.sum_bytes = 0
        self.sum_sq_bytes = 0.0
        self.min_bytes = None
        self.max_bytes = 0

        self.n_fwd = 0
        self.bytes_fwd = 0
        self.n_bwd = 0
        self.bytes_bwd = 0

        self.first_time = None
        self.last_time = None

        self.n_iat = 0
        self.sum_iat = 0.0
        self.sum_sq_iat = 0.0
        self.min_iat = None
        self.max_iat = 0.0
        # self.prev_time is intentionally NOT reset

    def extract(self, dest_port: int = 0, transport: str = "") -> Dict[str, float]:
        """Extract tabular features from the accumulated window statistics.

        Args:
            dest_port: Destination port number (defaults to 0 if unknown).
            transport: Protocol name ('tcp', 'udp', etc.).

        Returns:
            Dictionary containing 24 tabular statistical features.
        """
        # Packet length statistics
        if self.n > 0:
            pkt_len_mean = float(self.sum_bytes) / float(self.n)
            pkt_len_var = max(0.0, (float(self.sum_sq_bytes) / float(self.n)) - (pkt_len_mean * pkt_len_mean))
            pkt_len_std = math.sqrt(pkt_len_var)
            pkt_len_min = float(self.min_bytes) if self.min_bytes is not None else 0.0
            pkt_len_max = float(self.max_bytes)
        else:
            pkt_len_mean = 0.0
            pkt_len_std = 0.0
            pkt_len_min = 0.0
            pkt_len_max = 0.0

        pkt_len_fwd_mean = (float(self.bytes_fwd) / float(self.n_fwd)) if self.n_fwd > 0 else 0.0

        # Ratios (smoothed to prevent division by zero)
        fwd_bwd_pkt_ratio = float(self.n_fwd) / float(max(1, self.n_bwd))
        bytes_ratio = float(self.bytes_bwd) / float(self.bytes_fwd + 1)
        bytes_down_ratio = float(self.bytes_bwd) / float(self.sum_bytes + 1)
        bytes_up_ratio = float(self.bytes_fwd) / float(self.sum_bytes + 1)

        # IAT statistics
        if self.n_iat > 0:
            iat_mean = float(self.sum_iat) / float(self.n_iat)
            iat_var = max(0.0, (float(self.sum_sq_iat) / float(self.n_iat)) - (iat_mean * iat_mean))
            iat_std = math.sqrt(iat_var)
            iat_max = float(self.max_iat)
            iat_min = float(self.min_iat) if self.min_iat is not None else 0.0
        else:
            iat_mean = 0.0
            iat_std = 0.0
            iat_max = 0.0
            iat_min = 0.0

        # Packet arrival rates (pkts/sec)
        window_duration = (
            max(0.0, float(self.last_time - self.first_time))
            if (self.first_time is not None and self.last_time is not None)
            else 0.0
        )
        if window_duration > 0.0:
            fwd_pkt_per_sec = float(self.n_fwd) / window_duration
            bwd_pkt_per_sec = float(self.n_bwd) / window_duration
        else:
            fwd_pkt_per_sec = 0.0
            bwd_pkt_per_sec = 0.0

        proto = transport.lower()
        is_udp = 1.0 if proto == "udp" else 0.0
        is_tcp = 1.0 if proto == "tcp" else 0.0

        return {
            # 1. Packet counts & packet ratio
            "n_pkts_total": float(self.n),
            "bytes_total": float(self.sum_bytes),
            "n_pkts_fwd": float(self.n_fwd),
            "n_pkts_bwd": float(self.n_bwd),
            "fwd_bwd_pkt_ratio": fwd_bwd_pkt_ratio,
            # 2. Packet length moments
            "pkt_len_mean": pkt_len_mean,
            "pkt_len_std": pkt_len_std,
            "pkt_len_min": pkt_len_min,
            "pkt_len_max": pkt_len_max,
            "pkt_len_fwd_mean": pkt_len_fwd_mean,
            # 3. Directional bytes & ratios
            "bytes_fwd": float(self.bytes_fwd),
            "bytes_bwd": float(self.bytes_bwd),
            "bytes_ratio": bytes_ratio,
            # 4. Inter-arrival time (IAT) statistics
            "iat_mean": iat_mean,
            "iat_std": iat_std,
            "iat_max": iat_max,
            "iat_min": iat_min,
            # 5. Throughput rates
            "fwd_pkt_per_sec": fwd_pkt_per_sec,
            "bwd_pkt_per_sec": bwd_pkt_per_sec,
            # 6. Transport & port indicators
            "dest_port": float(dest_port) if dest_port > 0 else 0.0,
            "is_udp": is_udp,
            "is_tcp": is_tcp,
            # 7. Relative byte distribution ratios
            "bytes_down_ratio": bytes_down_ratio,
            "bytes_up_ratio": bytes_up_ratio,
        }


def extract_flow_features(
    flow: FlowState,
    dest_port: int = 0,
    transport: str = "",
) -> Dict[str, float]:
    """Extract tabular features from FlowState online window statistics.

    Args:
        flow: FlowState instance containing .win WindowStats.
        dest_port: Target server destination port (falls back to flow.dest_port if 0).
        transport: Transport protocol name ('tcp', 'udp') (falls back to flow.transport if empty).

    Returns:
        Dictionary of extracted statistical features.
    """
    effective_port = dest_port if dest_port > 0 else getattr(flow, "dest_port", 0)
    effective_proto = transport if transport else getattr(flow, "transport", "")
    feats = flow.win.extract(dest_port=effective_port, transport=effective_proto)
    feats["dest_port"] = float(effective_port)
    proto_lower = str(effective_proto).lower()
    feats["is_udp"] = 1.0 if proto_lower == "udp" else 0.0
    feats["is_tcp"] = 1.0 if proto_lower == "tcp" else 0.0
    return feats


def extract_first_pkts_sequence(flow: FlowState, n: int = 20) -> np.ndarray:
    """Extract normalized early packet sequence representation for CNN classification.

    Args:
        flow: FlowState instance containing .first_pkts list of (signed_size, timestamp).
        n: Sequence length (number of packets, default: 20).

    Returns:
        np.ndarray of shape (n, 2) with dtype float32:
            - Column 0: signed_size / 1500.0 (positive=forward, negative=backward)
            - Column 1: log1p(iat_ms) where IAT is in milliseconds from previous packet.
        Padded with zeros if fewer than n packets were captured.
    """
    seq = np.zeros((n, 2), dtype=np.float32)
    pkts: List[Tuple[int, float]] = getattr(flow, "first_pkts", [])
    if not pkts or n <= 0:
        return seq

    limit = min(n, len(pkts))
    prev_ts = pkts[0][1]

    for i in range(limit):
        signed_size, ts = pkts[i]
        norm_size = float(signed_size) / 1500.0
        if i == 0:
            iat_ms = 0.0
        else:
            iat_ms = max(0.0, float(ts - prev_ts) * 1000.0)
        prev_ts = ts
        seq[i, 0] = norm_size
        seq[i, 1] = float(np.log1p(iat_ms))

    return seq


class DeviceWindowCollector:
    """Collects and aggregates per-device network traffic into fixed time bins.

    Supports:
        - 2D time-series matrices of shape (T, 4) for device-level CNN/LSTM models.
        - Summary window features (total upload/download, ratios, active flow count).
    """

    def __init__(self, max_history_s: float = 120.0) -> None:
        """Initialize collector with bounded historical retention.

        Args:
            max_history_s: Maximum time in seconds to retain historical packet records.
        """
        self.max_history_s: float = max_history_s
        # mac -> deque of (timestamp, packet_size, direction)
        self._records: Dict[str, collections.deque[Tuple[float, int, int]]] = {}
        # mac -> last observed timestamp
        self._last_seen: Dict[str, float] = {}

    def update(self, mac: str, size: int, direction: int, timestamp: float) -> None:
        """Record a packet event for a specific device MAC address.

        Args:
            mac: Device MAC address string (e.g. "AA:BB:CC:DD:EE:FF").
            size: Packet size in bytes.
            direction: +1 for upload (device -> internet), -1 for download (internet -> device).
            timestamp: Packet arrival epoch timestamp in seconds.
        """
        if not mac:
            return

        key = mac.lower().strip()
        pkt_size = max(0, int(size))
        dir_val = 1 if direction > 0 else -1

        if key not in self._records:
            self._records[key] = collections.deque()

        dq = self._records[key]
        dq.append((timestamp, pkt_size, dir_val))

        current_last = self._last_seen.get(key, timestamp)
        self._last_seen[key] = max(current_last, timestamp)

        # Prune records older than retention limit
        cutoff = timestamp - self.max_history_s
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def get_timeseries(
        self,
        mac: str,
        window_s: float = 30.0,
        bin_s: float = 0.5,
        current_time: Optional[float] = None,
    ) -> np.ndarray:
        """Construct 2D binned time-series matrix for CNN/LSTM inference.

        Args:
            mac: Device MAC address.
            window_s: Total time window span in seconds (default: 30.0s).
            bin_s: Time bin resolution in seconds (default: 0.5s).
            current_time: Reference end timestamp (defaults to device's last seen time).

        Returns:
            np.ndarray of shape (T, 4) with dtype float32 where T = int(window_s / bin_s):
                [log1p(bytes_up), log1p(bytes_down), log1p(pkts_up), log1p(pkts_down)]
        """
        num_bins = max(1, int(round(window_s / bin_s)))
        output_matrix = np.zeros((num_bins, 4), dtype=np.float32)

        if not mac:
            return output_matrix

        key = mac.lower().strip()
        dq = self._records.get(key)
        if not dq:
            return output_matrix

        t_end = current_time if current_time is not None else self._last_seen.get(key, 0.0)
        t_start = t_end - window_s
        if t_end <= 0.0:
            return output_matrix

        # Bins buffer: [bytes_up, bytes_down, pkts_up, pkts_down]
        accum = np.zeros((num_bins, 4), dtype=np.float64)

        for ts, size, dir_val in dq:
            if t_start <= ts <= t_end:
                bin_idx = int((ts - t_start) / bin_s)
                if bin_idx >= num_bins:
                    bin_idx = num_bins - 1
                if bin_idx >= 0:
                    if dir_val > 0:
                        accum[bin_idx, 0] += size  # bytes_up
                        accum[bin_idx, 2] += 1     # pkts_up
                    else:
                        accum[bin_idx, 1] += size  # bytes_down
                        accum[bin_idx, 3] += 1     # pkts_down

        return np.log1p(accum).astype(np.float32)

    def get_device_window_features(
        self,
        mac: str,
        window_s: float = 30.0,
        current_time: Optional[float] = None,
        n_active_flows: int = 0,
    ) -> Dict[str, float]:
        """Aggregate statistical traffic summary over the device's rolling window.

        Args:
            mac: Device MAC address.
            window_s: Temporal window span in seconds (default: 30.0s).
            current_time: Reference end timestamp (defaults to device's last seen time).
            n_active_flows: Number of active concurrent flows for this device.

        Returns:
            Dictionary containing:
                total_bytes_up, total_bytes_down, total_pkts_up, total_pkts_down,
                bytes_down_ratio, pkt_down_ratio, bytes_total_log, n_active_flows
        """
        defaults: Dict[str, float] = {
            "total_bytes_up": 0.0,
            "total_bytes_down": 0.0,
            "total_pkts_up": 0.0,
            "total_pkts_down": 0.0,
            "bytes_down_ratio": 0.0,
            "pkt_down_ratio": 0.0,
            "bytes_total_log": 0.0,
            "n_active_flows": float(n_active_flows),
        }
        if not mac:
            return defaults

        key = mac.lower().strip()
        dq = self._records.get(key)
        if not dq:
            return defaults

        t_end = current_time if current_time is not None else self._last_seen.get(key, 0.0)
        t_start = t_end - window_s

        bytes_up = 0
        bytes_down = 0
        pkts_up = 0
        pkts_down = 0

        for ts, size, dir_val in dq:
            if t_start <= ts <= t_end:
                if dir_val > 0:
                    bytes_up += size
                    pkts_up += 1
                else:
                    bytes_down += size
                    pkts_down += 1

        total_bytes = bytes_up + bytes_down
        total_pkts = pkts_up + pkts_down

        bytes_down_ratio = float(bytes_down) / float(total_bytes + 1)
        pkt_down_ratio = float(pkts_down) / float(total_pkts + 1)
        bytes_total_log = float(np.log1p(total_bytes))

        return {
            "total_bytes_up": float(bytes_up),
            "total_bytes_down": float(bytes_down),
            "total_pkts_up": float(pkts_up),
            "total_pkts_down": float(pkts_down),
            "bytes_down_ratio": bytes_down_ratio,
            "pkt_down_ratio": pkt_down_ratio,
            "bytes_total_log": bytes_total_log,
            "n_active_flows": float(n_active_flows),
        }

    def cleanup(self, current_time: float, idle_timeout: float = 300.0) -> None:
        """Evict inactive device records that have been idle past idle_timeout seconds.

        Args:
            current_time: Current epoch timestamp in seconds.
            idle_timeout: Expiration threshold in seconds (default: 300.0s).
        """
        expired_macs = [
            mac
            for mac, last_ts in self._last_seen.items()
            if (current_time - last_ts) > idle_timeout
        ]
        for mac in expired_macs:
            self._records.pop(mac, None)
            self._last_seen.pop(mac, None)
