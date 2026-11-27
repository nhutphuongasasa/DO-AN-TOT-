import csv
from dataclasses import replace

import pytest

from appid.domain.models import PacketRecord, TransportProtocol
from appid.flow.tracker import FlowTracker
from appid.ml import (
    BidirectionalFlowReconstructor,
    BurstSegmentationPolicy,
    BurstSegmenter,
    export_burst_features_csv,
    export_flow_features_csv,
)
from appid.ml.schemas import BURST_STATISTICS_FIELDS, FLOW_STATISTICS_FIELDS


def _bursts(session="csv-s1", reverse=False):
    tracker = FlowTracker(lan_subnets=["192.168.1.0/24"])
    flow = None
    packets = [
        (1.0, "192.168.1.10", "203.0.113.8", 51000, 443, 100),
        (1.1, "192.168.1.10", "203.0.113.8", 51000, 443, 120),
        (1.2, "203.0.113.8", "192.168.1.10", 443, 51000, 80),
    ]
    for index, (ts, src, dst, sport, dport, length) in enumerate(packets):
        flow = tracker.add_packet(PacketRecord(
            session, index, ts, src, dst, sport, dport, TransportProtocol.TCP, length
        ))
    assert flow is not None
    result = BurstSegmenter.segment(
        BidirectionalFlowReconstructor().reconstruct(flow), BurstSegmentationPolicy()
    )
    return tuple(replace(b, flow_id=f"{b.flow_id}-other") for b in result) if reverse else result


def _read(path):
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def test_burst_csv_has_exact_schema_and_one_row_per_burst(tmp_path):
    bursts = _bursts()
    path = export_burst_features_csv(bursts, tmp_path / "nested" / "bursts.csv")
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        rows = list(reader)
        assert tuple(reader.fieldnames) == BURST_STATISTICS_FIELDS
    assert len(rows) == len(bursts) == 2
    assert [int(row["burst_index"]) for row in rows] == [0, 1]
    assert rows[0]["direction"] == "FORWARD"
    assert rows[1]["direction"] == "BACKWARD"
    assert rows[0]["iat_min_seconds"] != ""


def test_single_packet_burst_serializes_missing_iat_as_empty_cells(tmp_path):
    # Construct a one-packet flow; its IAT values are undefined.
    tracker = FlowTracker(lan_subnets=["192.168.1.0/24"])
    flow = tracker.add_packet(PacketRecord(
        "single", 0, 2.0, "192.168.1.10", "203.0.113.8", 51000, 443,
        TransportProtocol.TCP, 64,
    ))
    assert flow is not None
    single = BurstSegmenter.segment(
        BidirectionalFlowReconstructor().reconstruct(flow), BurstSegmentationPolicy()
    )
    path = export_burst_features_csv(single, tmp_path / "single.csv")
    row = _read(path)[0]
    for field in ("iat_min_seconds", "iat_max_seconds", "iat_mean_seconds", "iat_std_population_seconds"):
        assert row[field] == ""


def test_flow_csv_has_one_aggregate_row_per_flow(tmp_path):
    first, second = _bursts(), _bursts(session="csv-s2")
    path = export_flow_features_csv([first, second], tmp_path / "flows.csv")
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        rows = list(reader)
        assert tuple(reader.fieldnames) == FLOW_STATISTICS_FIELDS
    assert len(rows) == 2
    assert [row["session_id"] for row in rows] == ["csv-s1", "csv-s2"]
    assert [int(row["burst_count"]) for row in rows] == [2, 2]
    assert [int(row["packet_count"]) for row in rows] == [3, 3]


@pytest.mark.parametrize("exporter,args,fields", [
    (export_burst_features_csv, ([],), BURST_STATISTICS_FIELDS),
    (export_flow_features_csv, ([],), FLOW_STATISTICS_FIELDS),
])
def test_empty_input_writes_header_only_csv(tmp_path, exporter, args, fields):
    path = exporter(*args, tmp_path / "empty.csv")
    assert path.read_text(encoding="utf-8").strip() == ",".join(fields)
    assert _read(path) == []


def test_burst_csv_rejects_malformed_burst_without_silent_row(tmp_path):
    burst = _bursts()[0]
    malformed = replace(burst, total_bytes=burst.total_bytes + 1)
    path = tmp_path / "bad.csv"
    with pytest.raises(ValueError, match="total_bytes"):
        export_burst_features_csv([malformed], path)
    # Validate all rows before opening the destination; no partial file remains.
    assert not path.exists()


def test_flow_csv_rejects_mixed_flow_lineage(tmp_path):
    bursts = _bursts()
    malformed = replace(bursts[1], flow_id="different-flow")
    with pytest.raises(ValueError, match="same session and Flow"):
        export_flow_features_csv([[bursts[0], malformed]], tmp_path / "bad.csv")


def test_csv_does_not_export_payload_or_endpoint_columns(tmp_path):
    path = export_burst_features_csv(_bursts(), tmp_path / "features.csv")
    header = path.read_text(encoding="utf-8").splitlines()[0]
    for forbidden in ("payload", "src_ip", "dst_ip", "src_port", "dst_port"):
        assert forbidden not in header
