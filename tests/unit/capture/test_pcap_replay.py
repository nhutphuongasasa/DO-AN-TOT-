import sys
import types

import pytest

from appid.capture.pcap import replay_pcap
from appid.domain.models import PacketRecord, TransportProtocol
from appid.pipeline import processor as processor_module


class FakePacket:
    def __init__(self, timestamp):
        self.time = timestamp


def fake_record(raw_packet, *, session_id, packet_index):
    return PacketRecord(
        session_id=session_id,
        packet_index=packet_index,
        timestamp=raw_packet.time,
        src_ip="192.168.1.20",
        dst_ip="1.1.1.1",
        src_port=55000,
        dst_port=443,
        transport=TransportProtocol.TCP,
        packet_length=120,
    )


class FakeReader:
    packets = []

    def __init__(self, _path):
        # Layer registry must be loaded before PcapReader selects a decoder.
        assert "scapy.all" in sys.modules
        self._packets = iter(self.packets)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def __iter__(self):
        return self._packets


def install_fake_scapy(monkeypatch, packets):
    FakeReader.packets = packets
    scapy = types.ModuleType("scapy")
    utils = types.ModuleType("scapy.utils")
    utils.PcapReader = FakeReader
    all_layers = types.ModuleType("scapy.all")
    all_layers.Ether = object()
    monkeypatch.setitem(sys.modules, "scapy", scapy)
    monkeypatch.setitem(sys.modules, "scapy.all", all_layers)
    monkeypatch.setitem(sys.modules, "scapy.utils", utils)


def test_pcap_replay_uses_shared_pipeline_and_preserves_timestamps(tmp_path, monkeypatch):
    path = tmp_path / "input.pcap"
    path.touch()
    install_fake_scapy(monkeypatch, [FakePacket(10.25), FakePacket(11.5)])
    monkeypatch.setattr(processor_module, "parse_packet", fake_record)

    result = replay_pcap(path, lan_network="192.168.1.0/24", session_id="pcap-session")

    assert result.stats.raw_packets == 2
    assert result.stats.tracked_packets == 2
    assert len(result.flows) == 1
    assert [p.timestamp for p in result.flows[0].ordered_packets] == [10.25, 11.5]


def test_empty_pcap_is_reported(tmp_path, monkeypatch):
    path = tmp_path / "empty.pcap"
    path.touch()
    install_fake_scapy(monkeypatch, [])
    with pytest.raises(ValueError, match="no packets"):
        replay_pcap(path, lan_network="192.168.1.0/24")


def test_pcap_replay_runs_completed_flows_through_burst_pipeline_and_exports(tmp_path, monkeypatch):
    from appid.domain.models import Direction

    path = tmp_path / "burst-input.pcap"
    path.touch()
    packets = [FakePacket(ts) for ts in (1.0, 1.1, 1.2, 1.3, 2.0, 2.7)]
    install_fake_scapy(monkeypatch, packets)

    directions = [Direction.FORWARD, Direction.FORWARD, Direction.BACKWARD,
                  Direction.BACKWARD, Direction.FORWARD, Direction.FORWARD]
    records = iter([
        PacketRecord(
            "burst-pcap", index, timestamp,
            "192.168.1.20" if direction is not Direction.BACKWARD else "1.1.1.1",
            "1.1.1.1" if direction is not Direction.BACKWARD else "192.168.1.20",
            55000 if direction is not Direction.BACKWARD else 443,
            443 if direction is not Direction.BACKWARD else 55000,
            TransportProtocol.TCP, 100 + index,
        )
        for index, (timestamp, direction) in enumerate(
            zip((1.0, 1.1, 1.2, 1.3, 2.0, 2.7), directions))
    ])
    monkeypatch.setattr(processor_module, "parse_packet", lambda *a, **k: next(records))
    jsonl_path = tmp_path / "bursts.jsonl"
    tsv_path = tmp_path / "bursts.tsv"

    result = replay_pcap(
        path, lan_network="192.168.1.0/24", session_id="burst-pcap",
        burst_jsonl=jsonl_path, burst_tsv=tsv_path,
    )

    assert len(result.flows) == 1
    assert result.stats.ml_candidates_evaluated == 1
    assert result.stats.ml_candidates_admitted == 1
    assert result.stats.bursts_created == 4
    assert [burst.direction for burst in result.bursts] == [
        Direction.FORWARD, Direction.BACKWARD, Direction.FORWARD, Direction.FORWARD
    ]
    assert [burst.packet_count for burst in result.bursts] == [2, 2, 1, 1]
    assert all(burst.flow_id == result.flows[0].flow_id for burst in result.bursts)
    assert all(burst.session_id == "burst-pcap" for burst in result.bursts)
    assert jsonl_path.is_file() and len(jsonl_path.read_text().splitlines()) == 4
    assert tsv_path.is_file() and len(tsv_path.read_text().splitlines()) == 5


def test_udp_expiration_finalizes_flow_once(monkeypatch):
    records = iter([
        PacketRecord("udp-expire", 0, 1.0, "192.168.1.10", "203.0.113.10", 50000, 9000,
                     TransportProtocol.UDP, 80),
        PacketRecord("udp-expire", 1, 1.1, "192.168.1.10", "203.0.113.10", 50000, 9000,
                     TransportProtocol.UDP, 90),
        PacketRecord("udp-expire", 2, 62.0, "192.168.1.10", "203.0.113.11", 50001, 9001,
                     TransportProtocol.UDP, 100),
    ])
    monkeypatch.setattr(processor_module, "parse_packet", lambda *a, **k: next(records))
    processor = __import__("appid.pipeline.processor", fromlist=["PacketProcessor"]).PacketProcessor(
        session_id="udp-expire", lan_network="192.168.1.0/24")
    processor.process(FakePacket(1.0))
    processor.process(FakePacket(1.1))
    processor.process(FakePacket(62.0))
    assert processor.stats.udp_flows_expired == 1
    assert processor.stats.burst_flows_finalized == 1
    assert processor.stats.bursts_created == 1
    processor.close()
    assert processor.stats.burst_flows_finalized == 2
    processor.close()
    assert processor.stats.burst_flows_finalized == 2


def test_pcap_cli_forwards_burst_export_paths(monkeypatch, capsys, tmp_path):
    from types import SimpleNamespace

    from appid.capture import pcap as pcap_module

    jsonl_path = tmp_path / "cli-bursts.jsonl"
    tsv_path = tmp_path / "cli-bursts.tsv"
    captured = {}

    stats = SimpleNamespace(
        raw_packets=0, parsed_packets=0, tracked_packets=0, outside_lan_packets=0,
        unsupported_packets=0, parse_errors=0, dns_bindings_created=0,
        dns_identified_flows=0, sni_parsed_client_hellos=0,
        sni_identified_flows=0, sni_unmapped_hostnames=0, sni_parse_errors=0,
        udp_datagrams=0, udp_protocols={}, udp_flows_expired=0,
        udp_flow_capacity_evictions=0, quic_initial_candidates=0,
        quic_initial_decrypted=0, quic_initial_rejected=0,
        quic_sni_identified_flows=0, quic_sni_unmapped_hostnames=0,
        quic_ech_detected=0, quic_connection_capacity_evictions=0,
        dns_processing_errors=0, ml_candidates_evaluated=0,
        ml_candidates_admitted=0, bursts_created=0,
    )

    def fake_replay(path, **kwargs):
        captured["path"] = path
        captured.update(kwargs)
        return SimpleNamespace(session_id="cli-session", stats=stats, flows=())

    monkeypatch.setattr(pcap_module, "replay_pcap", fake_replay)
    monkeypatch.setattr(
        sys, "argv",
        ["appid-pcap-replay", "capture.pcap", "--lan-subnet", "192.168.1.0/24",
         "--session-id", "cli-session", "--burst-jsonl", str(jsonl_path),
         "--burst-tsv", str(tsv_path)],
    )

    pcap_module.main()

    assert captured == {
        "path": "capture.pcap",
        "lan_network": "192.168.1.0/24",
        "session_id": "cli-session",
        "burst_jsonl": str(jsonl_path),
        "burst_tsv": str(tsv_path),
    }
    assert "bursts=0" in capsys.readouterr().out
