"""Offline PCAP replay using the same PacketProcessor as live capture."""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path

from appid.ml.burst_output import write_bursts_jsonl, write_bursts_tsv
from appid.pipeline.processor import PacketProcessor, PipelineStats


@dataclass(frozen=True, slots=True)
class ReplayResult:
    session_id: str
    stats: PipelineStats
    flows: tuple
    bursts: tuple = ()


def replay_pcap(
    path: str | Path,
    *,
    lan_network: str,
    session_id: str | None = None,
    burst_jsonl: str | Path | None = None,
    burst_tsv: str | Path | None = None,
    ml_model_path: str | Path | None = None,
    cnn_model_path: str | Path | None = None,
    fusion_metrics_path: str | Path | None = None,
    fusion_alpha: float | None = None,
) -> ReplayResult:
    pcap_path = Path(path)
    if not pcap_path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    active_session = session_id or str(uuid.uuid4())
    processor = PacketProcessor(
        session_id=active_session,
        lan_network=lan_network,
        ml_model_path=ml_model_path,
        cnn_model_path=cnn_model_path,
        fusion_metrics_path=fusion_metrics_path,
        fusion_alpha=fusion_alpha,
    )
    try:
        # Import scapy.all before constructing PcapReader.  This registers
        # link-layer decoders (including DLT_EN10MB/Ethernet) in conf.l2types.
        # Importing only scapy.utils first can otherwise make Ethernet frames
        # decode as Raw, causing every packet to be counted as unsupported.
        from scapy.all import Ether  # noqa: F401
        from scapy.utils import PcapReader

        with PcapReader(str(pcap_path)) as reader:
            for raw_packet in reader:
                processor.process(raw_packet)
    except EOFError as exc:
        processor.close()
        if processor.stats.raw_packets == 0:
            raise ValueError(f"PCAP contains no packets: {pcap_path}") from exc
        raise
    except Exception:
        processor.close()
        raise

    if processor.stats.raw_packets == 0:
        processor.close()
        raise ValueError(f"PCAP contains no packets: {pcap_path}")

    processor.close()
    bursts = tuple(processor.bursts)
    if burst_jsonl is not None:
        write_bursts_jsonl(bursts, burst_jsonl)
    if burst_tsv is not None:
        write_bursts_tsv(bursts, burst_tsv)
    return ReplayResult(
        session_id=active_session,
        stats=processor.stats,
        flows=processor.tracker.flows,
        bursts=bursts,
    )


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Replay a PCAP through the Flow pipeline")
    parser.add_argument("pcap", help="Path to input .pcap/.pcapng file")
    parser.add_argument("--lan-subnet", required=True, help="LAN subnet used for filtering/direction")
    parser.add_argument("--session-id", default=None)
    parser.add_argument("--burst-jsonl", default=None, help="Optional Burst JSONL output path")
    parser.add_argument("--burst-tsv", default=None, help="Optional Burst TSV output path")
    parser.add_argument(
        "--ml-model", default=None, help="CatBoost Flow V2 model (.cbm)",
    )
    parser.add_argument(
        "--cnn-model", default=None, help="P1.5 CNN1D checkpoint (.pt); requires --ml-model",
    )
    parser.add_argument(
        "--fusion-metrics", default=None,
        help="Late-fusion metrics.json (default: outputs/.../late_fusion/metrics.json)",
    )
    parser.add_argument(
        "--fusion-alpha", type=float, default=None,
        help="Override validation-selected CatBoost weight (0..1)",
    )
    args = parser.parse_args()

    replay_kwargs = {
        "lan_network": args.lan_subnet,
        "session_id": args.session_id,
        "burst_jsonl": args.burst_jsonl,
        "burst_tsv": args.burst_tsv,
    }

    if args.ml_model:
        replay_kwargs["ml_model_path"] = args.ml_model
    if args.cnn_model:
        replay_kwargs["cnn_model_path"] = args.cnn_model
        replay_kwargs["fusion_metrics_path"] = args.fusion_metrics
        replay_kwargs["fusion_alpha"] = args.fusion_alpha

    result = replay_pcap(args.pcap, **replay_kwargs)
    stats = result.stats
    print(f"Session: {result.session_id}")
    print(
        f"raw={stats.raw_packets} parsed={stats.parsed_packets} "
        f"tracked={stats.tracked_packets} outside_lan={stats.outside_lan_packets} "
        f"unsupported={stats.unsupported_packets} parse_errors={stats.parse_errors} "
        f"dns_bindings={stats.dns_bindings_created} dns_identified_flows={stats.dns_identified_flows} "
        f"sni_client_hellos={stats.sni_parsed_client_hellos} "
        f"sni_identified_flows={stats.sni_identified_flows} "
        f"sni_unmapped={stats.sni_unmapped_hostnames} sni_errors={stats.sni_parse_errors} "
        f"udp_datagrams={stats.udp_datagrams} udp_protocols={stats.udp_protocols} "
        f"udp_flows_expired={stats.udp_flows_expired} udp_flow_capacity_evictions={stats.udp_flow_capacity_evictions} "
        f"quic_initial_candidates={stats.quic_initial_candidates} "
        f"quic_initial_decrypted={stats.quic_initial_decrypted} "
        f"quic_initial_rejected={stats.quic_initial_rejected} "
        f"quic_sni_identified_flows={stats.quic_sni_identified_flows} "
        f"quic_sni_unmapped={stats.quic_sni_unmapped_hostnames} "
        f"quic_ech={stats.quic_ech_detected} "
        f"quic_capacity_evictions={stats.quic_connection_capacity_evictions} "
        f"dns_errors={stats.dns_processing_errors} "
        f"ml_evaluated={stats.ml_candidates_evaluated} "
        f"ml_admitted={stats.ml_candidates_admitted} "
        f"ml_rejected={getattr(stats, 'ml_candidates_rejected', 0)} "
        f"ml_pending={getattr(stats, 'ml_candidates_pending', 0)} "
        f"ml_predictions={getattr(stats, 'ml_predictions', 0)} "
        f"ml_catboost={getattr(stats, 'ml_catboost_predictions', 0)} "
        f"ml_cnn={getattr(stats, 'ml_cnn_predictions', 0)} "
        f"ml_fusion={getattr(stats, 'ml_fusion_predictions', 0)} "
        f"ml_errors={getattr(stats, 'ml_inference_errors', 0)} "
        f"bursts={stats.bursts_created}"
    )
    print(f"Flows: {len(result.flows)}")
    for flow in result.flows:
        print(
            f"{flow.flow_id} {flow.status.value} transport={flow.key.protocol.value} "
            f"application_protocol={flow.application_protocol or 'UNKNOWN'} "
            f"app={flow.identification_result.application if flow.identification_result else 'UNKNOWN'} "
            f"method={flow.identification_result.method.value if flow.identification_result and flow.identification_result.method else '-'} "
            f"reason={flow.identification_result.reason_code if flow.identification_result else '-'} "
            f"quic_connection={flow.quic_connection_id or '-'} packets={len(flow.packets)} "
            f"first={flow.first_seen} last={flow.last_seen}"
        )


if __name__ == "__main__":
    main()
