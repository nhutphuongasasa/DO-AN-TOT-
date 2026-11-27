#!/usr/bin/env python3
"""Live ML-only AppID experiment.

Captures real packets from one NIC and invokes the project's existing
Flow -> Burst -> CatBoost/CNN1D -> weighted late-fusion APIs directly.
DNS and SNI parsers/identifiers are intentionally not instantiated or called.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import sys
import time
import uuid
from pathlib import Path

# Allow direct execution from the repository without requiring an editable install.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
if SOURCE_ROOT.is_dir():
    sys.path.insert(0, str(SOURCE_ROOT))

from scapy.all import sniff

from appid.domain.models import TransportProtocol
from appid.flow.tracker import FlowTracker
from appid.ml.burst import (
    BidirectionalFlowReconstructor,
    BurstSegmentationPolicy,
    BurstSegmenter,
)
from appid.ml.candidate_gate import (
    CandidateState,
    FlowObservationPolicy,
    MLCandidateGate,
)
from appid.ml.catboost_inference import CatBoostFlowV2
from appid.ml.cnn1d_inference import CNN1DInference
from appid.ml.flow_aggregation import build_flow_features
from appid.ml.late_fusion import load_fusion_alpha, weighted_late_fusion
from appid.ml.sequence import build_burst_sequence
from appid.network.interfaces import select_interface
from appid.packet.parser import parse_packet

LOG = logging.getLogger("appid.ml_live_only")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run CatBoost + CNN1D late fusion directly on real live traffic; bypass DNS/SNI."
    )
    parser.add_argument("--config", default="config/network.json")
    parser.add_argument("--interface", default=None)
    parser.add_argument(
        "--ml-model",
        default="outputs/p1_5_full_dataset_wirelen_v2/catboost_flow_v2/catboost_flow_v2.cbm",
    )
    parser.add_argument(
        "--cnn-model",
        default="outputs/p1_5_full_dataset_wirelen_v2/cnn1d/cnn1d_best.pt",
    )
    parser.add_argument(
        "--fusion-metrics",
        default="outputs/p1_5_full_dataset_wirelen_v2/late_fusion/metrics.json",
    )
    parser.add_argument("--duration", type=float, default=60.0,
                        help="Capture duration in seconds (default: 60; 0 means until Ctrl+C).")
    parser.add_argument("--idle-timeout", type=float, default=5.0,
                        help="Finalize a Flow after this many idle seconds (default: 5).")
    parser.add_argument("--burst-gap", type=float, default=0.5,
                        help="Burst idle-gap boundary in seconds (default: 0.5).")
    parser.add_argument("--min-packets", type=int, default=2)
    parser.add_argument("--include-dns-flows", action="store_true",
                        help="Include flows with source/destination port 53; skipped by default.")
    parser.add_argument("--jsonl", default="artifacts/ml-live-only-predictions.jsonl",
                        help="Append prediction records to this JSONL file; empty string disables.")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


class LiveMLOnly:
    def __init__(self, args: argparse.Namespace):
        config = json.loads(Path(args.config).read_text(encoding="utf-8"))
        network_config = dict(config.get("network", {}))
        if args.interface:
            network_config.update(mode="manual", interface=args.interface)
        self.interface = select_interface(network_config)
        self.session_id = str(uuid.uuid4())

        self.tracker = FlowTracker(lan_subnets=[self.interface.network])
        self.gate = MLCandidateGate()
        self.observation_policy = FlowObservationPolicy(
            min_packets=args.min_packets,
            min_duration_seconds=0.0,
        )
        self.reconstructor = BidirectionalFlowReconstructor()
        self.burst_policy = BurstSegmentationPolicy(
            idle_gap_seconds=args.burst_gap,
        )

        self.catboost = CatBoostFlowV2(args.ml_model)
        self.cnn = CNN1DInference(args.cnn_model)
        self.alpha = load_fusion_alpha(args.fusion_metrics, self.catboost.classes)
        if set(self.catboost.classes) != set(self.cnn.classes):
            raise ValueError("CatBoost and CNN1D class sets do not match")

        self.duration = args.duration
        self.idle_timeout = args.idle_timeout
        self.include_dns_flows = args.include_dns_flows
        self.verbose = args.verbose
        self.packet_index = 0
        self.started_at = 0.0
        self.finalized: set[str] = set()
        self.jsonl_path = Path(args.jsonl) if args.jsonl else None
        if self.jsonl_path:
            self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)

        self.counts = {
            "captured": 0,
            "parsed": 0,
            "outside_lan": 0,
            "unsupported": 0,
            "dns_flows_skipped": 0,
            "flows_finalized": 0,
            "candidates_admitted": 0,
            "candidates_rejected_or_pending": 0,
            "predictions": 0,
            "inference_errors": 0,
        }

    def on_packet(self, raw_packet) -> None:
        self.counts["captured"] += 1
        try:
            record = parse_packet(
                raw_packet,
                session_id=self.session_id,
                packet_index=self.packet_index,
            )
        except Exception:
            LOG.exception("Packet parse failed")
            self.packet_index += 1
            return
        self.packet_index += 1

        if record is None:
            self.counts["unsupported"] += 1
            return
        self.counts["parsed"] += 1

        src = ipaddress.ip_address(record.src_ip)
        dst = ipaddress.ip_address(record.dst_ip)
        subnet = self.interface.network
        src_in = src.version == subnet.version and src in subnet
        dst_in = dst.version == subnet.version and dst in subnet
        if not src_in and not dst_in:
            self.counts["outside_lan"] += 1
            return

        self.tracker.add_packet(record)
        if self.verbose:
            print(
                f"[PACKET] {record.transport.value} "
                f"{record.src_ip}:{record.src_port} -> {record.dst_ip}:{record.dst_port} "
                f"len={record.packet_length}",
                flush=True,
            )

    def finalize(self, flow) -> None:
        if flow.flow_id in self.finalized:
            return
        self.finalized.add(flow.flow_id)
        self.counts["flows_finalized"] += 1

        if not self.include_dns_flows and (
            flow.key.endpoint_a.port == 53 or flow.key.endpoint_b.port == 53
        ):
            self.counts["dns_flows_skipped"] += 1
            return

        decision = self.gate.evaluate(flow, policy=self.observation_policy)
        if decision.state is not CandidateState.ELIGIBLE:
            self.counts["candidates_rejected_or_pending"] += 1
            if self.verbose:
                print(
                    f"[SKIP] flow={flow.flow_id} gate={decision.state.value} "
                    f"reason={decision.reason.value}",
                    flush=True,
                )
            return

        self.counts["candidates_admitted"] += 1
        try:
            observation = self.reconstructor.reconstruct(flow)
            bursts = BurstSegmenter.segment(observation, self.burst_policy)
            if not bursts:
                self.counts["candidates_rejected_or_pending"] += 1
                return

            flow_features = build_flow_features(bursts)
            cat_prediction = self.catboost.predict(flow_features)

            sequence = build_burst_sequence(bursts)
            cnn_prediction = self.cnn.predict(sequence.bursts)

            fused = weighted_late_fusion(
                cat_prediction["probabilities"],
                cnn_prediction["probabilities"],
                alpha_catboost=self.alpha,
            )
            application = max(fused, key=fused.get)
            confidence = float(fused[application])

            result = {
                "timestamp": time.time(),
                "session_id": flow.session_id,
                "flow_id": flow.flow_id,
                "protocol": flow.key.protocol.value,
                "src_client": (
                    f"{flow.client_endpoint.ip}:{flow.client_endpoint.port}"
                    if flow.client_endpoint else None
                ),
                "remote": (
                    f"{flow.remote_endpoint.ip}:{flow.remote_endpoint.port}"
                    if flow.remote_endpoint else None
                ),
                "packet_count": len(flow.packets),
                "burst_count": len(bursts),
                "flow_feature_count": len(flow_features),
                "cnn_sequence_length": sequence.sequence_length,
                "catboost": cat_prediction,
                "cnn1d": cnn_prediction,
                "fusion_alpha_catboost": self.alpha,
                "fusion_alpha_cnn": 1.0 - self.alpha,
                "fusion_probabilities": fused,
                "application": application,
                "confidence": confidence,
                "method": "CATBOOST_CNN1D_WEIGHTED_LATE_FUSION",
            }
            self.counts["predictions"] += 1

            print(
                f"[ML_ONLY][PREDICTION] flow={flow.flow_id} "
                f"app={application} confidence={confidence:.4f} "
                f"catboost={cat_prediction['application']} "
                f"cnn1d={cnn_prediction['application']} "
                f"packets={len(flow.packets)} bursts={len(bursts)} "
                f"fusion=({self.alpha:.2f}/{1.0-self.alpha:.2f})",
                flush=True,
            )
            if self.jsonl_path:
                with self.jsonl_path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(result, ensure_ascii=False) + "\n")
        except Exception:
            self.counts["inference_errors"] += 1
            LOG.exception("[ML_ONLY][INFERENCE_ERROR] flow=%s", flow.flow_id)

    def flush_idle(self, now: float) -> None:
        # UDP expiration follows the FlowTracker's explicit UDP lifecycle API.
        expired_udp = self.tracker.expire_udp_flows(
            now, idle_timeout=self.idle_timeout
        )
        for flow in expired_udp:
            self.finalize(flow)

        # FlowTracker intentionally has no implicit TCP idle timeout. This
        # experiment supplies one explicitly so TCP Flows can be tested live.
        stale_tcp = [
            flow for flow in self.tracker.active_flows
            if flow.key.protocol is TransportProtocol.TCP
            and now - flow.last_seen >= self.idle_timeout
        ]
        for flow in stale_tcp:
            self.finalize(self.tracker.close_flow(flow.flow_id))

    def close(self) -> None:
        for flow in self.tracker.close_session(self.session_id):
            self.finalize(flow)

    def run(self) -> None:
        print(f"NIC       : {self.interface.name}")
        print(f"Address   : {self.interface.address}")
        print(f"Subnet    : {self.interface.network}")
        print(f"Session   : {self.session_id}")
        print(f"CatBoost  : {self.catboost.model_path}")
        print(f"CNN1D     : {self.cnn.checkpoint_path}")
        print(f"Fusion    : CatBoost {self.alpha:.3f} / CNN1D {1.0-self.alpha:.3f}")
        print("Mode      : ML ONLY (DNS/SNI are not called)")
        print("Press Ctrl+C to stop early.\n", flush=True)

        self.started_at = time.monotonic()
        try:
            while True:
                sniff(
                    iface=self.interface.name,
                    prn=self.on_packet,
                    store=False,
                    timeout=1,
                )
                self.flush_idle(time.time())
                if self.duration > 0 and time.monotonic() - self.started_at >= self.duration:
                    break
        except KeyboardInterrupt:
            print("\n[INFO] Capture stopped by user.", flush=True)
        finally:
            self.close()
            print("\n========== ML-ONLY SUMMARY ==========")
            for key, value in self.counts.items():
                print(f"{key}: {value}")
            if self.jsonl_path:
                print(f"predictions_jsonl: {self.jsonl_path}")


def main() -> None:
    args = parse_args()
    if args.duration < 0:
        raise SystemExit("--duration must be >= 0")
    if args.idle_timeout <= 0:
        raise SystemExit("--idle-timeout must be > 0")
    if args.burst_gap <= 0:
        raise SystemExit("--burst-gap must be > 0")
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    LiveMLOnly(args).run()


if __name__ == "__main__":
    main()
