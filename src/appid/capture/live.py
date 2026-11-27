"""Single-NIC live capture entry point using the shared PacketProcessor."""
from __future__ import annotations

import argparse
import json
import uuid
from pathlib import Path

from appid.ml.burst_output import write_bursts_jsonl, write_bursts_tsv
from appid.network.interfaces import SelectedInterface, select_interface
from appid.pipeline.processor import PacketProcessor


class SingleNICCapture:
    """Bind capture to one selected interface and use the shared pipeline."""

    def __init__(
        self,
        config_path: str | Path = "config/network.json",
        *,
        interface_name: str | None = None,
        burst_jsonl: str | Path | None = None,
        burst_tsv: str | Path | None = None,
        ml_model_path: str | Path | None = None,
        cnn_model_path: str | Path | None = None,
        fusion_metrics_path: str | Path | None = None,
        fusion_alpha: float | None = None,
        verbose: bool = False,
        results_jsonl: str | Path = "artifacts/live-appid-results.jsonl",
    ) -> None:
        config = json.loads(Path(config_path).read_text(encoding="utf-8"))
        network_config = dict(config.get("network", {}))
        if interface_name:
            network_config.update(mode="manual", interface=interface_name)
        self.interface: SelectedInterface = select_interface(network_config)
        self.session_id = str(uuid.uuid4())
        self.processor = PacketProcessor(
            session_id=self.session_id,
            lan_network=self.interface.network,
            ml_model_path=ml_model_path,
            cnn_model_path=cnn_model_path,
            fusion_metrics_path=fusion_metrics_path,
            fusion_alpha=fusion_alpha,
        )
        self.burst_jsonl = Path(burst_jsonl) if burst_jsonl else None
        self.burst_tsv = Path(burst_tsv) if burst_tsv else None
        self.verbose = verbose
        self.results_jsonl = Path(results_jsonl)
        self.results_jsonl.parent.mkdir(parents=True, exist_ok=True)
        self.results_jsonl.write_text("", encoding="utf-8")
        self._published_flow_count = 0
        self.ml_model_path = Path(ml_model_path) if ml_model_path else None
        self._reported_states: dict[str, tuple[str, str, str]] = {}

    def run(self) -> None:
        from scapy.all import sniff

        print(f"NIC     : {self.interface.name}")
        print(f"Address : {self.interface.address}")
        print(f"Subnet  : {self.interface.network}")
        print(f"Session : {self.session_id}")
        print("Capturing on this NIC only. Press Ctrl+C to stop.")
        try:
            sniff(
                iface=self.interface.name,
                prn=self._handle_packet,
                store=False,
            )
        except KeyboardInterrupt:
            print("\n[INFO] Capture stopped by user.", flush=True)
        finally:
            try:
                self.processor.close()
                self._publish_finalized_flows()
            except Exception as exc:  # noqa: BLE001
                print(f"[ERROR] Processor close failed: {exc}", flush=True)
                import traceback
                traceback.print_exc()

            try:
                self._write_burst_outputs()
            except Exception as exc:  # noqa: BLE001
                print(f"[ERROR] Burst export failed: {exc}", flush=True)
                import traceback
                traceback.print_exc()

            try:
                self._print_stats()
            except Exception as exc:  # noqa: BLE001
                print(f"[ERROR] Capture statistics failed: {exc}", flush=True)
                import traceback
                traceback.print_exc()

    def _handle_packet(self, raw_packet) -> None:
        # Do not print provisional UNKNOWN states for active flows. The dashboard
        # receives a row only after PacketProcessor finalizes the Flow.
        self.processor.process(raw_packet)
        self._publish_finalized_flows()

    def _publish_finalized_flows(self) -> None:
        """Append newly finalized Flow decisions for the dashboard to consume."""
        finalized = self.processor.finalized_flows
        if self._published_flow_count >= len(finalized):
            return

        with self.results_jsonl.open("a", encoding="utf-8") as handle:
            for flow in finalized[self._published_flow_count:]:
                result = flow.identification_result

                # The dashboard feed contains only confirmed AppID decisions.
                # UNKNOWN / pending / unclassified flows remain internal to the
                # pipeline and are deliberately not written to the results JSONL.
                if (
                    result is None
                    or result.status.value != "CLASSIFIED"
                    or not isinstance(result.application, str)
                    or not result.application.strip()
                    or result.application.strip().upper() == "UNKNOWN"
                    or result.method is None
                ):
                    continue

                client = flow.client_endpoint
                remote = flow.remote_endpoint
                record = {
                    "session_id": flow.session_id,
                    "flow_id": flow.flow_id,
                    "src_ip": client.ip if client else None,
                    "src_port": client.port if client else None,
                    "dst_ip": remote.ip if remote else None,
                    "dst_port": remote.port if remote else None,
                    "protocol": flow.key.protocol.value,
                    "application": result.application if result and result.application else "UNKNOWN",
                    "method": result.method.value if result and result.method else "-",
                    "reason": result.reason_code if result else "not_classified",
                    "confidence": result.confidence if result else None,
                    "first_seen": flow.first_seen,
                    "last_seen": flow.last_seen,
                    "packets": len(flow.packets),
                    "status": result.status.value if result else "UNKNOWN",
                }
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            handle.flush()

        self._published_flow_count = len(finalized)
        print(
            f"[APPID] Published {self._published_flow_count} finalized flows "
            f"to {self.results_jsonl}",
            flush=True,
        )

    def _write_burst_outputs(self) -> None:
        if self.burst_jsonl is not None:
            path = write_bursts_jsonl(self.processor.bursts, self.burst_jsonl)
            print(f"Burst JSONL: {path} ({len(self.processor.bursts)} records)")
        if self.burst_tsv is not None:
            path = write_bursts_tsv(self.processor.bursts, self.burst_tsv)
            print(f"Burst TSV  : {path} ({len(self.processor.bursts)} records)")

    def _print_stats(self) -> None:
        stats = self.processor.stats
        print(
            "Capture summary: "
            f"raw={stats.raw_packets}, parsed={stats.parsed_packets}, "
            f"tracked={stats.tracked_packets}, outside_lan={stats.outside_lan_packets}, "
            f"unsupported={stats.unsupported_packets}, parse_errors={stats.parse_errors}, "
            f"dns_bindings={stats.dns_bindings_created}, "
            f"dns_identified_flows={stats.dns_identified_flows}, "
            f"sni_client_hellos={stats.sni_parsed_client_hellos}, "
            f"sni_identified_flows={stats.sni_identified_flows}, "
            f"sni_unmapped={stats.sni_unmapped_hostnames}, sni_errors={stats.sni_parse_errors}, "
            f"sni_unsupported={stats.sni_unsupported_records}, "
            f"udp_datagrams={stats.udp_datagrams}, udp_protocols={stats.udp_protocols}, "
            f"udp_flows_expired={stats.udp_flows_expired}, "
            f"quic_initial_candidates={stats.quic_initial_candidates}, "
            f"quic_initial_decrypted={stats.quic_initial_decrypted}, "
            f"quic_initial_rejected={stats.quic_initial_rejected}, "
            f"quic_sni_identified_flows={stats.quic_sni_identified_flows}, "
            f"quic_sni_unmapped={stats.quic_sni_unmapped_hostnames}, "
            f"quic_ech={stats.quic_ech_detected}, dns_errors={stats.dns_processing_errors}, "
            f"ml_evaluated={stats.ml_candidates_evaluated}, "
            f"ml_admitted={stats.ml_candidates_admitted}, "
            f"ml_rejected={stats.ml_candidates_rejected}, "
            f"ml_pending={stats.ml_candidates_pending}, "
            f"ml_predictions={stats.ml_predictions}, "
            f"ml_catboost={stats.ml_catboost_predictions}, "
            f"ml_cnn={stats.ml_cnn_predictions}, "
            f"ml_fusion={stats.ml_fusion_predictions}, "
            f"ml_inference_errors={stats.ml_inference_errors}, "
            f"flows_finalized={stats.burst_flows_finalized}, bursts={stats.bursts_created}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Capture traffic on one NIC through the Hybrid AppID pipeline"
    )
    parser.add_argument("--config", default="config/network.json")
    parser.add_argument(
        "--interface",
        help="Explicit NIC name; overrides network.mode/interface in the config",
    )
    parser.add_argument("--burst-jsonl", help="Optional JSONL output for completed Bursts")
    parser.add_argument("--burst-tsv", help="Optional TSV output for completed Bursts")
    parser.add_argument("--results-jsonl", default="artifacts/live-appid-results.jsonl", help="Final AppID results consumed by the dashboard")
    parser.add_argument("--ml-model", help="CatBoost Flow V2 model (.cbm)")
    parser.add_argument("--cnn-model", help="P1.5 CNN1D checkpoint (.pt); requires --ml-model")
    parser.add_argument("--fusion-metrics", help="Late-fusion metrics.json (default: outputs/.../late_fusion/metrics.json)")
    parser.add_argument("--fusion-alpha", type=float, default=None,
                        help="Override validation-selected CatBoost weight (0..1)")
    parser.add_argument(
        "--verbose", action="store_true", help="Print every processed packet (high-volume)"
    )
    args = parser.parse_args()
    SingleNICCapture(
        args.config,
        interface_name=args.interface,
        burst_jsonl=args.burst_jsonl,
        burst_tsv=args.burst_tsv,
        ml_model_path=args.ml_model,
        cnn_model_path=args.cnn_model,
        fusion_metrics_path=args.fusion_metrics,
        fusion_alpha=args.fusion_alpha,
        verbose=args.verbose,
        results_jsonl=args.results_jsonl,
    ).run()


if __name__ == "__main__":
    main()
