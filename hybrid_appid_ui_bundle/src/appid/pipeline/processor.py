
"""Shared live/PCAP packet path with continuous DNS evidence updates."""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from pathlib import Path

from appid.appid.evidence_engine import EvidenceEngine
from appid.dns import (
    ApplicationDomainRules,
    DNSApplicationIdentifier,
    DNSCache,
    DNSParser,
)
from appid.domain.models import (
    Evidence,
    IdentificationMethod,
    IdentificationResult,
    IdentificationStatus,
    PacketRecord,
    TransportProtocol,
)
from appid.flow.identity import normalize_flow_key
from appid.flow.tracker import FlowState, FlowTracker
from appid.ml import (
    BidirectionalFlowReconstructor,
    Burst,
    BurstSegmentationPolicy,
    BurstSegmenter,
    CandidateDecision,
    CandidateState,
    FlowObservationPolicy,
    MLCandidateGate,
)
from appid.ml.burst_statistics import compute_burst_statistics
from appid.ml.flow_aggregation import build_flow_features
from appid.packet.parser import parse_packet
from appid.sni import (
    SNIApplicationIdentifier,
    SNIParseStatus,
    TCPReassembler,
    TLSClientHelloParser,
)
from appid.udp.analyzer import UDPAnalyzer
from appid.udp.protocol_identifier import UDPProtocol

logger = logging.getLogger("appid.pipeline.processor")


@dataclass(slots=True)
class PipelineStats:
    raw_packets: int = 0
    parsed_packets: int = 0
    unsupported_packets: int = 0
    outside_lan_packets: int = 0
    parse_errors: int = 0
    tracked_packets: int = 0

    dns_bindings_created: int = 0
    dns_identified_flows: int = 0
    dns_processing_errors: int = 0
    dns_error_types: dict[str, int] | None = None

    tcp_payload_packets: int = 0
    sni_parsed_client_hellos: int = 0
    sni_identified_flows: int = 0
    sni_unmapped_hostnames: int = 0
    sni_parse_errors: int = 0
    sni_unsupported_records: int = 0
    sni_ech_detected: int = 0

    udp_datagrams: int = 0
    udp_protocols: dict[str, int] | None = None

    quic_initial_candidates: int = 0
    quic_initial_decrypted: int = 0
    quic_initial_rejected: int = 0
    quic_sni_identified_flows: int = 0
    quic_sni_unmapped_hostnames: int = 0
    quic_ech_detected: int = 0
    quic_connection_capacity_evictions: int = 0

    udp_flows_expired: int = 0
    udp_flow_capacity_evictions: int = 0

    ml_candidates_evaluated: int = 0
    ml_candidates_admitted: int = 0
    ml_candidates_rejected: int = 0
    ml_candidates_pending: int = 0

    ml_predictions: int = 0
    ml_catboost_predictions: int = 0
    ml_cnn_predictions: int = 0
    ml_fusion_predictions: int = 0
    ml_inference_errors: int = 0

    burst_flows_finalized: int = 0
    bursts_created: int = 0


class PacketProcessor:
    """Shared packet processing pipeline for live capture and PCAP replay."""

    def __init__(
        self,
        *,
        session_id: str,
        lan_network: str | ipaddress._BaseNetwork,
        dns_rules_path: str | Path | None = None,
        udp_idle_timeout: float = 60.0,
        max_active_udp_flows: int = 10000,
        enable_udp_analysis: bool = True,
        enable_quic_analysis: bool = True,
        flow_observation_policy: FlowObservationPolicy | None = None,
        burst_segmentation_policy: BurstSegmentationPolicy | None = None,
        ml_model_path: str | Path | None = None,
        cnn_model_path: str | Path | None = None,
        fusion_metrics_path: str | Path | None = None,
        fusion_alpha: float | None = None,
    ):
        if udp_idle_timeout <= 0 or max_active_udp_flows < 1:
            raise ValueError("UDP lifecycle limits must be positive")

        self.udp_idle_timeout = float(udp_idle_timeout)
        self.max_active_udp_flows = int(max_active_udp_flows)
        self.enable_udp_analysis = bool(enable_udp_analysis)

        self.session_id = session_id
        self.lan_network = ipaddress.ip_network(lan_network, strict=False)

        self.tracker = FlowTracker(lan_subnets=[self.lan_network])
        self.stats = PipelineStats(
            dns_error_types={},
            udp_protocols={},
        )

        self._next_packet_index = 0

        # DNS
        self.dns_parser = DNSParser()
        self.dns_cache = DNSCache()

        rules_path = (
            Path(dns_rules_path)
            if dns_rules_path
            else Path(__file__).resolve().parents[3]
            / "config"
            / "dns_mapping.yaml"
        )

        self.dns_rules = (
            ApplicationDomainRules.from_yaml(rules_path)
            if rules_path.is_file()
            else ApplicationDomainRules()
        )

        self.dns_identifier = DNSApplicationIdentifier(
            self.dns_cache,
            self.dns_rules,
        )

        # SNI
        self.sni_parser = TLSClientHelloParser()
        self.sni_identifier = SNIApplicationIdentifier(self.dns_rules)

        # Evidence
        self.evidence_engine = EvidenceEngine()

        # ML Candidate Gate
        self.ml_candidate_gate = MLCandidateGate()

        self.flow_observation_policy = (
            flow_observation_policy
            or FlowObservationPolicy(
                min_packets=2,
                min_duration_seconds=0.0,
            )
        )

        self.burst_segmentation_policy = (
            burst_segmentation_policy
            or BurstSegmentationPolicy(
                idle_gap_seconds=0.5,
            )
        )

        self.burst_reconstructor = BidirectionalFlowReconstructor()

        # Burst storage
        self.bursts: list[Burst] = []
        self.finalized_flows: list[FlowState] = []
        self._finalized_flow_ids: set[str] = set()

        # CatBoost + optional CNN1D runtime. Fusion is enabled only when both
        # checkpoints are explicitly configured; DNS/SNI/QUIC remain higher priority.
        if cnn_model_path is not None and ml_model_path is None:
            raise ValueError("--cnn-model requires --ml-model for CatBoost + CNN late fusion")

        self.fusion_alpha = 0.5 if fusion_alpha is None else float(fusion_alpha)
        if not 0.0 <= self.fusion_alpha <= 1.0:
            raise ValueError("fusion_alpha must be in [0, 1]")
        self.ml_inference = None
        self.cnn_inference = None

        if ml_model_path is not None:
            from appid.ml.catboost_inference import CatBoostFlowV2

            self.ml_inference = CatBoostFlowV2(ml_model_path)
            logger.info(
                "[ML][CATBOOST_LOADED] path=%s features=%s classes=%s",
                ml_model_path,
                len(self.ml_inference.feature_names),
                self.ml_inference.classes,
            )

        if cnn_model_path is not None:
            from appid.ml.cnn1d_inference import CNN1DInference
            from appid.ml.late_fusion import load_fusion_alpha

            self.cnn_inference = CNN1DInference(cnn_model_path)
            if fusion_alpha is None:
                metrics_path = (
                    Path(fusion_metrics_path) if fusion_metrics_path is not None
                    else Path(__file__).resolve().parents[3]
                    / "outputs" / "p1_5_full_dataset_wirelen_v2" / "late_fusion" / "metrics.json"
                )
                self.fusion_alpha = load_fusion_alpha(metrics_path, self.ml_inference.classes)
            else:
                self.fusion_alpha = float(fusion_alpha)
                if not 0.0 <= self.fusion_alpha <= 1.0:
                    raise ValueError("fusion_alpha must be in [0, 1]")
            if set(self.ml_inference.classes) != set(self.cnn_inference.classes):
                raise ValueError(
                    "CatBoost and CNN checkpoints must contain the same application classes"
                )
            logger.info(
                "[ML][CNN1D_LOADED] path=%s classes=%s fusion_alpha_catboost=%.3f",
                cnn_model_path,
                self.cnn_inference.classes,
                self.fusion_alpha,
            )

        if ml_model_path is None:
            logger.info("[ML][DISABLED] No model path configured")

        # UDP / QUIC
        self.udp_analyzer = UDPAnalyzer(
            domain_identifier=self.sni_identifier,
            enable_quic=enable_quic_analysis,
        )

        # TCP reassembly for TLS ClientHello
        self.tcp_reassembler = TCPReassembler()
        self._sni_stream_data: dict[str, bytearray] = {}
        self._sni_stream_last_seen: dict[str, float] = {}
        self._sni_done_flows: set[str] = set()
        self._quic_sni_counted_flows: set[str] = set()

    # ------------------------------------------------------------------
    # Main packet processing
    # ------------------------------------------------------------------

    def process(self, raw_packet) -> FlowState | None:
        packet_index = self._next_packet_index
        self._next_packet_index += 1

        self.stats.raw_packets += 1

        try:
            record: PacketRecord | None = parse_packet(
                raw_packet,
                session_id=self.session_id,
                packet_index=packet_index,
            )
        except Exception:
            self.stats.parse_errors += 1
            logger.exception(
                "[PIPELINE][PACKET_PARSE_ERROR] packet=%s",
                packet_index,
            )
            return None

        if record is None:
            self.stats.unsupported_packets += 1
            return None

        self.stats.parsed_packets += 1

        source = ipaddress.ip_address(record.src_ip)
        destination = ipaddress.ip_address(record.dst_ip)

        source_in = (
            source.version == self.lan_network.version
            and source in self.lan_network
        )

        destination_in = (
            destination.version == self.lan_network.version
            and destination in self.lan_network
        )

        if not source_in and not destination_in:
            self.stats.outside_lan_packets += 1
            return None

        # DNS evidence is updated continuously.
        try:
            observation = self.dns_parser.parse(
                raw_packet,
                session_id=self.session_id,
                packet_index=packet_index,
                lan_networks=(self.lan_network,),
            )

            if observation is not None:
                created = self.dns_cache.update(observation)
                self.stats.dns_bindings_created += created

                logger.debug(
                    "[PIPELINE][DNS_OBSERVATION] packet=%s txid=%s "
                    "client=%s resolver=%s qname=%s answers=%s bindings=%s",
                    packet_index,
                    observation.transaction_id,
                    observation.client_ip,
                    observation.resolver_ip,
                    observation.query_name,
                    len(observation.answers),
                    created,
                )

        except Exception as exc:
            self.stats.dns_processing_errors += 1

            error_type = type(exc).__name__
            self.stats.dns_error_types[error_type] = (
                self.stats.dns_error_types.get(error_type, 0) + 1
            )

            logger.exception(
                "[PIPELINE][DNS_PROCESSING_ERROR] packet=%s error_type=%s",
                packet_index,
                error_type,
            )

        # UDP lifecycle management.
        if record.transport is TransportProtocol.UDP:
            expired = self.tracker.expire_udp_flows(
                record.timestamp,
                idle_timeout=self.udp_idle_timeout,
            )

            self.stats.udp_flows_expired += len(expired)
            self._finalize_flows(expired)

            key = normalize_flow_key(record)

            if self.tracker.get_active_flow(key) is None:
                active_udp = [
                    item
                    for item in self.tracker.active_flows
                    if item.key.protocol is TransportProtocol.UDP
                ]

                if len(active_udp) >= self.max_active_udp_flows:
                    oldest = min(
                        active_udp,
                        key=lambda item: item.last_seen,
                    )

                    evicted = self.tracker.close_flow(oldest.flow_id)
                    self._finalize_flows((evicted,))

                    self.stats.udp_flow_capacity_evictions += 1

        # Track packet.
        flow = self.tracker.add_packet(record)
        self.stats.tracked_packets += 1

        # Identification priority:
        # DNS -> TCP SNI -> UDP/QUIC.
        #
        # Classified flows will be rejected by the ML Candidate Gate
        # when they are finalized.

        if self._try_dns_identification(flow):
            return flow

        self._try_sni_identification(
            raw_packet,
            flow,
            record,
        )

        if flow.identification_result is not None:
            return flow

        self._try_udp_identification(
            raw_packet,
            flow,
            record,
        )

        return flow

    # ------------------------------------------------------------------
    # DNS identification
    # ------------------------------------------------------------------

    def _try_dns_identification(self, flow: FlowState) -> bool:
        """Return True when DNS has identified this Flow."""

        current_result = flow.identification_result

        if (
            current_result is not None
            and current_result.method is IdentificationMethod.DNS
        ):
            return True

        if flow.client_endpoint is None or flow.remote_endpoint is None:
            return False

        # DNS transactions are evidence producers, not application flows.
        if (
            flow.key.endpoint_a.port == 53
            or flow.key.endpoint_b.port == 53
        ):
            return False

        result = self.dns_identifier.identify(
            session_id=flow.session_id,
            flow_id=flow.flow_id,
            client_ip=flow.client_endpoint.ip,
            destination_ip=flow.remote_endpoint.ip,
            timestamp=flow.last_seen,
        )

        if result.status != "DNS_IDENTIFIED":
            return False

        dns_evidence = tuple(
            [Evidence("dns_domain", domain) for domain in result.matched_domains]
            + [Evidence("dns_destination_ip", result.destination_ip)]
            + [Evidence("dns_client_ip", result.client_ip or "")]
            + [Evidence("dns_rule_id", rule_id) for rule_id in result.rule_ids]
        )

        # DNS has priority over an earlier SNI result.
        flow.identification_result = IdentificationResult(
            session_id=flow.session_id,
            flow_id=flow.flow_id,
            status=IdentificationStatus.CLASSIFIED,
            application=result.application_id,
            method=IdentificationMethod.DNS,
            reason_code=result.reason_code,
            evidence=dns_evidence,
            metadata={
                "dns_expires_at": result.expires_at,
                "dns_matched_domains": list(result.matched_domains),
            },
        )

        self.stats.dns_identified_flows += 1
        return True

    # ------------------------------------------------------------------
    # TCP SNI identification
    # ------------------------------------------------------------------

    def _try_sni_identification(
        self,
        raw_packet,
        flow: FlowState,
        record: PacketRecord,
    ) -> None:
        """Reassemble the client-to-server TCP stream and inspect ClientHello."""

        if (
            flow.identification_result is not None
            or record.transport is not TransportProtocol.TCP
            or flow.flow_id in self._sni_done_flows
        ):
            return

        expired_before = {
            flow_id
            for flow_id, seen in self._sni_stream_last_seen.items()
            if record.timestamp - seen >= self.tcp_reassembler.idle_timeout
        }

        self.tcp_reassembler.cleanup(record.timestamp)

        for expired_flow_id in expired_before:
            self._sni_stream_data.pop(expired_flow_id, None)
            self._sni_stream_last_seen.pop(expired_flow_id, None)

        if flow.client_endpoint is None or flow.remote_endpoint is None:
            return

        tcp = (
            raw_packet.getlayer("TCP")
            if hasattr(raw_packet, "getlayer")
            else None
        )

        if tcp is None:
            try:
                tcp = raw_packet["TCP"]
            except (KeyError, TypeError, IndexError):
                return

        payload = bytes(tcp.payload)
        flags = int(tcp.flags)

        if payload:
            self.stats.tcp_payload_packets += 1

        direction = flow.packets[-1].direction

        if direction.value != "FORWARD":
            if flags & 0x04:
                self.tcp_reassembler.push(
                    flow.flow_id,
                    direction,
                    int(tcp.seq),
                    b"",
                    timestamp=record.timestamp,
                    rst=True,
                )

                self._sni_stream_data.pop(flow.flow_id, None)
                self._sni_stream_last_seen.pop(flow.flow_id, None)

            return

        if not payload and not (flags & (0x02 | 0x01 | 0x04)):
            return

        reassembled = self.tcp_reassembler.push(
            flow.flow_id,
            direction,
            int(tcp.seq),
            payload,
            timestamp=record.timestamp,
            syn=bool(flags & 0x02),
            fin=bool(flags & 0x01),
            rst=bool(flags & 0x04),
        )

        self._sni_stream_last_seen[flow.flow_id] = record.timestamp

        if (
            reassembled.status.value in ("BUFFER_LIMIT", "STREAM_LIMIT")
            or (
                reassembled.status.value == "CLOSED"
                and not reassembled.data
            )
        ):
            self._sni_stream_data.pop(flow.flow_id, None)
            self._sni_stream_last_seen.pop(flow.flow_id, None)
            return

        if not reassembled.data:
            return

        stream = self._sni_stream_data.setdefault(
            flow.flow_id,
            bytearray(),
        )

        if len(stream) + len(reassembled.data) > 64 * 1024:
            self._sni_stream_data.pop(flow.flow_id, None)
            self._sni_stream_last_seen.pop(flow.flow_id, None)

            self.tcp_reassembler.close_flow(flow.flow_id)
            self.stats.sni_parse_errors += 1
            return

        stream.extend(reassembled.data)
        parsed = self.sni_parser.parse(stream)

        if parsed.status is SNIParseStatus.INCOMPLETE:
            return

        if parsed.status is SNIParseStatus.ECH_DETECTED:
            self.stats.sni_ech_detected += 1

        elif (
            parsed.status is SNIParseStatus.PARSED
            and parsed.server_name
        ):
            self.stats.sni_parsed_client_hellos += 1

            match = self.sni_identifier.identify(parsed.server_name)

            if match.application_id:
                self._apply_sni_result(
                    flow,
                    parsed.server_name,
                    match.application_id,
                    match.rule_ids,
                )
            else:
                self.stats.sni_unmapped_hostnames += 1

        elif parsed.status is SNIParseStatus.INVALID_TLS:
            self.stats.sni_parse_errors += 1

        elif parsed.status is SNIParseStatus.UNSUPPORTED:
            self.stats.sni_unsupported_records += 1

        self._sni_done_flows.add(flow.flow_id)
        self._sni_stream_data.pop(flow.flow_id, None)
        self._sni_stream_last_seen.pop(flow.flow_id, None)

        self.tcp_reassembler.close_flow(flow.flow_id)

    # ------------------------------------------------------------------
    # UDP / QUIC identification
    # ------------------------------------------------------------------

    def _try_udp_identification(
        self,
        raw_packet,
        flow: FlowState,
        record: PacketRecord,
    ) -> None:
        if (
            flow.identification_result is not None
            or record.transport is not TransportProtocol.UDP
            or not self.enable_udp_analysis
        ):
            return

        udp = (
            raw_packet.getlayer("UDP")
            if hasattr(raw_packet, "getlayer")
            else None
        )

        if udp is None:
            try:
                udp = raw_packet["UDP"]
            except (KeyError, TypeError, IndexError):
                return

        payload = bytes(udp.payload)

        self.stats.udp_datagrams += 1

        analysis = self.udp_analyzer.analyze(
            payload,
            src_port=record.src_port or 0,
            dst_port=record.dst_port or 0,
            flow_id=flow.flow_id,
            timestamp=record.timestamp,
        )

        protocol_key = analysis.protocol.value

        if analysis.protocol is not UDPProtocol.UNKNOWN:
            flow.application_protocol = (
                "QUIC_INITIAL"
                if analysis.decrypt_status == "DECRYPTED"
                else analysis.protocol.value
            )

        self.stats.udp_protocols[protocol_key] = (
            self.stats.udp_protocols.get(protocol_key, 0) + 1
        )

        if analysis.protocol is UDPProtocol.QUIC_INITIAL_CANDIDATE:
            self.stats.quic_initial_candidates += 1

            if analysis.decrypt_status == "DECRYPTED":
                self.stats.quic_initial_decrypted += 1

            elif analysis.decrypt_status == "REJECTED":
                self.stats.quic_initial_rejected += 1

        if analysis.ech_detected:
            self.stats.quic_ech_detected += 1

        if analysis.hostname and analysis.application_id:
            self.evidence_engine.apply_sni(
                flow=flow,
                hostname=analysis.hostname,
                application=analysis.application_id,
                source="quic_tls_sni",
                rule_ids=analysis.rule_ids,
            )

            if flow.flow_id not in self._quic_sni_counted_flows:
                self.stats.quic_sni_identified_flows += 1
                self._quic_sni_counted_flows.add(flow.flow_id)

        elif analysis.hostname:
            self.stats.quic_sni_unmapped_hostnames += 1

        self.stats.quic_connection_capacity_evictions = (
            self.udp_analyzer.quic_tracker.capacity_evictions
        )

        if analysis.connection_id:
            flow.quic_connection_id = analysis.connection_id
            flow.application_protocol = "QUIC_INITIAL"

            current = flow.identification_result

            if current is not None:
                flow.identification_result = IdentificationResult(
                    session_id=current.session_id,
                    flow_id=current.flow_id,
                    status=current.status,
                    application=current.application,
                    method=current.method,
                    reason_code=current.reason_code,
                    evidence=current.evidence,
                    confidence=current.confidence,
                    model_versions=current.model_versions,
                    metadata={
                        **current.metadata,
                        "quic_connection_id": analysis.connection_id,
                        "application_protocol": "QUIC_INITIAL",
                    },
                )

    # ------------------------------------------------------------------
    # SNI result
    # ------------------------------------------------------------------

    def _apply_sni_result(
        self,
        flow: FlowState,
        hostname: str,
        application: str,
        rule_ids: tuple[str, ...],
    ) -> None:
        evidence = (
            Evidence("tls_sni", hostname),
        ) + tuple(
            Evidence("sni_rule_id", rule_id)
            for rule_id in rule_ids
        )

        current = flow.identification_result

        if current is not None:
            return

        flow.identification_result = IdentificationResult(
            session_id=flow.session_id,
            flow_id=flow.flow_id,
            status=IdentificationStatus.CLASSIFIED,
            application=application,
            method=IdentificationMethod.SNI,
            reason_code="SNI_HOSTNAME_RULE_MATCH",
            evidence=evidence,
            confidence=1.0,
            metadata={
                "sni_hostname": hostname,
            },
        )

        self.stats.sni_identified_flows += 1

    # ------------------------------------------------------------------
    # ML Candidate Gate
    # ------------------------------------------------------------------

    def evaluate_ml_candidate(
        self,
        flow: FlowState,
        *,
        policy: FlowObservationPolicy | None = None,
    ) -> CandidateDecision:
        """Evaluate a Flow; this method does not execute model inference."""

        return self.ml_candidate_gate.evaluate(
            flow,
            policy=policy,
        )

    # ------------------------------------------------------------------
    # CatBoost Flow V2 inference
    # ------------------------------------------------------------------

    def _classify_flow_with_ml(
        self,
        flow: FlowState,
        bursts: list[Burst],
    ) -> None:
        """Run CatBoost and optional CNN1D, then weighted probability fusion."""
        if self.ml_inference is None or not bursts:
            return
        if flow.identification_result is not None:
            logger.debug("[ML][SKIP] flow=%s reason=already_classified", flow.flow_id)
            return

        try:
            from appid.ml.late_fusion import weighted_late_fusion

            flow_features = build_flow_features(bursts)
            if len(flow_features) != 70:
                raise ValueError(f"Expected 70 Flow features, got {len(flow_features)}")

            catboost_prediction = self.ml_inference.predict(flow_features)
            catboost_probabilities = catboost_prediction["probabilities"]
            self.stats.ml_catboost_predictions += 1

            model_versions = {"catboost_flow_v2": catboost_prediction["model"]}
            metadata = {
                "catboost_probabilities": catboost_probabilities,
                "feature_count": catboost_prediction["feature_count"],
                "feature_schema": "catboost_flow_v2_wirelen_70",
            }
            evidence = [
                Evidence("catboost_model", catboost_prediction["model"]),
                Evidence("catboost_feature_count", str(catboost_prediction["feature_count"])),
            ]
            probabilities = catboost_probabilities
            reason_code = "CATBOOST_FLOW_V2_PREDICTION"

            if self.cnn_inference is not None:
                from appid.ml.sequence import build_burst_sequence

                sequence = build_burst_sequence(bursts)
                try:
                    cnn_prediction = self.cnn_inference.predict(sequence.bursts)
                except Exception as cnn_error:
                    # Preserve service availability: a CNN runtime failure degrades
                    # to the already-computed CatBoost result and remains observable.
                    self.stats.ml_inference_errors += 1
                    logger.exception(
                        "[ML][CNN1D_ERROR_CATBOOST_FALLBACK] flow=%s", flow.flow_id
                    )
                    metadata["cnn_fallback_error"] = str(cnn_error)
                    reason_code = "CATBOOST_FALLBACK_CNN1D_ERROR"
                else:
                    cnn_probabilities = cnn_prediction["probabilities"]
                    self.stats.ml_cnn_predictions += 1
                    probabilities = weighted_late_fusion(
                        catboost_probabilities,
                        cnn_probabilities,
                        alpha_catboost=self.fusion_alpha,
                    )
                    self.stats.ml_fusion_predictions += 1
                    model_versions["cnn1d"] = cnn_prediction["model"]
                    metadata.update({
                        "cnn_probabilities": cnn_probabilities,
                        "fusion_probabilities": probabilities,
                        "fusion_alpha_catboost": self.fusion_alpha,
                        "fusion_alpha_cnn": 1.0 - self.fusion_alpha,
                        "cnn_feature_count": cnn_prediction["feature_count"],
                        "sequence_length": sequence.sequence_length,
                        "cnn_tensor_shape": cnn_prediction["tensor_shape"],
                    })
                    evidence.extend((
                        Evidence("cnn1d_model", cnn_prediction["model"]),
                        Evidence("late_fusion_alpha_catboost", str(self.fusion_alpha)),
                    ))
                    reason_code = "CATBOOST_CNN1D_WEIGHTED_LATE_FUSION"

            application = max(probabilities, key=probabilities.get)
            confidence = float(probabilities[application])
            metadata["probabilities"] = probabilities
            flow.identification_result = IdentificationResult(
                session_id=flow.session_id,
                flow_id=flow.flow_id,
                status=IdentificationStatus.CLASSIFIED,
                application=application,
                method=IdentificationMethod.BURST_FUSION,
                reason_code=reason_code,
                evidence=tuple(evidence),
                confidence=confidence,
                model_versions=model_versions,
                metadata=metadata,
            )
            self.stats.ml_predictions += 1
            logger.info(
                "[ML][PREDICTION] flow=%s app=%s confidence=%.4f method=%s",
                flow.flow_id, application, confidence, reason_code,
            )
        except Exception:
            self.stats.ml_inference_errors += 1
            logger.exception("[ML][INFERENCE_ERROR] flow=%s", flow.flow_id)

    # ------------------------------------------------------------------
    # Flow finalization
    # ------------------------------------------------------------------

    def _finalize_flows(
        self,
        flows: tuple[FlowState, ...] | list[FlowState],
    ) -> None:
        """Gate, segment and classify each completed Flow exactly once."""

        for flow in flows:
            if flow.flow_id in self._finalized_flow_ids:
                continue

            self._finalized_flow_ids.add(flow.flow_id)
            self.stats.burst_flows_finalized += 1

            # DNS/SNI/QUIC-classified flows are rejected here.
            decision = self.ml_candidate_gate.evaluate(
                flow,
                policy=self.flow_observation_policy,
            )

            self.stats.ml_candidates_evaluated += 1

            if decision.state is CandidateState.REJECTED:
                self.stats.ml_candidates_rejected += 1
                self.finalized_flows.append(flow)
                continue

            if (
                decision.state is CandidateState.PENDING
                or decision.observation is None
            ):
                self.stats.ml_candidates_pending += 1
                self.finalized_flows.append(flow)
                continue

            self.stats.ml_candidates_admitted += 1

            # Reconstruct from the canonical completed Flow.
            observation = self.burst_reconstructor.reconstruct(flow)

            created = BurstSegmenter.segment(
                observation,
                self.burst_segmentation_policy,
            )

            self.bursts.extend(created)
            self.stats.bursts_created += len(created)

            # Run inference only after successful segmentation.
            self._classify_flow_with_ml(
                flow,
                created,
            )
            self.finalized_flows.append(flow)

    # ------------------------------------------------------------------
    # Session close
    # ------------------------------------------------------------------

    def close(self) -> tuple[FlowState, ...]:
        """Close session resources and finalize remaining Flows."""

        self.dns_parser.close()

        for flow in self.tracker.active_flows:
            self.tcp_reassembler.close_flow(flow.flow_id)

        self._sni_stream_data.clear()
        self._sni_stream_last_seen.clear()
        self._sni_done_flows.clear()
        self._quic_sni_counted_flows.clear()

        closed = self.tracker.close_session(self.session_id)

        self._finalize_flows(closed)

        return closed
