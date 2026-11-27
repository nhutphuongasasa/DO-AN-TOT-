"""Deterministic evidence-fusion policy shared by transport analyzers."""
from __future__ import annotations

from appid.domain.models import (
    Evidence,
    IdentificationMethod,
    IdentificationResult,
    IdentificationStatus,
)


class EvidenceEngine:
    """Apply SNI only to Flows that remain unresolved after DNS."""
    def apply_sni(self, *, flow, hostname: str, application: str, source: str,
                  rule_ids: tuple[str, ...] = ()) -> IdentificationResult:
        current = flow.identification_result
        # DNS has higher precedence and is an early exit. Never replace it with SNI.
        if current is not None:
            return current
        evidence = (Evidence(source, hostname),) + tuple(Evidence("sni_rule_id", item) for item in rule_ids)
        method = IdentificationMethod.SNI
        reason = "SNI_HOSTNAME_RULE_MATCH"
        metadata = {"sni_hostname": hostname, "sni_source": source}

        result = IdentificationResult(session_id=flow.session_id, flow_id=flow.flow_id,
            status=IdentificationStatus.CLASSIFIED, application=application, method=method,
            reason_code=reason, evidence=evidence, confidence=1.0, metadata=metadata)
        flow.identification_result = result
        return result
