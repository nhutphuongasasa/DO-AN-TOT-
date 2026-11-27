"""Typed DNS evidence models. These contain metadata only, never application payload."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DNSAnswerRecord:
    owner_name: str
    record_type: str
    value: str
    ttl_seconds: int


@dataclass(frozen=True, slots=True)
class DNSObservation:
    session_id: str
    packet_index: int
    observed_at: float
    client_ip: str | None
    resolver_ip: str
    transaction_id: int
    query_name: str
    query_type: str
    response_code: int
    answers: tuple[DNSAnswerRecord, ...]


@dataclass(frozen=True, slots=True)
class DNSBinding:
    session_id: str
    client_ip: str
    queried_domain: str
    resolved_ip: str
    domain_candidates: tuple[str, ...]
    record_types: tuple[str, ...]
    observed_at: float
    expires_at: float


@dataclass(frozen=True, slots=True)
class DNSCandidate:
    domain: str
    resolved_ip: str
    expires_at: float
    record_types: tuple[str, ...]
    domain_candidates: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DomainRuleMatch:
    application_id: str
    rule_id: str
    domain: str
    match_type: str


@dataclass(frozen=True, slots=True)
class DNSIdentification:
    session_id: str
    flow_id: str
    status: str  # DNS_IDENTIFIED | DNS_UNRESOLVED
    application_id: str | None
    method: str | None
    reason_code: str
    client_ip: str | None
    destination_ip: str
    matched_domains: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] = ()
    expires_at: float | None = None
