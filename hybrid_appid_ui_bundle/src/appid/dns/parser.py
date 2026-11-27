"""Scapy-backed DNS parser with query/response correlation."""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass

from appid.dns.domain_rules import normalize_domain
from appid.dns.models import DNSAnswerRecord, DNSObservation

logger = logging.getLogger("appid.dns.parser")


@dataclass(frozen=True, slots=True)
class _PendingQuery:
    client_ip: str
    client_port: int
    resolver_ip: str
    resolver_port: int
    query_name: str
    query_type: str
    observed_at: float


class DNSParser:
    def __init__(self, *, pending_ttl_seconds: float = 30.0, max_cname_depth: int = 16) -> None:
        if pending_ttl_seconds <= 0 or max_cname_depth < 1:
            raise ValueError("pending_ttl_seconds and max_cname_depth must be positive")
        self.pending_ttl_seconds = pending_ttl_seconds
        self.max_cname_depth = max_cname_depth
        self._pending: dict[tuple, _PendingQuery] = {}
        self.diagnostics: dict[str, int] = {}

    def _count(self, reason: str) -> None:
        self.diagnostics[reason] = self.diagnostics.get(reason, 0) + 1

    def parse(self, raw_packet, *, session_id: str, packet_index: int,
              lan_networks=()) -> DNSObservation | None:
        try:
            from scapy.layers.dns import DNS, DNSQR
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.layers.inet6 import IPv6
            if DNS not in raw_packet:
                return None
            dns = raw_packet[DNS]
            if IP in raw_packet:
                src_ip, dst_ip = raw_packet[IP].src, raw_packet[IP].dst
            elif IPv6 in raw_packet:
                src_ip, dst_ip = raw_packet[IPv6].src, raw_packet[IPv6].dst
            else:
                return None
            if UDP in raw_packet:
                src_port, dst_port, transport = int(raw_packet[UDP].sport), int(raw_packet[UDP].dport), "UDP"
            elif TCP in raw_packet:
                src_port, dst_port, transport = int(raw_packet[TCP].sport), int(raw_packet[TCP].dport), "TCP"
            else:
                return None
            now = float(raw_packet.time)
            self._expire_pending(now)
            # Scapy may leave qdcount/ancount unset on an in-memory packet
            # until it is serialized. The section object itself is authoritative.
            questions = self._section_packets(dns.qd)
            if not questions:
                self._count("DNS_QUESTION_EMPTY")
                logger.debug("[DNS][IGNORE] reason=DNS_QUESTION_EMPTY txid=%s packet=%s", dns.id, packet_index)
                return None
            question = questions[0]
            qname = normalize_domain(question.qname.decode(errors="replace") if isinstance(question.qname, bytes) else str(question.qname))
            qtype_num = int(question.qtype)
            qtype = {1: "A", 28: "AAAA", 5: "CNAME"}.get(qtype_num, str(qtype_num))
            txid = int(dns.id)
            if int(dns.qr) == 0:
                key = (session_id, txid, transport, src_ip, src_port, dst_ip, dst_port)
                self._pending[key] = _PendingQuery(src_ip, src_port, dst_ip, dst_port, qname, qtype, now)
                logger.debug("[DNS][QUERY] txid=%s transport=%s client=%s:%s resolver=%s:%s qname=%s qtype=%s packet=%s", txid, transport, src_ip, src_port, dst_ip, dst_port, qname, qtype, packet_index)
                return None

            key = (session_id, txid, transport, dst_ip, dst_port, src_ip, src_port)
            pending = self._pending.pop(key, None)
            if pending is not None:
                self._count("DNS_RESPONSE_CORRELATED")
            else:
                self._count("DNS_RESPONSE_UNCORRELATED")
            if pending is not None and (pending.query_name != qname or pending.query_type != qtype):
                self._count("DNS_QUERY_RESPONSE_MISMATCH")
                logger.warning("[DNS][CORRELATION_MISMATCH] txid=%s query=%s/%s response=%s/%s", txid, pending.query_name, pending.query_type, qname, qtype)
                return None
            client_ip = pending.client_ip if pending else self._fallback_client(
                dst_ip, src_ip, src_port, lan_networks
            )
            if int(dns.rcode) != 0:
                reason = f"DNS_RCODE_{int(dns.rcode)}"
                self._count(reason)
                logger.debug("[DNS][NEGATIVE_RESPONSE] txid=%s qname=%s rcode=%s", txid, qname, dns.rcode)
                return None
            if dns.an is None:
                self._count("DNS_ANSWER_EMPTY")
                logger.debug("[DNS][IGNORE] reason=DNS_ANSWER_EMPTY txid=%s qname=%s", txid, qname)
                return None
            answers: list[DNSAnswerRecord] = []
            # Scapy 2.8 exposes DNS answer sections as PacketListField lists
            # after packet dissection. Older/in-memory packets may expose a
            # single DNSRR packet with subsequent records chained as payload.
            answer_records = self._section_packets(dns.an)
            logger.debug("[DNS][RESPONSE] txid=%s qname=%s client=%s resolver=%s rcode=%s answer_records=%s correlated=%s packet=%s", txid, pending.query_name if pending else qname, client_ip, src_ip, dns.rcode, len(answer_records), pending is not None, packet_index)
            for rr_index, rr in enumerate(answer_records):
                rtype = int(getattr(rr, "type", 0))
                owner_raw = getattr(rr, "rrname", b"")
                owner = normalize_domain(owner_raw.decode(errors="replace") if isinstance(owner_raw, bytes) else str(owner_raw))
                ttl = max(0, int(getattr(rr, "ttl", 0)))
                value = None
                name = None
                if rtype == 1:
                    try:
                        value = str(ipaddress.IPv4Address(rr.rdata))
                    except ipaddress.AddressValueError:
                        pass
                    name = "A"
                elif rtype == 28:
                    try:
                        value = str(ipaddress.IPv6Address(rr.rdata))
                    except ipaddress.AddressValueError:
                        pass
                    name = "AAAA"
                elif rtype == 5:
                    raw_target = getattr(rr, "rdata", b"")
                    try:
                        value = normalize_domain(raw_target.decode(errors="replace") if isinstance(raw_target, bytes) else str(raw_target))
                    except ValueError:
                        pass
                    name = "CNAME"
                if name and value is not None:
                    answers.append(DNSAnswerRecord(owner, name, value, ttl))
                    logger.debug("[DNS][ANSWER] txid=%s index=%s type=%s owner=%s value=%s ttl=%s", txid, rr_index, name, owner, value, ttl)
                else:
                    self._count("DNS_ANSWER_UNSUPPORTED_OR_INVALID")
                    logger.debug("[DNS][ANSWER_SKIPPED] txid=%s index=%s rrtype=%s owner=%s", txid, rr_index, rtype, owner)
            if not answers:
                self._count("DNS_NO_USABLE_ANSWERS")
                logger.debug("[DNS][IGNORE] reason=DNS_NO_USABLE_ANSWERS txid=%s qname=%s", txid, qname)
                return None
            observation = DNSObservation(session_id, packet_index, now, client_ip, src_ip, txid,
                                  pending.query_name if pending else qname,
                                  pending.query_type if pending else qtype, int(dns.rcode), tuple(answers))
            self._count("DNS_RESPONSE_PARSED")
            return observation
        except (ImportError, AttributeError, IndexError, KeyError, TypeError, ValueError, UnicodeError) as exc:
            reason = f"DNS_PARSE_{type(exc).__name__}"
            self._count(reason)
            logger.exception("[DNS][PARSER_ERROR] packet=%s error_type=%s", packet_index, type(exc).__name__)
            return None

    @staticmethod
    def _section_packets(section) -> list:
        """Flatten Scapy DNS sections, including RR payload chains inside list items.

        Scapy 2.8 dissects DNS sections as PacketListField lists, but a list item
        can itself carry subsequent DNSRR records through its payload chain.
        Walking only the outer list silently drops those records (notably A/AAAA
        records following a CNAME).
        """
        if section is None:
            return []
        roots = list(section) if isinstance(section, (list, tuple)) else [section]
        records = []
        seen: set[int] = set()
        for root in roots:
            current = root
            while current is not None and current.__class__.__name__ != "NoPayload":
                identity = id(current)
                if identity in seen:
                    break
                seen.add(identity)
                # DNS question records (DNSQR) use qname/qtype rather than
                # rrname/type. Keep them too: this helper is shared by qd and an.
                is_answer_record = hasattr(current, "rrname") and hasattr(current, "type")
                is_question_record = hasattr(current, "qname") and hasattr(current, "qtype")
                if is_answer_record or is_question_record:
                    records.append(current)
                payload = getattr(current, "payload", None)
                if payload is None or payload.__class__.__name__ == "NoPayload":
                    break
                # Do not traverse into arbitrary network/application layers.
                payload_is_answer = hasattr(payload, "rrname") and hasattr(payload, "type")
                payload_is_question = hasattr(payload, "qname") and hasattr(payload, "qtype")
                if not (payload_is_answer or payload_is_question):
                    break
                current = payload
        return records

    def close(self) -> None:
        """Release pending query-correlation state at capture-session end."""
        self._pending.clear()

    def _expire_pending(self, now: float) -> None:
        self._pending = {k: v for k, v in self._pending.items()
                         if now - v.observed_at < self.pending_ttl_seconds}

    @staticmethod
    def _fallback_client(response_destination: str, response_source: str, response_source_port: int, lan_networks) -> str | None:
        """Infer client only for a conventional DNS response from source port 53.

        The resolver can itself be inside the LAN (for example, the home router),
        so requiring the response source to be outside the LAN incorrectly rejects
        valid replies. Source port 53 establishes the responder role; the destination
        must still be inside one of the configured LAN networks.
        """
        if response_source_port != 53:
            return None
        dst = ipaddress.ip_address(response_destination)
        networks = []
        for network in lan_networks:
            try:
                networks.append(network if hasattr(network, "version") else ipaddress.ip_network(str(network), strict=False))
            except ValueError:
                continue
        dst_lan = any(dst.version == n.version and dst in n for n in networks)
        return response_destination if dst_lan else None
