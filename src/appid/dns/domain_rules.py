"""Verified Application Domain Rules with label-aware exact/suffix matching."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


def normalize_domain(value: str) -> str:
    value = value.strip().rstrip(".").lower()
    if not value:
        raise ValueError("domain must not be empty")
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid IDN domain: {value}") from exc


@dataclass(frozen=True, slots=True)
class DomainRule:
    application_id: str
    rule_id: str
    domain: str
    match: str


class ApplicationDomainRules:
    def __init__(self, rules: list[DomainRule] | tuple[DomainRule, ...] = ()) -> None:
        normalized: list[DomainRule] = []
        seen: set[str] = set()
        for rule in rules:
            domain = normalize_domain(rule.domain)
            if rule.match not in {"exact", "suffix"}:
                raise ValueError("domain rule match must be 'exact' or 'suffix'")
            if not rule.application_id or not rule.rule_id:
                raise ValueError("application_id and rule_id are required")
            if rule.rule_id in seen:
                raise ValueError(f"duplicate domain rule_id: {rule.rule_id}")
            seen.add(rule.rule_id)
            normalized.append(DomainRule(rule.application_id, rule.rule_id, domain, rule.match))
        self.rules = tuple(normalized)

    @classmethod
    def from_yaml(cls, path: str | Path) -> ApplicationDomainRules:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if data.get("version") != 1:
            raise ValueError("dns_mapping.yaml must declare version: 1")
        rules: list[DomainRule] = []
        for app in data.get("applications", []):
            for item in app.get("domains", []):
                rules.append(DomainRule(
                    application_id=str(app["application_id"]),
                    rule_id=str(item["rule_id"]),
                    domain=str(item["domain"]),
                    match=str(item.get("match", "suffix")),
                ))
        return cls(rules)

    def match(self, domain: str) -> tuple[DomainRule, ...]:
        candidate = normalize_domain(domain)
        matches: list[DomainRule] = []
        for rule in self.rules:
            if rule.match == "exact" and candidate == rule.domain or rule.match == "suffix" and (candidate == rule.domain or candidate.endswith("." + rule.domain)):
                matches.append(rule)
        if not matches:
            return ()
        # Exact wins over suffix; among suffix rules, most-specific (longest) wins.
        priority = max((2 if r.match == "exact" else 1, len(r.domain)) for r in matches)
        return tuple(r for r in matches if (2 if r.match == "exact" else 1, len(r.domain)) == priority)
