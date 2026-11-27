"""Map visible TLS SNI hostnames to the project's approved AppID labels."""
from __future__ import annotations

from dataclasses import dataclass

from appid.dns.domain_rules import ApplicationDomainRules


@dataclass(frozen=True, slots=True)
class SNIIdentification:
    application_id: str | None
    server_name: str
    rule_ids: tuple[str, ...] = ()
    reason_code: str = "SNI_DOMAIN_UNMAPPED"


class SNIApplicationIdentifier:
    """Reuse the reviewed application-domain policy; never guess generic providers."""

    def __init__(self, rules: ApplicationDomainRules) -> None:
        self.rules = rules

    def identify(self, server_name: str) -> SNIIdentification:
        matches = self.rules.match(server_name)
        applications = {rule.application_id for rule in matches}
        if len(applications) != 1:
            return SNIIdentification(None, server_name, (),
                                     "SNI_DOMAIN_UNMAPPED" if not matches else "SNI_RULE_AMBIGUOUS")
        application = next(iter(applications))
        return SNIIdentification(application, server_name,
                                tuple(sorted(rule.rule_id for rule in matches)),
                                "SNI_HOSTNAME_RULE_MATCH")
