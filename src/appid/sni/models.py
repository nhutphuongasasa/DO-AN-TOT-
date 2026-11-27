"""Typed TLS/SNI parsing results. No TLS payload is retained."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SNIParseStatus(str, Enum):
    PARSED = "PARSED"
    NO_SNI = "NO_SNI"
    INVALID_TLS = "INVALID_TLS"
    INCOMPLETE = "INCOMPLETE"
    UNSUPPORTED = "UNSUPPORTED"
    ECH_DETECTED = "ECH_DETECTED"


@dataclass(frozen=True, slots=True)
class TLSClientHello:
    status: SNIParseStatus
    server_name: str | None = None
    legacy_version: int | None = None
    cipher_suites: tuple[int, ...] = ()
    extension_types: tuple[int, ...] = ()
    reason_code: str = ""

    @property
    def has_sni(self) -> bool:
        return self.server_name is not None
