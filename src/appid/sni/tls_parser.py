"""Bounded TLS record and ClientHello parser for extracting visible SNI.

This parser consumes a complete TLS record beginning at the TCP payload. TCP
stream reassembly is deliberately out of scope for P0.6.1.
"""
from __future__ import annotations

from appid.sni.models import SNIParseStatus, TLSClientHello


class _NeedMoreData(Exception):
    pass


class _Malformed(Exception):
    pass


class _Cursor:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def take(self, size: int) -> bytes:
        if size < 0:
            raise _Malformed
        end = self.offset + size
        if end > len(self.data):
            raise _NeedMoreData
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def remaining(self) -> int:
        return len(self.data) - self.offset


def normalize_server_name(value: str) -> str:
    """Normalize and validate a DNS hostname from the SNI host_name field."""
    if not value or "\x00" in value or any(ch.isspace() for ch in value):
        raise ValueError("invalid hostname characters")
    name = value.rstrip(".").lower()
    if not name or len(name) > 253:
        raise ValueError("invalid hostname length")
    try:
        ascii_name = name.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid IDNA hostname") from exc
    labels = ascii_name.split(".")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
           or any(not (c.isalnum() or c == "-") for c in label) for label in labels):
        raise ValueError("invalid DNS label")
    return ascii_name


class TLSClientHelloParser:
    """Parse a TLS record containing a ClientHello and extract SNI."""

    MAX_RECORD_LENGTH = 18432
    MAX_HANDSHAKE_LENGTH = 1_048_576
    ECH_EXTENSION_TYPES = {0xFE0D}

    def parse(self, data: bytes | bytearray | memoryview) -> TLSClientHello:
        try:
            raw = bytes(data)
        except (TypeError, ValueError):
            return self._result(SNIParseStatus.INVALID_TLS, "INPUT_NOT_BYTES")
        if not raw:
            return self._result(SNIParseStatus.INCOMPLETE, "EMPTY_INPUT")
        try:
            record = _Cursor(raw)
            content_type = record.u8()
            major, minor = record.take(2)
            record_length = record.u16()
            if content_type != 22:
                return self._result(SNIParseStatus.UNSUPPORTED, "NOT_HANDSHAKE_RECORD")
            if major != 3 or minor > 4:
                return self._result(SNIParseStatus.UNSUPPORTED, "UNSUPPORTED_RECORD_VERSION")
            if record_length > self.MAX_RECORD_LENGTH:
                raise _Malformed
            record_bytes = record.take(record_length)
            hs = _Cursor(record_bytes)
            handshake_type = hs.u8()
            handshake_length = int.from_bytes(hs.take(3), "big")
            if handshake_length > self.MAX_HANDSHAKE_LENGTH:
                raise _Malformed
            if handshake_type != 1:
                return self._result(SNIParseStatus.UNSUPPORTED, "NOT_CLIENT_HELLO")
            if handshake_length > hs.remaining():
                raise _Malformed
            body = hs.take(handshake_length)
            try:
                return self._parse_client_hello(body)
            except _NeedMoreData as exc:
                # The enclosing TLS record and handshake are complete; a
                # nested vector claiming more bytes than its parent is malformed.
                raise _Malformed from exc
        except _NeedMoreData:
            return self._result(SNIParseStatus.INCOMPLETE, "TRUNCATED_TLS_RECORD_OR_HANDSHAKE")
        except _Malformed:
            return self._result(SNIParseStatus.INVALID_TLS, "MALFORMED_TLS_LENGTH")
        except (IndexError, OverflowError, TypeError, ValueError):
            return self._result(SNIParseStatus.INVALID_TLS, "MALFORMED_CLIENT_HELLO")

    def _parse_client_hello(self, body: bytes) -> TLSClientHello:
        cur = _Cursor(body)
        legacy_version = cur.u16()
        cur.take(32)  # Random
        session_id_length = cur.u8()
        if session_id_length > 32:
            raise _Malformed
        cur.take(session_id_length)
        cipher_length = cur.u16()
        if cipher_length < 2 or cipher_length % 2:
            raise _Malformed
        cipher_bytes = cur.take(cipher_length)
        ciphers = tuple(int.from_bytes(cipher_bytes[i:i + 2], "big")
                        for i in range(0, len(cipher_bytes), 2))
        compression_length = cur.u8()
        if compression_length < 1:
            raise _Malformed
        cur.take(compression_length)
        if cur.remaining() == 0:
            return TLSClientHello(SNIParseStatus.NO_SNI, legacy_version=legacy_version,
                                  cipher_suites=ciphers, reason_code="NO_EXTENSIONS")
        extensions_length = cur.u16()
        if extensions_length != cur.remaining():
            raise _Malformed
        extensions = _Cursor(cur.take(extensions_length))
        extension_types: list[int] = []
        server_name: str | None = None
        sni_extension_seen = False
        ech = False
        while extensions.remaining():
            ext_type = extensions.u16()
            ext_length = extensions.u16()
            ext_data = extensions.take(ext_length)
            extension_types.append(ext_type)
            if ext_type in self.ECH_EXTENSION_TYPES:
                ech = True
            if ext_type == 0:  # server_name
                if sni_extension_seen:
                    raise _Malformed
                sni_extension_seen = True
                server_name = self._parse_sni_extension(ext_data)
        if ech:
            return TLSClientHello(SNIParseStatus.ECH_DETECTED, server_name,
                                  legacy_version, ciphers, tuple(extension_types),
                                  "ENCRYPTED_CLIENT_HELLO_EXTENSION")
        if server_name is None:
            return TLSClientHello(SNIParseStatus.NO_SNI, None, legacy_version,
                                  ciphers, tuple(extension_types), "SNI_EXTENSION_ABSENT")
        return TLSClientHello(SNIParseStatus.PARSED, server_name, legacy_version,
                              ciphers, tuple(extension_types), "SNI_EXTRACTED")

    @staticmethod
    def _parse_sni_extension(data: bytes) -> str | None:
        cur = _Cursor(data)
        list_length = cur.u16()
        if list_length != cur.remaining() or list_length == 0:
            raise _Malformed
        names = _Cursor(cur.take(list_length))
        host_name: str | None = None
        while names.remaining():
            name_type = names.u8()
            name_length = names.u16()
            raw_name = names.take(name_length)
            if name_type == 0:
                if host_name is not None or name_length == 0:
                    raise _Malformed
                try:
                    host_name = raw_name.decode("ascii")
                except UnicodeDecodeError as exc:
                    raise _Malformed from exc
        if host_name is None:
            return None
        try:
            return normalize_server_name(host_name)
        except ValueError as exc:
            raise _Malformed from exc

    @staticmethod
    def _result(status: SNIParseStatus, reason: str) -> TLSClientHello:
        return TLSClientHello(status=status, reason_code=reason)
