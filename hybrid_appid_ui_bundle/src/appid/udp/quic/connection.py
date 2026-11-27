"""Stateful QUIC v1 Initial inspection and ClientHello/SNI extraction."""
from __future__ import annotations

from dataclasses import dataclass

from appid.sni.tls_parser import TLSClientHelloParser
from appid.udp.quic.crypto import decrypt_initial
from appid.udp.quic.crypto_reassembly import CryptoStreamReassembler
from appid.udp.quic.frame_parser import parse_frames
from appid.udp.quic.header import QUICParseError, parse_initial_header


@dataclass(frozen=True, slots=True)
class QUICInitialResult:
    status: str
    version: int | None = None
    sender_role: str | None = None
    packet_number: int | None = None
    dcid: bytes = b""
    scid: bytes = b""
    sni: str | None = None
    ech_detected: bool = False
    reason_code: str = ""
    frame_types: tuple[int,...] = ()

class QUICInitialConnection:
    def __init__(self, *, original_dcid: bytes | None = None, max_crypto_bytes: int=1_048_576) -> None:
        self.original_dcid=bytes(original_dcid) if original_dcid is not None else None
        self.streams={"client":CryptoStreamReassembler(max_bytes=max_crypto_bytes),
                      "server":CryptoStreamReassembler(max_bytes=max_crypto_bytes)}
        self.largest_pn={"client":None,"server":None}
        self.tls_parser=TLSClientHelloParser()

    def process_datagram(self, datagram: bytes) -> QUICInitialResult:
        try:
            header=parse_initial_header(datagram)
            # First observed client Initial establishes the original DCID. A server Initial
            # requires this connection context because its packet DCID is the client's SCID.
            key_dcid = self.original_dcid
            plaintext,pn,role=decrypt_initial(datagram,header,original_dcid=key_dcid,
                                               largest_received=self.largest_pn)
            if self.original_dcid is None:
                if role != "client":
                    raise QUICParseError("ORIGINAL_DCID_REQUIRED_FOR_SERVER_INITIAL")
                self.original_dcid = header.dcid
            self.largest_pn[role]=pn if self.largest_pn[role] is None else max(self.largest_pn[role],pn)
            frames=parse_frames(plaintext)
            stream=self.streams[role]
            handshake=b""
            for frame in frames.crypto_frames: handshake=stream.add(frame.offset,frame.data)
            sni=None; ech=False; reason="INITIAL_DECRYPTED"
            if len(handshake)>=4 and handshake[0]==1:
                length=int.from_bytes(handshake[1:4],"big")
                if length <= len(handshake)-4:
                    # QUIC carries TLS handshake messages directly, without TLS record framing.
                    record=b"\x16\x03\x03"+(len(handshake)).to_bytes(2,"big")+handshake
                    parsed=self.tls_parser.parse(record)
                    sni=parsed.server_name; ech=parsed.status.value == "ECH_DETECTED"
                    reason=parsed.reason_code
            return QUICInitialResult("DECRYPTED",1,role,pn,header.dcid,header.scid,sni,ech,reason,frames.frame_types)
        except (QUICParseError, ValueError) as exc:
            return QUICInitialResult("REJECTED",reason_code=str(exc))

