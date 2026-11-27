"""Bounded offset-based QUIC CRYPTO stream reassembly."""
from __future__ import annotations


class CryptoReassemblyError(ValueError): pass

class CryptoStreamReassembler:
    def __init__(self, *, max_bytes: int = 1_048_576) -> None:
        self.max_bytes=max_bytes; self.max_segments=4096
        self._segments: dict[int, bytes]={}; self._contiguous=bytearray()

    def add(self, offset: int, data: bytes) -> bytes:
        chunk=bytes(data)
        if offset < 0 or offset+len(chunk) > self.max_bytes: raise CryptoReassemblyError("CRYPTO_RANGE_LIMIT")
        if not chunk: return bytes(self._contiguous)
        end=offset+len(chunk)
        existing=self._segments.get(offset)
        if existing is not None:
            if existing.startswith(chunk): return bytes(self._contiguous)
            if chunk.startswith(existing):
                del self._segments[offset]
            else:
                raise CryptoReassemblyError("CRYPTO_OVERLAP_CONFLICT")
        if offset not in self._segments and len(self._segments) >= self.max_segments:
            raise CryptoReassemblyError("CRYPTO_SEGMENT_LIMIT")
        buffered=sum(len(value) for value in self._segments.values() if value is not existing)
        if buffered + len(chunk) > self.max_bytes:
            raise CryptoReassemblyError("CRYPTO_BUFFER_LIMIT")
        # Reject conflicting overlap; identical retransmissions are harmless.
        for old_off, old in self._segments.items():
            lo=max(offset,old_off); hi=min(end,old_off+len(old))
            if lo < hi and chunk[lo-offset:hi-offset] != old[lo-old_off:hi-old_off]:
                raise CryptoReassemblyError("CRYPTO_OVERLAP_CONFLICT")
        self._segments[offset]=chunk
        while True:
            next_off=len(self._contiguous)
            candidates=[(o,b) for o,b in self._segments.items() if o <= next_off < o+len(b)]
            if not candidates: break
            o,b=min(candidates,key=lambda x:x[0]); take=b[next_off-o:]
            self._contiguous.extend(take)
            if len(self._contiguous)>self.max_bytes: raise CryptoReassemblyError("CRYPTO_BUFFER_LIMIT")
        return bytes(self._contiguous)
