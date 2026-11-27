from appid.domain.models import Direction
from appid.sni.tcp_reassembly import ReassemblyStatus, TCPReassembler


def test_single_segment_emits_immediately():
    r = TCPReassembler()
    out = r.push("f1", Direction.FORWARD, 100, b"hello", timestamp=1)
    assert out.data == b"hello"
    assert out.status is ReassemblyStatus.DATA


def test_syn_sets_expected_sequence_and_payload_segments_are_joined():
    r = TCPReassembler()
    r.push("f1", Direction.FORWARD, 100, syn=True, timestamp=1)
    first = r.push("f1", Direction.FORWARD, 101, b"hello ", timestamp=2)
    second = r.push("f1", Direction.FORWARD, 107, b"world", timestamp=3)
    assert first.data == b"hello "
    assert second.data == b"world"


def test_out_of_order_is_buffered_then_emitted_in_order():
    r = TCPReassembler()
    r.push("f1", Direction.FORWARD, 100, syn=True, timestamp=1)
    later = r.push("f1", Direction.FORWARD, 106, b"world", timestamp=2)
    assert later.status is ReassemblyStatus.BUFFERED
    assert later.data == b""
    earlier = r.push("f1", Direction.FORWARD, 101, b"hello", timestamp=3)
    assert earlier.data == b"helloworld"
    assert r.buffered_bytes == 0


def test_retransmission_does_not_duplicate_delivered_bytes():
    r = TCPReassembler()
    r.push("f1", Direction.FORWARD, 10, b"abc", timestamp=1)
    duplicate = r.push("f1", Direction.FORWARD, 10, b"abc", timestamp=2)
    assert duplicate.data == b""
    assert duplicate.status is ReassemblyStatus.DUPLICATE


def test_overlap_uses_first_seen_bytes_and_emits_only_once():
    r = TCPReassembler()
    r.push("f1", Direction.FORWARD, 100, syn=True, timestamp=1)
    r.push("f1", Direction.FORWARD, 106, b"XYZ", timestamp=2)
    r.push("f1", Direction.FORWARD, 104, b"ab123", timestamp=3)
    result = r.push("f1", Direction.FORWARD, 101, b"123", timestamp=4)
    assert result.data == b"123abXYZ"


def test_directions_and_flow_ids_have_isolated_sequence_spaces():
    r = TCPReassembler()
    a = r.push("f1", Direction.FORWARD, 1, b"client", timestamp=1)
    b = r.push("f1", Direction.BACKWARD, 1, b"server", timestamp=1)
    c = r.push("f2", Direction.FORWARD, 1, b"other", timestamp=1)
    assert (a.data, b.data, c.data) == (b"client", b"server", b"other")


def test_sequence_number_wraparound_is_supported():
    r = TCPReassembler()
    r.push("f1", Direction.FORWARD, 0xFFFFFFFE, syn=True, timestamp=1)
    later = r.push("f1", Direction.FORWARD, 1, b"cd", timestamp=2)
    earlier = r.push("f1", Direction.FORWARD, 0xFFFFFFFF, b"ab", timestamp=3)
    assert later.data == b""
    assert earlier.data == b"abcd"


def test_stream_timeout_and_flow_cleanup_release_memory():
    r = TCPReassembler(idle_timeout=5)
    r.push("f1", Direction.FORWARD, 100, b"", timestamp=1, syn=True)
    r.push("f1", Direction.FORWARD, 106, b"later", timestamp=2)
    assert r.buffered_bytes == 5
    assert r.cleanup(now=7) == 1
    assert r.buffered_bytes == 0
    r.push("f2", Direction.FORWARD, 1, b"", timestamp=8, syn=True)
    r.push("f2", Direction.BACKWARD, 1, b"", timestamp=8, syn=True)
    assert r.close_flow("f2") == 2
    assert r.stream_count == 0


def test_buffer_limit_discards_stream_and_bounds_memory():
    r = TCPReassembler(max_buffered_bytes_per_stream=4,
                       max_buffered_bytes_total=4, max_gap_bytes=100)
    r.push("f1", Direction.FORWARD, 100, syn=True, timestamp=1)
    result = r.push("f1", Direction.FORWARD, 106, b"12345", timestamp=2)
    assert result.status is ReassemblyStatus.BUFFER_LIMIT
    assert result.stream_closed
    assert r.buffered_bytes == 0
    assert r.stream_count == 0


def test_reset_closes_and_releases_directional_stream():
    r = TCPReassembler()
    r.push("f1", Direction.FORWARD, 1, b"", timestamp=1, syn=True)
    result = r.push("f1", Direction.FORWARD, 2, b"", timestamp=2, rst=True)
    assert result.status is ReassemblyStatus.CLOSED
    assert r.stream_count == 0
