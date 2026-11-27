from appid.packet.parser import _packet_length


class FakeRawPacket:
    def __init__(self, captured_length, wirelen_marker=...):
        self.captured_length = captured_length
        if wirelen_marker is not ...:
            self.wirelen = wirelen_marker

    def __len__(self):
        return self.captured_length


def test_packet_length_prefers_original_pcap_wirelen():
    assert _packet_length(FakeRawPacket(128, 278)) == 278


def test_packet_length_falls_back_when_wirelen_is_missing():
    assert _packet_length(FakeRawPacket(128)) == 128


def test_packet_length_falls_back_when_wirelen_is_none_or_invalid():
    assert _packet_length(FakeRawPacket(128, None)) == 128
    assert _packet_length(FakeRawPacket(128, "not-a-length")) == 128


def test_packet_length_falls_back_for_nonpositive_wirelen():
    assert _packet_length(FakeRawPacket(128, 0)) == 128
