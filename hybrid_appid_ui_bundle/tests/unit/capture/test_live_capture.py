import ipaddress
import json
from types import SimpleNamespace

from appid.capture import live
from appid.network.interfaces import SelectedInterface


class FakeProcessor:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.bursts = []
        self.stats = SimpleNamespace()


def test_cli_interface_override_uses_manual_selection(tmp_path, monkeypatch):
    config_path = tmp_path / "network.json"
    config_path.write_text(
        json.dumps({"network": {"mode": "auto", "interface": None}}),
        encoding="utf-8",
    )
    selected = SelectedInterface(
        "wlp62s0", "192.168.133.251", ipaddress.ip_network("192.168.128.0/21")
    )
    seen = {}

    def fake_select_interface(config):
        seen.update(config)
        return selected

    monkeypatch.setattr(live, "select_interface", fake_select_interface)
    monkeypatch.setattr(live, "PacketProcessor", FakeProcessor)

    capture = live.SingleNICCapture(config_path, interface_name="wlp62s0")

    assert capture.interface == selected
    assert seen == {"mode": "manual", "interface": "wlp62s0"}
    assert capture.processor.kwargs["lan_network"] == selected.network


def test_live_capture_burst_exports_are_optional_and_writable(tmp_path, monkeypatch):
    config_path = tmp_path / "network.json"
    config_path.write_text(
        json.dumps({"network": {"mode": "auto", "interface": None}}),
        encoding="utf-8",
    )
    selected = SelectedInterface(
        "wlp62s0", "192.168.133.251", ipaddress.ip_network("192.168.128.0/21")
    )
    monkeypatch.setattr(live, "select_interface", lambda config: selected)
    monkeypatch.setattr(live, "PacketProcessor", FakeProcessor)

    jsonl_path = tmp_path / "out" / "bursts.jsonl"
    tsv_path = tmp_path / "out" / "bursts.tsv"
    capture = live.SingleNICCapture(
        config_path, burst_jsonl=jsonl_path, burst_tsv=tsv_path
    )
    capture._write_burst_outputs()

    assert jsonl_path.read_text(encoding="utf-8") == ""
    assert tsv_path.read_text(encoding="utf-8").startswith("session_id\tflow_id\tburst_index\t")
