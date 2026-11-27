import ipaddress

import pytest

from appid.capture.live import SelectedInterface, select_interface


def test_manual_interface_selection(monkeypatch):
    chosen = SelectedInterface("enp3s0", "192.168.5.10", ipaddress.ip_network("192.168.5.0/24"))
    monkeypatch.setattr("appid.network.interfaces.discover_usable_interfaces", lambda: (chosen,))
    assert select_interface({"mode": "manual", "interface": "enp3s0"}) == chosen


def test_manual_missing_interface_fails(monkeypatch):
    monkeypatch.setattr("appid.network.interfaces.discover_usable_interfaces", lambda: ())
    with pytest.raises(RuntimeError, match="unavailable"):
        select_interface({"mode": "manual", "interface": "eth99"})


def test_auto_selects_first_discovered(monkeypatch):
    first = SelectedInterface("enp3s0", "192.168.5.10", ipaddress.ip_network("192.168.5.0/24"))
    second = SelectedInterface("wlan0", "10.0.0.2", ipaddress.ip_network("10.0.0.0/24"))
    monkeypatch.setattr("appid.network.interfaces.discover_usable_interfaces", lambda: (first, second))
    assert select_interface({"mode": "auto"}) == first


def test_invalid_mode_fails():
    with pytest.raises(ValueError, match="network.mode"):
        select_interface({"mode": "all"})
