"""LAN network discovery from the host's active network interfaces."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from dataclasses import dataclass

import psutil


@dataclass(frozen=True, slots=True)
class InterfaceSubnet:
    """A subnet observed on a host network interface."""

    interface: str
    network: ipaddress.IPv4Network | ipaddress.IPv6Network


def discover_interface_subnets(
    *,
    interface_allowlist: Iterable[str] | None = None,
    interface_denylist: Iterable[str] = (),
) -> tuple[InterfaceSubnet, ...]:
    """Discover usable IP subnets from currently-up host interfaces.

    Loopback, link-local, unspecified and multicast addresses are excluded.
    Virtual interfaces are not guessed away: deployments can control them via
    allowlist/denylist because their meaning is environment-specific.
    """
    allowed = set(interface_allowlist) if interface_allowlist is not None else None
    denied = set(interface_denylist)
    discovered: set[InterfaceSubnet] = set()

    addresses_by_interface = psutil.net_if_addrs()
    stats_by_interface = psutil.net_if_stats()
    for interface, addresses in addresses_by_interface.items():
        if allowed is not None and interface not in allowed:
            continue
        if interface in denied:
            continue
        stats = stats_by_interface.get(interface)
        if stats is None or not stats.isup:
            continue

        for address in addresses:
            if address.family not in (socket.AF_INET, socket.AF_INET6):
                continue
            if not address.address or not address.netmask:
                continue
            ip_text = address.address.split("%", 1)[0]
            try:
                ip = ipaddress.ip_address(ip_text)
                network = ipaddress.ip_network(f"{ip}/{address.netmask}", strict=False)
            except ValueError:
                continue
            if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
                continue
            discovered.add(InterfaceSubnet(interface, network))

    return tuple(sorted(discovered, key=lambda item: (item.interface, item.network.version, int(item.network.network_address), item.network.prefixlen)))

@dataclass(frozen=True, slots=True)
class SelectedInterface:
    """The single interface selected for a capture session."""

    name: str
    address: str
    network: ipaddress.IPv4Network | ipaddress.IPv6Network


def discover_usable_interfaces() -> tuple[SelectedInterface, ...]:
    """Return active interfaces with usable unicast IPv4/IPv6 addresses.

    The operating-system enumeration order is preserved for deterministic
    `auto` selection. Loopback and link-local addresses are excluded.
    """
    found: list[SelectedInterface] = []
    addresses_by_interface = psutil.net_if_addrs()
    stats_by_interface = psutil.net_if_stats()
    for name, addresses in addresses_by_interface.items():
        state = stats_by_interface.get(name)
        if name == "lo" or state is None or not state.isup:
            continue
        for address in addresses:
            if address.family not in (socket.AF_INET, socket.AF_INET6):
                continue
            if not address.address or not address.netmask:
                continue
            try:
                ip = ipaddress.ip_address(address.address.split("%", 1)[0])
                network = ipaddress.ip_network(f"{ip}/{address.netmask}", strict=False)
            except ValueError:
                continue
            if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
                continue
            found.append(SelectedInterface(name, str(ip), network))
    return tuple(found)


def select_interface(config: dict) -> SelectedInterface:
    """Select exactly one NIC; manual mode never falls back to another NIC."""
    mode = config.get("mode", "auto")
    candidates = discover_usable_interfaces()
    if mode == "manual":
        requested = config.get("interface")
        for item in candidates:
            if item.name == requested:
                return item
        raise RuntimeError(
            f"Configured NIC {requested!r} is unavailable or has no usable IP address"
        )
    if mode == "auto":
        if not candidates:
            raise RuntimeError("No active NIC with a usable IPv4/IPv6 address was found")
        return candidates[0]
    raise ValueError("network.mode must be 'auto' or 'manual'")
