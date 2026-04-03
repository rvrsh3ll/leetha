"""
Active network probe scheduler and packet generation.

Generates common broadcast/multicast packets (ARP, mDNS, DHCP, SSDP,
NetBIOS) that blend in with ordinary network chatter.  Probing is
disabled by default and must be explicitly activated per interface.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from dataclasses import dataclass

from leetha.capture.interfaces import InterfaceConfig, classify_capture_mode

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Probe metadata
# ---------------------------------------------------------------------------

@dataclass
class ProbeSpec:
    """Descriptor for a single probe type."""
    label: str
    summary: str
    needs_layer2: bool  # True = requires tap / physical (not tun)


# Canonical catalog of every supported probe.
_PROBE_CATALOG: dict[str, ProbeSpec] = {
    "arp_sweep": ProbeSpec(
        label="arp_sweep",
        summary="Broadcast ARP who-has for every host in the local subnet",
        needs_layer2=True,
    ),
    "mdns_query": ProbeSpec(
        label="mdns_query",
        summary="Multicast mDNS service-discovery request",
        needs_layer2=True,
    ),
    "dhcp_discover": ProbeSpec(
        label="dhcp_discover",
        summary="Broadcast DHCP discover to locate DHCP servers",
        needs_layer2=True,
    ),
    "ssdp_search": ProbeSpec(
        label="ssdp_search",
        summary="UPnP M-SEARCH multicast for SSDP-capable devices",
        needs_layer2=False,
    ),
    "netbios_query": ProbeSpec(
        label="netbios_query",
        summary="Broadcast NetBIOS wildcard name query",
        needs_layer2=True,
    ),
}

# Backward-compatible alias
ProbeInfo = ProbeSpec
PROBE_REGISTRY: dict[str, ProbeSpec] = _PROBE_CATALOG


# ---------------------------------------------------------------------------
# Probe filtering
# ---------------------------------------------------------------------------

def list_compatible_probes(mode: str) -> dict[str, ProbeSpec]:
    """Return only the probes that can operate in the given capture *mode*.

    Tunnel interfaces lack Layer-2 access, so probes that require it
    are excluded when *mode* is ``"tun"``.
    """
    if mode == "tun":
        return {key: spec for key, spec in _PROBE_CATALOG.items()
                if not spec.needs_layer2}
    return dict(_PROBE_CATALOG)


# Backward-compatible alias
get_available_probes = list_compatible_probes


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

class ProbeScheduler:
    """Validates preconditions and executes probes against a target interface."""

    def check_preconditions(self, probe_id: str, iface_cfg: InterfaceConfig) -> None:
        """Raise ``ValueError`` when *probe_id* cannot run on *iface_cfg*."""
        if iface_cfg.probe_mode != "probe-enabled":
            raise ValueError(f"Probing not enabled on {iface_cfg.name}")

        if probe_id not in _PROBE_CATALOG:
            raise ValueError(f"Unknown probe: {probe_id}")

        cap_mode = classify_capture_mode(iface_cfg.name)
        allowed = list_compatible_probes(cap_mode)
        if probe_id not in allowed:
            raise ValueError(
                f"Probe {probe_id} requires L2 and is not available on "
                f"{cap_mode} interface {iface_cfg.name}"
            )

    async def execute_probe(self, probe_id: str, iface_cfg: InterfaceConfig) -> dict:
        """Run a single probe on *iface_cfg* and return a status dict."""
        self.check_preconditions(probe_id, iface_cfg)

        handler = _PROBE_HANDLERS.get(probe_id)
        if handler is None:
            raise ValueError(f"Probe {probe_id} not implemented")

        _log.info("Running probe %s on %s", probe_id, iface_cfg.name)
        return await handler(iface_cfg)

    async def execute_all(self, iface_cfg: InterfaceConfig) -> list[dict]:
        """Run every applicable probe on *iface_cfg*."""
        cap_mode = classify_capture_mode(iface_cfg.name)
        allowed = list_compatible_probes(cap_mode)
        outcomes: list[dict] = []
        for pid in allowed:
            try:
                outcome = await self.execute_probe(pid, iface_cfg)
                outcomes.append({"probe": pid, "status": "sent", **outcome})
            except Exception as exc:
                outcomes.append({"probe": pid, "status": "error",
                                 "error": str(exc)})
        return outcomes

    # Backward-compatible method aliases
    validate_probe = check_preconditions
    run_probe = execute_probe
    run_all = execute_all


# Backward-compatible alias
ProbeDispatcher = ProbeScheduler


# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------

def _build_arp_sweep_packets(iface_cfg: InterfaceConfig) -> list:
    """Construct ARP who-has frames for all hosts in the interface's subnet."""
    from scapy.all import Ether, ARP

    frames: list = []
    for bind in iface_cfg.bindings:
        if bind.family != "ipv4" or not bind.active:
            continue
        try:
            net = ipaddress.IPv4Network(bind.network, strict=False)
        except ValueError:
            continue
        origin = bind.address
        for addr in net.hosts():
            target = str(addr)
            if target == origin:
                continue
            frame = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=1, psrc=origin, pdst=target,
            )
            frames.append(frame)
    return frames


def _build_mdns_query_packet():
    """Construct an mDNS PTR query for service discovery."""
    from scapy.all import Ether, IP, UDP, DNS, DNSQR

    return (
        Ether(dst="01:00:5e:00:00:fb")
        / IP(dst="224.0.0.251")
        / UDP(sport=5353, dport=5353)
        / DNS(rd=0, qd=DNSQR(qname="_services._dns-sd._udp.local",
                              qtype="PTR"))
    )


def _build_dhcp_discover_packet():
    """Construct a DHCP Discover broadcast frame."""
    from scapy.all import Ether, IP, UDP, BOOTP, DHCP
    import random

    transaction_id = random.randint(0, 0xFFFFFFFF)
    return (
        Ether(dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(op=1, xid=transaction_id)
        / DHCP(options=[("message-type", "discover"), "end"])
    )


def _build_ssdp_search_packet():
    """Construct an SSDP M-SEARCH multicast frame."""
    from scapy.all import Ether, IP, UDP, Raw

    body = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 3\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    )
    return (
        Ether(dst="01:00:5e:7f:ff:fa")
        / IP(dst="239.255.255.250")
        / UDP(sport=1900, dport=1900)
        / Raw(load=body.encode())
    )


def _build_netbios_query_packet():
    """Construct a NetBIOS wildcard name-query broadcast frame."""
    from scapy.all import Ether, IP, UDP, Raw
    import struct

    tid = 0x0001
    encoded_name = b"\x20" + b"\x43\x4b" + b"\x41" * 30 + b"\x00"
    dgram = (
        struct.pack(">HHHHHH", tid, 0x0010, 1, 0, 0, 0)
        + encoded_name
        + struct.pack(">HH", 0x0021, 0x0001)
    )
    return (
        Ether(dst="ff:ff:ff:ff:ff:ff")
        / IP(dst="255.255.255.255")
        / UDP(sport=137, dport=137)
        / Raw(load=dgram)
    )


# ---------------------------------------------------------------------------
# Transmit helper
# ---------------------------------------------------------------------------

async def _transmit_frames(iface_name: str, frames: list,
                           pps_limit: int = 100) -> int:
    """Send *frames* on *iface_name* in a background thread.

    Returns the number of frames successfully handed to the NIC.
    """
    from scapy.all import sendp

    ev_loop = asyncio.get_event_loop()
    sent_count = 0

    def _do_send():
        nonlocal sent_count
        for frame in frames:
            sendp(frame, iface=iface_name, verbose=0)
            sent_count += 1

    await ev_loop.run_in_executor(None, _do_send)
    return sent_count


# Backward-compatible alias
_send_packets = _transmit_frames


# ---------------------------------------------------------------------------
# Probe runners
# ---------------------------------------------------------------------------

async def _run_arp_sweep(iface_cfg: InterfaceConfig) -> dict:
    frames = _build_arp_sweep_packets(iface_cfg)
    if not frames:
        return {"hosts": 0, "message": "No IPv4 bindings found"}
    total = await _transmit_frames(iface_cfg.name, frames)
    return {"hosts": total, "message": f"Sent {total} ARP who-has packets"}


async def _run_mdns_query(iface_cfg: InterfaceConfig) -> dict:
    frame = _build_mdns_query_packet()
    await _transmit_frames(iface_cfg.name, [frame])
    return {"message": "Sent mDNS service discovery query"}


async def _run_dhcp_discover(iface_cfg: InterfaceConfig) -> dict:
    frame = _build_dhcp_discover_packet()
    await _transmit_frames(iface_cfg.name, [frame])
    return {"message": "Sent DHCP discover broadcast"}


async def _run_ssdp_search(iface_cfg: InterfaceConfig) -> dict:
    frame = _build_ssdp_search_packet()
    await _transmit_frames(iface_cfg.name, [frame])
    return {"message": "Sent SSDP M-SEARCH multicast"}


async def _run_netbios_query(iface_cfg: InterfaceConfig) -> dict:
    frame = _build_netbios_query_packet()
    await _transmit_frames(iface_cfg.name, [frame])
    return {"message": "Sent NetBIOS name query broadcast"}


# Handler lookup table
_PROBE_HANDLERS: dict = {
    "arp_sweep": _run_arp_sweep,
    "mdns_query": _run_mdns_query,
    "dhcp_discover": _run_dhcp_discover,
    "ssdp_search": _run_ssdp_search,
    "netbios_query": _run_netbios_query,
}

# Backward-compatible alias
_PROBE_FUNCTIONS = _PROBE_HANDLERS
