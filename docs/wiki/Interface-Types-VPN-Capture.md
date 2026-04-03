# Interface Types and VPN Capture

Leetha's `scan_adapters` function enumerates available network adapters at startup and classifies each one to tailor BPF filters, promiscuous mode, and rule suppression. Understanding these classifications is essential when capturing on VPN tunnels, where traffic characteristics differ significantly from a physical Ethernet port.

---

## Adapter Classifications

### Physical Adapters

**Examples:** `eth0`, `enp3s0`, `wlan0`

Physical adapters connect directly to a LAN segment. Leetha applies a protocol-targeted BPF filter that selects only traffic relevant to fingerprinting (TCP SYN, DHCP, mDNS, SSDP, ARP, DNS, etc.), keeping CPU and memory overhead low. Promiscuous mode is left disabled because you typically only need your own traffic plus broadcast/multicast.

Visibility: your own transmissions and any broadcast or multicast frames on the segment.

### Tap Adapters (Layer 2 Bridged VPN)

**Examples:** `tap0`, `tap1`

A tap adapter carries full Ethernet frames, effectively bridging your machine into a remote Layer 2 segment. This is the richest capture environment:

- All broadcast and multicast traffic from the remote segment is visible (ARP, DHCP, mDNS, NetBIOS)
- Inter-host traffic may be visible if the VPN bridge forwards it
- Promiscuous mode is activated to ensure every frame on the virtual wire is captured
- BPF filter is broadened to `ip or ip6 or arp` to maximize passive discovery

Commonly created by OpenVPN in tap mode.

### Tun Adapters (Layer 3 Routed VPN)

**Examples:** `tun0`, `tun1`

A tun adapter transports raw IP packets with no Ethernet framing. This limits what Leetha can observe:

- No ARP traffic (there is no Layer 2)
- No broadcast domain visibility
- Only traffic explicitly routed to or from your machine appears
- BPF filter is set to `ip or ip6` since there are no Ethernet headers to match

On tun adapters, discovery primarily comes from:
- DNS replies transiting the tunnel
- HTTP User-Agent strings in cleartext traffic
- `ip_observed` evidence from any IP exchange
- SSDP responses (the only discovery probe that works without Layer 2)

Common with OpenVPN in tun mode and WireGuard.

---

## Classification Summary

| Property | Physical | Tap | Tun |
|----------|----------|-----|-----|
| BPF filter | Protocol-specific | `ip or ip6 or arp` | `ip or ip6` |
| Promiscuous mode | Off | On | Off |
| Layer 2 access | Yes | Yes | No |
| ARP visible | Yes (local segment) | Yes (remote segment) | No |
| Broadcast/multicast | Local only | Remote segment | No |
| Inter-host traffic | No (unless mirrored) | Possible | No |

---

## Maximizing Host Discovery

### Tap Adapters

Tap adapters provide the best reconnaissance environment. Recommended approach:

1. Passive processors (`ip_observed`, `dns_answer`, `http_useragent`) will detect most hosts from ambient traffic on the bridged segment.
2. Activate all five discovery probes -- `arp_sweep`, `mdns_query`, `dhcp_discover`, `ssdp_search`, `netbios_query` -- for hosts that produce little passive traffic.
3. `arp_sweep` is particularly effective: it solicits a response from every live IP in the subnet.

### Tun Adapters

Tun adapters offer limited passive visibility. Mitigations:

1. `dns_answer` is your strongest signal if the tunnel carries DNS traffic.
2. `ssdp_search` is the only discovery probe that functions (multicast, no Layer 2 requirement).
3. `ip_observed` will catch any host whose traffic is routed through the tunnel.
4. If deeper visibility is needed, request a tap-mode VPN from the network administrator.

### Physical Adapters

Standard physical adapters see only your own traffic plus the local segment's broadcast and multicast:

1. All five probes function, but ARP responses come only from the directly attached subnet.
2. Switch port mirroring (SPAN) dramatically increases visibility if the infrastructure supports it.
3. Passive processors capture broadcast protocols (DHCP, mDNS, LLMNR, NetBIOS, SSDP) from every device on the segment.

---

## How Classification Works

`scan_adapters` determines the adapter type from its name prefix:

- Names beginning with `tap` are classified as tap adapters
- Names beginning with `tun` are classified as tun adapters
- All other names default to physical

No manual classification is required. The `NetworkAdapter` object produced by `scan_adapters` carries the detected type, which `AdapterConfig` uses to select the appropriate BPF filter and promiscuous mode setting.

### Overriding the BPF Filter

If the automatic filter does not suit your environment, override it per adapter:

```python
AdapterConfig(name="tap0", bpf_filter="tcp or udp or arp")
```

Or in the persisted `interfaces.json`:

```json
{
  "selected": [
    {"name": "tap0", "type": "tunnel", "bpf_filter": "tcp or udp or arp"}
  ]
}
```
