# Leetha

Passive network fingerprinting and analysis engine. Identifies devices on your network by analyzing broadcast traffic, DHCP exchanges, mDNS announcements, DNS queries, TLS handshakes, and L2 management protocols — combining passive observation with active service probing.


## Quick Start

Requires **Python 3.11+** and **root/sudo** for packet capture.

```bash
# Sync fingerprint databases (optional, improves accuracy)
leetha sync

# Launch the web dashboard
sudo leetha --web

# Interactive console
sudo leetha -i eth0
```

Open `http://localhost:8080` to view discovered devices in real-time.

## Usage

```bash
sudo leetha --web -i eth0          # Web dashboard on a specific interface
sudo leetha -i eth0 -i wlan0       # Multi-interface capture
sudo leetha --live --decode -i eth0 # Live packet stream with protocol decode
leetha probe 192.168.1.1:22        # Actively probe a service
leetha interfaces list              # Manage saved interfaces
```

## Features

- **Passive fingerprinting** — DHCP, mDNS, DNS, SSDP, NetBIOS, ICMPv6, ARP, and TLS dissectors
- **Active probing** — 300+ protocol-specific probe plugins
- **Verdict engine** — Weighted certainty scoring with agreement boosting across all evidence per host
- **Web dashboard** — Real-time host inventory, split-pane detection triage, network topology, attack surface analysis, and configuration
- **Interactive console** — Command-driven workflow with live packet streaming
- **Attack surface analysis** — Exposed service identification and multi-step attack chain mapping
- **DHCP anomaly detection** — Rogue DHCP servers, MAC spoofing, starvation attacks
- **IoT/SCADA awareness** — Passive identification of industrial and IoT protocols (Modbus, BACnet, MQTT, CoAP)
- **Fingerprint database sync** — 12 upstream databases (~880 MB): IEEE OUI, p0f TCP signatures, Huginn-Muninn (MAC vendors, DHCP fingerprints, device hierarchy, DHCPv6), IANA enterprise IDs, JA3/JA4 TLS fingerprints
- **Identity shift detection** — CRITICAL alerts when a device's fingerprint class changes unexpectedly (category, vendor, or platform change indicates MAC spoofing or device swap)
- **Behavioral drift monitoring** — Tracks DNS vendor affinity per host over time; detects when a device's query profile shifts from one vendor ecosystem to another
- **Randomized MAC handling** — Identifies Apple, Android, and Windows devices despite MAC randomization using exclusive mDNS services (_apple-mobdev2._tcp, _companion-link._tcp) and DHCP Option 61 correlation
- **Container/VM/cloud awareness** — Identifies Docker containers, Proxmox/VMware/Hyper-V VMs, Kubernetes nodes, and cloud instances (AWS, GCP, Azure, DigitalOcean) from MAC OUI, hostname patterns, and DNS queries
- **API security** — Rate limiting (120 req/min), MAC address validation, query size limits, HTML sanitization on wiki content

## How It Works

```
Network Traffic --> Capture Engine (scapy, per-interface threads)
                          |
                    Parser Chain
          (ARP, DHCP, DNS, TLS, LLDP, CDP, SNMP, ...)
                          |
                    CapturedPacket
                          |
              Registry-Based Processors
     (Network, Services, Names, Infrastructure, IoT/SCADA)
                          |
                       Evidence
                          |
                    Verdict Engine
              (weighted certainty + agreement boost)
                          |
          +---------------+---------------+
          v               v               v
     Host Store      Finding Rules    Active Probes
     (SQLite)        (8 rule types)   (315 plugins)
          |
     Web Dashboard
```

1. **Capture** — Listens on selected interfaces, parsing protocols through an ordered chain
2. **Process** — Registered processors extract evidence from captured packets
3. **Fuse** — Verdict engine combines all evidence per host using weighted certainty
4. **Store** — Host identity, evidence chain, and findings persisted to SQLite
5. **Detect** — Finding rules evaluate each host for anomalies and threats
6. **Re-evaluate** — 60 seconds after startup, devices classified before fingerprint databases loaded are automatically re-fingerprinted

## Architecture

```
src/leetha/
├── core/             Application orchestrator and processing pipeline
├── capture/
│   ├── engine.py     Packet capture (per-interface threads)
│   └── protocols/    Split protocol parsers (ARP, DHCP, DNS, TLS, L2, ...)
├── processors/       Registry-based packet processors
│   ├── network.py    ARP, DHCP, DHCPv6, ICMPv6 — host discovery
│   ├── services.py   TCP SYN, TLS, HTTP User-Agent — OS/service fingerprinting
│   ├── names.py      DNS, mDNS, SSDP, NetBIOS — hostname and service resolution
│   ├── infrastructure.py  LLDP, CDP, STP, SNMP — network device identification
│   ├── iot_scada.py  Modbus, BACnet, CoAP, MQTT — industrial/IoT protocols
│   ├── passive.py    IP observed — TTL-based OS hints
│   └── active.py     Active probe results
├── evidence/         Evidence models and verdict computation engine
├── rules/            Registry-based finding rules
│   ├── discovery.py  new_host, low_certainty
│   ├── drift.py      identity_shift (category/vendor/platform change detection)
│   ├── behavioral.py behavioral_drift (DNS vendor affinity monitoring)
│   ├── anomaly.py    dhcp_anomaly, stale_source
│   └── randomization.py  randomized_addr (MAC randomization detection)
├── patterns/
│   ├── loader.py     JSON pattern loader with validation and caching
│   └── data/         Fingerprint pattern databases (JSON)
├── probe/
│   ├── base.py       ServiceProbe plugin interface
│   ├── connection.py ServiceConnection socket wrapper
│   └── plugins/      315 service identification plugins
├── store/            Repository-pattern SQLite persistence
├── analysis/         Attack surface analysis, DHCP anomaly detection
├── sync/             Fingerprint database sync from upstream feeds
├── ui/
│   ├── web/          FastAPI web dashboard with WebSocket updates
│   └── live.py       Live packet stream viewer
├── cli.py            Entry point and argument parsing
└── console.py        Interactive console (REPL)
```

## Detection Capabilities

**Protocols analyzed:** ARP, DHCPv4, DHCPv6, DNS, mDNS/Bonjour, SSDP/UPnP, NetBIOS/LLMNR, TLS (JA3/JA4), HTTP User-Agent, TCP SYN (p0f-style), ICMPv6, LLDP, CDP, STP, SNMP

**Device categories identified:**
- **Network infrastructure:** Routers, switches, access points, firewalls, load balancers, mesh routers
- **Compute:** Servers, workstations, laptops, desktops, hypervisors, virtual machines, containers, cloud instances
- **Mobile:** Phones, tablets
- **Entertainment:** Smart TVs, game consoles (PlayStation, Xbox, Nintendo), streaming devices (Roku, Chromecast, Apple TV), media players, smart speakers
- **IoT/Smart Home:** Cameras, doorbells, thermostats, smart locks, smart plugs, smart lighting, robot vacuums, microcontrollers, 3D printers
- **Storage:** NAS devices (Synology, QNAP, TrueNAS, Unraid, OpenMediaVault)
- **Office:** Printers, scanners

**Finding rules:** new_host, identity_shift, addr_conflict, low_certainty, stale_source, randomized_addr, dhcp_anomaly, behavioral_drift

## Documentation

See [docs/wiki/](docs/wiki/Home.md) for detailed guides on installation, configuration, fingerprint sources, CLI reference, and the web dashboard.

## Disclaimer

Leetha is a passive network analysis tool intended for **authorized use only** on networks you own or have explicit permission to monitor. Device identification relies on heuristic pattern matching against broadcast traffic and protocol fingerprints  results are probabilistic, not definitive. Detections surface suspicious activity patterns for analyst review; they are **not confirmed threats** and should always be validated independently before taking action.

This tool is provided as-is for educational, research, and defensive security purposes. The authors assume no liability for misuse, false positives, missed detections, or any actions taken based on its output. Unauthorized network monitoring may violate local, state, or federal law. Always ensure compliance with applicable regulations and organizational policies before deploying.
