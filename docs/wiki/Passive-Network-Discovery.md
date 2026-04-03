# Passive Network Discovery

Leetha builds a host inventory without transmitting a single packet. Beyond the primary protocol parsers (DHCP, mDNS, TLS, etc.), several processors in the `ProcessorRegistry` extract device information from ambient IP traffic, DNS replies, and unencrypted HTTP exchanges. These supplementary processors are especially valuable on VPN and tap adapters where many hosts never produce fingerprint-rich protocol traffic.

---

## Processor-Based Evidence Extraction

### IP Traffic Observer

**Registered as:** `ip_observed`
**Evidence confidence:** 20--30

Fires on any IP packet that no higher-priority parser in the `PARSER_CHAIN` claims. Because virtually every networked device sends at least some IP traffic, this processor acts as the broadest possible detection net.

Fields extracted:
- Source and destination IP addresses
- Source and destination MAC addresses
- IP protocol number (6 = TCP, 17 = UDP, etc.)
- Source and destination ports (where applicable)
- TTL with OS-class heuristic:
  - 64 or below: Linux / macOS family (initial TTL = 64)
  - 65--128: Windows family (initial TTL = 128)
  - Above 128: Network infrastructure (initial TTL = 255)
- Hop-count estimate derived from the difference between observed TTL and the probable initial value

Strongest on tap adapters where all Layer 2 frames on the bridged segment are visible, including host-to-host traffic that never crosses a router.

### DNS Response Harvester

**Registered as:** `dns_answer`
**Evidence confidence:** 50--60

Inspects DNS response packets to build a hostname-to-IP mapping table. Any DNS resolution on the wire -- not just the operator's own queries -- feeds into this processor.

Fields extracted:
- A and AAAA records: hostname to IPv4/IPv6 mapping
- PTR records: reverse IP-to-hostname resolution
- Record TTL (used to estimate cache freshness)

Strongest on networks with a local resolver or on VPN adapters that carry DNS traffic between multiple clients and a shared server.

### HTTP User-Agent Extractor

**Registered as:** `http_useragent`
**Evidence confidence:** 70--85

Parses cleartext HTTP requests (port 80) to pull the `User-Agent` header, which frequently identifies the operating system, browser, and device category.

Fields extracted:
- Full User-Agent string
- `Host` header (target server)
- HTTP method and request path

OS mapping examples:
- `Windows NT 10.0; Win64` -- Windows 10 or 11
- `Macintosh; Intel Mac OS X 14_4` -- macOS Sonoma
- `Linux; Android 14; Pixel 8` -- Android phone
- `iPhone; CPU iPhone OS 17_4` -- iOS device
- `X11; Ubuntu; Linux x86_64` -- Linux desktop

This processor only handles port 80 traffic. HTTPS on port 443 is covered by the TLS handshake analyzer and JA3/JA4 fingerprinting.

---

## Adapter Type and Visibility

Different adapter types expose different slices of network traffic:

| Adapter Type | ip_observed Coverage | dns_answer Coverage | http_useragent Coverage |
|-------------|---------------------|--------------------|-----------------------|
| Physical (eth0, wlan0) | Local traffic + broadcasts | DNS on local segment | Port 80 on local segment |
| tap (L2 VPN) | All bridged traffic including inter-host | All DNS across the bridge | All HTTP across the bridge |
| tun (L3 VPN) | Only traffic routed to/from operator | DNS only if routed through tunnel | HTTP only if routed through tunnel |

---

## From Packet to Verdict

Passive observations follow the same pipeline as every other data source:

1. **PacketCapture** delivers a raw frame from scapy.
2. **PARSER_CHAIN** attempts each protocol parser in order. If none matches, the IP observer claims the packet.
3. **ProcessorRegistry** dispatches the resulting `CapturedPacket` to all registered processors, which emit `Evidence` objects.
4. **VerdictEngine** fuses new evidence with existing records for the host, recalculating the weighted `Verdict`.
5. **Store** persists the updated host record in `HostRepository`.

No toggle or configuration is needed -- these passive processors run automatically on every adapter from the moment capture begins.

---

## Behavioral Drift Monitoring

### DNS Vendor Affinity Tracking

Leetha tracks DNS vendor affinity per host by classifying each DNS query into a vendor bucket (Apple, Microsoft, Google, etc.) and maintaining a rolling profile of the distribution. An adaptive window governs when drift alerts fire:

- **Learning period**: For the first 10 minutes after a host is discovered, the DNS profile is accumulated silently with no alerts.
- **First hour**: After the learning period, if the vendor profile shifts by more than 60% from the baseline (e.g. a device that queried 80% Apple domains suddenly queries 70% Microsoft domains), a WARNING finding is raised.
- **Sustained (after first hour)**: The threshold relaxes to 50% sustained shift to account for natural usage variation while still catching significant behavioral changes.

Behavioral drift findings are correlated with identity shift detection in the `AddressVerifier` -- a DNS vendor shift combined with a fingerprint class change strengthens the case for MAC spoofing or device substitution.

### Hostname-Based Vendor Inference

DHCP hostnames frequently embed device identity. When the DHCP processor extracts a hostname like "Beccas-Iphone", "DESKTOP-A1B2C3", or "Galaxy-S24", Leetha immediately produces vendor and OS evidence without waiting for mDNS or other slower protocols:

- Hostnames containing "iphone", "ipad", "macbook", or "airpods" generate Apple/iOS or Apple/macOS evidence
- Hostnames containing "galaxy", "samsung" generate Samsung/Android evidence
- Hostnames matching the `DESKTOP-` or `LAPTOP-` pattern generate Microsoft/Windows evidence
- Hostnames containing "android" generate generic Android evidence

This hostname-based inference fires on the very first DHCP exchange, providing an early vendor signal that the VerdictEngine can use while waiting for higher-confidence sources like mDNS exclusive services.
