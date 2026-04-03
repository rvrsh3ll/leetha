# Attack Surface Analysis

Leetha maps network observations to concrete penetration testing opportunities. The analysis engine reads `Evidence` and host records already accumulated in the `Store`, evaluates them against `FindingRule` implementations registered via `@register_rule`, and assembles multi-step attack playbooks from the results.

Two output types are produced:

- **Findings** -- discrete security observations tied to specific hosts and evidence. Each finding carries a rule ID, severity, affected device list, and supporting evidence.
- **Attack Chains** -- sequenced playbooks that combine related findings into end-to-end attack procedures with copy-ready tool commands.

Every attack chain card surfaces:
- The **adapter** the traffic was observed on (and through which attacks should be executed)
- The **triggering findings** with their underlying evidence
- **Numbered steps** describing the attack procedure
- **Tool commands** with template variables filled from the analysis context

---

## Evidence-to-Finding Pipeline

```
  CapturedPacket
       |
  PARSER_CHAIN + ProcessorRegistry
       |
  Evidence persisted in Store
       |
  FindingRules (registered via @register_rule)
  -- 23 passive rules query host/evidence repositories
  -- 12 service rules query ServiceIdentity results
       |
  Findings written to FindingRepository
       |
  Chain Assembler (prerequisite matching)
       |
  Attack Chains with adapter context and tool commands
```

### How a FindingRule Evaluates

1. **Store query**: The rule reads from `HostRepository` and `EvidenceRepository` looking for protocol-specific indicators. For example, the LLMNR rule searches evidence records where `protocol == "llmnr"`.

2. **Host attribution**: Each finding enumerates the exact hosts (MAC, IP, hostname) that produced the triggering evidence, so operators know precisely which machines are exposed.

3. **Chain prerequisite check**: The chain assembler inspects which rule IDs have produced findings. A chain like "LLMNR Poisoning -> NTLMv2 Relay" only materializes when finding NR-001 or NR-002 exists in the `FindingRepository`.

4. **Adapter awareness**: Findings inherit the capture adapter, ensuring chains indicate which network segment to attack through. Multi-adapter deployments produce per-segment analysis.

5. **Command template rendering**: Tool commands contain placeholders (`{interface}`, `{target_ip}`, `{domain}`, `{attacker_ip}`, `{dc_ip}`) that are populated from the analysis context at render time.

---

## FindingRule Catalog

### Name Resolution Poisoning Rules (NR-xxx)

Broadcast and multicast name resolution protocols are the most common entry point for internal network attacks because they can be silently poisoned to redirect authentication traffic.

**NR-001 -- LLMNR Broadcast Queries** (HIGH)
Triggered when LLMNR traffic is observed on UDP 5355. Hosts falling back to LLMNR accept responses from any device on the segment, enabling NTLMv2 hash capture.

**NR-002 -- NetBIOS Name Service Queries** (HIGH)
Same poisoning vector as LLMNR but over the legacy NetBIOS NS protocol (UDP 137). Prevalent in Windows-dominated environments.

**NR-003 -- mDNS Service Queries** (MEDIUM)
mDNS traffic on UDP 5353 can be spoofed to hijack service discovery. Exploitation requires more effort than LLMNR/NBT-NS, resulting in lower severity.

**NR-004 -- WPAD Auto-Proxy Queries** (HIGH)
WPAD lookups in DNS or NetBIOS allow an attacker to inject a proxy configuration that funnels all HTTP traffic through the attacker's machine.

Evidence captured: query names, source MAC/IP of querying hosts, protocol classification, query count.

---

### Data-Link Layer Rules (L2-xxx)

These rules assess conditions on the local Ethernet segment that enable ARP cache poisoning, NDP attacks, and switch-level exploitation. **All L2 rules are automatically suppressed on VPN, proxy, and pivot adapters** because Layer 2 observations across tunnels do not reflect the remote network.

**L2-001 -- ARP Exchange Observed** (MEDIUM)
ARP traffic from two or more distinct devices confirms a shared broadcast domain with no ARP authentication -- the prerequisite for cache poisoning MITM.

**L2-002 -- IP-to-MAC Conflict** (HIGH)
A single IP resolving to multiple MAC addresses may indicate active ARP spoofing, an IP address conflict, or a load-balancer / failover pair.

**L2-003 -- Gratuitous ARP Present** (MEDIUM)
Self-directed ARP replies (source IP equals destination IP) are legitimate for failover but can be weaponized for cache poisoning.

**L2-004 -- NDP Spoofing Exposure** (HIGH)
ICMPv6 Neighbor Discovery lacks built-in authentication (absent SEND), allowing an attacker to impersonate any IPv6 neighbor.

**L2-005 -- High MAC Diversity** (INFO)
More than 50 unique MACs on a segment. Informational -- larger populations increase the attack surface.

**L2-006 -- Discovery Protocol Leakage** (LOW)
CDP, LLDP, or similar protocols expose switch model, firmware, VLAN assignments, and port information useful for VLAN hopping and infrastructure mapping.

Evidence captured: MAC/IP pairs in ARP exchanges, gratuitous ARP counts, MAC diversity tally, discovery protocol payloads.

---

### DHCP Exploitation Rules (DH-xxx)

**DH-001 -- DHCP Client Requests Observed** (MEDIUM)
Discover/Request broadcasts confirm that clients accept dynamic configuration, enabling rogue DHCP server attacks.

**DH-002 -- DHCP Protocol Anomalies** (HIGH)
RFC 2132 violations logged to `dhcp_anomalies.jsonl` suggest an active attack, server misconfiguration, or rogue device.

**DH-003 -- Multiple DHCP Servers on Segment** (HIGH)
DHCP Offers or ACKs from more than one server IP may indicate a rogue server is already operating.

**DH-004 -- DHCPv6 Client Solicitations** (MEDIUM)
DHCPv6 Solicit/Request packets are especially dangerous because most networks lack a legitimate DHCPv6 server, meaning an attacker's response goes uncontested -- the basis of mitm6-style attacks.

Evidence captured: DHCP server IPs, client MACs requesting leases, message types, anomaly specifics, DHCPv6 DUIDs and enterprise IDs.

---

### Routing and Gateway Rules (RT-xxx)

**RT-001 -- IPv6 Router Advertisements Present** (HIGH)
Rogue RAs allow an attacker to claim the default IPv6 gateway and DNS server. Effective even on IPv4-primary networks because most modern operating systems auto-configure IPv6.

**RT-002 -- Routing Protocol Endpoints Exposed** (HIGH)
ServiceProbe results showing HSRP, VRRP, BGP, OSPF, EIGRP, or RIP services. These can be attacked for route injection or gateway takeover.

**RT-003 -- ICMP Redirect Feasibility** (MEDIUM)
Multiple gateways or ICMP redirect capability. Forged redirects can reroute traffic, though most modern kernels ignore them.

Evidence captured: router MAC/IP, RA flags, hop limits, routing protocol names and versions, gateway count.

---

### Service-Based Rules (SE-xxx)

Service rules fire when `ServiceProbe` results or prior reconnaissance data in the Store identify specific protocols.

| Rule ID | Severity | Target Services | Exploitation Path |
|---------|----------|----------------|-------------------|
| SE-001 | HIGH | Telnet | Cleartext credential interception via MITM |
| SE-002 | HIGH | FTP | Cleartext credential interception via MITM |
| SE-003 | HIGH | SMB, CIFS | NTLM relay -- validate signing with RelayKing |
| SE-004 | HIGH | SNMP | Community string brute-force, config extraction |
| SE-009 | CRITICAL | Modbus | Unauthenticated PLC register read/write |
| SE-010 | CRITICAL | DNP3 | Industrial control manipulation |
| SE-011 | CRITICAL | BACnet | Building automation system access |
| SE-012 | CRITICAL | EtherNet/IP | CIP protocol interaction |
| SE-018 | HIGH | LDAP | NTLM relay target, directory enumeration |
| SE-019 | HIGH | Kerberos | AS-REP roasting, Kerberoasting |
| SE-020 | CRITICAL | Docker API | Container escape to host |
| SE-021 | CRITICAL | Kubernetes API | Pod creation, secret exfiltration |
| SE-023 | MEDIUM | IMAP, POP3 | Cleartext mail credential capture |

Evidence captured: host IP, port, service name, version banner, protocol metadata (SMB signing, SNMP community, etc.).

---

### Cryptographic Weakness Rules (TC-xxx)

**TC-001 -- Deprecated TLS Versions** (MEDIUM)
ClientHello advertising TLS < 1.2. Susceptible to BEAST, POODLE, and downgrade attacks.

**TC-002 -- Unencrypted HTTP Endpoints** (MEDIUM)
HTTP on non-TLS ports exposes credentials, cookies, and session tokens to network-level interception.

---

### Reconnaissance Value Rules (NI-xxx)

Informational findings that aid network mapping without direct exploitation.

| Rule ID | Severity | Indicator | Intelligence Value |
|---------|----------|-----------|-------------------|
| NI-001 | LOW | SSDP/UPnP traffic | Device description XML, port mapping abuse |
| NI-002 | INFO | DNS queries for .local/.corp/.internal/.lan | Internal domain structure and naming patterns |
| NI-003 | LOW | Multiple gateways observed | Redundancy architecture or misconfiguration |
| NI-004 | INFO | IP without a host record | Transient device, tunnel endpoint, or BPF gap |

---

## Chain Definitions

A chain activates only when its prerequisite findings exist in the `FindingRepository`.

### Prerequisite Modes

- **any** -- at least one listed rule must have fired
- **all** -- every listed rule must have fired
- **custom** -- the first rule is mandatory; at least one additional rule must also fire

---

### CHAIN-001: Broadcast Name Resolution Poisoning -> Hash Relay

| Property | Value |
|----------|-------|
| Severity | CRITICAL |
| Prerequisites | NR-001 or NR-002 |
| Mode | any |

Activates when LLMNR or NetBIOS NS queries are present. Procedure: enumerate relay targets with RelayKing, poison queries with Responder or Pretender, relay captured NTLMv2 hashes with ntlmrelayx, optionally coerce authentication with Coercer.

### CHAIN-003: Rogue DHCP -> DNS Hijack -> Traffic Interception

| Property | Value |
|----------|-------|
| Severity | CRITICAL |
| Prerequisites | DH-001 or NR-004 |
| Mode | any |

Activates on DHCP client activity or WPAD queries. Procedure: deploy rogue DHCP server claiming attacker as gateway/DNS, respond to all DNS with attacker addresses, intercept traffic.

### CHAIN-004: Rogue IPv6 RA -> Gateway Hijack

| Property | Value |
|----------|-------|
| Severity | HIGH |
| Prerequisites | RT-001 |
| Mode | any |

Activates when Router Advertisements confirm IPv6 autoconfiguration. Procedure: broadcast rogue RAs to become the default gateway, serve as DHCPv6 DNS, relay captured authentication via ntlmrelayx.

### CHAIN-005: Industrial Protocol Exploitation

| Property | Value |
|----------|-------|
| Severity | CRITICAL |
| Prerequisites | SE-009 or SE-010 or SE-011 or SE-012 |
| Mode | any |

Activates when ICS protocols are detected. Procedure: enumerate ICS endpoints, read process registers/coils, assess write capability with appropriate safety controls.

### CHAIN-006: LLMNR + SMB -> Domain Takeover

| Property | Value |
|----------|-------|
| Severity | CRITICAL |
| Prerequisites | NR-001 and SE-003 |
| Mode | all |

Activates when both a poisoning vector (LLMNR) and relay targets (SMB) are confirmed. Procedure: validate unsigned SMB targets with RelayKing, capture NTLMv2 via Responder, relay to validated targets with ntlmrelayx, force authentication with Coercer.

### CHAIN-007: DHCPv6 Spoofing -> DNS Takeover -> Credential Relay

| Property | Value |
|----------|-------|
| Severity | CRITICAL |
| Prerequisites | DH-004 or NR-004 |
| Mode | any |

Activates on DHCPv6 solicitations or WPAD queries. Procedure: identify relay targets with RelayKing, assume DHCPv6 DNS role with mitm6 or Pretender, relay captured auth with ntlmrelayx.

### CHAIN-008: ARP MITM -> Cleartext Credential Harvest

| Property | Value |
|----------|-------|
| Severity | HIGH |
| Prerequisites | L2-001 (required) + at least one of SE-001, SE-002, SE-004, SE-023 |
| Mode | custom |

Activates when ARP confirms a shared segment and cleartext services are present. Procedure: ARP spoof with Bettercap, passively capture credentials from Telnet/FTP/SNMP/IMAP/POP3.

### CHAIN-010: STP Root Bridge Takeover -> Segment-Wide MITM

| Property | Value |
|----------|-------|
| Severity | HIGH |
| Prerequisites | L2-006 |
| Mode | any |

Activates when discovery protocols reveal managed switches without BPDU Guard. Procedure: inject superior BPDUs with Yersinia to claim root bridge, all forwarding paths recalculate through attacker, sniff traffic with Bettercap or tcpdump.

---

## Attack Surface by OSI Layer

### Layer 2 (Data Link)

| Technique | Triggering Rules | Related Chains |
|-----------|-----------------|----------------|
| ARP Cache Poisoning | L2-001, L2-002, L2-003 | CHAIN-008 |
| IPv6 NDP Spoofing | L2-004 | -- |
| STP Root Bridge Takeover | L2-006 | CHAIN-010 |
| VLAN Hopping | L2-006 (CDP/LLDP VLAN leak) | -- |

### Layer 3 (Network)

| Technique | Triggering Rules | Related Chains |
|-----------|-----------------|----------------|
| Rogue Router Advertisement | RT-001 | CHAIN-004 |
| Routing Protocol Injection | RT-002 | -- |
| ICMP Redirect Abuse | RT-003 | -- |
| Rogue DHCP Gateway | DH-001, DH-003 | CHAIN-003 |
| DHCPv6 Spoofing | DH-004 | CHAIN-007 |

### Name Resolution (Bridging L2 and L3)

| Technique | Triggering Rules | Related Chains |
|-----------|-----------------|----------------|
| LLMNR Poisoning | NR-001 | CHAIN-001, CHAIN-006 |
| NetBIOS NS Poisoning | NR-002 | CHAIN-001 |
| mDNS Spoofing | NR-003 | -- |
| WPAD Hijacking | NR-004 | CHAIN-003, CHAIN-007 |

---

## Analysis Context and Exclusions

### Context Object

The analysis engine operates with a context containing:

- `interface` -- capture adapter name (substituted into tool commands)
- `interface_type` -- `local`, `vpn`, `proxy`, or `pivot`
- `gateway_ip` -- detected default gateway
- `domain` -- detected Active Directory domain
- `attacker_ip` -- operator's IP on the capture adapter
- `dc_ip` -- detected domain controller

Template variables in tool commands (`{interface}`, `{target_ip}`, `{domain}`, `{attacker_ip}`, `{dc_ip}`) are resolved from this context.

### Exclusion Management

Suppress specific hosts or rules from analysis:

- **By IP** -- omit findings involving a particular address
- **By MAC** -- omit findings involving a particular device
- **By rule** -- disable a FindingRule entirely

Exclusions can be configured through the React dashboard or stored directly in `data_dir/attack_surface_exclusions.json`.

### Adapter-Type Rule Suppression

On adapters classified as `vpn`, `proxy`, or `pivot`, all Layer 2 rules (L2-xxx) are silently skipped. ARP and NDP frames on tunneled connections reflect the tunnel infrastructure rather than the target network, making L2 findings misleading.
