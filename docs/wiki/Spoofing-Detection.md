# Spoofing Detection

Leetha's `AddressVerifier` module continuously monitors ARP traffic and device fingerprint consistency to detect man-in-the-middle attacks and MAC address cloning in real time. All detection is passive -- no probe traffic is required.

---

## Detection Mechanisms

### ARP Anomaly Detection

**`addr_conflict` -- IP Address Claimed by Multiple MACs**
When the `AddressVerifier` observes two distinct MAC addresses asserting ownership of the same IP, it raises a WARNING finding. If one of those MACs belongs to a trusted binding (e.g. the default gateway), the finding escalates to CRITICAL.

**Gateway MAC Substitution**
Any ARP reply that claims a trusted gateway IP but originates from a MAC that does not match the pinned binding immediately generates a CRITICAL finding. This is the strongest passive indicator of an active ARP man-in-the-middle attack.

**Gratuitous ARP Volume Spike**
Self-referencing ARP replies (where sender IP equals target IP) exceeding 10 occurrences from a single MAC within a 60-second window produce a HIGH finding. Sustained gratuitous ARP floods are characteristic of cache poisoning campaigns or DHCP starvation tools.

**Rapid MAC-to-IP Oscillation**
When a single IP address alternates between two or more MAC addresses more than 3 times in a 5-minute interval, the `AddressVerifier` issues a HIGH finding. This oscillation pattern indicates a real-time contest between a legitimate host and an attacker for the same IP binding.

### MAC Cloning Indicators

**Identity Shift Detection**
Replaces the older platform_drift rule with a more granular approach. When a non-randomized MAC address changes its fingerprint, the `AddressVerifier` compares the full fingerprint class -- category, vendor, and platform -- against the stored verdict and assigns severity based on what shifted:

- **Category or vendor change** -- CRITICAL. A MAC previously identified as an Apple iPhone suddenly presenting as a Linux server indicates MAC spoofing or a physical device swap. The same applies to any vendor change (e.g. Cisco to Juniper).
- **Platform change** -- HIGH. The vendor and category remain the same but the platform differs (e.g. macOS to iOS within Apple). Likely a device swap within the same ecosystem.
- **Version-only change** -- INFO. Only the OS version changed (e.g. Windows 10 to Windows 11). Normal behavior from software updates.

Identity shift detection enforces several validation gates before firing:

| Gate | Value | Purpose |
|------|-------|---------|
| Minimum certainty | 50% | Both the old and new verdicts must exceed this threshold to avoid false positives from low-confidence guesses |
| Minimum evidence count | 3 | At least three independent evidence sources must back the new fingerprint |
| Grace period | 60 seconds | Changes within the first 60 seconds after a MAC is first seen are ignored (initial fingerprint convergence) |
| Cooldown | 5 minutes | After firing, the same MAC will not trigger another identity shift finding for 5 minutes |

The `AddressVerifier` cross-references identity shift findings with other corroborating evidence (ARP anomalies, gratuitous ARP spikes, trusted binding violations) to increase confidence in the detection.

Randomized MACs (locally-administered bit set) are exempt -- identity changes are expected on randomized addresses.

**Identity Drift on Stable MACs (Legacy)**
The older platform_drift behavior is subsumed by identity shift detection above. Existing findings produced by the legacy rule remain in the Store for historical reference.

**OUI vs Behavioral Contradiction**
When the OUI prefix (first 3 bytes) maps to one manufacturer but processor evidence (DHCP fingerprint, DNS query patterns, TCP stack) consistently identifies a different manufacturer, a WARNING finding is raised. The check only fires when the behavioral evidence reaches 60%+ confidence. Example: a Cisco OUI emitting Windows-style DHCP Option 55 sequences and querying `*.windowsupdate.com` is suspicious.

---

## Trusted Binding Management

Trusted bindings are pinned MAC/IP associations representing verified network infrastructure. Any violation of a trusted binding triggers a CRITICAL-severity finding.

### Automatic Discovery

The `AddressVerifier` automatically pins bindings from two sources:

- **DHCP server responses**: When a DHCP Offer or ACK is observed, the responding server's MAC and IP are stored as a `dhcp_server` binding.
- **ICMPv6 Router Advertisements**: When an RA arrives, the router's MAC and link-local address are stored as an `auto_gateway` binding.

Automatically discovered bindings never overwrite manually created ones.

### Manual Configuration

Register a known-good association:

```bash
leetha trust add de:ad:be:ef:00:01 10.10.14.1
```

View all current bindings:

```bash
leetha trust list
```

Delete a binding:

```bash
leetha trust remove de:ad:be:ef:00:01
```

REST API equivalents:

```
GET    /api/trust                 Retrieve all bindings
POST   /api/trust                 Create binding  (body: {"mac": "...", "ip": "..."})
DELETE /api/trust/{mac}           Delete binding
```

---

## Finding Severity Reference

| Level | Trigger Condition | Operator Action |
|-------|-------------------|-----------------|
| CRITICAL | Gateway impersonation or trusted binding violation | Immediate investigation -- high probability of active attack |
| HIGH | MAC-to-IP oscillation or gratuitous ARP volume spike | Search for rogue devices on the segment |
| WARNING | Untrusted IP conflict, identity drift, OUI-behavior contradiction | Review host -- possible misconfiguration or cloning |

---

## Alert Throttling

To prevent notification fatigue, the `AddressVerifier` suppresses duplicate findings (same finding type, same MAC, same context) for 5 minutes after the initial firing. The cooldown resets when Leetha restarts -- deliberately, so that persistent attacks are re-surfaced after a process restart.

---

## Persistent State

All spoofing-related state is stored in the `Store` (async SQLite):

- **arp_history** -- every ARP observation including per-MAC packet counts and timestamps
- **trusted_bindings** -- all pinned MAC/IP pairs with origin label and creation timestamp
- **fingerprint_history** -- identity snapshots over time for drift detection

Data survives restarts and supports forensic review across extended capture sessions.

---

## Reviewing ARP History

Query the full ARP timeline for a specific device through the API:

```
GET /api/devices/{mac}/arp-history
```

The response includes every IP the MAC has claimed, with first-seen and last-seen timestamps and packet counts.

---

## Known Limitations

- **VLAN isolation**: The `AddressVerifier` only analyzes ARP traffic on its own broadcast domain. Spoofing on a different VLAN will not be visible.
- **Perfect behavioral clones**: An attacker who clones both the MAC and replicates the victim's OS fingerprint (matching DHCP options, TCP stack, DNS patterns) will evade drift-based detection.
- **Legitimate failover protocols**: VRRP and HSRP use gratuitous ARPs during failover. You may need to raise the volume threshold or pin both virtual MACs as trusted.
- **Pre-capture poisoning**: If an attacker poisons the ARP cache before Leetha begins capturing, auto-learned gateway bindings may reflect the attacker's MAC. Pin critical infrastructure manually to avoid this.
