# Identity Grouping + Fingerprint History Migration

**Date:** 2026-04-05
**Status:** Approved

## Problem

Two systems still depend on the old Database class:

1. **Device identity grouping** — correlating randomized MACs to a physical device.
   The `device_identities` table and all identity methods live in the old DB.
   The new pipeline sets `Host.real_hw_addr` from DHCP Option 61 but doesn't
   maintain identity records or run correlation scoring.

2. **Fingerprint history** — per-MAC snapshots used by the spoofing detector
   to detect drift and MAC spoofing. `process_device_update()` reads/writes
   `fingerprint_history` in the old DB. No equivalent in the new Store.

## Design

### New Store Tables

**`identities`** — one row per physical device, survives MAC rotation:

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment identity ID |
| primary_mac | TEXT UNIQUE | Canonical MAC (real OUI MAC if known) |
| manufacturer | TEXT | Aggregated from best verdict |
| device_type | TEXT | Aggregated category |
| os_family | TEXT | Aggregated platform |
| os_version | TEXT | Aggregated platform version |
| hostname | TEXT | Best known hostname |
| confidence | INTEGER | Aggregated confidence 0-100 |
| fingerprint | TEXT | JSON correlation signals |
| first_seen | TEXT | ISO-8601 |
| last_seen | TEXT | ISO-8601 |

**`fingerprint_snapshots`** — per-MAC identity snapshots for drift detection:

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| hw_addr | TEXT NOT NULL | MAC being tracked |
| timestamp | TEXT NOT NULL | ISO-8601 when captured |
| os_family | TEXT | Observed OS |
| manufacturer | TEXT | Inferred vendor |
| device_type | TEXT | Category |
| hostname | TEXT | Device hostname |
| oui_vendor | TEXT | NIC vendor from OUI lookup |

**`hosts` table migration** — add `identity_id INTEGER` column (nullable FK).

### Correlation Fingerprint JSON

Stored on `identities.fingerprint`:

```json
{
  "hostname": "iphone-jane",
  "dhcp_opt60": "dhcpcd-6.11.5:Linux-5.10",
  "dhcp_opt55": "1,3,6,15,26,28,51,58,59",
  "tcp_sig": "64:65535:1460:mss,nop,ws,nop,nop,ts,sack,eol",
  "mdns_name": "Janes-iPhone"
}
```

Scoring weights (from mac_intel.py): hostname 0.35, dhcp_opt60 0.25,
dhcp_opt55 0.15, tcp_sig 0.15, mdns_name 0.10. Match threshold: 0.40.

### Pipeline Data Flow

On every verdict computation:

1. **Non-randomized MAC**: find-or-create identity by `primary_mac = hw_addr`,
   link `Host.identity_id`, update identity metadata from verdict.

2. **Randomized MAC**: extract correlation signals from sightings. Score
   against all existing identities with `compute_correlation_score()`.
   - Score >= 0.40 → link to matched identity, set `Host.real_hw_addr`
   - No match → create new identity with this MAC as primary, link host.

3. **Write fingerprint snapshot**: always, using new `fingerprint_snapshots` table.

4. **Spoofing detector**: `process_device_update()` reads prior snapshot from
   `fingerprint_snapshots` instead of old `fingerprint_history`. Same drift/spoofing
   logic, different storage backend.

### API Changes

- `GET /api/devices` — include `identity_id` in device dict
- `GET /api/devices/{mac}` — include identity info + all MACs sharing identity
- `GET /api/devices?group_by=identity` — optional grouping

### Spoofing Detector Changes

Replace in `process_device_update()`:
- `self._db.get_fingerprint_history()` → query `fingerprint_snapshots` via Store
- `self._db.add_fingerprint_snapshot()` → insert into `fingerprint_snapshots` via Store

No logic changes to drift/spoofing detection.

### Pruning

Fingerprint snapshots: keep last 50 per MAC, prune in `_analysis_loop`
alongside sightings pruning.
