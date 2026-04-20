# Changelog

All notable changes to Leetha will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-04-10

### Added
- **mDNS SRV target extraction** -- capture device hostnames, service ports, and model names from DNS type-33 SRV records and TXT fields (SYSTYPE, devtype, HAP category)
- **Infrastructure mDNS filtering** -- automatically detect routers/gateways/APs via OUI and DHCP, suppress forwarded multicast traffic that would pollute device identity
- **Cross-device mDNS detection** -- detect AirPlay `<hex>@<name>` patterns and reject hostnames from other devices
- **Hostname coherence validation** -- reject hostnames containing vendor keywords that don't match the resolved device vendor
- **Firmware SDK hostname rejection** -- filter auto-generated hostnames from embedded SDKs (ESDK, ESP, Tasmota, Shelly, Tuya, ewelink, etc.)
- **PCAP import via CLI** -- `leetha import` processes captured traffic through the full fingerprinting pipeline into the hosts table
- **CLI `--version` flag** -- `leetha --version` displays the current version
- **`/api/version` endpoint** -- returns version, Python version, and platform
- **Version display in web UI** -- shown in the sidebar
- **Paginated alerts API** -- `/api/alerts` now accepts `page` and `per_page` parameters
- **Numeric IPv4 sorting** -- inventory sorts IP addresses numerically (192.168.1.2 before 192.168.1.100)
- **All columns sortable** -- added missing sort columns: ip_v4, os_family, alert_status
- **Error banners** -- Dashboard and Devices pages show error messages when API calls fail
- **WebSocket auth rejection handling** -- stops reconnecting on invalid token (close code 1008)
- **LRU eviction for pipeline caches** -- prevents unbounded memory growth on long-running deployments
- **Process thread architecture** -- packet processing runs in a dedicated thread with its own event loop and DB connection, immune to event loop contention
- **Sniff auto-restart** -- capture thread automatically restarts on transient NIC errors
- **Thread-safe event dispatch** -- live packet stream uses `call_soon_threadsafe()` for cross-thread WebSocket events

### Changed
- **Default sort** -- inventory defaults to IP address ascending instead of last-seen descending
- **CI Python version** -- upgraded from 3.11 to 3.13 across all workflows
- **Evidence weights** -- `mdns_exclusive` lowered from 0.96 to 0.80 (below OUI 0.90) to prevent forwarded mDNS from overriding hardware identification
- **Hostname hex regex** -- changed from `{6,}` to `{12,}` to preserve valid names like `DESKTOP-ABC123`
- **`last_active` debouncing** -- only updates when 30+ seconds have passed, preventing constant row shuffling in the UI
- **WebSocket throttle** -- invalidation interval increased from 2s to 10s; polling from 30s to 60s
- **Apprise instance** -- created once in `__init__` instead of per-send

### Fixed
- **Capture pipeline dying after 60-300s** -- caused by event loop contention between packet processing, analysis tasks, and DB queries sharing one aiosqlite connection
- **Missing devices in inventory** -- pipeline early returns bypassed host upsert for packets without a matching processor or when the processor crashed
- **Gateway IP overwriting** -- forwarded multicast traffic from other VLANs overwrote the router's IP with a different subnet's address
- **Tailscale ghost devices** -- TUN interfaces returned IPs as MAC addresses; now rejected by `_is_valid_mac()` validation
- **Lutron/Apple/Google hostname contamination** -- forwarded mDNS services attributed to the router instead of the originating device
- **`dns_answer` hostname leaking** -- DNS PTR responses forwarded by routers attributed to the wrong device; now included in cross-validation source list
- **React table key instability** -- removed array index from key, preventing row remounts on sort changes
- **Device activity endpoint format** -- returned dict instead of array; frontend charts now render correctly
- **Alert delete endpoints** -- returned HTTP 200 on database failure; now returns 500 with error message
- **Identity TOCTOU race** -- `find_or_create` changed from SELECT-then-INSERT to `INSERT OR IGNORE`
- **Notification rate limiter false positive** -- `time.monotonic()` near zero on fresh CI runners blocked first notification
- **CLI `-i` flag override** -- saved interface config no longer overrides explicit `-i` when provided
- **`bytes` serialization crash** -- scapy fields containing raw bytes crashed JSON serialization in WebSocket events and sighting storage
- **`exclusive` variable undefined** -- mDNS processor referenced undefined variable, breaking exclusive service detection
- **Multi-worker pipeline** -- `worker_count > 1` path used incompatible asyncio.Queue after stdlib queue change; all processing now uses thread-based approach
