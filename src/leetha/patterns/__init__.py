"""Leetha fingerprint pattern database.

All pattern data is loaded from JSON files in the data/ directory.
The loader provides validation, caching, and regex pre-compilation.
Matching functions live in ``patterns.matching``.
"""
from leetha.patterns.loader import load

# =====================================================================
# Load pattern data from JSON and expose as module-level constants
# for backward compatibility with existing imports like:
#   from leetha.patterns import SSH_PATTERNS
# =====================================================================

_banners = load("banners")  # dict of category -> list of pattern dicts

# Banner categories (basic 6-element format in legacy code)
SSH_PATTERNS = _banners.get("ssh", [])
HTTP_PATTERNS = _banners.get("http", [])
SMB_PATTERNS = _banners.get("smb", [])
FTP_PATTERNS = _banners.get("ftp", [])
SMTP_PATTERNS = _banners.get("smtp", [])
IMAP_POP_PATTERNS = _banners.get("imap_pop", [])
TELNET_PATTERNS = _banners.get("telnet", [])
BANNER_DNS_PATTERNS = _banners.get("dns", [])
LDAP_PATTERNS = _banners.get("ldap", [])
SNMP_PATTERNS = _banners.get("snmp", [])
RDP_VNC_PATTERNS = _banners.get("rdp_vnc", [])
SIP_PATTERNS = _banners.get("sip", [])
NTP_PATTERNS = _banners.get("ntp", [])
MQTT_PATTERNS = _banners.get("mqtt", [])
PRINTER_PATTERNS = _banners.get("printer", [])
GAMING_MEDIA_PATTERNS = _banners.get("gaming_media", [])
NETWORK_PATTERNS = _banners.get("network", [])
STORAGE_PATTERNS = _banners.get("storage", [])
BACKUP_PATTERNS = _banners.get("backup", [])
KERBEROS_PATTERNS = _banners.get("kerberos", [])
RADIUS_PATTERNS = _banners.get("radius", [])
MESSAGE_QUEUE_PATTERNS = _banners.get("message_queue", [])
CACHE_PATTERNS = _banners.get("cache", [])
STREAMING_PATTERNS = _banners.get("streaming", [])
VCS_PATTERNS = _banners.get("vcs", [])
CHAT_PATTERNS = _banners.get("chat", [])
WEBRTC_PATTERNS = _banners.get("webrtc", [])
INDUSTRIAL_PATTERNS = _banners.get("industrial", [])
IOT_PROTOCOL_PATTERNS = _banners.get("iot_protocol", [])
FILE_SYNC_PATTERNS = _banners.get("file_sync", [])
API_PATTERNS = _banners.get("api", [])

# Banner categories (extended 7-element format with device_type)
IOT_HTTP_PATTERNS = _banners.get("iot_http", [])
SCADA_PATTERNS = _banners.get("scada", [])
VIRTUALIZATION_PATTERNS = _banners.get("virtualization", [])
CONTAINER_PATTERNS = _banners.get("container", [])
WEBAPP_PATTERNS = _banners.get("webapp", [])
DATABASE_PATTERNS = _banners.get("database", [])
SECURITY_PATTERNS = _banners.get("security", [])
COMMUNICATION_PATTERNS = _banners.get("communication", [])
CLOUD_PATTERNS = _banners.get("cloud", [])

# Hostname patterns
HOSTNAME_PATTERNS = load("hostname")

# mDNS patterns
_mdns = load("mdns")
MDNS_SERVICE_PATTERNS = _mdns.get("services", {})
MDNS_NAME_PATTERNS = _mdns.get("names", [])

# SSDP patterns
_ssdp = load("ssdp")
SERVER_PATTERNS = _ssdp.get("server_patterns", [])
UPNP_DEVICE_TYPES = _ssdp.get("upnp_device_types", {})

# DHCP patterns (loaded via matching module's internal loader)
from leetha.patterns.matching import _get_dhcp_patterns as _gdp  # noqa: E402
_opt55, _opt60 = _gdp()
DHCP_OPT55_PATTERNS = _opt55
DHCP_OPT60_PATTERNS = _opt60

# DHCPv6 patterns
_dhcpv6 = load("dhcpv6")
DHCPV6_ORO_PATTERNS = _dhcpv6.get("oro", {})
DHCPV6_ENTERPRISE_IDS = _dhcpv6.get("enterprise_ids", {})
DHCPV6_VENDOR_CLASS_PATTERNS = _dhcpv6.get("vendor_class", [])
DUID_TYPE_HINTS = {1: "DUID-LLT", 2: "DUID-EN", 3: "DUID-LL", 4: "DUID-UUID"}

# NetBIOS suffixes (small fixed data, kept inline via JSON or matching module)
from leetha.patterns.matching import match_netbios_suffix as _tmp_nb  # noqa: E402
NETBIOS_SUFFIXES = {
    0x00: {"service": "Workstation", "device_type": "workstation"},
    0x01: {"service": "Messenger (client)", "device_type": "workstation"},
    0x03: {"service": "Messenger", "device_type": "workstation"},
    0x06: {"service": "RAS Server", "device_type": "server"},
    0x1B: {"service": "Domain Master Browser", "device_type": "server"},
    0x1C: {"service": "Domain Controller", "device_type": "server"},
    0x1D: {"service": "Master Browser", "device_type": "server"},
    0x1E: {"service": "Browser Service Elections", "device_type": "workstation"},
    0x1F: {"service": "NetDDE Service", "device_type": "workstation"},
    0x20: {"service": "File Server", "device_type": "server"},
    0x21: {"service": "RAS Client", "device_type": "workstation"},
    0x22: {"service": "Microsoft Exchange Interchange", "device_type": "server"},
    0x23: {"service": "Microsoft Exchange Store", "device_type": "server"},
    0x24: {"service": "Microsoft Exchange Directory", "device_type": "server"},
    0x30: {"service": "Modem Sharing Server", "device_type": "server"},
    0x31: {"service": "Modem Sharing Client", "device_type": "workstation"},
    0x43: {"service": "SMS Clients Remote Control", "device_type": "workstation"},
    0x44: {"service": "SMS Admin Remote Control Tool", "device_type": "server"},
    0x45: {"service": "SMS Clients Remote Chat", "device_type": "workstation"},
    0x46: {"service": "SMS Clients Remote Transfer", "device_type": "workstation"},
    0x4C: {"service": "DEC Pathworks TCP/IP Service", "device_type": "server"},
    0x52: {"service": "DEC Pathworks TCP/IP Service", "device_type": "server"},
    0x87: {"service": "Microsoft Exchange MTA", "device_type": "server"},
    0x6A: {"service": "Microsoft Exchange IMC", "device_type": "server"},
    0xBE: {"service": "Network Monitor Agent", "device_type": "server"},
    0xBF: {"service": "Network Monitor Application", "device_type": "server"},
}
del _tmp_nb

# ICMPv6 RA fingerprints
RA_FINGERPRINTS = load("icmpv6")

# TLS functions stay as Python (they compute, not just store data)
from leetha.patterns.tls import GREASE_VALUES, KNOWN_JA3, compute_ja3, compute_ja4  # noqa: E402,F401

# Re-export matching functions for backward compatibility
from leetha.patterns.matching import (  # noqa: E402,F401
    match_banner,
    match_banner_extended,
    match_ssdp_server,
    match_upnp_device_type,
    match_mdns_service,
    match_dns_query,
    match_dhcp_opt55,
    match_dhcp_opt60,
    get_dhcp_fingerprint_hash,
    match_dhcpv6_oro,
    match_dhcpv6_enterprise,
    match_dhcpv6_vendor_class,
    get_duid_type_hint,
    match_netbios_suffix,
    match_llmnr_query,
    match_ra_fingerprint,
    analyze_slaac_address,
    detect_ra_spoofing,
    match_hostname,
    match_http_ai_path,
    AI_PORT_HINTS,
    MDNS_SERVICE_DEVICE_MAP,
)

# Convenience groupings for bulk loading
BASIC_PATTERN_LISTS = [
    SSH_PATTERNS, HTTP_PATTERNS, FTP_PATTERNS,
    SMTP_PATTERNS, TELNET_PATTERNS,
]

EXTENDED_PATTERN_LISTS = [
    SMB_PATTERNS, IMAP_POP_PATTERNS, BANNER_DNS_PATTERNS,
    LDAP_PATTERNS, SNMP_PATTERNS, RDP_VNC_PATTERNS,
    SIP_PATTERNS, NTP_PATTERNS, MQTT_PATTERNS,
    PRINTER_PATTERNS, GAMING_MEDIA_PATTERNS,
    NETWORK_PATTERNS, STORAGE_PATTERNS,
    BACKUP_PATTERNS, KERBEROS_PATTERNS,
    RADIUS_PATTERNS, MESSAGE_QUEUE_PATTERNS,
    CACHE_PATTERNS, STREAMING_PATTERNS,
    VCS_PATTERNS, CHAT_PATTERNS, WEBRTC_PATTERNS,
    INDUSTRIAL_PATTERNS, IOT_PROTOCOL_PATTERNS,
    FILE_SYNC_PATTERNS, API_PATTERNS,
    IOT_HTTP_PATTERNS, SCADA_PATTERNS,
    VIRTUALIZATION_PATTERNS, CONTAINER_PATTERNS,
    WEBAPP_PATTERNS, DATABASE_PATTERNS,
    SECURITY_PATTERNS, COMMUNICATION_PATTERNS,
    CLOUD_PATTERNS,
]
