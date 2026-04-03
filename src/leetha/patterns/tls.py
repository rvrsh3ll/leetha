"""Leetha TLS fingerprint computation and matching.

Implements JA3 and JA4 fingerprint algorithms for identifying TLS client
applications from their ClientHello parameters. GREASE values are filtered
per the JA3/JA4 specifications to ensure consistent hashing.

JA3: https://github.com/salesforce/ja3
JA4: https://github.com/FoxIO-LLC/ja4
"""

import hashlib
from typing import Dict, List, Optional, Tuple


# RFC 8701 GREASE Values

# Generate Randomized Extensions And Sustain Extensibility (GREASE)
# These values are injected by TLS clients to test server tolerance
# and must be filtered before fingerprint computation.
GREASE_VALUES: set[int] = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
    0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}


# Known JA3 Hashes

# Well-known JA3 hashes mapped to application/OS identification.
# Each entry: ja3_hash -> {app, os_family (optional), confidence}
KNOWN_JA3: Dict[str, dict] = {
    # Chrome on Windows
    "e7d705a3286e19ea42f587b344ee6865": {
        "app": "Chrome",
        "os_family": "Windows",
        "confidence": 70,
    },
    # Firefox (cross-platform)
    "769baa87ef9078cf6b3a85d12e0d3f40": {
        "app": "Firefox",
        "confidence": 65,
    },
    # Safari on macOS
    "b32309a26951912be7dba376398abc3b": {
        "app": "Safari",
        "os_family": "macOS",
        "confidence": 70,
    },
    # curl (cross-platform)
    "3b5074b1b5d032e5620f69f9f700ff0e": {
        "app": "curl",
        "confidence": 60,
    },
    # Python requests library (cross-platform)
    "cd08e31494f9531f560d64c695473da9": {
        "app": "Python requests",
        "confidence": 60,
    },
}


# JA4 Version and ALPN Mappings

_JA4_VERSION_MAP: Dict[int, str] = {
    0x0301: "10",  # TLS 1.0
    0x0302: "11",  # TLS 1.1
    0x0303: "12",  # TLS 1.2
    0x0304: "13",  # TLS 1.3
}

_JA4_ALPN_MAP: Dict[str, str] = {
    "h2": "h2",
    "http/1.1": "h1",
    "h3": "h3",
}


# Helper Functions

def _filter_grease(values: List[int]) -> List[int]:
    """Remove RFC 8701 GREASE values from a list of TLS parameters.

    Args:
        values: List of integer TLS parameter values (cipher suites,
                extensions, elliptic curves, etc.).

    Returns:
        New list with all GREASE values removed.
    """
    return [v for v in values if v not in GREASE_VALUES]


# JA3 Computation

def compute_ja3(
    tls_version: int,
    ciphers: List[int],
    extensions: List[int],
    elliptic_curves: List[int],
    ec_point_formats: List[int],
) -> Tuple[str, str]:
    """Compute a JA3 fingerprint hash from TLS ClientHello parameters.

    The JA3 full string is built by joining five comma-separated sections
    with commas, where each section's values are dash-separated:
        TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats

    GREASE values are filtered from ciphers, extensions, and elliptic_curves
    before hashing.

    Args:
        tls_version: TLS version as integer (e.g. 0x0303 for TLS 1.2).
        ciphers: List of cipher suite values from ClientHello.
        extensions: List of extension type values from ClientHello.
        elliptic_curves: List of supported elliptic curve/group values.
        ec_point_formats: List of EC point format values.

    Returns:
        Tuple of (md5_hash, full_string) where md5_hash is the 32-char
        lowercase hex MD5 digest and full_string is the raw JA3 string.
    """
    filtered_ciphers = _filter_grease(ciphers)
    filtered_extensions = _filter_grease(extensions)
    filtered_curves = _filter_grease(elliptic_curves)

    parts = [
        str(tls_version),
        "-".join(str(c) for c in filtered_ciphers),
        "-".join(str(e) for e in filtered_extensions),
        "-".join(str(g) for g in filtered_curves),
        "-".join(str(p) for p in ec_point_formats),
    ]

    full_string = ",".join(parts)
    md5_hash = hashlib.md5(full_string.encode("ascii")).hexdigest()

    return md5_hash, full_string


# JA4 Computation

def compute_ja4(
    tls_version: int,
    ciphers: List[int],
    extensions: List[int],
    sni: Optional[str] = None,
    alpn: Optional[str] = None,
) -> str:
    """Compute a JA4 fingerprint string from TLS ClientHello parameters.

    JA4 format: {proto}{version}{sni_flag}{cipher_count}{ext_count}{alpn_first}_{cipher_hash}_{ext_hash}

    Where:
        - proto: "t" for TLS
        - version: "10"/"11"/"12"/"13" from TLS version
        - sni_flag: "d" if SNI present, "i" if absent
        - cipher_count: 2-digit zero-padded count (max 99)
        - ext_count: 2-digit zero-padded count (max 99)
        - alpn_first: ALPN shorthand ("h2", "h1", "h3", first 2 chars, or "00")
        - cipher_hash: first 12 hex chars of SHA-256 of sorted cipher values
        - ext_hash: first 12 hex chars of SHA-256 of sorted extension values

    GREASE values are filtered from ciphers and extensions before computation.

    Args:
        tls_version: TLS version as integer (e.g. 0x0303 for TLS 1.2).
        ciphers: List of cipher suite values from ClientHello.
        extensions: List of extension type values from ClientHello.
        sni: Server Name Indication value, or None if absent.
        alpn: Application-Layer Protocol Negotiation value, or None.

    Returns:
        JA4 fingerprint string with three underscore-separated sections.
    """
    filtered_ciphers = _filter_grease(ciphers)
    filtered_extensions = _filter_grease(extensions)

    # Protocol
    proto = "t"

    # Version
    version = _JA4_VERSION_MAP.get(tls_version, "00")

    # SNI flag
    sni_flag = "d" if sni else "i"

    # Counts (2-digit zero-padded, capped at 99)
    cipher_count = f"{min(len(filtered_ciphers), 99):02d}"
    ext_count = f"{min(len(filtered_extensions), 99):02d}"

    # ALPN first
    if alpn is None:
        alpn_first = "00"
    elif alpn in _JA4_ALPN_MAP:
        alpn_first = _JA4_ALPN_MAP[alpn]
    else:
        alpn_first = alpn[:2] if len(alpn) >= 2 else alpn.ljust(2, "0")

    # Cipher hash: SHA-256 of sorted comma-separated cipher values, truncated to 12 hex chars
    sorted_ciphers = sorted(filtered_ciphers)
    cipher_str = ",".join(str(c) for c in sorted_ciphers)
    cipher_hash = hashlib.sha256(cipher_str.encode("ascii")).hexdigest()[:12]

    # Extension hash: SHA-256 of sorted comma-separated extension values, truncated to 12 hex chars
    sorted_extensions = sorted(filtered_extensions)
    ext_str = ",".join(str(e) for e in sorted_extensions)
    ext_hash = hashlib.sha256(ext_str.encode("ascii")).hexdigest()[:12]

    # Build JA4 string
    section_a = f"{proto}{version}{sni_flag}{cipher_count}{ext_count}{alpn_first}"
    return f"{section_a}_{cipher_hash}_{ext_hash}"


# Lookup

def lookup_ja3(ja3_hash: str) -> Optional[dict]:
    """Look up a JA3 hash in the known fingerprint database.

    Args:
        ja3_hash: 32-character lowercase hex MD5 JA3 hash string.

    Returns:
        Dictionary with identification info (app, os_family, confidence)
        if the hash is known, or None if not found.
    """
    return KNOWN_JA3.get(ja3_hash)
