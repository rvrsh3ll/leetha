"""Dovecot probe plugin — Dovecot-specific IMAP/POP3 banner detection."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class DovecotProbePlugin(ServiceProbe):
    name = "dovecot"
    protocol = "tcp"
    default_ports = [143, 110]

    _DOVECOT_RE = re.compile(r"Dovecot(?:\s+[\w.-]+)?\s+ready", re.IGNORECASE)
    _VERSION_RE = re.compile(r"Dovecot\s+([\d.]+)", re.IGNORECASE)
    _IMAP_RE = re.compile(r"^\* OK", re.MULTILINE)
    _POP3_RE = re.compile(r"^\+OK", re.MULTILINE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            data = conn.read(1024)
            if not data:
                return None

            banner = data.decode("utf-8", errors="replace").strip()

            # Must contain "Dovecot" somewhere in the banner
            if "Dovecot" not in banner and "dovecot" not in banner:
                return None

            # Must look like IMAP or POP3 greeting
            if not self._IMAP_RE.search(banner) and not self._POP3_RE.search(banner):
                return None

            metadata: dict = {}
            version = None

            ver = self._VERSION_RE.search(banner)
            if ver:
                version = ver.group(1)

            if self._IMAP_RE.search(banner):
                metadata["protocol"] = "imap"
            elif self._POP3_RE.search(banner):
                metadata["protocol"] = "pop3"

            if self._DOVECOT_RE.search(banner):
                metadata["ready"] = True

            return ServiceIdentity(
                service="dovecot",
                certainty=90,
                version=version,
                metadata=metadata,
                banner=banner,
            )
        except (socket.timeout, OSError):
            return None
