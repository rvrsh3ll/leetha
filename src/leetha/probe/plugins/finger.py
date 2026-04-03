"""Finger protocol probe plugin — detect finger daemon."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class FingerProbePlugin(ServiceProbe):
    name = "finger"
    protocol = "tcp"
    default_ports = [79]

    _USER_RE = re.compile(r"(?:Login|User|Name|Directory|Shell|Mail)[\s:]+\S+", re.IGNORECASE)
    _FINGER_RE = re.compile(r"(?:finger|In real life|No Plan|Plan:)", re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send CRLF query (list all users)
            conn.write(b"\r\n")

            data = conn.read(4096)
            if not data:
                return None

            text = data.decode("utf-8", errors="replace").strip()
            if not text:
                return None

            metadata: dict = {}

            # Look for finger-specific response patterns
            user_matches = self._USER_RE.findall(text)
            finger_matches = self._FINGER_RE.findall(text)

            if not user_matches and not finger_matches:
                # Also check for finger daemon error/rejection messages
                lower = text.lower()
                if not any(kw in lower for kw in ("finger", "no such user",
                                                    "line", "tty", "idle")):
                    return None

            if user_matches:
                metadata["user_fields"] = len(user_matches)
            if finger_matches:
                metadata["finger_markers"] = len(finger_matches)

            banner = text[:512] if text else None

            return ServiceIdentity(
                service="finger",
                certainty=80,
                version=None,
                banner=banner,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
