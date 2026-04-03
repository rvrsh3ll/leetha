"""SMTP Submission (MSA) probe plugin — conn.port 587 mail submission agent."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SubmissionProbePlugin(ServiceProbe):
    name = "submission"
    protocol = "tcp"
    default_ports = [587]

    _BANNER_RE = re.compile(r"^220\s+(\S+)\s+(.*)", re.DOTALL)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            data = conn.read(1024)
            if not data:
                return None

            banner = data.decode("utf-8", errors="replace").strip()

            if not banner.startswith("220"):
                return None

            # Must contain ESMTP or submission-related keywords
            if "ESMTP" not in banner and "Submission" not in banner:
                return None

            metadata: dict = {}
            version = None

            match = self._BANNER_RE.match(banner)
            if match:
                metadata["hostname"] = match.group(1)

            for pattern, name in [
                (r"Postfix", "Postfix"),
                (r"Exim ([\d.]+)", "Exim"),
                (r"Microsoft ESMTP", "Microsoft Exchange"),
                (r"Dovecot", "Dovecot"),
            ]:
                vm = re.search(pattern, banner, re.IGNORECASE)
                if vm:
                    version = vm.group(0)
                    metadata["product"] = name
                    break

            return ServiceIdentity(
                service="submission",
                certainty=85,
                version=version,
                metadata=metadata,
                banner=banner,
            )
        except (socket.timeout, OSError):
            return None
