"""SMTP probe plugin — banner grab."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SMTPProbePlugin(ServiceProbe):
    name = "smtp"
    protocol = "tcp"
    default_ports = [25, 465, 587]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            data = conn.read(1024)
            if not data:
                return None
            banner = data.decode("utf-8", errors="replace").strip()
            if not banner.startswith("220"):
                return None
            metadata = {}
            version = None
            for pattern, name in [
                (r"Postfix", "Postfix"),
                (r"Exim ([\d.]+)", "Exim"),
                (r"Microsoft ESMTP", "Microsoft Exchange"),
                (r"Sendmail ([\d./]+)", "Sendmail"),
            ]:
                vm = re.search(pattern, banner, re.IGNORECASE)
                if vm:
                    version = vm.group(0)
                    metadata["product"] = name
                    break
            return ServiceIdentity(service="smtp", version=version, banner=banner, metadata=metadata, certainty=90)
        except (socket.timeout, OSError):
            return None
