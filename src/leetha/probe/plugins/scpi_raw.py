"""SCPI Raw Socket probe plugin — lab instrument identification."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SCPIRawProbePlugin(ServiceProbe):
    name = "scpi_raw"
    protocol = "tcp"
    default_ports = [5025]

    # *IDN? response format: Manufacturer,Model,SerialNumber,FirmwareVersion
    _IDN_RE = re.compile(r"^(.+?),\s*(.+?),\s*(.+?),\s*(.+?)$", re.MULTILINE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            conn.write(b"*IDN?\n")
            data = conn.read(4096)
            if not data:
                return None

            text = data.decode("utf-8", errors="replace").strip()
            if not text:
                return None

            m = self._IDN_RE.match(text)
            if not m:
                return None

            manufacturer = m.group(1).strip()
            model = m.group(2).strip()
            serial = m.group(3).strip()
            firmware = m.group(4).strip()

            metadata: dict = {
                "manufacturer": manufacturer,
                "model": model,
                "serial_number": serial,
            }

            return ServiceIdentity(
                service="scpi_raw",
                certainty=90,
                version=firmware,
                metadata=metadata,
                banner=text[:512],
            )

        except (socket.timeout, OSError):
            return None
