"""HL7 MLLP probe plugin — Health Level 7 Minimal Lower Layer Protocol."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

# MLLP framing bytes
_SB = b"\x0b"   # Start Block
_EB = b"\x1c"   # End Block
_CR = b"\x0d"   # Carriage Return

class HL7MLLPProbePlugin(ServiceProbe):
    name = "hl7_mllp"
    protocol = "tcp"
    default_ports = [2575]

    _MSH_RE = re.compile(r"MSH\|")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build a minimal HL7 QBP^Q22 query wrapped in MLLP framing
            hl7_msg = (
                "MSH|^~\\&|PROBE|PROBE|TARGET|TARGET|"
                "20240101120000||QBP^Q22|1|P|2.5\r"
                "QPD|IHE PDQ Query|Q0001|@PID.3.1^PROBE\r"
            )
            mllp_frame = _SB + hl7_msg.encode("utf-8") + _EB + _CR
            conn.write(mllp_frame)
            data = conn.read(4096)
            if not data or len(data) < 4:
                return None

            # Strip MLLP framing if present
            payload = data
            if payload[0:1] == _SB:
                payload = payload[1:]
            eb_pos = payload.find(_EB)
            if eb_pos != -1:
                payload = payload[:eb_pos]

            text = payload.decode("utf-8", errors="replace")

            # Must contain MSH segment to be HL7
            if not self._MSH_RE.search(text):
                return None

            metadata: dict = {}
            # Try to parse MSH fields
            fields = text.split("\r")[0].split("|") if "\r" in text else text.split("|")
            if len(fields) >= 12:
                metadata["sending_app"] = fields[2] if fields[2] else None
                metadata["sending_facility"] = fields[3] if fields[3] else None
                metadata["message_type"] = fields[8] if fields[8] else None
                metadata["version"] = fields[11] if fields[11] else None

            version = metadata.get("version")
            return ServiceIdentity(
                service="hl7_mllp",
                certainty=90,
                version=version,
                metadata=metadata,
                banner=text[:512],
            )

        except (socket.timeout, OSError):
            return None
