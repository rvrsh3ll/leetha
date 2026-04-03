"""Cisco Smart Install probe plugin — detects Cisco SMI protocol on conn.port 4786."""
from __future__ import annotations
import struct
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class CiscoSmartInstallProbePlugin(ServiceProbe):
    name = "cisco_smart_install"
    protocol = "tcp"
    default_ports = [4786]

    # Smart Install protocol header constants
    _SMI_HEADER = struct.pack(">IIII", 0x00000001, 0x00000001, 0x00000004, 0x00000008)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send Smart Install protocol header
            conn.write(self._SMI_HEADER)

            data = conn.read(4096)
            if not data:
                return None

            # A valid SMI response should be at least 4 bytes
            if len(data) < 4:
                return None

            metadata: dict = {"response_length": len(data)}

            # Check for valid Smart Install response
            # The response typically starts with the SMI magic or a known pattern
            if len(data) >= 16:
                try:
                    fields = struct.unpack(">IIII", data[:16])
                    metadata["response_fields"] = list(fields)
                    # A valid response echoes back recognizable field values
                    if fields[0] == 0x00000004:
                        metadata["smi_version"] = 1
                except struct.error:
                    pass

            # Even a non-empty response to the SMI header is significant
            # since non-SMI services would typically close or send HTTP/SSH/etc
            # We check the response doesn't look like common other protocols
            response_text = data.decode("utf-8", errors="replace")
            for proto_sig in ("HTTP/", "SSH-", "220 ", "+OK", "* OK"):
                if response_text.startswith(proto_sig):
                    return None

            return ServiceIdentity(
                service="cisco_smart_install",
                certainty=75,
                version=None,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
