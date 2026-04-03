"""TN3270 probe plugin — IBM mainframe TN3270E terminal detection."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class TN3270ProbePlugin(ServiceProbe):
    name = "tn3270"
    protocol = "tcp"
    default_ports = [23, 2023]

    # Telnet IAC opcodes
    _IAC = 0xFF
    _DO = 0xFD
    _WILL = 0xFB
    _DONT = 0xFE
    _WONT = 0xFC
    _TN3270E = 0x28  # TN3270E option code

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send Telnet DO TN3270E negotiation
            # IAC DO TN3270E
            request = bytes([self._IAC, self._DO, self._TN3270E])
            conn.write(request)

            data = conn.read(4096)
            if not data or len(data) < 3:
                return None

            # Parse response looking for IAC WILL/WONT TN3270E or IAC DO/DONT TN3270E
            metadata: dict = {}
            found_tn3270e = False
            i = 0
            while i < len(data) - 2:
                if data[i] == self._IAC:
                    opcode = data[i + 1]
                    option = data[i + 2]
                    if option == self._TN3270E:
                        found_tn3270e = True
                        if opcode == self._WILL:
                            metadata["tn3270e_response"] = "WILL"
                        elif opcode == self._WONT:
                            metadata["tn3270e_response"] = "WONT"
                        elif opcode == self._DO:
                            metadata["tn3270e_response"] = "DO"
                        elif opcode == self._DONT:
                            metadata["tn3270e_response"] = "DONT"
                    i += 3
                else:
                    i += 1

            if not found_tn3270e:
                return None

            # Extract any banner text after IAC sequences
            banner = self._extract_banner(data)
            if banner:
                metadata["banner"] = banner

            return ServiceIdentity(
                service="tn3270",
                certainty=85,
                version=None,
                banner=banner,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None

    @staticmethod
    def _extract_banner(data: bytes) -> str | None:
        """Strip IAC sequences and return any readable text."""
        cleaned = bytearray()
        i = 0
        while i < len(data):
            if data[i] == 0xFF and i + 2 < len(data):
                i += 3
            else:
                cleaned.append(data[i])
                i += 1
        text = bytes(cleaned).decode("utf-8", errors="replace").strip()
        return text if text else None
