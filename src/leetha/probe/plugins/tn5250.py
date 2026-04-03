"""TN5250 probe plugin — IBM AS/400 terminal emulation detection."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class TN5250ProbePlugin(ServiceProbe):
    name = "tn5250"
    protocol = "tcp"
    default_ports = [23, 992]

    # Telnet IAC opcodes
    _IAC = 0xFF
    _DO = 0xFD
    _WILL = 0xFB
    _DONT = 0xFE
    _WONT = 0xFC
    _SB = 0xFA
    _SE = 0xF0
    _NEW_ENVIRON = 0x27  # NEW-ENVIRON option
    _TN5250E = 0x28  # TN3270E/TN5250E shares code point 0x28

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send Telnet DO NEW-ENVIRON + DO TN5250E negotiation
            request = bytes([
                self._IAC, self._DO, self._NEW_ENVIRON,
                self._IAC, self._DO, self._TN5250E,
            ])
            conn.write(request)

            data = conn.read(4096)
            if not data or len(data) < 3:
                return None

            # Parse response for 5250 indicators
            metadata: dict = {}
            found_5250 = False
            has_new_environ = False
            i = 0
            while i < len(data) - 2:
                if data[i] == self._IAC:
                    opcode = data[i + 1]
                    option = data[i + 2]
                    if option == self._NEW_ENVIRON and opcode in (self._WILL, self._DO):
                        has_new_environ = True
                    if option == self._TN5250E and opcode in (self._WILL, self._DO):
                        found_5250 = True
                        metadata["tn5250e_response"] = "WILL" if opcode == self._WILL else "DO"
                    i += 3
                else:
                    i += 1

            if not found_5250:
                return None

            metadata["new_environ"] = has_new_environ

            # Check for AS/400 sign-on screen markers in any extra data
            text = data.decode("latin-1", errors="replace")
            if "AS/400" in text or "IBM i" in text or "iSeries" in text:
                metadata["platform"] = "AS/400"

            return ServiceIdentity(
                service="tn5250",
                certainty=80,
                version=None,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
