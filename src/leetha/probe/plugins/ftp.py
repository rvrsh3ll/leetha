"""FTP probe plugin — banner grab."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class FTPProbePlugin(ServiceProbe):
    name = "ftp"
    protocol = "tcp"
    default_ports = [21]

    _BANNER_RE = re.compile(r"^(\d{3})[ -](.+)", re.DOTALL)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            data = conn.read(1024)
            if not data:
                return None
            banner = data.decode("utf-8", errors="replace").strip()
            m = self._BANNER_RE.match(banner)
            if not m:
                return None
            code = m.group(1)
            if code not in ("220", "421"):
                return None
            metadata = {"banner_code": code}
            version = None
            for pattern, name in [
                (r"vsftpd ([\d.]+)", "vsftpd"),
                (r"ProFTPD ([\d.]+)", "ProFTPD"),
                (r"Pure-FTPd", "Pure-FTPd"),
                (r"FileZilla Server ([\d.]+)", "FileZilla"),
                (r"Microsoft FTP Service", "Microsoft FTP"),
            ]:
                vm = re.search(pattern, banner, re.IGNORECASE)
                if vm:
                    version = vm.group(0)
                    metadata["product"] = name
                    break
            return ServiceIdentity(service="ftp", version=version, banner=banner, metadata=metadata, certainty=90)
        except (socket.timeout, OSError):
            return None
