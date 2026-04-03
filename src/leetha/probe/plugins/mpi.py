"""MPI Process Manager (hydra/PMI) probe plugin — sends PMI hello, detects PMI response."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class MPIProbePlugin(ServiceProbe):
    name = "mpi"
    protocol = "tcp"
    default_ports = [8888]

    _CMD_RE = re.compile(r"cmd=(\S+)")
    _PMI_VERSION_RE = re.compile(r"pmi_version=(\d+)")
    _PMI_SUBVERSION_RE = re.compile(r"pmi_subversion=(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send PMI wire protocol init command
            pmi_hello = "cmd=init pmi_version=1 pmi_subversion=1\n"
            conn.write(pmi_hello.encode("utf-8"))
            data = conn.read(4096)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace").strip()

            if "cmd=" not in response:
                return None

            metadata: dict = {}
            version = None

            m = self._CMD_RE.search(response)
            if m:
                metadata["response_cmd"] = m.group(1)

            vm = self._PMI_VERSION_RE.search(response)
            sm = self._PMI_SUBVERSION_RE.search(response)
            if vm:
                pmi_ver = vm.group(1)
                pmi_sub = sm.group(1) if sm else "0"
                version = f"{pmi_ver}.{pmi_sub}"
                metadata["pmi_version"] = int(pmi_ver)
                metadata["pmi_subversion"] = int(pmi_sub)

            return ServiceIdentity(
                service="mpi",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
