"""Banner processor — converts passive service banners into Evidence."""
from __future__ import annotations

from leetha.processors.registry import register_processor
from leetha.processors.base import Processor
from leetha.capture.packets import CapturedPacket
from leetha.evidence.models import Evidence


_SERVICE_CATEGORIES: dict[str, str] = {
    "ssh": "server", "ftp": "server", "smtp": "server",
    "imap": "server", "pop3": "server",
    "mysql": "server", "postgresql": "server", "mssql": "server",
    "mongodb": "server", "redis": "server", "irc": "server",
    "ipp": "printer", "jetdirect": "printer", "lpd": "printer",
    "mqtt": "server", "amqp": "server",
    "sip": "server",
    "rtsp": "ip_camera",
    "unifiprotect": "ip_camera",
    "ldap": "server",
    "cassandra": "server", "elasticsearch": "server",
    "docker_api": "server", "kubernetes_api": "server",
    "socks": "server",
    "bgp": "router",
    "pptp": "server",
}

_SERVICE_PLATFORMS: dict[str, str] = {
    "rdp": "Windows",
    "mssql": "Windows",
}

_SOFTWARE_VENDORS: dict[str, str] = {
    "openssh": "OpenSSH",
    "dropbear": "Dropbear",
    "proftpd": "ProFTPD",
    "vsftpd": "vsFTPd",
    "postfix": "Postfix",
    "exim": "Exim",
    "dovecot": "Dovecot",
    "mysql": "MySQL",
    "mariadb": "MariaDB",
    "postgresql": "PostgreSQL",
    "microsoft sql server": "Microsoft",
    "mongodb": "MongoDB",
    "redis": "Redis",
    "elasticsearch": "Elastic",
    "docker": "Docker",
    "kubernetes": "Kubernetes",
    "rabbitmq": "RabbitMQ",
    "unifi protect": "Ubiquiti",
    "ubiquiti": "Ubiquiti",
}

_SSH_OS_HINTS: dict[str, str] = {
    "ubuntu": "Linux",
    "debian": "Linux",
    "freebsd": "FreeBSD",
}


@register_processor("service_banner")
class BannerProcessor(Processor):
    """Converts passive service banner captures into fingerprint evidence."""

    def analyze(self, packet: CapturedPacket) -> list[Evidence]:
        service = packet.get("service")
        if not service:
            return []

        software = packet.get("software", "")
        version = packet.get("version")
        server_port = packet.get("server_port")

        category = _SERVICE_CATEGORIES.get(service)
        platform = _SERVICE_PLATFORMS.get(service)
        vendor = self._resolve_vendor(software)
        platform_version = version

        # SSH OS hints from the software string
        if service == "ssh" and software:
            sw_lower = software.lower()
            for hint, os_name in _SSH_OS_HINTS.items():
                if hint in sw_lower:
                    platform = os_name
                    break

        evidence = [Evidence(
            source="passive_banner",
            method="pattern",
            certainty=0.85,
            category=category,
            vendor=vendor,
            platform=platform,
            platform_version=platform_version,
            raw={
                "service": service,
                "software": software,
                "version": version,
                "server_port": server_port,
            },
        )]

        # OT device identity extraction from banner content
        banner_text = packet.get("banner", "") or ""
        if banner_text:
            ot_evidence = self._extract_ot_identity(banner_text)
            if ot_evidence:
                evidence.extend(ot_evidence)

        return evidence

    def _extract_ot_identity(self, banner: str) -> list[Evidence]:
        """Extract OT device identity from service banner content."""
        import re
        results = []

        # SEL relay banners (Telnet/SSH): "SEL-351-7 FID=SEL-351-7-R107-V0-Z002002-D20130514"
        sel_match = re.search(r'(SEL-\d{3,4}[A-Z]?)', banner, re.IGNORECASE)
        if sel_match:
            model = sel_match.group(1).upper()
            fid_match = re.search(r'FID=([\w-]+)', banner)
            results.append(Evidence(
                source="passive_banner", method="pattern", certainty=0.90,
                vendor="SEL", model=model, category="ics_device",
                raw={"banner": banner[:200], "fid": fid_match.group(1) if fid_match else None},
            ))

        # GE Multilin banners: "GE Multilin T60" or "UR-series"
        ge_match = re.search(r'(?:GE\s+)?Multilin\s+([A-Z]\d{2,3})', banner, re.IGNORECASE)
        if ge_match:
            model = f"GE Multilin {ge_match.group(1).upper()}"
            results.append(Evidence(
                source="passive_banner", method="pattern", certainty=0.90,
                vendor="GE", model=model, category="ics_device",
                raw={"banner": banner[:200]},
            ))

        # Schneider Modicon: "BMX P34 2020" or "Modicon M340"
        schneider_match = re.search(r'(?:BMX\s*[A-Z]\d{2}\s*\d{4}|Modicon\s+[A-Z]\d{3,4})', banner, re.IGNORECASE)
        if schneider_match:
            model = schneider_match.group(0)
            results.append(Evidence(
                source="passive_banner", method="pattern", certainty=0.85,
                vendor="Schneider Electric", model=model, category="plc",
                raw={"banner": banner[:200]},
            ))

        # Siemens PLC: "S7-300" or "SIMATIC S7-1200" or "6ES7"
        siemens_match = re.search(r'(?:SIMATIC\s+)?S7-(\d{3,4})', banner, re.IGNORECASE)
        if not siemens_match:
            siemens_match = re.search(r'6ES7\s*\d{3}', banner)
        if siemens_match:
            results.append(Evidence(
                source="passive_banner", method="pattern", certainty=0.85,
                vendor="Siemens", model=siemens_match.group(0), category="plc",
                raw={"banner": banner[:200]},
            ))

        # Woodward controller: "easYgen" or "2301" or "MicroNet"
        woodward_match = re.search(r'(?:easYgen|MicroNet|Woodward.*(?:2301|DECS|ProTech))', banner, re.IGNORECASE)
        if woodward_match:
            results.append(Evidence(
                source="passive_banner", method="pattern", certainty=0.85,
                vendor="Woodward", model=woodward_match.group(0), category="ics_device",
                raw={"banner": banner[:200]},
            ))

        # ABB controllers/relays: "AC500" or "ABB AC800M" or "REF615" or "ACS880"
        abb_match = re.search(r'ABB\s+(AC\d{3}[A-Z]?|ACS\d{3}|RE[FTL]\d{3}|800xA|Relion)', banner, re.IGNORECASE)
        if not abb_match:
            abb_match = re.search(r'(AC500|AC800[A-Z]?|ACS\d{3}|RE[FTL]\d{3})', banner, re.IGNORECASE)
        if abb_match:
            model = abb_match.group(0)
            results.append(Evidence(
                source="passive_banner", method="pattern", certainty=0.85,
                vendor="ABB", model=model, category="plc" if "AC" in model.upper() else "ics_device",
                raw={"banner": banner[:200]},
            ))

        # Rockwell/Allen-Bradley: "ControlLogix" or "CompactLogix" or "1756-" or "1769-"
        rockwell_match = re.search(r'(?:Allen-Bradley\s+)?(?:ControlLogix|CompactLogix|MicroLogix|GuardLogix|PanelView|PowerFlex|Stratix)\s*\d*', banner, re.IGNORECASE)
        if not rockwell_match:
            rockwell_match = re.search(r'(?:1756|1769|1762|2711|20-)[A-Z0-9-]+', banner)
        if rockwell_match:
            model = rockwell_match.group(0)
            cat = "plc"
            if "panelview" in model.lower(): cat = "hmi"
            elif "stratix" in model.lower(): cat = "industrial_switch"
            elif "powerflex" in model.lower(): cat = "ics_device"
            results.append(Evidence(
                source="passive_banner", method="pattern", certainty=0.85,
                vendor="Rockwell", model=model, category=cat,
                raw={"banner": banner[:200]},
            ))

        # Honeywell: "Experion" or "ControlEdge" or "HC900" or "Safety Manager"
        honeywell_match = re.search(r'(?:Honeywell\s+)?(?:Experion|ControlEdge|HC900|Safety\s*Manager|MasterLogic)', banner, re.IGNORECASE)
        if honeywell_match:
            model = honeywell_match.group(0)
            results.append(Evidence(
                source="passive_banner", method="pattern", certainty=0.85,
                vendor="Honeywell", model=model, category="scada_server" if "experion" in model.lower() else "plc",
                raw={"banner": banner[:200]},
            ))

        # Emerson: "DeltaV" or "ROC800" or "Ovation" or "Fisher"
        emerson_match = re.search(r'(?:Emerson\s+)?(?:DeltaV|ROC\d{3,4}|Ovation|Fisher\s+ROC)', banner, re.IGNORECASE)
        if emerson_match:
            model = emerson_match.group(0)
            results.append(Evidence(
                source="passive_banner", method="pattern", certainty=0.85,
                vendor="Emerson", model=model, category="rtu" if "roc" in model.lower() else "scada_server",
                raw={"banner": banner[:200]},
            ))

        # Yokogawa: "CENTUM" or "ProSafe" or "STARDOM" or "FA-M3"
        yokogawa_match = re.search(r'(?:Yokogawa\s+)?(?:CENTUM\s*VP?|ProSafe|STARDOM|FA-M3|FAST/TOOLS)', banner, re.IGNORECASE)
        if yokogawa_match:
            model = yokogawa_match.group(0)
            results.append(Evidence(
                source="passive_banner", method="pattern", certainty=0.85,
                vendor="Yokogawa", model=model, category="scada_server",
                raw={"banner": banner[:200]},
            ))

        # Mitsubishi: "MELSEC" or "iQ-R" or "FX5U" or "GOT2000"
        mitsubishi_match = re.search(r'(?:Mitsubishi\s+)?(?:MELSEC|iQ-[RF]\s*\w*|FX[35][A-Z]+|GOT\d{4}|Q\d{2}[A-Z]*CPU)', banner, re.IGNORECASE)
        if mitsubishi_match:
            model = mitsubishi_match.group(0)
            cat = "hmi" if "got" in model.lower() else "plc"
            results.append(Evidence(
                source="passive_banner", method="pattern", certainty=0.85,
                vendor="Mitsubishi", model=model, category=cat,
                raw={"banner": banner[:200]},
            ))

        # Omron: "NX102" or "NJ501" or "CJ2M" or "Sysmac"
        omron_match = re.search(r'(?:Omron\s+)?(?:NX\d{3}|NJ\d{3}|CJ[12][A-Z]|CP1[A-Z]|Sysmac)', banner, re.IGNORECASE)
        if omron_match:
            results.append(Evidence(
                source="passive_banner", method="pattern", certainty=0.80,
                vendor="Omron", model=omron_match.group(0), category="plc",
                raw={"banner": banner[:200]},
            ))

        # Moxa: "ioLogik" or "NPort" or "EDS-"
        moxa_match = re.search(r'(?:Moxa\s+)?(?:ioLogik\s*[A-Z]?\d{4}|NPort\s*\d{4}|EDS-\d{3,4})', banner, re.IGNORECASE)
        if moxa_match:
            model = moxa_match.group(0)
            cat = "industrial_switch" if "eds" in model.lower() else "ics_device"
            results.append(Evidence(
                source="passive_banner", method="pattern", certainty=0.85,
                vendor="Moxa", model=model, category=cat,
                raw={"banner": banner[:200]},
            ))

        # Schneider SCADAPack: "SCADAPack" or "Telvent"
        scadapack_match = re.search(r'SCADAPack\s*\d*', banner, re.IGNORECASE)
        if scadapack_match:
            results.append(Evidence(
                source="passive_banner", method="pattern", certainty=0.85,
                vendor="Schneider Electric", model=scadapack_match.group(0), category="rtu",
                raw={"banner": banner[:200]},
            ))

        # CODESYS runtime (used by many PLC vendors)
        codesys_match = re.search(r'CODESYS\s*(?:Control)?(?:\s*V?(\d+\.\d+))?', banner, re.IGNORECASE)
        if codesys_match:
            results.append(Evidence(
                source="passive_banner", method="pattern", certainty=0.70,
                model="CODESYS Runtime", category="plc",
                platform="CODESYS",
                platform_version=codesys_match.group(1) if codesys_match.group(1) else None,
                raw={"banner": banner[:200]},
            ))

        # Firmware version extraction: "FW:" or "Firmware:" or "Version:" followed by digits
        fw_match = re.search(r'(?:FW|Firmware|Version|Rev)[:\s]+([0-9]+(?:\.[0-9]+)+)', banner, re.IGNORECASE)
        if fw_match and results:
            results[0].platform_version = fw_match.group(1)

        return results

    @staticmethod
    def _resolve_vendor(software: str | None) -> str | None:
        if not software:
            return None
        sw_lower = software.lower()
        for key, vendor_name in _SOFTWARE_VENDORS.items():
            if key in sw_lower:
                return vendor_name
        return software
