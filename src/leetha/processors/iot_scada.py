"""IoT/SCADA processor -- Modbus, BACnet, CoAP, MQTT, EtherNet/IP."""
from __future__ import annotations

from leetha.processors.registry import register_processor
from leetha.processors.base import Processor
from leetha.capture.packets import CapturedPacket
from leetha.evidence.models import Evidence


_MQTT_CLIENT_PATTERNS: list[tuple[str, str | None, str]] = [
    ("tasmota", "Tasmota", "iot_device"),
    ("shelly", "Shelly", "iot_device"),
    ("sonoff", "Sonoff", "iot_device"),
    ("homebridge", "Homebridge", "smart_home"),
    ("zigbee2mqtt", None, "smart_home"),
    ("node-red", "Node-RED", "smart_home"),
    ("homeassistant", "Home Assistant", "smart_home"),
    ("hass", "Home Assistant", "smart_home"),
    ("esphome", "ESPHome", "iot_device"),
]


@register_processor("modbus", "bacnet", "coap", "mqtt", "enip")
class IotScadaProcessor(Processor):
    """Handles ICS/SCADA and IoT protocols.

    Passive observation of these protocols provides presence detection
    and basic device categorization.
    """

    def analyze(self, packet: CapturedPacket) -> list[Evidence]:
        protocol = packet.protocol
        if protocol == "modbus":
            return self._analyze_modbus(packet)
        elif protocol == "bacnet":
            return self._analyze_bacnet(packet)
        elif protocol == "coap":
            return self._analyze_coap(packet)
        elif protocol == "mqtt":
            return self._analyze_mqtt(packet)
        elif protocol == "enip":
            return self._analyze_enip(packet)
        return []

    def _analyze_modbus(self, packet: CapturedPacket) -> list[Evidence]:
        unit_id = packet.get("unit_id")
        function_code = packet.get("function_code")
        return [Evidence(
            source="modbus", method="heuristic", certainty=0.60,
            category="ics_device",
            raw={"unit_id": unit_id, "function_code": function_code},
        )]

    def _analyze_bacnet(self, packet: CapturedPacket) -> list[Evidence]:
        vendor_id = packet.get("vendor_id")
        object_name = packet.get("object_name")
        model_name = packet.get("model_name")
        return [Evidence(
            source="bacnet", method="heuristic", certainty=0.65,
            category="building_automation",
            model=model_name,
            raw={"vendor_id": vendor_id, "object_name": object_name,
                 "model_name": model_name},
        )]

    def _analyze_coap(self, packet: CapturedPacket) -> list[Evidence]:
        uri_path = packet.get("uri_path")
        content_format = packet.get("content_format")
        return [Evidence(
            source="coap", method="heuristic", certainty=0.50,
            category="iot_device",
            raw={"uri_path": uri_path, "content_format": content_format},
        )]

    def _analyze_mqtt(self, packet: CapturedPacket) -> list[Evidence]:
        evidence: list[Evidence] = []
        client_id = packet.get("client_id", "")
        topic = packet.get("topic")

        # Baseline evidence for any MQTT traffic
        evidence.append(Evidence(
            source="mqtt", method="heuristic", certainty=0.55,
            category="iot_device",
            raw={"client_id": client_id, "topic": topic},
        ))

        # Pattern-match client_id to known IoT/smart-home prefixes
        if client_id:
            cid_lower = client_id.lower()
            for prefix, vendor, category in _MQTT_CLIENT_PATTERNS:
                if cid_lower.startswith(prefix):
                    evidence.append(Evidence(
                        source="mqtt",
                        method="pattern",
                        certainty=0.75,
                        vendor=vendor,
                        category=category,
                        raw={"client_id": client_id},
                    ))
                    break

        return evidence

    def _analyze_enip(self, packet: CapturedPacket) -> list[Evidence]:
        product_name = packet.get("product_name")
        vendor_id = packet.get("vendor_id")
        device_type = packet.get("device_type")
        return [Evidence(
            source="enip", method="heuristic", certainty=0.65,
            category="ics_device",
            model=product_name,
            raw={"product_name": product_name, "vendor_id": vendor_id,
                 "device_type": device_type},
        )]
