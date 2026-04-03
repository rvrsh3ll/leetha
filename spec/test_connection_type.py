"""Tests for connection type inference."""
from leetha.connection_type import infer_connection_type


def test_lldp_always_wired():
    assert infer_connection_type(mac="aa:bb:cc:dd:ee:ff", device_type="unknown", has_lldp=True) == "wired"


def test_cdp_always_wired():
    assert infer_connection_type(mac="aa:bb:cc:dd:ee:ff", device_type="unknown", has_cdp=True) == "wired"


def test_router_wired():
    assert infer_connection_type(mac="aa:bb:cc:dd:ee:ff", device_type="router") == "wired"


def test_switch_wired():
    assert infer_connection_type(mac="aa:bb:cc:dd:ee:ff", device_type="switch") == "wired"


def test_server_wired():
    assert infer_connection_type(mac="aa:bb:cc:dd:ee:ff", device_type="server") == "wired"


def test_nas_wired():
    assert infer_connection_type(mac="aa:bb:cc:dd:ee:ff", device_type="nas") == "wired"


def test_printer_wired():
    assert infer_connection_type(mac="aa:bb:cc:dd:ee:ff", device_type="printer") == "wired"


def test_randomized_mac_wireless():
    assert infer_connection_type(mac="da:5e:7d:bb:28:1b", device_type="unknown", is_randomized_mac=True) == "wireless"


def test_smartphone_wireless():
    assert infer_connection_type(mac="aa:bb:cc:dd:ee:ff", device_type="smartphone") == "wireless"


def test_tablet_wireless():
    assert infer_connection_type(mac="aa:bb:cc:dd:ee:ff", device_type="tablet") == "wireless"


def test_smart_speaker_wireless():
    assert infer_connection_type(mac="aa:bb:cc:dd:ee:ff", device_type="smart_speaker") == "wireless"


def test_iot_wireless():
    assert infer_connection_type(mac="aa:bb:cc:dd:ee:ff", device_type="iot") == "wireless"


def test_thermostat_wireless():
    assert infer_connection_type(mac="aa:bb:cc:dd:ee:ff", device_type="thermostat") == "wireless"


def test_laptop_wireless():
    assert infer_connection_type(mac="aa:bb:cc:dd:ee:ff", device_type="laptop") == "wireless"


def test_espressif_oui_wireless():
    # Espressif ESP32 OUI - always wireless
    assert infer_connection_type(mac="24:0a:c4:11:22:33", device_type="unknown") == "wireless"


def test_intel_wireless_oui():
    assert infer_connection_type(mac="08:d4:0c:11:22:33", device_type="unknown") == "wireless"


def test_mdns_apple_mobile_wireless():
    assert infer_connection_type(
        mac="aa:bb:cc:dd:ee:ff", device_type="unknown",
        observed_services=["_apple-mobdev2._tcp"]
    ) == "wireless"


def test_mdns_google_cast_wireless():
    assert infer_connection_type(
        mac="aa:bb:cc:dd:ee:ff", device_type="unknown",
        observed_services=["_googlecast._tcp"]
    ) == "wireless"


def test_desktop_unknown():
    assert infer_connection_type(mac="aa:bb:cc:dd:ee:ff", device_type="desktop") == "unknown"


def test_workstation_unknown():
    assert infer_connection_type(mac="aa:bb:cc:dd:ee:ff", device_type="workstation") == "unknown"


def test_no_signals_unknown():
    assert infer_connection_type(mac="aa:bb:cc:dd:ee:ff", device_type=None) == "unknown"
