from pathlib import Path

from src.zeek.manager import ZeekManager


def test_manager_uses_expected_default_log_directory():
    manager = ZeekManager()
    assert manager.log_dir == (
        Path(__file__).resolve().parents[1]
        / "data"
        / "processed"
        / "zeek"
        / "live"
    )


def test_status_reports_installation_without_starting_sensor(monkeypatch):
    manager = ZeekManager()
    monkeypatch.setattr(manager, "is_installed", lambda: True)
    monkeypatch.setattr(manager, "version", lambda: "zeek version 8.2.2")

    status = manager.status()

    assert status.installed is True
    assert status.version == "zeek version 8.2.2"
    assert status.running is False
    assert status.pid is None


def test_start_rejects_unknown_interface(monkeypatch):
    manager = ZeekManager()
    monkeypatch.setattr(manager, "is_installed", lambda: True)
    monkeypatch.setattr(manager, "list_interfaces", lambda: ["lo", "wlan0"])

    try:
        manager.start("does-not-exist")
    except ValueError as exc:
        assert str(exc) == "Network interface not found: does-not-exist"
    else:
        raise AssertionError("Expected ValueError for an unknown interface")


def test_windows_local_binary_is_detected(monkeypatch, tmp_path):
    local = tmp_path / "zeek.exe"
    local.write_text("stub", encoding="utf-8")

    manager = ZeekManager()
    monkeypatch.setattr(manager, "is_installed", lambda: True)
    manager.zeek_binary = str(local)

    assert manager.is_installed() is True


def test_verify_live_capture_rolls_back_on_failure(monkeypatch):
    manager = ZeekManager()
    calls = []

    monkeypatch.setattr(manager, "start", lambda interface, startup_timeout=5.0: calls.append(("start", interface)))
    monkeypatch.setattr(manager, "wait_for_log", lambda *args, **kwargs: False)
    monkeypatch.setattr(manager, "stop", lambda: calls.append(("stop", None)))

    result = manager.verify_live_capture("wlan0", startup_timeout=1.0, log_timeout=0.1)

    assert result["ready"] is False
    assert calls == [("start", "wlan0"), ("stop", None)]



def test_validate_interface_rejects_loopback(monkeypatch):
    manager = ZeekManager()
    monkeypatch.setattr(
        manager,
        "list_interface_details",
        lambda: [
            {
                "name": "lo",
                "display_name": "lo",
                "kind": "loopback",
                "up": True,
                "loopback": True,
                "usable": False,
            }
        ],
    )

    result = manager.validate_interface("lo")

    assert result["valid"] is False
    assert "Loopback" in result["reason"]


def test_validate_interface_accepts_active_adapter(monkeypatch):
    manager = ZeekManager()
    monkeypatch.setattr(
        manager,
        "list_interface_details",
        lambda: [
            {
                "name": "wlan0",
                "display_name": "wlan0",
                "kind": "wifi",
                "up": True,
                "loopback": False,
                "usable": True,
            }
        ],
    )

    result = manager.validate_interface("wlan0")

    assert result["valid"] is True
    assert result["details"]["kind"] == "wifi"
