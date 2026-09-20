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
