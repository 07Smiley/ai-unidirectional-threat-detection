from types import SimpleNamespace

from src.zeek.installer import ZeekInstaller


def test_windows_installer_requires_npcap(monkeypatch):
    installer = ZeekInstaller(system="Windows")
    monkeypatch.setattr(installer, "_npcap_present", lambda: False)

    result = installer.ensure(auto_install=True)

    assert result.installed is False
    assert result.method == "npcap-required"


def test_windows_installer_accepts_project_local_binary(tmp_path, monkeypatch):
    installer = ZeekInstaller(system="Windows")
    local = tmp_path / "zeek.exe"
    local.write_text("stub", encoding="utf-8")
    monkeypatch.setattr(installer, "_repo_root", lambda: tmp_path)
    monkeypatch.setattr(installer, "_command_exists", lambda name: False)

    local_dir = tmp_path / ".third_party" / "zeek" / "build" / "src"
    local_dir.mkdir(parents=True)
    local = local_dir / "zeek.exe"
    local.write_text("stub", encoding="utf-8")

    result = installer.ensure(auto_install=True)

    assert result.installed is True
    assert result.method == "project-local"


def test_linux_installer_uses_direct_package_command_when_running_as_root(monkeypatch):
    installer = ZeekInstaller(system="Linux")
    monkeypatch.setattr(installer, "_command_exists", lambda name: name in {"apt-get", "zeek"})
    monkeypatch.setattr(installer, "_sudo_command_available", lambda: False)
    monkeypatch.setattr(installer, "_linux_release", lambda: ("ubuntu", "24.04"))
    monkeypatch.setattr(
        installer,
        "runner",
        lambda command, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    result = installer.ensure(auto_install=True)

    assert result.installed is True
    assert result.method == "apt"
