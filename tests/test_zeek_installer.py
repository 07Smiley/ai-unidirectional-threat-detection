from types import SimpleNamespace

from src.zeek.installer import ZeekInstaller


def test_windows_installer_runs_bootstrap(monkeypatch):
    installer = ZeekInstaller(system="Windows")
    monkeypatch.setattr(installer, "_command_exists", lambda name: False)
    monkeypatch.setattr(
        installer,
        "_run_windows_setup",
        lambda: __import__("src.zeek.installer", fromlist=["InstallResult"]).InstallResult(
            True, "Windows", "windows-bootstrap", "ok"
        ),
    )

    result = installer.ensure(auto_install=True)

    assert result.installed is True
    assert result.method == "windows-bootstrap"


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
    state = {"zeek": False}
    monkeypatch.setattr(
        installer,
        "_command_exists",
        lambda name: name == "apt-get" or (name == "zeek" and state["zeek"]),
    )
    monkeypatch.setattr(installer, "_sudo_command_available", lambda: False)
    monkeypatch.setattr(installer, "_linux_release", lambda: ("fedora", "40"))
    monkeypatch.setattr(
        installer,
        "runner",
        lambda command, **kwargs: (
            state.update(zeek=True) if command[:2] == ["apt-get", "install"] else None
        ) or SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    result = installer.ensure(auto_install=True)

    assert result.installed is True
    assert result.method == "apt"


def test_windows_npcap_sdk_detection_uses_windows_paths(tmp_path, monkeypatch):
    installer = ZeekInstaller(system="Windows")
    monkeypatch.setattr(installer, "_repo_root", lambda: tmp_path)
    sdk = tmp_path / ".third_party" / "npcap-sdk"
    (sdk / "Include").mkdir(parents=True)
    (sdk / "Lib" / "x64").mkdir(parents=True)

    assert installer._find_npcap_sdk() == sdk


def test_windows_bootstrap_accepts_successful_local_build(tmp_path, monkeypatch):
    installer = ZeekInstaller(system="Windows")
    monkeypatch.setattr(installer, "_repo_root", lambda: tmp_path)
    monkeypatch.setattr(installer, "_command_exists", lambda name: name in {"powershell"})
    script = tmp_path / "scripts" / "windows" / "setup-zeek.ps1"
    script.parent.mkdir(parents=True)
    script.write_text("Write-Host bootstrap", encoding="utf-8")
    binary = tmp_path / ".third_party" / "zeek" / "build" / "src"
    binary.mkdir(parents=True)
    zeek_path = binary / "zeek.exe"
    state = {"built": False}
    monkeypatch.setattr(
        installer,
        "_command_exists",
        lambda name: name == "powershell",
    )
    monkeypatch.setattr(
        installer,
        "find_local_zeek",
        lambda: str(zeek_path) if state["built"] and zeek_path.is_file() else None,
    )
    def run_setup(command, **kwargs):
        zeek_path.write_text("stub", encoding="utf-8")
        state["built"] = True
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")
    installer.runner = run_setup

    result = installer.ensure(auto_install=True)

    assert result.installed is True
    assert result.method == "windows-bootstrap"


def test_linux_ubuntu_uses_official_obs_repository(monkeypatch):
    installer = ZeekInstaller(system="Linux")
    monkeypatch.setattr(installer, "_linux_release", lambda: ("ubuntu", "24.04"))
    state = {"zeek": False}
    monkeypatch.setattr(
        installer,
        "_command_exists",
        lambda name: name == "apt-get" or (name == "zeek" and state["zeek"]),
    )
    monkeypatch.setattr(installer, "_sudo_command_available", lambda: True)
    monkeypatch.setattr(installer, "_linux_privileged", lambda command: command)
    commands = []
    def run(command, **kwargs):
        commands.append((command, kwargs))
        if command[:2] == ["apt-get", "install"]:
            state["zeek"] = True
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    installer.runner = run

    result = installer.ensure(auto_install=True)

    assert result.installed is True
    assert result.method == "zeek-obs"
    assert any("download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/" in " ".join(command) for command, _ in commands)


def test_macos_installer_bootstraps_homebrew_when_missing(monkeypatch):
    installer = ZeekInstaller(system="Darwin")
    state = {"brew": None, "zeek": False}

    def find_brew():
        return state["brew"]

    def bootstrap():
        state["brew"] = "/opt/homebrew/bin/brew"
        return __import__(
            "src.zeek.installer", fromlist=["InstallResult"]
        ).InstallResult(True, "Darwin", "homebrew-bootstrap", "ok")

    monkeypatch.setattr(installer, "_find_brew", find_brew)
    monkeypatch.setattr(installer, "_install_homebrew", bootstrap)
    monkeypatch.setattr(installer, "_command_exists", lambda name: name == "zeek" and state["zeek"])
    import src.zeek.installer as installer_module
    real_which = installer_module.shutil.which
    monkeypatch.setattr(
        installer_module.shutil,
        "which",
        lambda name: "/opt/homebrew/bin/zeek" if name == "zeek" and state["zeek"] else real_which(name),
    )
    def run(command, **kwargs):
        if len(command) >= 2 and command[1] == "install" and command[-1] == "zeek":
            state["zeek"] = True
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    installer.runner = run

    result = installer.ensure(auto_install=True)

    assert result.installed is True
    assert result.method == "homebrew"
