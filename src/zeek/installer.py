from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class InstallResult:
    installed: bool
    platform: str
    method: str | None = None
    message: str = ""

    def to_dict(self) -> dict:
        return {
            "installed": self.installed,
            "platform": self.platform,
            "method": self.method,
            "message": self.message,
        }


class ZeekInstaller:
    """Cross-platform Zeek setup.

    Linux uses the Zeek OBS packages when the distro can be identified.
    macOS uses Homebrew. Windows is experimental in Zeek itself, so this
    installer only accepts a working Npcap-linked Zeek binary or prepares the
    native build prerequisites; it does not download an unofficial binary.
    """

    def __init__(self, runner=None, system: str | None = None) -> None:
        self.system = system or platform.system()
        self.runner = runner or self._run

    @staticmethod
    def _run(command: list[str], **kwargs):
        return subprocess.run(command, check=False, text=True, **kwargs)

    def _command_exists(self, name: str) -> bool:
        return shutil.which(name) is not None

    @staticmethod
    def _repo_root() -> Path:
        return Path(__file__).resolve().parents[2]

    def local_zeek_candidates(self) -> list[Path]:
        root = self._repo_root()
        candidates = [
            root / ".third_party" / "zeek-install" / "bin" / "zeek",
            root / ".third_party" / "zeek-install" / "bin" / "zeek.exe",
            root / ".third_party" / "zeek" / "build" / "src" / "zeek",
            root / ".third_party" / "zeek" / "build" / "src" / "zeek.exe",
            root / ".third_party" / "zeek" / "install" / "bin" / "zeek",
            root / ".third_party" / "zeek" / "install" / "bin" / "zeek.exe",
        ]
        return candidates

    def find_local_zeek(self) -> str | None:
        for path in self.local_zeek_candidates():
            if path.is_file():
                return str(path)
        return None

    def ensure(self, auto_install: bool = True) -> InstallResult:
        if self._command_exists("zeek") or self._command_exists("zeek.exe"):
            return InstallResult(True, self.system, "existing", "Zeek is already installed.")

        local = self.find_local_zeek()
        if local:
            return InstallResult(True, self.system, "project-local", f"Using project-local Zeek binary: {local}")

        if not auto_install:
            return InstallResult(False, self.system, message="Zeek is not installed.")

        if self.system == "Darwin":
            return self._install_macos()
        if self.system == "Linux":
            return self._install_linux()
        if self.system == "Windows":
            return self._prepare_windows()

        return InstallResult(
            False,
            self.system,
            message=f"Automatic Zeek installation is not supported on {self.system}.",
        )

    def _install_macos(self) -> InstallResult:
        if not self._command_exists("brew"):
            return InstallResult(
                False,
                self.system,
                "homebrew",
                "Homebrew is required. Install Homebrew first, then restart the app.",
            )

        result = self.runner(["brew", "install", "zeek"], capture_output=True)
        if result.returncode == 0 and self._command_exists("zeek"):
            return InstallResult(True, self.system, "homebrew", "Zeek installed with Homebrew.")

        return InstallResult(
            False,
            self.system,
            "homebrew",
            (result.stderr or result.stdout or "Homebrew could not install Zeek.").strip(),
        )

    def _linux_release(self) -> tuple[str | None, str | None]:
        path = Path("/etc/os-release")
        if not path.exists():
            return None, None

        data: dict[str, str] = {}
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            data[key] = value.strip().strip('"')
        return data.get("ID"), data.get("VERSION_ID")

    @staticmethod
    def _sudo_command_available() -> bool:
        return shutil.which("sudo") is not None

    def _linux_privileged(self, command: list[str]) -> list[str]:
        if os.geteuid() == 0:
            return command
        if self._sudo_command_available():
            return ["sudo", *command]
        raise RuntimeError("Linux installation requires root or sudo privileges.")

    def _run_linux(self, command: list[str]):
        return self.runner(self._linux_privileged(command), capture_output=True)

    def _install_apt_zeek(self, distro: str | None, version: str | None) -> InstallResult | None:
        if distro not in {"ubuntu", "debian"} or not version:
            return None

        if distro == "ubuntu":
            repo = f"https://download.opensuse.org/repositories/security:/zeek/xUbuntu_{version}/"
        else:
            repo = f"https://download.opensuse.org/repositories/security:/zeek/Debian_{version}/"

        list_file = "/etc/apt/sources.list.d/security:zeek.list"
        key_file = "/etc/apt/trusted.gpg.d/security_zeek.gpg"
        key_download = "/tmp/security_zeek_release.key"

        commands = [
            ["apt-get", "install", "-y", "curl", "gnupg", "ca-certificates"],
            ["curl", "-fsSL", f"{repo}Release.key", "-o", key_download],
            ["gpg", "--dearmor", "--yes", "-o", key_file, key_download],
            ["apt-get", "update"],
            ["apt-get", "install", "-y", "zeek"],
        ]

        for command in commands:
            result = self._run_linux(command)
            if result.returncode != 0:
                return InstallResult(
                    False,
                    self.system,
                    "zeek-obs",
                    (result.stderr or result.stdout or f"Command failed: {' '.join(command)}").strip(),
                )

        # Write the repository file without invoking a shell.
        result = self._run_linux(["tee", list_file])
        if result.returncode != 0:
            return InstallResult(False, self.system, "zeek-obs", "Could not configure the Zeek OBS repository.")

        if self._command_exists("zeek") or Path("/opt/zeek/bin/zeek").is_file():
            return InstallResult(True, self.system, "zeek-obs", f"Zeek installed from the official OBS repository: {repo}")
        return None

    def _install_linux(self) -> InstallResult:
        distro, version = self._linux_release()

        if self._command_exists("apt-get"):
            official = self._install_apt_zeek(distro, version)
            if official and official.installed:
                return official

            result = self._run_linux(["apt-get", "update"])
            if result.returncode == 0:
                result = self._run_linux(["apt-get", "install", "-y", "zeek"])
                if result.returncode == 0 and (self._command_exists("zeek") or self.find_local_zeek()):
                    return InstallResult(True, self.system, "apt", "Zeek installed with the system package manager.")

        if self._command_exists("dnf"):
            result = self._run_linux(["dnf", "install", "-y", "zeek"])
            if result.returncode == 0 and self._command_exists("zeek"):
                return InstallResult(True, self.system, "dnf", "Zeek installed with dnf.")

        if self._command_exists("pacman"):
            result = self._run_linux(["pacman", "-Sy", "--noconfirm", "zeek"])
            if result.returncode == 0 and self._command_exists("zeek"):
                return InstallResult(True, self.system, "pacman", "Zeek installed with pacman.")

        return InstallResult(
            False,
            self.system,
            "linux-package",
            "Zeek could not be installed automatically for this Linux distribution.",
        )

    def _npcap_present(self) -> bool:
        if self.system != "Windows":
            return False
        candidates = [
            Path(r"C:\Windows\System32\Npcap\wpcap.dll"),
            Path(r"C:\Windows\System32\Npcap\Packet.dll"),
            Path(r"C:\Windows\System32\wpcap.dll"),
        ]
        return any(path.exists() for path in candidates)

    def _find_npcap_sdk(self) -> Path | None:
        if self.system != "Windows":
            return None

        roots = [
            Path(r"C:\NpcapSDK"),
            Path(r"C:\Program Files\NpcapSDK"),
            Path(r"C:\Program Files\Npcap\SDK"),
            self._repo_root() / ".third_party" / "npcap-sdk",
        ]
        for root in roots:
            if root.exists() and any(
                (root / relative).exists()
                for relative in ("Include", "Lib", "Lib/x64", "Lib/wpcap.lib")
            ):
                return root
        return None

    def _windows_build_prerequisites(self) -> list[str]:
        required = []
        for name in ("git", "cmake", "ninja"):
            if not self._command_exists(name):
                required.append(name)

        # The native C++ compiler is normally exposed after loading the VS
        # developer environment. We deliberately do not guess its installation.
        if not self._command_exists("cl"):
            required.append("MSVC developer environment (cl.exe)")
        return required

    def _windows_setup_script(self) -> Path:
        return self._repo_root() / "scripts" / "windows" / "setup-zeek.ps1"

    def _run_windows_setup(self) -> InstallResult:
        script = self._windows_setup_script()
        if not script.is_file():
            return InstallResult(
                False,
                self.system,
                "native-build",
                f"Windows setup script not found: {script}",
            )

        powershell = shutil.which("powershell") or shutil.which("pwsh")
        if not powershell:
            return InstallResult(
                False,
                self.system,
                "powershell-required",
                "PowerShell is required for automatic Windows Zeek setup.",
            )

        result = self.runner(
            [
                powershell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script),
            ],
            cwd=str(self._repo_root()),
        )
        local = self.find_local_zeek()
        if result.returncode == 0 and local:
            return InstallResult(
                True,
                self.system,
                "windows-bootstrap",
                f"Zeek was prepared automatically: {local}",
            )

        output = "\n".join(
            part.strip()
            for part in (
                getattr(result, "stdout", "") or "",
                getattr(result, "stderr", "") or "",
            )
            if part and part.strip()
        )
        return InstallResult(
            False,
            self.system,
            "windows-bootstrap",
            output or "Windows Zeek bootstrap did not complete successfully.",
        )

    def _prepare_windows(self) -> InstallResult:
        # The project-local bootstrap owns elevation, Npcap installation,
        # Visual Studio/CMake/Ninja setup, SDK download, source checkout,
        # and the native Zeek build. A UAC prompt may still be required.
        return self._run_windows_setup()


def ensure_zeek_installed(auto_install: bool = True) -> InstallResult:
    return ZeekInstaller().ensure(auto_install=auto_install)
