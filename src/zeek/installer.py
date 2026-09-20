from __future__ import annotations

import platform
import shutil
import subprocess
import tempfile
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

    Linux/macOS use supported package-manager paths. Windows uses the
    native Zeek build path documented by Zeek; because Zeek does not publish
    official Windows binaries, the installer prepares/checks the required
    capture/build prerequisites rather than downloading an untrusted binary.
    """

    def __init__(self, runner=None) -> None:
        self.system = platform.system()
        self.runner = runner or self._run

    @staticmethod
    def _run(command: list[str], **kwargs):
        return subprocess.run(command, check=False, text=True, **kwargs)

    def _command_exists(self, name: str) -> bool:
        return shutil.which(name) is not None

    def ensure(self, auto_install: bool = True) -> InstallResult:
        if self._command_exists("zeek") or self._command_exists("zeek.exe"):
            return InstallResult(True, self.system, "existing", "Zeek is already installed.")

        if not auto_install:
            return InstallResult(False, self.system, message="Zeek is not installed.")

        if self.system == "Darwin":
            return self._install_macos()
        if self.system == "Linux":
            return self._install_linux()
        if self.system == "Windows":
            return self._prepare_windows()

        return InstallResult(False, self.system, message=f"Automatic Zeek installation is not supported on {self.system}.")

    def _install_macos(self) -> InstallResult:
        if not self._command_exists("brew"):
            return InstallResult(False, self.system, "homebrew", "Homebrew is required. Install Homebrew first, then restart the app.")
        result = self.runner(["brew", "install", "zeek"], capture_output=True)
        if result.returncode == 0 and self._command_exists("zeek"):
            return InstallResult(True, self.system, "homebrew", "Zeek installed with Homebrew.")
        return InstallResult(False, self.system, "homebrew", (result.stderr or result.stdout or "Homebrew could not install Zeek.").strip())

    def _install_linux(self) -> InstallResult:
        if self._command_exists("apt-get"):
            for command in (["sudo", "apt-get", "update"], ["sudo", "apt-get", "install", "-y", "zeek"]):
                result = self.runner(command, capture_output=True)
                if result.returncode != 0:
                    return InstallResult(False, self.system, "apt", (result.stderr or result.stdout or "apt failed.").strip())
            if self._command_exists("zeek"):
                return InstallResult(True, self.system, "apt", "Zeek installed with apt.")
        if self._command_exists("dnf"):
            result = self.runner(["sudo", "dnf", "install", "-y", "zeek"], capture_output=True)
            if result.returncode == 0 and self._command_exists("zeek"):
                return InstallResult(True, self.system, "dnf", "Zeek installed with dnf.")
            return InstallResult(False, self.system, "dnf", (result.stderr or result.stdout or "dnf failed.").strip())
        if self._command_exists("pacman"):
            result = self.runner(["sudo", "pacman", "-Sy", "--noconfirm", "zeek"], capture_output=True)
            if result.returncode == 0 and self._command_exists("zeek"):
                return InstallResult(True, self.system, "pacman", "Zeek installed with pacman.")
            return InstallResult(False, self.system, "pacman", (result.stderr or result.stdout or "pacman failed.").strip())
        return InstallResult(False, self.system, message="No supported Linux package manager found.")

    def _npcap_present(self) -> bool:
        if self.system != "Windows":
            return False
        candidates = [
            Path(r"C:\Windows\System32\Npcap\wpcap.dll"),
            Path(r"C:\Windows\System32\Npcap\Packet.dll"),
            Path(r"C:\Windows\System32\wpcap.dll"),
        ]
        return any(path.exists() for path in candidates)

    def _prepare_windows(self) -> InstallResult:
        if not self._npcap_present():
            return InstallResult(
                False,
                self.system,
                "npcap-required",
                "Windows live capture requires Npcap. Zeek's official Windows build is experimental and must be built against the Npcap SDK. Install Npcap, then run the Windows setup script in scripts/windows/setup-zeek.ps1.",
            )

        required = ["git", "cmake"]
        missing = [name for name in required if not self._command_exists(name)]
        if missing:
            return InstallResult(
                False,
                self.system,
                "native-build-prerequisites",
                "Windows native Zeek setup still needs: " + ", ".join(missing) + ". Run scripts/windows/setup-zeek.ps1 as Administrator.",
            )

        return InstallResult(
            False,
            self.system,
            "native-build",
            "Npcap is present, but no official prebuilt Zeek Windows binary is published. Run scripts/windows/setup-zeek.ps1 to build Zeek against the Npcap SDK.",
        )


def ensure_zeek_installed(auto_install: bool = True) -> InstallResult:
    return ZeekInstaller().ensure(auto_install=auto_install)
