from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass


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
    """Best-effort cross-platform installer for Zeek.

    Linux/macOS use their native package managers. Windows is handled
    explicitly because native live-capture support is still experimental
    and requires an Npcap-linked Zeek build.
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
        if self._command_exists("zeek"):
            return InstallResult(True, self.system, "existing", "Zeek is already installed.")

        if not auto_install:
            return InstallResult(False, self.system, message="Zeek is not installed.")

        if self.system == "Darwin":
            return self._install_macos()
        if self.system == "Linux":
            return self._install_linux()
        if self.system == "Windows":
            return self._install_windows()

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

    def _install_linux(self) -> InstallResult:
        if self._command_exists("apt-get"):
            commands = [
                ["sudo", "apt-get", "update"],
                ["sudo", "apt-get", "install", "-y", "zeek"],
            ]
            for command in commands:
                result = self.runner(command, capture_output=True)
                if result.returncode != 0:
                    return InstallResult(
                        False,
                        self.system,
                        "apt",
                        (result.stderr or result.stdout or "apt failed.").strip(),
                    )
            if self._command_exists("zeek"):
                return InstallResult(True, self.system, "apt", "Zeek installed with apt.")

        if self._command_exists("dnf"):
            result = self.runner(
                ["sudo", "dnf", "install", "-y", "zeek"],
                capture_output=True,
            )
            if result.returncode == 0 and self._command_exists("zeek"):
                return InstallResult(True, self.system, "dnf", "Zeek installed with dnf.")
            return InstallResult(
                False, self.system, "dnf",
                (result.stderr or result.stdout or "dnf failed.").strip(),
            )

        if self._command_exists("pacman"):
            result = self.runner(
                ["sudo", "pacman", "-Sy", "--noconfirm", "zeek"],
                capture_output=True,
            )
            if result.returncode == 0 and self._command_exists("zeek"):
                return InstallResult(True, self.system, "pacman", "Zeek installed with pacman.")
            return InstallResult(
                False, self.system, "pacman",
                (result.stderr or result.stdout or "pacman failed.").strip(),
            )

        return InstallResult(
            False,
            self.system,
            message="No supported Linux package manager found. Install Zeek from the official Zeek packages.",
        )

    def _install_windows(self) -> InstallResult:
        # Zeek documents native Windows support as experimental. Live packet
        # capture additionally requires an Npcap-linked Zeek build, so we do
        # not silently download an unofficial binary or claim native support.
        if self._command_exists("wsl"):
            return InstallResult(
                False,
                self.system,
                "wsl",
                "Windows detected: native Zeek live capture is experimental. "
                "A WSL/Npcap deployment is required; automatic native installation "
                "is intentionally not performed.",
            )

        return InstallResult(
            False,
            self.system,
            "windows-native",
            "Windows Zeek live capture requires an Npcap-linked build and additional "
            "development dependencies. Automatic native installation is not available.",
        )


def ensure_zeek_installed(auto_install: bool = True) -> InstallResult:
    return ZeekInstaller().ensure(auto_install=auto_install)
