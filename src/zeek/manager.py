from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import shutil
import signal
import subprocess
import time
from typing import Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOG_DIR = REPO_ROOT / "data" / "processed" / "zeek" / "live"


@dataclass
class ZeekStatus:
    installed: bool
    version: str | None = None
    running: bool = False
    interface: str | None = None
    log_dir: str = str(DEFAULT_LOG_DIR)
    pid: int | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class ZeekManager:
    """Manage a local Zeek sensor process for live network monitoring.

    This class deliberately does not install packages or select an interface
    silently. Installation and interface selection are application-level
    decisions that can be added once the sensor lifecycle is verified.
    """

    def __init__(self, log_dir: str | Path = DEFAULT_LOG_DIR, zeek_binary: str = "zeek") -> None:
        self.log_dir = Path(log_dir).resolve()
        self.zeek_binary = zeek_binary
        self.process: subprocess.Popen[str] | None = None
        self.interface: str | None = None

    def is_installed(self) -> bool:
        return shutil.which(self.zeek_binary) is not None

    def version(self) -> str | None:
        if not self.is_installed():
            return None
        try:
            result = subprocess.run(
                [self.zeek_binary, "--version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        output = (result.stdout or result.stderr).strip()
        return output or None

    def list_interfaces(self) -> list[str]:
        """Return interfaces visible to the operating system."""
        interfaces_dir = Path("/sys/class/net")
        if interfaces_dir.exists():
            return sorted(p.name for p in interfaces_dir.iterdir() if p.is_dir())

        # Fallback for systems without /sys/class/net.
        try:
            result = subprocess.run(
                ["ip", "-o", "link", "show"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return []

        interfaces: list[str] = []
        for line in result.stdout.splitlines():
            parts = line.split(": ", 1)
            if len(parts) == 2:
                name = parts[1].split(":", 1)[0]
                if name:
                    interfaces.append(name)
        return interfaces

    def status(self) -> ZeekStatus:
        running = self.process is not None and self.process.poll() is None
        return ZeekStatus(
            installed=self.is_installed(),
            version=self.version(),
            running=running,
            interface=self.interface,
            log_dir=str(self.log_dir),
            pid=self.process.pid if running and self.process else None,
        )

    def start(self, interface: str) -> ZeekStatus:
        if not self.is_installed():
            raise RuntimeError(
                "Zeek is not installed. Install Zeek first; automatic package "
                "installation will be added in a later deployment step."
            )
        if interface not in self.list_interfaces():
            raise ValueError(f"Network interface not found: {interface}")
        if self.process is not None and self.process.poll() is None:
            raise RuntimeError("Zeek is already running.")

        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Zeek needs elevated capture privileges on most Linux systems.
        # The caller should run the application with the required privileges
        # (or configure the system's capture permissions) rather than having
        # this library invoke sudo and prompt for a password.
        command = [
            self.zeek_binary,
            "-i",
            interface,
            "-C",
            "local",
        ]

        self.process = subprocess.Popen(
            command,
            cwd=self.log_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        self.interface = interface

        # Give Zeek a short startup window and fail early if it exits.
        time.sleep(1.0)
        if self.process.poll() is not None:
            error = self.process.stderr.read().strip() if self.process.stderr else ""
            self.process = None
            self.interface = None
            raise RuntimeError(f"Zeek failed to start{': ' + error if error else '.'}")

        return self.status()

    def stop(self, timeout: float = 5.0) -> ZeekStatus:
        if self.process is None:
            self.interface = None
            return self.status()

        if self.process.poll() is None:
            try:
                self.process.send_signal(signal.SIGTERM)
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)

        self.process = None
        self.interface = None
        return self.status()

    def __enter__(self) -> "ZeekManager":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.stop()


def main() -> None:
    manager = ZeekManager()
    status = manager.status()

    print("=== Zeek Sensor ===")
    print(f"Zeek installed : {'YES' if status.installed else 'NO'}")
    print(f"Zeek version   : {status.version or 'N/A'}")
    print(f"Log directory  : {status.log_dir}")
    print("\nNetwork interfaces:")
    interfaces = manager.list_interfaces()
    if interfaces:
        for index, interface in enumerate(interfaces, start=1):
            print(f"  {index}. {interface}")
    else:
        print("  No interfaces detected")


if __name__ == "__main__":
    main()
