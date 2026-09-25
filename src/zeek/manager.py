from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import os
import shutil
import signal
import socket
import subprocess
import time

from src.zeek.installer import ZeekInstaller


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOG_DIR = REPO_ROOT / "data" / "processed" / "zeek" / "live"
LIVE_LOGS = ("conn.log", "dns.log", "ssl.log", "quic.log")
COMMON_ZEEK_PATHS = (
    "/opt/zeek/bin/zeek",
    "/opt/zeek/bin/zeek.exe",
    "/opt/homebrew/bin/zeek",
    "/usr/local/bin/zeek",
    "/usr/bin/zeek",
)


@dataclass
class ZeekStatus:
    installed: bool
    version: str | None = None
    running: bool = False
    interface: str | None = None
    log_dir: str = str(DEFAULT_LOG_DIR)
    pid: int | None = None
    logs: dict[str, bool] | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class ZeekManager:
    """Manage a local Zeek sensor process for live network monitoring."""

    def __init__(
        self,
        log_dir: str | Path = DEFAULT_LOG_DIR,
        zeek_binary: str | None = None,
        auto_install: bool = True,
    ) -> None:
        self.log_dir = Path(log_dir).resolve()
        self.auto_install = auto_install
        self.zeek_binary = zeek_binary or self._find_zeek()
        self.process: subprocess.Popen[str] | None = None
        self.interface: str | None = None
        self.install_message: str | None = None

    @staticmethod
    def _find_zeek() -> str:
        found = shutil.which("zeek") or shutil.which("zeek.exe")
        if found:
            return found

        installer = ZeekInstaller()
        local = installer.find_local_zeek()
        if local:
            return local

        candidates = list(COMMON_ZEEK_PATHS)
        if os.name == "nt":
            candidates.extend(
                [
                    r"C:\Program Files\Zeek\bin\zeek.exe",
                    r"C:\Program Files\Zeek\zeek.exe",
                    r"C:\Program Files (x86)\Zeek\bin\zeek.exe",
                ]
            )

        for candidate in candidates:
            path = Path(candidate)
            if path.is_file() and (os.name == "nt" or path.stat().st_mode & 0o111):
                return str(path)
        return "zeek.exe" if os.name == "nt" else "zeek"

    def is_installed(self) -> bool:
        path = Path(self.zeek_binary)
        return path.is_file() or shutil.which(self.zeek_binary) is not None

    def ensure_installed(self) -> bool:
        if self.is_installed():
            return True

        result = ZeekInstaller().ensure(auto_install=self.auto_install)
        self.install_message = result.message
        if not result.installed:
            return False

        self.zeek_binary = self._find_zeek()
        return self.is_installed()

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
        if os.name != "nt" and interfaces_dir.exists():
            return sorted(p.name for p in interfaces_dir.iterdir() if p.is_dir())

        try:
            names = [name for _, name in socket.if_nameindex()]
            if names:
                return sorted(dict.fromkeys(names))
        except (AttributeError, OSError):
            pass

        if os.name == "nt":
            try:
                result = subprocess.run(
                    [
                        "powershell",
                        "-NoProfile",
                        "-Command",
                        "(Get-NetAdapter | Where-Object {$_.Status -ne 'Disabled'}).Name",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
            except (OSError, subprocess.SubprocessError):
                return []
            names = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            return sorted(dict.fromkeys(names))

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
        return sorted(dict.fromkeys(interfaces))

    def clear_logs(self) -> None:
        """Remove logs from the dedicated live-capture directory."""
        self.log_dir.mkdir(parents=True, exist_ok=True)
        for path in self.log_dir.glob("*.log"):
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    def log_status(self) -> dict[str, bool]:
        return {name: (self.log_dir / name).exists() for name in LIVE_LOGS}

    def has_live_log_data(self, log_name: str = "conn.log") -> bool:
        path = self.log_dir / log_name
        return path.exists() and path.stat().st_size > 0

    def status(self) -> ZeekStatus:
        running = self.process is not None and self.process.poll() is None
        error = self.install_message if not self.is_installed() else None
        return ZeekStatus(
            installed=self.is_installed(),
            version=self.version(),
            running=running,
            interface=self.interface,
            log_dir=str(self.log_dir),
            pid=self.process.pid if running and self.process else None,
            logs=self.log_status(),
            error=error,
        )

    def _diagnose_start_error(self, detail: str) -> str:
        detail = (detail or "").strip()
        lower = detail.lower()

        if "permission" in lower or "operation not permitted" in lower or "access denied" in lower:
            return (
                f"Zeek could not capture interface '{self.interface or 'selected interface'}': "
                f"{detail or 'permission denied'}. "
                "Run the launcher with the required packet-capture privileges."
            )

        if os.name == "nt" and any(token in lower for token in ("npcap", "wpcap", "pcap", "winpcap")):
            return (
                f"Zeek could not open Windows capture interface '{self.interface or 'selected interface'}': "
                f"{detail}. Verify that Npcap is installed and that this Zeek build was linked "
                "against the Npcap SDK."
            )

        if any(token in lower for token in ("interface", "device", "no such", "not found")):
            return (
                f"Zeek could not open interface '{self.interface or 'selected interface'}': "
                f"{detail or 'device was not found'}. "
                "Refresh the interface list and choose an active adapter."
            )

        return f"Zeek failed to start on '{self.interface or 'selected interface'}': {detail or 'unknown error'}"

    def start(self, interface: str, startup_timeout: float = 5.0) -> ZeekStatus:
        if not self.ensure_installed():
            raise RuntimeError(
                "Zeek is not installed and automatic installation failed: "
                f"{self.install_message or 'unknown installation error'}"
            )
        if interface not in self.list_interfaces():
            raise ValueError(f"Network interface not found: {interface}")
        if self.process is not None and self.process.poll() is None:
            raise RuntimeError("Zeek is already running.")

        self.clear_logs()

        command = [
            self.zeek_binary,
            "-i",
            interface,
            "-C",
            "local",
            "Log::default_rotation_interval=0sec",
        ]

        popen_kwargs = {
            "cwd": self.log_dir,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.PIPE,
            "text": True,
        }
        if os.name == "nt":
            popen_kwargs["creationflags"] = getattr(
                subprocess, "CREATE_NEW_PROCESS_GROUP", 0
            )
        else:
            popen_kwargs["start_new_session"] = True

        self.process = subprocess.Popen(command, **popen_kwargs)
        self.interface = interface

        deadline = time.monotonic() + startup_timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                error = self.process.stderr.read().strip() if self.process.stderr else ""
                self.process = None
                self.interface = None
                raise RuntimeError(self._diagnose_start_error(error))
            if self.log_dir.exists():
                break
            time.sleep(0.1)

        return self.status()

    def verify_live_capture(
        self,
        interface: str,
        startup_timeout: float = 5.0,
        log_timeout: float = 3.0,
    ) -> dict[str, object]:
        """Smoke-test Zeek on the selected interface and cleanly stop it."""
        if self.process is not None and self.process.poll() is None:
            return {
                "ready": True,
                "interface": interface,
                "message": "Zeek live capture is already running.",
            }

        try:
            self.start(interface, startup_timeout=startup_timeout)
            log_ready = self.wait_for_log("conn.log", timeout=log_timeout)
            if self.process is None or self.process.poll() is not None:
                raise RuntimeError("Zeek exited during live-capture verification.")
            return {
                "ready": bool(log_ready),
                "interface": interface,
                "log_ready": bool(log_ready),
                "message": (
                    "Zeek accepted the interface and conn.log is live."
                    if log_ready
                    else "Zeek started, but conn.log did not receive data yet."
                ),
            }
        except Exception as exc:
            return {
                "ready": False,
                "interface": interface,
                "message": str(exc),
            }
        finally:
            self.stop()

    def wait_for_log(self, log_name: str = "conn.log", timeout: float = 10.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.has_live_log_data(log_name):
                return True
            if self.process is not None and self.process.poll() is not None:
                return False
            time.sleep(0.25)
        return self.has_live_log_data(log_name)

    def stop(self, timeout: float = 5.0) -> ZeekStatus:
        if self.process is None:
            self.interface = None
            return self.status()

        if self.process.poll() is None:
            try:
                if os.name == "nt":
                    self.process.terminate()
                else:
                    self.process.send_signal(signal.SIGTERM)
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)

        self.process = None
        self.interface = None
        self.clear_logs()
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
    print(f"Zeek binary    : {manager.zeek_binary}")
    print(f"Zeek version   : {status.version or 'N/A'}")
    print(f"Log directory  : {status.log_dir}")

    print("\nNetwork interfaces:")
    interfaces = manager.list_interfaces()
    if interfaces:
        for index, interface in enumerate(interfaces, start=1):
            print(f"  {index}. {interface}")
    else:
        print("  No interfaces detected")

    if status.logs:
        print("\nLive log files:")
        for name, exists in status.logs.items():
            print(f"  {name:<12} {'✓' if exists else '—'}")


if __name__ == "__main__":
    main()
