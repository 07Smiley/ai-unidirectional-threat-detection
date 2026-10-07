from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import ctypes
import json
import os
import shutil
import signal
import socket
import subprocess
import time

from src.zeek.installer import ZeekInstaller

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOG_DIR = REPO_ROOT / "data" / "processed" / "zeek" / "live"
ZEEK_SOURCE_DIR = REPO_ROOT / ".third_party" / "zeek"
LIVE_LOGS = ("conn.log", "dns.log", "ssl.log", "quic.log")
INTERFACE_CACHE_TTL = 10.0
STARTUP_GRACE = 2.0
COMMON_ZEEK_PATHS = (
    "/opt/zeek/bin/zeek",
    "/opt/zeek/bin/zeek.exe",
    "/opt/homebrew/bin/zeek",
    "/usr/local/bin/zeek",
    "/usr/bin/zeek",
)

# ---------------------------------------------------------------------------
# Windows Job Object: guarantees Zeek dies when this process dies
# ---------------------------------------------------------------------------

_JOB_HANDLE = None  # must stay alive as long as this process lives


def _assign_to_kill_on_close_job(pid: int) -> None:
    """Windows only: make the given process die automatically when this
    process exits for any reason (crash, console closed, force-kill)."""
    global _JOB_HANDLE
    if os.name != "nt":
        return

    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            (n, ctypes.c_ulonglong)
            for n in (
                "ReadOps",
                "WriteOps",
                "OtherOps",
                "ReadBytes",
                "WriteBytes",
                "OtherBytes",
            )
        ]

    class BASIC(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class EXTENDED(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BASIC),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    if _JOB_HANDLE is None:
        job = k32.CreateJobObjectW(None, None)
        if not job:
            return
        info = EXTENDED()
        info.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE
        # 9 = JobObjectExtendedLimitInformation
        if not k32.SetInformationJobObject(
            job, 9, ctypes.byref(info), ctypes.sizeof(info)
        ):
            k32.CloseHandle(job)
            return
        _JOB_HANDLE = job

    # PROCESS_SET_QUOTA | PROCESS_TERMINATE
    proc = k32.OpenProcess(0x0100 | 0x0001, False, pid)
    if proc:
        k32.AssignProcessToJobObject(_JOB_HANDLE, proc)
        k32.CloseHandle(proc)


@dataclass
class InterfaceInfo:
    name: str
    display_name: str
    kind: str = "unknown"
    up: bool = False
    running: bool = False
    loopback: bool = False
    virtual: bool = False
    mac: str | None = None
    ipv4: list[str] | None = None
    ipv6: list[str] | None = None
    usable: bool = False
    reason: str | None = None
    capture_name: str | None = None  # name actually passed to `zeek -i`

    def to_dict(self) -> dict:
        return asdict(self)


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
        # Remembered so clear_logs() can fall back to a session subfolder
        # and start() can return to the base folder when it is free again.
        self._base_log_dir = self.log_dir
        self.auto_install = auto_install
        self.zeek_binary = zeek_binary or self._find_zeek()
        self.process: subprocess.Popen | None = None
        self.interface: str | None = None
        self.install_message: str | None = None
        self._iface_cache: tuple[float, list[dict]] | None = None
        self._version_cache: str | None = None
        self._stderr_file = None
        # Outside log_dir so clear_logs() never deletes it.
        self.stderr_path = self._base_log_dir.parent / "zeek-live-stderr.txt"

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
        self._version_cache = None
        return self.is_installed()

    # ------------------------------------------------------- script path

    @staticmethod
    def _zeek_env() -> dict[str, str]:
        """Environment for the Zeek process.

        A source-built Zeek on Windows can't find its base scripts because the
        install step doesn't copy them. If the checked-out source tree is
        present, point ZEEKPATH at it. A ZEEKPATH set by the user wins.
        """
        env = os.environ.copy()
        if env.get("ZEEKPATH"):
            return env

        scripts = ZEEK_SOURCE_DIR / "scripts"
        if not (scripts / "base" / "init-bare.zeek").is_file():
            return env  # system install: Zeek knows its own paths

        parts = [
            scripts,
            scripts / "policy",
            scripts / "site",
            ZEEK_SOURCE_DIR / "build" / "scripts",
        ]
        env["ZEEKPATH"] = os.pathsep.join(str(p) for p in parts if p.is_dir())
        return env

    def version(self) -> str | None:
        if self._version_cache:
            return self._version_cache
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
        self._version_cache = output or None
        return self._version_cache

    def list_interfaces(self) -> list[str]:
        """Return interface names visible to the operating system."""
        return [item["name"] for item in self.list_interface_details()]

    @staticmethod
    def _interface_kind(
        name: str, wireless: bool = False, virtual: bool = False
    ) -> str:
        lower = name.lower()
        if lower in {"lo", "lo0", "loopback"} or lower.startswith("loopback"):
            return "loopback"
        if wireless:
            return "wifi"
        if virtual or any(
            token in lower
            for token in ("docker", "veth", "virbr", "br-", "tun", "tap", "vmnet")
        ):
            return "virtual"
        if lower.startswith(("en", "eth", "em", "eno", "ens", "enp")):
            return "ethernet"
        return "unknown"

    def list_interface_details(self, refresh: bool = False) -> list[dict]:
        """Return capture-relevant metadata for every visible interface (cached)."""
        now = time.monotonic()
        cached = self._iface_cache
        if not refresh and cached and now - cached[0] < INTERFACE_CACHE_TTL:
            return [dict(item) for item in cached[1]]

        if os.name == "nt":
            details = self._windows_details()
        else:
            details = self._posix_details()

        self._iface_cache = (now, details)
        return [dict(item) for item in details]

    # ------------------------------------------------------------ Windows

    def _windows_adapters(self) -> list[dict]:
        script = (
            "Get-NetAdapter | Select-Object Name,InterfaceDescription,"
            "@{n='Status';e={[string]$_.Status}},MacAddress,InterfaceGuid,"
            "@{n='Virtual';e={[bool]$_.Virtual}} | ConvertTo-Json -Compress"
        )
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError):
            return []
        try:
            payload = json.loads(result.stdout or "[]")
        except (ValueError, TypeError):
            return []
        if isinstance(payload, dict):
            payload = [payload]
        return [item for item in payload if isinstance(item, dict) and item.get("Name")]

    def _windows_details(self) -> list[dict]:
        details: list[InterfaceInfo] = []
        for item in self._windows_adapters():
            name = str(item["Name"])
            desc = str(item.get("InterfaceDescription") or "")
            lower_desc = desc.lower()
            up = str(item.get("Status") or "").lower() in {"up", "connected"}
            wireless = any(t in lower_desc for t in ("wi-fi", "wireless", "802.11"))
            virtual = bool(item.get("Virtual")) or any(
                t in lower_desc
                for t in (
                    "virtual",
                    "vmware",
                    "hyper-v",
                    "vbox",
                    "wireguard",
                    "tap-",
                    "vethernet",
                )
            )
            kind = self._interface_kind(name, wireless=wireless, virtual=virtual)
            loopback = kind == "loopback"

            guid = str(item.get("InterfaceGuid") or "").strip()
            capture_name = f"\\Device\\NPF_{guid}" if guid else name

            usable = up and not loopback
            reason = None
            if loopback:
                reason = "Loopback is not a normal live-capture adapter."
            elif not up:
                reason = "Interface is not up."

            details.append(
                InterfaceInfo(
                    name=name,
                    display_name=f"{name} - {desc}" if desc else name,
                    kind=kind,
                    up=up,
                    running=up,
                    loopback=loopback,
                    virtual=virtual,
                    mac=item.get("MacAddress"),
                    usable=usable,
                    reason=reason,
                    capture_name=capture_name,
                )
            )
        return [d.to_dict() for d in details]

    # -------------------------------------------------------- Linux / macOS

    def _posix_details(self) -> list[dict]:
        details: list[InterfaceInfo] = []
        for name in self._raw_interface_names():
            base = Path("/sys/class/net") / name
            operstate = ""
            mac = None
            wireless = (base / "wireless").exists()
            virtual = not (base / "device").exists() if base.exists() else False
            try:
                operstate = (
                    (base / "operstate").read_text(encoding="utf-8").strip().lower()
                )
            except (OSError, UnicodeError):
                pass
            try:
                mac = (base / "address").read_text(encoding="utf-8").strip() or None
            except (OSError, UnicodeError):
                pass
            kind = self._interface_kind(name, wireless=wireless, virtual=virtual)
            loopback = kind == "loopback"
            up = operstate in {"up", "unknown"} or name in {"lo", "lo0"}
            if not base.exists():
                up = self._ifconfig_interface_up(name)
            reason = None
            usable = up and not loopback
            if loopback:
                reason = "Loopback is not a normal live-capture adapter."
            elif not up:
                reason = "Interface is not up."
            details.append(
                InterfaceInfo(
                    name=name,
                    display_name=name,
                    kind=kind,
                    up=up,
                    running=up,
                    loopback=loopback,
                    virtual=virtual,
                    mac=mac,
                    usable=usable,
                    reason=reason,
                    capture_name=name,
                )
            )
        return [d.to_dict() for d in details]

    def _raw_interface_names(self) -> list[str]:
        interfaces_dir = Path("/sys/class/net")
        if interfaces_dir.exists():
            return sorted(p.name for p in interfaces_dir.iterdir() if p.is_dir())
        try:
            names = [name for _, name in socket.if_nameindex()]
            if names:
                return sorted(dict.fromkeys(names))
        except (AttributeError, OSError):
            pass
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
        return sorted(
            dict.fromkeys(
                parts[1].split(":", 1)[0]
                for line in result.stdout.splitlines()
                if len(parts := line.split(": ", 1)) == 2 and parts[1].split(":", 1)[0]
            )
        )

    @staticmethod
    def _ifconfig_interface_up(name: str) -> bool:
        try:
            result = subprocess.run(
                ["ifconfig", name],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        output = result.stdout.lower()
        return result.returncode == 0 and (
            "status: active" in output or " flags=" in output and "<up" in output
        )

    # ----------------------------------------------------------- validation

    def validate_interface(
        self, interface: str, refresh: bool = False
    ) -> dict[str, object]:
        """Validate that an interface is suitable for normal live capture."""
        details = next(
            (
                item
                for item in self.list_interface_details(refresh=refresh)
                if item["name"] == interface or item.get("capture_name") == interface
            ),
            None,
        )
        if details is None:
            return {
                "valid": False,
                "interface": interface,
                "reason": f"Network interface not found: {interface}",
            }
        if details.get("loopback"):
            return {
                "valid": False,
                "interface": interface,
                "reason": "Loopback interfaces are not supported for normal live capture.",
                "details": details,
            }
        if not details.get("up"):
            return {
                "valid": False,
                "interface": interface,
                "reason": "Interface is not up. Connect or enable the adapter first.",
                "details": details,
            }
        return {
            "valid": True,
            "interface": interface,
            "reason": None,
            "details": details,
        }

    # ---------------------------------------------------------------- logs

    def clear_logs(self) -> list[Path]:
        """Remove logs from the live-capture directory.

        Files held open by another process (e.g. an orphaned Zeek from a
        previous run) can't be deleted on Windows. In that case switch to a
        fresh session subdirectory instead of crashing. Returns the files
        that were locked.
        """
        self.log_dir.mkdir(parents=True, exist_ok=True)
        locked: list[Path] = []
        for path in self.log_dir.glob("*.log"):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except PermissionError:
                locked.append(path)

        if locked:
            self.log_dir = (
                self._base_log_dir / f"session-{time.strftime('%Y%m%d-%H%M%S')}"
            )
            self.log_dir.mkdir(parents=True, exist_ok=True)
        return locked

    def log_status(self) -> dict[str, bool]:
        return {name: (self.log_dir / name).exists() for name in LIVE_LOGS}

    def has_live_log_data(self, log_name: str = "conn.log") -> bool:
        path = self.log_dir / log_name
        return path.exists() and path.stat().st_size > 0

    def status(self) -> ZeekStatus:
        running = self.process is not None and self.process.poll() is None
        installed = self.is_installed()
        error = self.install_message if not installed else None
        return ZeekStatus(
            installed=installed,
            version=self.version(),
            running=running,
            interface=self.interface,
            log_dir=str(self.log_dir),
            pid=self.process.pid if running and self.process else None,
            logs=self.log_status(),
            error=error,
        )

    # ------------------------------------------------------- stderr capture

    def _close_stderr_file(self) -> None:
        if self._stderr_file is not None:
            try:
                self._stderr_file.close()
            except OSError:
                pass
            self._stderr_file = None

    def _read_stderr(self) -> str:
        self._close_stderr_file()
        try:
            text = self.stderr_path.read_text(
                encoding="utf-8", errors="replace"
            ).strip()
        except OSError:
            return ""
        return text[-2000:]  # keep the tail, that's where the error is

    def _exit_error(self) -> str:
        """Build a readable error for a Zeek process that already exited."""
        code = self.process.returncode if self.process is not None else None
        detail = self._read_stderr()
        if not detail:
            detail = (
                f"no output (exit code {code}). Run Zeek manually to see why: "
                f"{self.zeek_binary} -i <iface> -C local"
            )
        return self._diagnose_start_error(detail)

    def _diagnose_start_error(self, detail: str) -> str:
        detail = (detail or "").strip()
        lower = detail.lower()
        iface = self.interface or "selected interface"

        if (
            "permission" in lower
            or "operation not permitted" in lower
            or "access denied" in lower
        ):
            return (
                f"Zeek could not capture interface '{iface}': "
                f"{detail or 'permission denied'}. "
                "Run the launcher with the required packet-capture privileges."
            )

        if any(
            t in lower
            for t in (
                "can't find",
                "cannot find",
                "unable to find",
                "local.zeek",
                "base/init",
                "zeekpath",
            )
        ):
            return (
                f"Zeek cannot find its script files: {detail}. "
                f"Expected the Zeek source scripts at {ZEEK_SOURCE_DIR / 'scripts'} "
                "(or set the ZEEKPATH environment variable to your Zeek scripts folder)."
            )

        if os.name == "nt" and any(
            token in lower for token in ("npcap", "wpcap", "pcap", "winpcap")
        ):
            return (
                f"Zeek could not open Windows capture interface '{iface}': "
                f"{detail}. Verify that Npcap is installed and that this Zeek build was linked "
                "against the Npcap SDK."
            )

        if any(
            token in lower for token in ("interface", "device", "no such", "not found")
        ):
            return (
                f"Zeek could not open interface '{iface}': "
                f"{detail or 'device was not found'}. "
                "Refresh the interface list and choose an active adapter."
            )

        return f"Zeek failed on '{iface}': {detail or 'unknown error'}"

    # --------------------------------------------------------------- start

    def start(self, interface: str, startup_timeout: float = 5.0) -> ZeekStatus:
        if not self.ensure_installed():
            raise RuntimeError(
                "Zeek is not installed and automatic installation failed: "
                f"{self.install_message or 'unknown installation error'}"
            )
        validation = self.validate_interface(interface, refresh=True)
        if not validation["valid"]:
            raise ValueError(str(validation["reason"]))
        if self.process is not None and self.process.poll() is None:
            raise RuntimeError("Zeek is already running.")

        details = validation.get("details") or {}
        capture_name = details.get("capture_name") or interface

        # Try the base folder first; clear_logs() falls back to a session
        # subfolder only if something still has the old logs open.
        self.log_dir = self._base_log_dir
        self.clear_logs()

        command = [
            self.zeek_binary,
            "-i",
            capture_name,
            "-C",
            "local",
            "Log::default_rotation_interval=0sec",
        ]

        env = self._zeek_env()

        # stderr goes to a file: survives process exit, can't fill a pipe and block.
        self._close_stderr_file()
        self.stderr_path.parent.mkdir(parents=True, exist_ok=True)
        self._stderr_file = open(
            self.stderr_path, "w", encoding="utf-8", errors="replace"
        )
        self._stderr_file.write(f"# command: {' '.join(command)}\n")
        self._stderr_file.write(f"# ZEEKPATH: {env.get('ZEEKPATH', '(default)')}\n")
        self._stderr_file.flush()

        popen_kwargs = {
            "cwd": self.log_dir,
            "env": env,
            "stdout": subprocess.DEVNULL,
            "stderr": self._stderr_file,
            "text": True,
        }
        if os.name == "nt":
            popen_kwargs["creationflags"] = getattr(
                subprocess, "CREATE_NEW_PROCESS_GROUP", 0
            ) | getattr(subprocess, "CREATE_NO_WINDOW", 0)
        else:
            popen_kwargs["start_new_session"] = True

        try:
            self.process = subprocess.Popen(command, **popen_kwargs)
        except OSError as exc:
            self._close_stderr_file()
            self.process = None
            raise RuntimeError(
                f"Could not launch Zeek ({self.zeek_binary}): {exc}"
            ) from exc

        # Windows: tie Zeek's lifetime to this process so it can never be orphaned.
        try:
            _assign_to_kill_on_close_job(self.process.pid)
        except Exception:
            pass  # best effort; never block startup on this

        self.interface = interface

        # Zeek must stay alive for the grace period; a bad script path or
        # device usually kills it within a second.
        deadline = time.monotonic() + min(startup_timeout, STARTUP_GRACE)
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                message = self._exit_error()
                self.process = None
                self.interface = None
                raise RuntimeError(message)
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
            # A quiet interface may legitimately produce no conn.log records
            # during the short smoke-test window. Process survival is the
            # authoritative startup check; actual log records can arrive later.
            log_ready = self.wait_for_log("conn.log", timeout=log_timeout)
            if self.process is None or self.process.poll() is not None:
                raise RuntimeError(self._exit_error())
            return {
                "ready": True,
                "interface": interface,
                "log_ready": bool(log_ready),
                "message": (
                    "Zeek accepted the interface and conn.log is live."
                    if log_ready
                    else "Zeek accepted the interface; no traffic was observed during preflight."
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
            self._close_stderr_file()
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
        self._close_stderr_file()
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
    print(f"ZEEKPATH       : {manager._zeek_env().get('ZEEKPATH', '(default)')}")

    print("\nNetwork interfaces:")
    details = manager.list_interface_details(refresh=True)
    if details:
        for index, item in enumerate(details, start=1):
            flag = "UP " if item["up"] else "down"
            print(f"  {index}. [{flag}] {item['name']}  ->  {item.get('capture_name')}")
    else:
        print("  No interfaces detected")

    if status.logs:
        print("\nLive log files:")
        for name, exists in status.logs.items():
            print(f"  {name:<12} {'✓' if exists else '—'}")


if __name__ == "__main__":
    main()