from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PYTHON = sys.executable
BACKEND_HOST = os.environ.get("BACKEND_HOST", "127.0.0.1")
BACKEND_PORT = os.environ.get("BACKEND_PORT", "8000")
DASHBOARD_HOST = os.environ.get("DASHBOARD_HOST", "127.0.0.1")
DASHBOARD_PORT = os.environ.get("DASHBOARD_PORT", "9000")
ZEEK_PATHS = ("/opt/zeek/bin/zeek", "/usr/local/bin/zeek", "/usr/bin/zeek")


def find_zeek() -> str | None:
    found = shutil.which("zeek")
    if found:
        return found
    for candidate in ZEEK_PATHS:
        path = Path(candidate)
        if path.is_file() and path.stat().st_mode & 0o111:
            return candidate
    return None


def start_process(command: list[str], name: str) -> subprocess.Popen:
    print(f"[launcher] Starting {name}: {' '.join(command)}")
    return subprocess.Popen(command, cwd=ROOT)


def preflight() -> None:
    if sys.version_info < (3, 10):
        raise RuntimeError("Python 3.10 or newer is required.")

    zeek = find_zeek()
    if zeek is None:
        raise RuntimeError(
            "Zeek was not found. Check that the Zeek package is installed "
            "and that /opt/zeek/bin/zeek exists."
        )
    print(f"[launcher] Zeek: {zeek}")

    if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0:
        print(
            "[launcher] WARNING: not running as root. The dashboard can open, "
            "but Zeek live capture may fail unless capture permissions/capabilities "
            "are configured for your user."
        )

    required_imports = {
        "fastapi": "fastapi",
        "uvicorn": "uvicorn",
        "flask": "Flask",
        "dotenv": "python-dotenv",
        "google.genai": "google-genai",
        "pandas": "pandas",
        "sklearn": "scikit-learn",
    }
    missing: list[str] = []
    for module, package in required_imports.items():
        try:
            __import__(module)
        except ImportError:
            missing.append(package)

    if missing:
        packages = ", ".join(sorted(set(missing)))
        raise RuntimeError(
            f"Missing Python dependencies: {packages}. "
            "Run: python -m pip install -r requirements.txt"
        )


def wait_for_url(url: str, process: subprocess.Popen, name: str, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None

    while time.monotonic() < deadline:
        code = process.poll()
        if code is not None:
            raise RuntimeError(f"{name} exited during startup with code {code}.")

        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status < 500:
                    print(f"[launcher] {name} ready.")
                    return
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc

        time.sleep(0.25)

    raise RuntimeError(f"{name} did not become ready at {url}: {last_error}")


def shutdown(processes: list[tuple[str, subprocess.Popen]]) -> None:
    for name, process in reversed(processes):
        if process.poll() is None:
            print(f"[launcher] Stopping {name}...")
            process.terminate()

    deadline = time.time() + 5
    for _, process in reversed(processes):
        if process.poll() is None:
            remaining = max(0.1, deadline - time.time())
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)


def main() -> int:
    processes: list[tuple[str, subprocess.Popen]] = []

    try:
        print("[launcher] Running preflight checks...")
        preflight()

        backend = start_process(
            [
                PYTHON,
                "-m",
                "uvicorn",
                "backend.main:app",
                "--host",
                BACKEND_HOST,
                "--port",
                BACKEND_PORT,
            ],
            "FastAPI backend",
        )
        processes.append(("FastAPI backend", backend))
        wait_for_url(
            f"http://{BACKEND_HOST}:{BACKEND_PORT}/health",
            backend,
            "FastAPI backend",
        )

        dashboard_env = os.environ.copy()
        dashboard_env["DASHBOARD_HOST"] = DASHBOARD_HOST
        dashboard_env["DASHBOARD_PORT"] = DASHBOARD_PORT
        print(f"[launcher] Starting Sentry dashboard: {PYTHON} dashboard.py")
        dashboard = subprocess.Popen(
            [PYTHON, "dashboard.py"],
            cwd=ROOT,
            env=dashboard_env,
        )
        processes.append(("Sentry dashboard", dashboard))
        wait_for_url(
            f"http://{DASHBOARD_HOST}:{DASHBOARD_PORT}/",
            dashboard,
            "Sentry dashboard",
        )

        print()
        print("[launcher] AI Unidirectional Threat Detection is ready.")
        print(f"[launcher] Backend:   http://{BACKEND_HOST}:{BACKEND_PORT}")
        print(f"[launcher] Dashboard: http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
        print("[launcher] Select a network interface and press Start Live.")
        print("[launcher] Press Ctrl+C to stop everything.")

        while True:
            for name, process in processes:
                code = process.poll()
                if code is not None:
                    raise RuntimeError(f"{name} exited with code {code}.")
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[launcher] Shutting down...")
    except Exception as exc:
        print(f"[launcher] ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        shutdown(processes)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
