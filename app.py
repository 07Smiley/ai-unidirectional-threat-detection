from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PYTHON = sys.executable
BACKEND_HOST = os.environ.get("BACKEND_HOST", "127.0.0.1")
BACKEND_PORT = os.environ.get("BACKEND_PORT", "8000")
DASHBOARD_HOST = os.environ.get("DASHBOARD_HOST", "127.0.0.1")
DASHBOARD_PORT = os.environ.get("DASHBOARD_PORT", "9000")


def start_process(command: list[str], name: str) -> subprocess.Popen:
    print(f"[launcher] Starting {name}: {' '.join(command)}")
    return subprocess.Popen(command, cwd=ROOT)


def main() -> int:
    processes: list[tuple[str, subprocess.Popen]] = []

    try:
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

        dashboard = start_process(
            [
                PYTHON,
                "dashboard.py",
            ],
            "Sentry dashboard",
        )
        processes.append(("Sentry dashboard", dashboard))

        print()
        print("[launcher] AI Unidirectional Threat Detection is running.")
        print(f"[launcher] Backend:   http://{BACKEND_HOST}:{BACKEND_PORT}")
        print(f"[launcher] Dashboard: http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
        print("[launcher] Open the dashboard in your browser and select an interface.")
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
        for _, process in reversed(processes):
            if process.poll() is None:
                process.terminate()

        deadline = time.time() + 5
        for _, process in reversed(processes):
            if process.poll() is None:
                remaining = max(0.1, deadline - time.time())
                try:
                    process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    process.kill()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
