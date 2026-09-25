from __future__ import annotations

import os
import subprocess
import shutil
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from src.zeek.installer import ZeekInstaller


ROOT = Path(__file__).resolve().parent
VENV_DIR = ROOT / ".venv"
PYTHON = sys.executable
BACKEND_HOST = os.environ.get("BACKEND_HOST", "127.0.0.1")
BACKEND_PORT = os.environ.get("BACKEND_PORT", "8000")
DASHBOARD_HOST = os.environ.get("DASHBOARD_HOST", "127.0.0.1")
DASHBOARD_PORT = os.environ.get("DASHBOARD_PORT", "9000")


def start_process(command, name, env=None):
    print("[launcher] Starting " + name + ": " + " ".join(command))
    return subprocess.Popen(command, cwd=ROOT, env=env)


def _venv_python() -> Path:
    if os.name == "nt":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def ensure_python_environment() -> None:
    if sys.version_info < (3, 10):
        raise RuntimeError("Python 3.10 or newer is required.")

    target = _venv_python()
    if Path(sys.executable).resolve() != target.resolve():
        if not target.is_file():
            print("[launcher] Creating project Python environment...")
            subprocess.run(
                [sys.executable, "-m", "venv", str(VENV_DIR)],
                cwd=ROOT,
                check=True,
            )
        print("[launcher] Using project Python environment: " + str(target))
        os.execv(str(target), [str(target), str(Path(__file__).resolve()), *sys.argv[1:]])

    requirements = ROOT / "requirements.txt"
    marker = VENV_DIR / ".dependencies-ready"
    if not requirements.is_file():
        raise RuntimeError("requirements.txt was not found.")

    if marker.is_file() and marker.stat().st_mtime >= requirements.stat().st_mtime:
        return

    print("[launcher] Installing/updating Python dependencies...")
    result = subprocess.run(
        [str(target), "-m", "pip", "install", "-r", str(requirements)],
        cwd=ROOT,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Python dependency installation failed.")

    marker.write_text("ready\\n", encoding="utf-8")
    print("[launcher] Python dependencies ready.")


def ensure_capture_privileges() -> None:
    """Relaunch the launcher with capture privileges when the OS requires them."""
    if os.environ.get("AI_UD_PRIV_ESCALATED") == "1":
        return

    if os.name == "nt":
        try:
            import ctypes

            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            is_admin = False

        if not is_admin:
            print("[launcher] Live capture requires administrator privileges; requesting UAC...")
            import ctypes

            params = subprocess.list2cmdline([str(Path(__file__).resolve()), *sys.argv[1:]])
            result = ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                params,
                str(ROOT),
                1,
            )
            if result <= 32:
                raise RuntimeError("Windows elevation was denied or failed.")
            raise SystemExit(0)
        return

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        sudo = shutil.which("sudo")
        if not sudo:
            raise RuntimeError(
                "Live packet capture requires root privileges. sudo was not found."
            )

        print("[launcher] Live capture requires elevated privileges; requesting sudo...")
        env = os.environ.copy()
        env["AI_UD_PRIV_ESCALATED"] = "1"
        os.execvpe(
            sudo,
            [sudo, "-E", sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]],
            env,
        )


def preflight():
    ensure_python_environment()

    result = ZeekInstaller().ensure(auto_install=True)
    if not result.installed:
        raise RuntimeError("Zeek setup is incomplete: " + (result.message or "unknown installation error"))
    print("[launcher] Zeek ready (" + str(result.method) + ").")

    ensure_capture_privileges()

    required_imports = {
        "fastapi": "fastapi", "uvicorn": "uvicorn", "flask": "Flask",
        "dotenv": "python-dotenv", "google.genai": "google-genai",
        "pandas": "pandas", "sklearn": "scikit-learn",
    }
    missing = []
    for module, package in required_imports.items():
        try:
            __import__(module)
        except ImportError:
            missing.append(package)
    if missing:
        raise RuntimeError("Missing Python dependencies after installation: " + ", ".join(sorted(set(missing))))


def wait_for_url(url, process, name, timeout=60.0):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(name + " exited during startup with code " + str(process.returncode))
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status < 500:
                    print("[launcher] " + name + " ready.")
                    return
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
        time.sleep(0.25)
    raise RuntimeError(name + " did not become ready at " + url + ": " + str(last_error))


def shutdown(processes):
    for name, process in reversed(processes):
        if process.poll() is None:
            print("[launcher] Stopping " + name + "...")
            process.terminate()
    for _, process in reversed(processes):
        if process.poll() is None:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)


def main():
    processes = []
    try:
        print("[launcher] Running preflight checks...")
        preflight()

        backend = start_process(
            [PYTHON, "-m", "uvicorn", "backend.main:app",
             "--host", BACKEND_HOST, "--port", BACKEND_PORT],
            "FastAPI backend",
        )
        processes.append(("FastAPI backend", backend))
        wait_for_url(
            "http://" + BACKEND_HOST + ":" + BACKEND_PORT + "/health",
            backend,
            "FastAPI backend",
            timeout=60.0,
        )

        dashboard_env = os.environ.copy()
        dashboard_env["DASHBOARD_HOST"] = DASHBOARD_HOST
        dashboard_env["DASHBOARD_PORT"] = DASHBOARD_PORT
        dashboard = start_process([PYTHON, "dashboard.py"], "Sentry dashboard", dashboard_env)
        processes.append(("Sentry dashboard", dashboard))
        wait_for_url(
            "http://" + DASHBOARD_HOST + ":" + DASHBOARD_PORT + "/",
            dashboard,
            "Sentry dashboard",
            timeout=30.0,
        )

        print("\n[launcher] AI Unidirectional Threat Detection is ready.")
        print("[launcher] Dashboard: http://" + DASHBOARD_HOST + ":" + DASHBOARD_PORT)
        print("[launcher] Select a network interface and press Start Live.")
        print("[launcher] Press Ctrl+C to stop everything.")

        while True:
            for name, process in processes:
                if process.poll() is not None:
                    raise RuntimeError(name + " exited with code " + str(process.returncode))
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[launcher] Shutting down...")
    except Exception as exc:
        print("[launcher] ERROR: " + str(exc), file=sys.stderr)
        return 1
    finally:
        shutdown(processes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
