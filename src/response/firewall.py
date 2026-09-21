"""User-confirmed host firewall actions for detected source IPs.

The API layer must require explicit confirmation before calling this module.
Commands are passed as argument arrays; shell=True is never used.
"""

from __future__ import annotations

import ipaddress
import json
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


class FirewallActionError(RuntimeError):
    """Raised when a firewall action cannot be completed."""


class HostFirewall:
    COMMENT = "AI-UTD"

    def __init__(self, audit_path: str | Path = "data/processed/response_actions.jsonl") -> None:
        self.audit_path = Path(audit_path)

    @staticmethod
    def _validate_ip(value: str) -> str:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise FirewallActionError(f"Invalid IP address: {value}") from exc

    def _run(self, command: list[str]) -> None:
        try:
            subprocess.run(command, check=True, capture_output=True, text=True)
        except FileNotFoundError as exc:
            raise FirewallActionError(f"Required firewall command is unavailable: {command[0]}") from exc
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or exc.stdout or "").strip()
            raise FirewallActionError(detail or f"Firewall command failed: {' '.join(command)}") from exc

    def _linux(self, ip: str, action: str) -> list[str]:
        family = "ip6tables" if ipaddress.ip_address(ip).version == 6 else "iptables"
        if not shutil.which(family):
            raise FirewallActionError(f"{family} is not installed.")
        base = [family, "-I" if action == "block" else "-D", "INPUT", "-s", ip, "-j", "DROP"]
        return base + ["-m", "comment", "--comment", self.COMMENT]

    def _windows(self, ip: str, action: str) -> list[str]:
        if not shutil.which("netsh"):
            raise FirewallActionError("netsh is not available.")
        name = f"AI-UTD {ip}"
        if action == "block":
            return [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name}", "dir=in", "action=block", f"remoteip={ip}",
            ]
        return [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={name}",
        ]

    def _command(self, ip: str, action: str) -> list[str]:
        system = platform.system()
        if system == "Linux":
            return self._linux(ip, action)
        if system == "Windows":
            return self._windows(ip, action)
        raise FirewallActionError(
            f"Host firewall actions are not implemented for {system}."
        )

    def _audit(self, action: str, ip: str) -> None:
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "ip": ip,
            "platform": platform.system(),
        }
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")

    def block(self, ip: str) -> dict[str, str]:
        normalized = self._validate_ip(ip)
        self._run(self._command(normalized, "block"))
        self._audit("block", normalized)
        return {"action": "block", "ip": normalized}

    def unblock(self, ip: str) -> dict[str, str]:
        normalized = self._validate_ip(ip)
        self._run(self._command(normalized, "unblock"))
        self._audit("unblock", normalized)
        return {"action": "unblock", "ip": normalized}
