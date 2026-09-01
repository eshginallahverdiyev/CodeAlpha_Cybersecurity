"""
alert.py — Structured alert handling for the NIDS.

Every detection produces an Alert, which is:
  1. Printed to the console with a color-coded severity tag.
  2. Appended to a JSON-Lines log file (one JSON object per line) so it can
     be parsed later by SIEM tooling, the bundled visualizer, or a SOC
     analyst's own scripts.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


_COLOR = {
    Severity.LOW: "\033[36m",       # cyan
    Severity.MEDIUM: "\033[33m",    # yellow
    Severity.HIGH: "\033[31m",      # red
    Severity.CRITICAL: "\033[41m",  # red background
}
_RESET = "\033[0m"


@dataclass
class Alert:
    rule: str
    severity: Severity
    src_ip: str
    description: str
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    meta: dict = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_json(self) -> str:
        d = asdict(self)
        d["severity"] = self.severity.value
        return json.dumps(d)

    def to_console_line(self) -> str:
        color = _COLOR.get(self.severity, "")
        target = f" -> {self.dst_ip}:{self.dst_port}" if self.dst_ip else ""
        return (
            f"{color}[{self.severity.value:8s}]{_RESET} "
            f"{self.timestamp}  {self.rule:<20s} "
            f"src={self.src_ip}{target}  {self.description}"
        )


class AlertManager:
    """Thread-safe alert sink: console + append-only JSONL file."""

    def __init__(self, log_path: str = "logs/alerts.log", echo: bool = True):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.echo = echo
        self._lock = threading.Lock()
        self._counts: dict[str, int] = {}

    def raise_alert(self, alert: Alert) -> None:
        with self._lock:
            self._counts[alert.rule] = self._counts.get(alert.rule, 0) + 1
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(alert.to_json() + "\n")
            if self.echo:
                print(alert.to_console_line())

    def summary(self) -> dict:
        return dict(self._counts)
