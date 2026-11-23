"""Append-only JSONL audit trail: one file per investigation run."""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .paths import RUNS


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class AuditLog:
    def __init__(self, alert_id: str, runs_dir: Path = RUNS):
        self.run_id = f"{alert_id}_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}_{uuid.uuid4().hex[:6]}"
        self.dir = Path(runs_dir) / self.run_id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "audit.jsonl"

    def record(self, event: str, **data) -> None:
        line = {"ts": utc_now(), "run_id": self.run_id, "event": event, **data}
        with self.path.open("a") as f:
            f.write(json.dumps(line, ensure_ascii=False, default=str) + "\n")

    def write_artifact(self, name: str, obj: dict) -> Path:
        out = self.dir / name
        out.write_text(json.dumps(obj, indent=2, ensure_ascii=False))
        return out
