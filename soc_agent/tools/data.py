"""Read-only access to the synthetic datasets. No tool can write anywhere."""
import json
from functools import lru_cache
from pathlib import Path

from ..paths import ROOT
from .base import DataUnavailable

DATA = ROOT / "data"
EVENTS = DATA / "logs" / "events.jsonl"
IP_INTEL = DATA / "intel" / "ip_reputation_mock.json"
THREAT_INTEL = DATA / "intel" / "threat_intel_snapshot.json"
ASSETS = DATA / "assets" / "inventory.json"


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise DataUnavailable(f"{path.name} not found") from exc
    except json.JSONDecodeError as exc:
        raise DataUnavailable(f"{path.name} is corrupt: {exc}") from exc


@lru_cache(maxsize=None)
def load_events(path: Path = EVENTS) -> tuple[tuple[dict, ...], int]:
    """Returns (events, malformed_line_count). Each event gets `ref` = file#Lline for evidence citations."""
    if not path.exists():
        raise DataUnavailable(f"{path.name} not found")
    events, bad = [], 0
    for n, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            e = json.loads(line)
            if not all(k in e for k in ("ts", "event_type", "event_id")):
                raise ValueError("missing required keys")
        except ValueError:
            bad += 1
            continue
        e["ref"] = f"{path.relative_to(ROOT)}#L{n}"
        events.append(e)
    return tuple(events), bad


def ip_intel() -> dict:
    return _read_json(IP_INTEL)


def threat_intel() -> dict:
    return _read_json(THREAT_INTEL)


def assets() -> dict:
    return _read_json(ASSETS)
