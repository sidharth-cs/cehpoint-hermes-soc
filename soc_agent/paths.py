import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas"
RUNS = ROOT / "runs"
HERMES_HOME = ROOT / ".hermes_home"
LAB = ROOT / "lab"                     # the lab system we own: target app, attack script, inventory
LAB_STATE = LAB / "state"              # runtime: live event log, blocklist, auto-created alerts (git-ignored)
FIXTURES = ROOT / "tests" / "fixtures"  # frozen synthetic dataset, used only by the offline tests


def fixture_mode() -> bool:
    """Tests set SOC_DATA=fixtures. Everything else reads the live lab system and live intel APIs."""
    return os.environ.get("SOC_DATA") == "fixtures"
