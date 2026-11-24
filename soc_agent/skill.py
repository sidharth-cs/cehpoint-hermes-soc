"""Loads the packaged skill (skills/soc-alert-investigation/SKILL.md) that drives every Hermes stage.

The skill is the single written procedure the agent follows: each stage's system prompt is its stage-specific
contract plus the skill. The skill is also installed into the isolated Hermes home, so Hermes' own skill index
sees it. Hermes' `skills` toolset is NOT enabled for the agent: it includes `skill_manage`, which can write.
"""
import hashlib
import shutil
from functools import lru_cache
from pathlib import Path

import yaml

from .paths import ROOT

NAME = "soc-alert-investigation"
SKILLS = ROOT / "skills"
SKILL_MD = SKILLS / NAME / "SKILL.md"


@lru_cache(maxsize=1)
def load() -> dict:
    text = SKILL_MD.read_text()
    if not text.startswith("---\n"):
        raise ValueError(f"{SKILL_MD} has no YAML frontmatter")
    _, front, body = text.split("---\n", 2)
    meta = yaml.safe_load(front)
    if meta.get("name") != NAME or len(meta["name"]) > 64:
        raise ValueError(f"skill name must be {NAME!r} (max 64 chars)")
    if not meta.get("description") or len(meta["description"]) > 1024:
        raise ValueError("skill description is required (max 1024 chars)")
    return {"name": meta["name"], "version": str(meta.get("version", "0")), "description": meta["description"],
            "sha256": hashlib.sha256(text.encode()).hexdigest()[:16], "body": body.strip()}


def with_skill(stage_prompt: str) -> str:
    s = load()
    return (f"{stage_prompt.rstrip()}\n\n=== Operating procedure: skill {s['name']} v{s['version']} ===\n"
            "Follow it. Where it differs from the stage instructions above, the stage instructions win, "
            "because they define this stage's exact output.\n\n" + s["body"])


def install(hermes_home: Path) -> Path:
    """Copy the skill into <HERMES_HOME>/skills so Hermes lists it (e.g. `hermes skills list`)."""
    dest = Path(hermes_home) / "skills" / NAME
    shutil.copytree(SKILL_MD.parent, dest, dirs_exist_ok=True)
    return dest
