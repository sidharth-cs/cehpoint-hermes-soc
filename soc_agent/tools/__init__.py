"""Approved SOC tools and their registration as the Hermes `soc` toolset."""
import json

from .base import ToolSpec, execute, start_trace, stop_trace  # noqa: F401
from .specs import ALL_TOOLS

TOOLSET = "soc"
BY_NAME = {t.name: t for t in ALL_TOOLS}


def run_tool(name: str, args: dict) -> dict:
    """Run an approved tool by name. Unknown names are refused, never guessed."""
    spec = BY_NAME.get(name)
    if spec is None:
        return {"tool": name, "ok": False, "error": {"code": "not_permitted", "message": f"'{name}' is not an approved tool"}}
    return execute(spec, args)


def register_with_hermes() -> list[str]:
    """Register the four tools in Hermes' registry under toolset `soc`. Safe to call more than once."""
    from tools.registry import registry  # Hermes' registry; import after HERMES_HOME is set

    for spec in ALL_TOOLS:
        registry.register(
            name=spec.name,
            toolset=TOOLSET,
            schema=spec.hermes_schema(),
            handler=lambda args, _spec=spec, **_kw: json.dumps(execute(_spec, args), default=str),
            description=spec.description,
            max_result_size_chars=60_000,
        )
    return [t.name for t in ALL_TOOLS]
