"""Builds the Hermes agent used as the orchestration layer.

Hermes runs with an isolated home directory inside this project (.hermes_home/),
so the reviewer's or developer's personal Hermes config, memory and persona are
never loaded. Only the toolsets passed in `enabled_toolsets` are exposed to the
model: Day 1 passes an empty list, so the agent can plan but cannot act.
"""
import os
from pathlib import Path

from .paths import HERMES_HOME, ROOT

PROVIDER = "deepseek"
DEFAULT_MODEL = "deepseek-chat"


def load_dotenv(path: Path = ROOT / ".env") -> None:
    """Minimal .env loader (KEY=VALUE lines). Existing environment variables win."""
    if not path.exists():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def isolate_hermes_home() -> Path:
    HERMES_HOME.mkdir(exist_ok=True)
    os.environ["HERMES_HOME"] = str(HERMES_HOME)
    return HERMES_HOME


class MissingCredentials(RuntimeError):
    pass


def build_agent(enabled_toolsets: list[str], model: str | None = None, max_iterations: int = 8):
    load_dotenv()
    isolate_hermes_home()
    api_key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
    if not api_key:
        raise MissingCredentials("DEEPSEEK_API_KEY is not set. Copy .env.example to .env and add your key.")

    if "soc" in enabled_toolsets:
        from .tools import register_with_hermes
        register_with_hermes()
    from run_agent import AIAgent  # imported after HERMES_HOME is set

    return AIAgent(
        provider=PROVIDER,
        model=model or os.environ.get("SOC_MODEL") or DEFAULT_MODEL,
        api_key=api_key,
        enabled_toolsets=list(enabled_toolsets),  # [] => no tools at all
        max_iterations=max_iterations,
        quiet_mode=True,
        skip_context_files=True,
        skip_memory=True,
        load_soul_identity=False,
        checkpoints_enabled=False,
        save_trajectories=False,
    )


def hermes_llm(model: str | None = None):
    """Returns a callable(system, user) -> (text, meta) backed by a tool-less Hermes agent."""
    agent = build_agent(enabled_toolsets=[], model=model)

    def call(system: str, user: str):
        result = agent.run_conversation(user_message=user, system_message=system)
        if result.get("failed"):
            raise RuntimeError(f"Hermes call failed: {result.get('error')}")
        meta = {
            "provider": PROVIDER,
            "model": agent.model,
            "api_calls": result.get("api_calls"),
            "tool_calls": sum(len(m.get("tool_calls") or []) for m in result.get("messages", []) if isinstance(m, dict)),
        }
        return result.get("final_response") or "", meta

    return call
