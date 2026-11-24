"""Common wrapper for every SOC tool.

A tool is a pure, read-only function plus two JSON Schemas (arguments and result).
`execute()` is the only way a tool runs. It:
  1. validates the arguments (unknown fields, wrong types, bad formats are rejected),
  2. runs the function with a timeout,
  3. validates the result shape (a malformed result is never passed to the model),
  4. wraps everything in one envelope: {tool, ok, source, mock, result, error, duration_ms},
  5. records the call in the active trace (audit trail).
Every tool requires a `reason` argument so the agent must state why it is calling it.
"""
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from typing import Callable

from jsonschema import Draft202012Validator, FormatChecker

REASON = {"type": "string", "minLength": 10, "maxLength": 300,
          "description": "One sentence: why this call is needed for the investigation."}


class ToolInputError(ValueError):
    """Arguments are well-typed but make no sense (e.g. end before start)."""


class DataUnavailable(RuntimeError):
    """The backing dataset is missing or unreadable."""


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict
    result_schema: dict
    func: Callable[[dict], dict]
    source: str
    mock: bool
    timeout_s: float = 5.0
    _arg_validator: Draft202012Validator = field(init=False, repr=False)
    _out_validator: Draft202012Validator = field(init=False, repr=False)

    def __post_init__(self):
        self._arg_validator = Draft202012Validator(self.parameters, format_checker=FormatChecker())
        self._out_validator = Draft202012Validator(self.result_schema, format_checker=FormatChecker())

    def hermes_schema(self) -> dict:
        return {"name": self.name, "description": self.description, "parameters": self.parameters}


# ---- tracing (module-level: Hermes may run tools on worker threads, where ContextVars don't follow) ----
_trace_lock = threading.Lock()
_active_trace = None


class Trace:
    def __init__(self, audit=None):
        self.audit = audit
        self.calls: list[dict] = []

    def add(self, entry: dict) -> None:
        with _trace_lock:
            entry = {"seq": len(self.calls) + 1, **entry}
            self.calls.append(entry)
        if self.audit is not None:
            self.audit.record("tool_call", **entry)


def start_trace(audit=None) -> Trace:
    global _active_trace
    _active_trace = Trace(audit)
    return _active_trace


def stop_trace() -> None:
    global _active_trace
    _active_trace = None


# ---- fault injection for demos/tests: SOC_FAULTS="lookup_ip=timeout,search_logs=malformed" ----
def _injected_fault(tool: str) -> str | None:
    for item in os.environ.get("SOC_FAULTS", "").split(","):
        name, _, fault = item.strip().partition("=")
        if name == tool and fault in {"timeout", "malformed", "unavailable", "crash"}:
            return fault
    return None


_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="soc-tool")


def execute(spec: ToolSpec, args: dict) -> dict:
    started = time.monotonic()
    env = {"tool": spec.name, "ok": False, "source": spec.source, "mock": spec.mock, "result": None, "error": None}

    def finish(**kw):
        env.update(kw)
        env["duration_ms"] = round((time.monotonic() - started) * 1000, 1)
        if _active_trace is not None:
            _active_trace.add({
                "tool": spec.name,
                "reason": args.get("reason") if isinstance(args, dict) else None,
                "arguments": {k: v for k, v in (args or {}).items() if k != "reason"} if isinstance(args, dict) else args,
                "ok": env["ok"],
                "error": env["error"],
                "result_summary": _summarize(env["result"]),
                "result": env["result"],
                "duration_ms": env["duration_ms"],
                "source": spec.source,
                "mock": spec.mock,
            })
        return env

    if not isinstance(args, dict):
        return finish(error={"code": "invalid_input", "message": "arguments must be a JSON object"})
    problems = [f"{'/'.join(map(str, e.path)) or '<root>'}: {e.message}" for e in spec._arg_validator.iter_errors(args)]
    if problems:
        return finish(error={"code": "invalid_input", "message": "; ".join(problems)})

    fault = _injected_fault(spec.name)
    if fault == "unavailable":
        return finish(error={"code": "data_unavailable", "message": f"{spec.source} is unavailable (injected fault)"})

    def run():
        if fault == "timeout":
            time.sleep(spec.timeout_s + 1)
        if fault == "crash":
            raise RuntimeError("injected crash")
        out = spec.func(args)
        if fault == "malformed":
            out = {"garbage": True}
        return out

    future = _pool.submit(run)
    try:
        result = future.result(timeout=spec.timeout_s)
    except FutureTimeout:
        return finish(error={"code": "timeout", "message": f"{spec.name} did not answer within {spec.timeout_s}s"})
    except ToolInputError as exc:
        return finish(error={"code": "invalid_input", "message": str(exc)})
    except DataUnavailable as exc:
        return finish(error={"code": "data_unavailable", "message": str(exc)})
    except Exception as exc:  # never leak a stack trace to the model
        return finish(error={"code": "internal_error", "message": f"{type(exc).__name__}: {exc}"})

    out_problems = [e.message for e in spec._out_validator.iter_errors(result)]
    if out_problems:
        return finish(error={"code": "malformed_output", "message": "tool returned data that failed its result schema; discarded"})
    return finish(ok=True, result=result)


def _summarize(result) -> str | None:
    if result is None:
        return None
    for key in ("returned", "count"):
        if isinstance(result, dict) and key in result:
            return f"{key}={result[key]}"
    if isinstance(result, dict) and "found" in result:
        return f"found={result['found']}"
    return json.dumps(result)[:120]
