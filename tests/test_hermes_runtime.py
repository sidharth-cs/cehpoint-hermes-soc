import pytest

from soc_agent import hermes_runtime


def test_missing_key_fails_clearly(monkeypatch, tmp_path):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.setattr(hermes_runtime, "load_dotenv", lambda *a, **k: None)
    with pytest.raises(hermes_runtime.MissingCredentials):
        hermes_runtime.build_agent([])


def test_day1_agent_has_no_tools_and_isolated_home(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test-not-a-real-key")
    agent = hermes_runtime.build_agent([])
    assert agent.tools in (None, []) or len(agent.tools) == 0
    assert agent.model
    import os
    assert os.environ["HERMES_HOME"].endswith(".hermes_home")
