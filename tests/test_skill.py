"""The packaged skill: valid for Hermes, drives every stage, and gives the agent no new capability."""
import json

from soc_agent import skill
from soc_agent.assess import ASSESS_PROMPT
from soc_agent.investigate import EVIDENCE_PROMPT
from soc_agent.planner import SYSTEM_PROMPT


def test_skill_metadata_meets_hermes_limits():
    s = skill.load()
    assert s["name"] == "soc-alert-investigation" and len(s["description"]) <= 1024
    for section in ("## Procedure", "## Guardrails", "Propose containment, never execute it", "unknown"):
        assert section in s["body"]


def test_every_stage_runs_with_the_skill():
    body = skill.load()["body"]
    for stage in (SYSTEM_PROMPT, EVIDENCE_PROMPT, ASSESS_PROMPT):
        prompt = skill.with_skill(stage)
        assert prompt.startswith(stage.rstrip()) and body in prompt


def test_hermes_skill_index_finds_the_installed_skill(tmp_path, monkeypatch):
    skill.install(tmp_path)
    import tools.skills_tool as st                      # Hermes' own skill loader
    monkeypatch.setattr(st, "SKILLS_DIR", tmp_path / "skills")
    listed = json.loads(st.skills_list())
    names = [x["name"] for x in listed.get("skills", [])]
    assert "soc-alert-investigation" in names
    front, _ = st._parse_frontmatter((tmp_path / "skills/soc-alert-investigation/SKILL.md").read_text())
    assert front["version"] == skill.load()["version"]


def test_agent_does_not_get_the_skills_toolset(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test-not-a-real-key")
    from soc_agent.hermes_runtime import build_agent
    names = set(build_agent(enabled_toolsets=["soc"]).valid_tool_names)
    assert not names & {"skills_list", "skill_view", "skill_manage"}
