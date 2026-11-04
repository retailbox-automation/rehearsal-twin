"""What the model is told about the target server agrees with the server and with the prompts."""
from __future__ import annotations

from rt.agent.planner import load_prompt
from rt.orchestrator.settings import DEFAULT_TARGET_DESC


def test_target_description_names_the_shop_role_not_root():
    # Scripts log in to Postgres as role shop (PGUSER=shop in the sandbox unit): owner of the
    # app tables, not a superuser. The description must not promise a superuser connection.
    d = DEFAULT_TARGET_DESC
    assert "connects as root" not in d
    assert "role shop" in d and "not a superuser" in d and "owns these tables" in d


def test_target_description_and_prompts_agree_on_how_to_connect():
    # The prompts tell the model: no environment variables, `psql shop` as is. The target
    # description says the same thing, so the model gets one instruction, not two.
    assert "`psql shop` works as is" in DEFAULT_TARGET_DESC
    assert "no environment variables" in DEFAULT_TARGET_DESC
    for name in ("planner_system.md", "explain_system.md"):
        prompt = load_prompt(name)
        assert "`psql shop`" in prompt and "no environment variables" in prompt
        assert "PGUSER" not in prompt
