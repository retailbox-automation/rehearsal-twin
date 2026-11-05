"""Static checks of the screen fixes of 05.11 (web/): the agent's explanation panel, replay mode for finished
runs, the operator token and the layout guards found while checking the frames by eye."""
import json
import re
from pathlib import Path

from rt.orchestrator import core

WEB = Path(__file__).resolve().parents[2] / "web"
APP = (WEB / "app.js").read_text()
HTML = (WEB / "index.html").read_text()
CSS = (WEB / "style.css").read_text()


def test_explain_event_is_shown_from_its_own_fields_only():
    assert '"explain"' in APP and 'case "explain": state.explain = data;' in APP
    for field in ("x.n", "x.summary", "x.why_safer"):
        assert field in APP
    assert re.search(r'<section class="explain" id="explain" hidden>', HTML)
    # a display rule on .explain must not override the hidden attribute (seen on the first frame)
    assert ".explain[hidden]" in CSS


def test_replay_statuses_are_the_orchestrator_terminal_statuses():
    m = re.search(r"const TERMINAL = (\[[^\]]*\]);", APP)
    assert m, "TERMINAL list missing in app.js"
    assert tuple(json.loads(m.group(1))) == core.TERMINAL


def test_operator_token_comes_only_from_session_storage():
    assert 'sessionStorage.getItem("rt-operator-token")' in APP
    assert 'headers["X-RT-Token"] = t' in APP
    assert APP.count("withToken(") == 2  # the run and the approve POSTs
    assert "token" not in "".join(re.findall(r'qs\.get\("([^"]+)"\)', APP))  # never read from the URL
    assert "console.log" not in APP


def test_layout_guards():
    assert "DESIGN_H = 941" in APP  # fit the whole console to the window height as well
    assert '<div class="ledger-body"><table id="ledger">' in HTML
    assert "#ledger.dense tr { height: 28px; }" in CSS  # 7 rows fit the ledger card
    rule = re.search(r"\.outside, \.blocked \{[^}]*\}", CSS)
    assert rule and "white-space: nowrap" not in rule.group(0)  # the egress line wraps inside the card


def test_uptime_zero_is_not_shown_as_zero_days():
    assert 'if (!(s > 0)) return "\\u2014";' in APP
