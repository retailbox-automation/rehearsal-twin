"""The TWIN card subtitle says what is true of a twin: it carries decoys (.env.canary and friends) but no
real secrets. The same words live in three places (the API view, the screen's empty record and the
fixture screen), so they are checked together and cannot drift apart again."""
import json
from pathlib import Path

from rt.orchestrator import view

ROOT = Path(__file__).resolve().parents[2]
WANT = "Vultr VM from snapshot · VPC-only · no real secrets"


def test_view_subtitle_names_no_real_secrets():
    assert view.TWIN_SUBTITLE == WANT
    assert "no keys" not in view.TWIN_SUBTITLE


def test_screen_and_fixture_carry_the_same_subtitle():
    app = (ROOT / "web" / "app.js").read_text()
    assert WANT.replace("·", "\\u00b7") in app
    assert "no keys" not in app
    fx = json.loads((ROOT / "web" / "fixtures" / "rehearsal-a.json").read_text())
    assert fx["twin"]["subtitle"] == WANT


def test_readme_does_not_claim_no_keys():
    readme = (ROOT / "README.md").read_text()
    assert "holds no keys" not in readme
    assert readme.count("no real secrets") >= 2
