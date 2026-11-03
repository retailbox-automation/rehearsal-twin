from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from rt.agent.inference import InferenceClient
from rt.agent.planner import Planner
from rt.agent.safety import SafetyFilter
from rt.orchestrator import Orchestrator, Settings
from rt.receipts.sign import Signer
from rt.twin.lifecycle import SSH
from rt.twin.vultr import Vultr
from tests.agent.fake_inference import FakeInference
from tests.orchestrator import ledgers as L
from tests.orchestrator.fakes import FakeFleet, ModelRouter, reply_safe_unless, sha
from tests.twin.fake_vultr import FakeVultr

FAKE_KEY = "unit-test-placeholder"
REPO = Path(__file__).resolve().parents[2]
SNAPSHOT = "snap-golden-1"
VPC = "vpc-1"

EXPLAIN_A = {
    "summary": "The script deleted every file under /srv because CACHE_SUBDIR was empty, "
               "and tried to call prod-api.internal/purge.",
    "notes": [{"index": 0, "note": "rm -rf ran on /srv/*"}],
    "safer_script": L.SAFE_A,
    "why_safer": "Literal cache path with rm -rf --, explicit WHERE, no purge call.",
}


@dataclass
class Harness:
    orch: Orchestrator
    vultr_fake: FakeVultr
    inference_fake: FakeInference
    fleet: FakeFleet
    prod_id: str
    signer: Signer
    settings: Settings
    explain_replies: list = field(default_factory=list)

    @property
    def prod(self):
        return self.fleet.targets[self.prod_id]

    def twins(self):
        return [t for name, t in self.fleet.targets.items() if name != self.prod_id]

    def live_twins(self):
        return [i for i in self.vultr_fake.instances.values() if "rt-twin" in i["tags"]]

    def run_preset(self, preset="a", **kw):
        rec = self.orch.create(preset=preset, **kw)
        return self.orch.run(rec["id"])

    def events(self, rid):
        return self.orch.store.events(rid)


@pytest.fixture
def harness(tmp_path, monkeypatch):
    monkeypatch.delenv("RT_JUMP_HOST", raising=False)
    vf = FakeVultr().start()
    inf = FakeInference().start()
    prod_id = vf.add_instance(tags=["rt-keep", "prod"], created=datetime.now(timezone.utc), label="prod-shop-01",
                              main_ip="203.0.113.9")
    fleet = FakeFleet(L.machine_state, {sha(L.RISKY_A.encode()): L.risky_a_facts(),
                                        sha(L.SAFE_A.encode()): L.safe_a_facts()})
    fleet.add(prod_id, L.machine_state(), {sha(L.SAFE_A.encode()): L.safe_a_facts(wall=1.7)})

    h_box: dict = {}

    def route(body: dict) -> dict:
        if body["model"] == "nemotron-3.5-content-safety":
            return {"content": reply_safe_unless(("drop table",))(body)}
        fmt = (body.get("response_format") or {}).get("json_schema", {}).get("name")
        if fmt == "rehearsal_explain":
            replies = h_box["h"].explain_replies
            return {"content": json.dumps(replies.pop(0) if replies else EXPLAIN_A)}
        return {"content": "unexpected request"}

    inf.queue = ModelRouter(inf, route)

    key = tmp_path / "ssh-key"
    key.write_text("placeholder")
    settings = Settings(data_dir=tmp_path / "data", presets_dir=REPO / "presets", snapshot_id=SNAPSHOT,
                        vpc_id=VPC, prod_instance_id=prod_id, ssh_key_file=str(key), poll_s=0,
                        ready_timeout_s=30, missing=[])
    vultr = Vultr(api_key=FAKE_KEY, base_url=vf.url, sleep=lambda s: None, timing=lambda line: None)
    client = InferenceClient(api_key=FAKE_KEY, base_url=inf.url, sleep=lambda s: None)
    signer = Signer(Ed25519PrivateKey.generate())
    orch = Orchestrator(
        settings, vultr=vultr,
        ssh_factory=lambda: SSH(key_file=str(key), jump=None, runner=fleet, state_dir=str(tmp_path / "ssh")),
        planner=Planner(client), safety=SafetyFilter(client), signer=signer, inference=client)
    h = Harness(orch, vf, inf, fleet, prod_id, signer, settings)
    h_box["h"] = h
    yield h
    vf.stop()
    inf.stop()
