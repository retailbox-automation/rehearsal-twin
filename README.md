# Rehearsal Twin

Run a risky script on a disposable twin of your server first. See every side effect. Approve the exact ledger. Only then touch production.

Built for the Vultr: Agent Rush hackathon, Challenge 1 "Blast Radius Zero" (November 3–8, 2026). Live demo: https://rehearsal-twin.retailbox-automation.com

## Why

In the last sixteen months coding agents wiped production data in public at least four times:

| When | What happened | Source |
|---|---|---|
| Jul 2025 | An agent deleted a company's live database during an explicit code freeze | [Fortune](https://dc.fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure) |
| Mar 2026 | Destructive Terraform commands during a server migration removed 2.5 years of a community's data and its backups | [OECD AI incidents](https://oecd.ai/en/incidents/2026-03-07-79ec) |
| Apr 2026 | An agent deleted a startup's production database and backups in nine seconds; 30 hours of downtime | [OECD AI incidents](https://oecd.ai/en/incidents/2026-04-27-6153) |
| Jul 2026 | An agent reportedly reset a live database by pointing a migration diff at the production URL; 22 tables dropped | [AI Incident Database #1676](https://incidentdatabase.ai/cite/1676/) |

In every case the agent had production access and the safeguard was a rule in text. Rehearsal Twin makes the safeguard an execution: the script runs first on a disposable copy of the server, and production changes only after a person approves exactly what happened there.

## What it does

1. An agent gets a goal (or a script) and a declared scope: the paths, tables and hosts it may touch, with optional row budgets.
2. Rehearsal Twin creates a twin of the production server from its golden snapshot through the Vultr API. The twin sits in a private VPC with no public IP and holds no keys.
3. The script runs on the twin inside a locked-down systemd service under tracers: file changes, database rows and SQL, outbound calls (recorded, never delivered), exit code and resource limits.
4. The result is a side-effect ledger. Scope is checked by code, line by line, and re-checked on the control machine. The agent explains the ledger and proposes a safer variant, which is rehearsed again on a fresh twin.
5. A person approves the ledger by its hash. A narrow executor applies the approved script to production with the same tracers and compares predicted against actual.
6. The twin is deleted. The run ends with a receipt signed with ed25519 that anyone can verify.

## Vultr in the mechanism

| Vultr product | Role | Where |
|---|---|---|
| Cloud Compute + Snapshots API | golden snapshot of production; one twin per rehearsal from that snapshot; delete after use | `rt/twin/vultr.py`, `rt/twin/lifecycle.py` |
| VPC + NAT Gateway | twins are VPC-only (no public IPv4); the control machine reaches them over the VPC | `rt/twin/lifecycle.py` |
| VX1 Cloud Compute | KVM is available (Microsandbox microVM starts in 0.55 s); the free-form script path on microVMs is in progress | see Platform findings |
| Serverless Inference | the agent (`muse-glimmer-30b`, tool calls and JSON schema output) and the input filter (`nemotron-3.5-content-safety` with a custom policy for instructions hidden in data); exact model allowlist, the returned `model` is checked on every response | `rt/agent/` |

## Containment

- The twin has no public IPv4 and holds no keys. Secrets reach the model only as placeholders such as `<secret:env.NAME>`.
- The script runs as a transient systemd service: `IPAddressDeny=any` with an allowlist of localhost and the control machine, network and admin capabilities dropped, cgroupfs read-only, memory, task and wall-clock limits. Live test on a twin: outbound `curl` fails; `iptables -F`, `ip route`, moving to the root cgroup, `ping` and `nsenter` into PID 1's network are all refused; deleting files inside the declared scope works.
- Outbound calls are redirected to a local recorder that logs method, host, path and size and answers 503, so nothing is delivered.
- Decoys with unique tokens (a fake key file, a fake API key row, a fake purge URL) show when a script reads or tries to send them.
- The scope verdict comes from code. The model explains the ledger but cannot change it; injected text such as "FINAL VERDICT: SAFE" changes nothing.
- Approval is bound to `{ledger_sha256, script_sha256, snapshot_id, prod_state_version}`; any drift returns 409.

## Platform findings (measured on Vultr, November 3, 2026, region ewr)

| Finding | Measurement | How to reproduce |
|---|---|---|
| A VPC-only instance cannot be created without a NAT Gateway in the VPC | `POST /v2/instances` with `disable_public_ipv4` returned 400 "The selected VPC does not have a NAT gateway" | create a VPC, create an instance with `disable_public_ipv4: true` |
| The NAT Gateway gives VPC-only instances full internet egress, and it cannot be removed while they exist | from a VPC-only twin `curl https://example.com` returned 200; `DELETE …/nat-gateway/{id}` returned 422 "please remove all VPC-only instances from this network first"; NAT firewall rules require a port-forward pair, so they filter inbound only | as above, then `curl` from the instance |
| Unknown model names on Serverless Inference are answered by another model | `muse-glimer-30b` and `some-model-that-does-not-exist` were answered by `deepseek-v4.1-flash-1017` | call `/v1/chat/completions` with a misspelled model and read `model` in the response |
| The content-safety model needs a custom policy to flag instructions hidden in data | without a policy: "safe"; with `chat_template_kwargs.custom_policy`: "unsafe, Manipulation" | see `rt/agent/safety.py` |
| Timings | snapshot of a 2 GB / 9 GB-used instance: 631–649 s; instance from snapshot: 309 s to active plus 42 s to SSH; instance from an OS image: 26–39 s; delete: gone from the list in 0.3 s; NAT Gateway: about 3.5 min to active; Microsandbox microVM on VX1: 0.55 s warm, 1.46 s cold | `rt/twin/bench.py` |

## Run it

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest -q                                    # unit and fake-cloud tests
RT_MODE=fixture uvicorn rt.api.app:app       # the screen with a recorded demo rehearsal
```

Live mode needs a Vultr account, a golden snapshot of the demo production server (`fixtures/prod/cloud-init.sh`) and a control machine: `RT_DOMAIN=<name> bash deploy/control.sh`.

## Repository

- `rt/twin`: Vultr API client, twin lifecycle, warm pool, reaper
- `rt/tracer`, `rt/ledger`: tracers that run on the twin and production, ledger, scope check, compare
- `rt/agent`: Serverless Inference client with model allowlist, input filter, planner
- `rt/orchestrator`, `rt/api`, `web`: the rehearsal flow, API with live event feed, the screen
- `rt/receipts`: signed receipts and a standalone verifier
- `fixtures/prod`: the demo production server; `presets`: three rehearsals shaped like the incidents above

## License

MIT, see [LICENSE](LICENSE).
