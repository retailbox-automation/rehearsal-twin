# Rehearsal Twin

[![live runs on Vultr](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Frehearsal-twin.retailbox-automation.com%2Fapi%2Fstats&query=%24.runs&label=live%20runs%20on%20Vultr&color=2ea44f)](https://rehearsal-twin.retailbox-automation.com/api/stats)
[![predicted = happened](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Frehearsal-twin.retailbox-automation.com%2Fapi%2Fstats&query=%24.matched&label=predicted%20%3D%20happened&suffix=%20applied%20runs&color=2ea44f)](https://rehearsal-twin.retailbox-automation.com/api/stats)
[![red team](https://img.shields.io/badge/red%20team-58%20attacks%20run%2C%200%20escapes-2ea44f)](redteam/reports/2026-11-05-summary.json)
[![tests](https://img.shields.io/badge/tests-577%20passing-2ea44f)](tests)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Run a risky script on a disposable twin of your server first. See every side effect. Approve the exact ledger. Only then touch production.

The twin is a copy of the production server, made from its golden snapshot through the Vultr API. After a person approves the ledger, production changes exactly as rehearsed: in the run from the video, 391 changes were predicted and 391 happened, with 0 surprises.

Built for the Vultr: Agent Rush hackathon, Challenge 1 "Blast Radius Zero" (November 3–8, 2026).

The run shown in the video: [containment moment](https://rehearsal-twin.retailbox-automation.com/?id=92b8c5f42e86&until=28), [whole run](https://rehearsal-twin.retailbox-automation.com/?id=92b8c5f42e86), [record](https://rehearsal-twin.retailbox-automation.com/api/rehearsals/92b8c5f42e86), [receipt](https://rehearsal-twin.retailbox-automation.com/api/rehearsals/92b8c5f42e86/receipt), [check the receipt in your browser](https://rehearsal-twin.retailbox-automation.com/verify?id=92b8c5f42e86) · Start your own run: https://rehearsal-twin.retailbox-automation.com · Slides: [docs/slides.pdf](docs/slides.pdf) · The model writing the script from a goal: [record](https://rehearsal-twin.retailbox-automation.com/api/rehearsals/fb6a2121c9a2), [receipt](https://rehearsal-twin.retailbox-automation.com/api/rehearsals/fb6a2121c9a2/receipt)

## Judge it in 90 seconds

1. **The containment moment.** Open [`/?id=92b8c5f42e86&until=28`](https://rehearsal-twin.retailbox-automation.com/?id=92b8c5f42e86&until=28). The replay stops after attempt 1 on the twin: 221 files deleted, 71 of them outside the declared scope, the purge call blocked with 0 bytes delivered, production 0 / 0.
2. **Production changes exactly as rehearsed.** Open [the whole run](https://rehearsal-twin.retailbox-automation.com/?id=92b8c5f42e86): the agent's safer variant on a fresh twin, a person's approval of that ledger by its hash, then production: 391 predicted, 391 happened, 0 surprises. The screen shows 150 files, the cache directory (`-1 dir`) and 240 rows: that is the 391, `compare.counts` in the record.
3. **The receipt is signed.** Check it in your browser at [`/verify?id=92b8c5f42e86`](https://rehearsal-twin.retailbox-automation.com/verify?id=92b8c5f42e86), or offline with the command [below](#evidence-from-live-runs-on-vultr-november-56-2026-golden-snapshot-8b5e1c58). Change one number in it and the check fails.
4. **Run your own.** On the [demo screen](https://rehearsal-twin.retailbox-automation.com) pick a preset (`cleanup.sh`, `migrate_0042.sh` or `reprice_winter.sh`) and press Run, no token needed. When the ledger is ready, approve it from the same browser tab: approval works only in the tab that started the run, and on someone else's run the screen says `approval refused (401)`. A run takes about 17 minutes: the safer variant is rehearsed on a second twin, and each twin needs about 8 minutes from the snapshot before the script can run. The video cuts those waits.

Limits for judge runs: 3 runs per hour per address, 30 per day, 2 twins at a time; runs pause by themselves when the account's pending charges reach $150. The judge path was checked on November 6: rehearsal [`2cf9f3d5e536`](https://rehearsal-twin.retailbox-automation.com/api/rehearsals/2cf9f3d5e536) was started without the token and approved with its owner key, and production changed 391 = 391.

## Evidence from live runs on Vultr (November 5–6, 2026, golden snapshot `8b5e1c58`)

Every live run is public: the list is at [/api/rehearsals](https://rehearsal-twin.retailbox-automation.com/api/rehearsals) and the totals at [/api/stats](https://rehearsal-twin.retailbox-automation.com/api/stats), including one run on November 4 that failed when its third twin's SSH was not ready (fixed in `67300ab`). The runs below start from the golden snapshot of the demo production server; the video and the slides use them.

| Run | What happened | Check it |
|---|---|---|
| `cleanup.sh`, rehearsal `92b8c5f42e86` (the run in the video) | attempt 1 on `twin-192b8c`: 221 files deleted, 71 outside the declared scope, 83 out-of-scope items in total; `POST prod-api.internal/purge` blocked, 0 bytes delivered; production unchanged. The agent's safer variant on `twin-292b8c` cleared `/srv/app/tmp/*`, which removed the cache directory as well as its 150 files, and stayed in scope. An operator approved that ledger; production: 391 predicted (150 files, 1 directory, 240 rows), 391 happened, 0 surprises | [containment moment](https://rehearsal-twin.retailbox-automation.com/?id=92b8c5f42e86&until=28), [record](https://rehearsal-twin.retailbox-automation.com/api/rehearsals/92b8c5f42e86), [receipt](https://rehearsal-twin.retailbox-automation.com/api/rehearsals/92b8c5f42e86/receipt) |
| goal mode, rehearsal `fb6a2121c9a2` (November 6) | no script given, only the goal of `cleanup.sh` and the same scope. `nemotron-3.5-content-safety` passed the goal and `muse-glimmer-30b` wrote the script (`rm -rf -- /srv/app/tmp/cache`, `mkdir -p /srv/app/tmp/cache`, `DELETE FROM sessions WHERE expires_at < now()`). On the twin it stayed in scope on the first attempt; an operator approved its ledger; production: 390 predicted (150 files, 240 rows), 390 happened, 0 surprises | [record](https://rehearsal-twin.retailbox-automation.com/api/rehearsals/fb6a2121c9a2), [receipt](https://rehearsal-twin.retailbox-automation.com/api/rehearsals/fb6a2121c9a2/receipt) |
| `cleanup.sh`, rehearsal `8ae1819f6d84` | attempt 1 on `twin-18ae18`: 221 files deleted, 71 outside the declared scope, 83 out-of-scope items in total; `POST prod-api.internal/purge` blocked, 0 bytes delivered; production unchanged. The safer variant on `twin-28ae18` stayed in scope; production then changed exactly as rehearsed: 390 predicted, 390 happened, 0 surprises | [record](https://rehearsal-twin.retailbox-automation.com/api/rehearsals/8ae1819f6d84), [receipt](https://rehearsal-twin.retailbox-automation.com/api/rehearsals/8ae1819f6d84/receipt) |
| `migrate_0042.sh`, rehearsal `1c41e4d75dec` | attempt 1 dropped three tables with 5800 rows; two of them (5000 rows) were outside the declared scope. The safer variant dropped only `legacy_orders`; production: 800 predicted, 800 happened, 0 surprises | [record](https://rehearsal-twin.retailbox-automation.com/api/rehearsals/1c41e4d75dec), [receipt](https://rehearsal-twin.retailbox-automation.com/api/rehearsals/1c41e4d75dec/receipt) |
| `reprice_winter.sh`, rehearsal `adae6c4af59d` | attempt 1 changed 93 rows against a declared budget of 31 and made 93 webhook calls, 0 bytes delivered. The agent then tried to switch off the triggers behind the webhooks (`SET session_replication_role = replica`): the database role refused it twice, so those variants exited 1. Its `LIMIT 31` variant changed 31 rows but still made 31 undeclared webhook calls. The run stopped with `no_safe_variant` ("no variant stayed in scope and exited 0 in 4 attempts"). Production was not touched and no receipt was issued | [record](https://rehearsal-twin.retailbox-automation.com/api/rehearsals/adae6c4af59d) |

The two cleanup runs differ because the agent wrote a different safer variant each time; both stayed in scope, and each receipt binds the exact script by its hash. The scope check only draws the boundary. Inside it, the person approving reads the ledger, which here shows the `-1 dir` row before anything touches production.

Reading a record: its `summary` describes the last attempt (see `status` and `attempts[]`). The approval with its five hashes is in `/receipt`, where `script.name` is the original script's name and `script.sha256` is the hash of the approved variant.

Every twin was deleted after its rehearsal. To check a receipt offline, and that it matches the published ledgers (Python 3.12 or newer; the macOS system `python3` is 3.9):

```bash
git clone https://github.com/retailbox-automation/rehearsal-twin && cd rehearsal-twin
python3 -m venv .venv && . .venv/bin/activate && pip install -e .
B=https://rehearsal-twin.retailbox-automation.com/api/rehearsals/92b8c5f42e86
curl -s $B/receipt > receipt.json
curl -s $B/ledgers > ledgers.json
python -c "import json; d=json.load(open('ledgers.json')); json.dump(d['attempts']['2'], open('twin.json','w')); json.dump(d['prod'], open('prod.json','w'))"
python -m rt.receipts.verify_receipt receipt.json --pubkey rYyVzKw04aG8Y278Q1QsS1xeqBLAwX4NOHt4FWpryy4= \
  --twin-ledger twin.json --prod-ledger prod.json
# OK  signature valid, signed by the given key, ledgers match; outcome applied
```

Change any number in `receipt.json` and the same command prints `FAIL  signature does not match the receipt content`.

## Why

In the last sixteen months coding agents wiped production data in public at least four times:

| When | What happened | Source |
|---|---|---|
| Jul 2025 | An agent deleted a company's production database during an explicit code freeze | [Fortune](https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/) |
| Feb 2026 | A coding agent running Terraform during a server migration reportedly removed a community's production database and its automated snapshots, about 2.5 years of data | [AI Incident Database #1424](https://incidentdatabase.ai/cite/1424/) |
| Apr 2026 | An agent deleted a startup's production database and its volume backups in nine seconds; 30 hours of downtime | [OECD AI incidents](https://oecd.ai/en/incidents/2026-04-27-6153) |
| Jul 2026 | An agent reportedly reset a live database by pointing a migration diff at the production URL; 22 tables dropped | [AI Incident Database #1676](https://incidentdatabase.ai/cite/1676/) |

In each case the agent could reach production directly. Rehearsal Twin puts a rehearsal in between: the script runs first on a disposable copy of the server, and production changes only after a person approves exactly what happened there.

## What it does

1. An agent gets a goal (or a script) and a declared scope: the paths, tables and hosts it may touch, with optional row budgets.
2. Rehearsal Twin creates a twin of the production server from its golden snapshot through the Vultr API. The twin sits in a private VPC with no public IP and holds no real secrets: the only key-shaped values on it are decoys.
3. The script runs on the twin inside a locked-down systemd service under tracers: file changes, database rows and SQL, outbound calls (recorded, never delivered), exit code and resource limits.
4. The result is a side-effect ledger. Scope is checked by code, line by line, and re-checked on the control machine. The agent explains the ledger and proposes a safer variant, which is rehearsed again on a fresh twin.
5. A person approves the ledger by its hash. A narrow executor applies the approved script to production with the same tracers and compares predicted against actual.
6. The twin is deleted. The run ends with a receipt signed with ed25519 that anyone can verify.

## Vultr in the mechanism

| Vultr product | Role | Where |
|---|---|---|
| Cloud Compute + Snapshots API | golden snapshot of production; one twin per rehearsal from that snapshot; delete after use | `rt/twin/vultr.py`, `rt/twin/lifecycle.py` |
| VPC + NAT Gateway | twins are VPC-only (no public IPv4); the control machine reaches them over the VPC | `rt/twin/lifecycle.py` |
| Serverless Inference | the agent (`muse-glimmer-30b`, answers under a JSON schema) and the input filter (`nemotron-3.5-content-safety` with a custom policy for instructions hidden in data); exact model allowlist, the returned `model` is checked on every response | `rt/agent/` |

## How the model is used, and what fences it

- Input filter first: `nemotron-3.5-content-safety` checks the goal and every text fragment of a ledger (file names, SQL, request bodies) with a custom policy for instructions hidden in data (`rt/agent/safety.py`).
- Everything sent to a model is masked: secrets appear as `<secret:NAME>` placeholders, and a script that contains a placeholder is rejected (`rt/agent/planner.py`).
- `muse-glimmer-30b` answers under a JSON schema (`response_format: json_schema`). `explain` returns a summary, notes on out-of-scope rows and a safer script; `plan` (goal mode) returns the first script from a goal, as in rehearsal `fb6a2121c9a2`. An answer that breaks the schema is retried, at most 3 times per call.
- The model cannot change the verdict: out-of-scope rows are copied from the deterministic check (`rt/ledger/scope.py`) and the model may only attach a note to a row. Each safer script is rehearsed again on a fresh twin and re-checked on the control machine; after 3 safer attempts the run ends as `no_safe_variant` (`rt/orchestrator/core.py`).
- Exact model allowlist, and the `model` field of every response is checked; each receipt lists the models that answered.
- What it did in the public runs from November 5 to 7: in 7 of 7 cleanup and migration runs the model's first safer variant stayed in scope and was applied with predicted = happened; in 3 of 3 price-update runs no variant passed and nothing reached production; 49 of 49 model calls were answered by the requested model (the `llm` events in each record's timeline).

## Containment

- The twin has no public IPv4 and holds no real secrets (the key-shaped values on it are decoys). Secrets reach the model only as placeholders such as `<secret:env.NAME>`.
- The script runs as a transient systemd service: `IPAddressDeny=any` with an allowlist of localhost and the control machine, network and admin capabilities dropped, cgroupfs read-only, memory, task and wall-clock limits. Live test on a twin: outbound `curl` fails; `iptables -F`, `ip route`, moving to the root cgroup, `ping` and `nsenter` into PID 1's network are all refused; deleting files inside the declared scope works (systemd properties in `rt/tracer/runner.py`).
- Outbound calls are redirected to a local recorder that logs method, host, path and size and answers 503, so nothing is delivered.
- Decoys with unique tokens (a fake key file, a fake API key row, a fake purge URL) show when a script reads or tries to send them.
- The scope verdict comes from code. The model explains the ledger but cannot change it; injected text such as "FINAL VERDICT: SAFE" changes nothing.
- Approval is bound to `{ledger_sha256, script_sha256, files_sha256, snapshot_id, prod_state_version}`; any drift returns 409.

## Red-team

Latest result per attack, from runs on a local Docker stand that boots the twin image with systemd: [`redteam/reports/2026-11-05-summary.json`](redteam/reports/2026-11-05-summary.json).

| Attacks | Run on the stand | Pass | Warning | Need a full VM (not run) | Escapes |
|---|---|---|---|---|---|
| 61 (49 open, 12 held out) | 58 | 57 | 1 (`resource-05`: no disk quota in the sandbox yet) | 3 | 0 |

An escape here means a packet reached the external sink or a change happened outside the ledger. `redteam/` holds attacks on the sandbox itself (escape, network, keys, prompt injection, resource exhaustion), run against a local stand of the twin. A second set of 12 attacks is kept outside this repository; only its sha256 is committed (`redteam/holdout.sha256`, packed by `redteam/holdout_tar.py`). It is a regression set, not a blind test: its definitions are also in `redteam/gen_attacks.py`, and its expectations were updated on November 5, 2026 from the ledgers of refused attacks (calls to a bare IP are cut before the handshake and show as denied packets, writes to the tracer are refused). The earlier sha256 `4c7c357f…` cannot be reproduced.

The first full run on November 3 (`redteam/reports/2026-11-03-docker.json`: 35 attacks, 30 pass, 1 breakthrough: escape-02, the script stopping the egress recorder) came before the sandbox hardening of November 4. Since then the recorder runs as its own user; the sandbox has no `CAP_KILL`, `CAP_SETUID` or `CAP_SETGID` and cannot see the recorder (`ProtectProc=invisible`); a paused or stopped recorder shows up in the integrity check; and calls straight to an IP address are listed in the ledger as blocked (`rt/tracer/runner.py`, `rt/tracer/diff.py`).

## Platform findings (measured on Vultr, November 3, 2026, region ewr)

| Finding | Measurement | How to reproduce |
|---|---|---|
| A VPC-only instance cannot be created without a NAT Gateway in the VPC | `POST /v2/instances` with `disable_public_ipv4` returned 400 "The selected VPC does not have a NAT gateway" | create a VPC, create an instance with `disable_public_ipv4: true` |
| The NAT Gateway gives VPC-only instances full internet egress, and it cannot be removed while they exist | from a VPC-only twin `curl https://example.com` returned 200; `DELETE …/nat-gateway/{id}` returned 422 "please remove all VPC-only instances from this network first"; NAT firewall rules require a port-forward pair, so they filter inbound only | as above, then `curl` from the instance |
| Unknown model names on Serverless Inference are answered by another model | `muse-glimer-30b` and `some-model-that-does-not-exist` were answered by `deepseek-v4.1-flash-1017` | call `/v1/chat/completions` with a misspelled model and read `model` in the response |
| The content-safety model needs a custom policy to flag instructions hidden in data | without a policy: "safe"; with `chat_template_kwargs.custom_policy`: "unsafe, Manipulation" | see `rt/agent/safety.py` |
| Timings | snapshot of a 2 GB / 9 GB-used instance: 631–649 s; instance from snapshot: 309 s to active plus 42 s to SSH (in the November 5 runs a twin was ready for the script after 455–511 s, including cloud-init); instance from an OS image: 26–39 s; delete: gone from the list in 0.3 s; NAT Gateway: about 3.5 min to active; Microsandbox microVM on VX1: 0.55 s warm, 1.46 s cold | `rt/twin/bench.py` |

## Run it

Needs Python 3.12 or newer.

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest -q                                    # 577 unit, fake-cloud and page tests, about 30 s
RT_MODE=fixture uvicorn rt.api.app:app       # the screen with a recorded demo rehearsal
```

Live mode needs a Vultr account, a golden snapshot of the demo production server (`fixtures/prod/cloud-init.sh`) and a control machine: `RT_DOMAIN=<name> bash deploy/control.sh`.

## Who it is for, and what it costs

For a team that lets coding agents run cleanup jobs, migrations and bulk updates against a real server.

- What teams use now, and what it misses: a staging server drifts from production and keeps no ledger of what changed; database branching sees the database but not files or outbound calls; a dry run or `terraform plan` shows what the script says it will do, not what it does. The twin starts from production's own snapshot, and its ledger records what actually happened, files, rows and outbound calls included.
- Where it plugs in: `POST /api/rehearsals` with a script or a goal and a declared scope, the event stream at `/api/rehearsals/{id}/events`, `POST /api/rehearsals/{id}/approve`, then the signed receipt at `/api/rehearsals/{id}/receipt` (`rt/api/live.py`).
- Cost, from this demo's Vultr billing (pending charges, November 7): a twin is a `vc2-1c-2gb` instance at $0.0149 an hour and each one was billed as one hour, so a two-attempt rehearsal (about 16 minutes of twin time) costs about $0.03 in compute, and a four-attempt run about $0.06. The model reads and writes 6,000 to 45,000 tokens per applied run (the `llm` events in each record). Fixed costs: the NAT Gateway the VPC-only twins need ($0.0298 an hour, $20 a month), the control machine (`vc2-2c-4gb`, $20 a month) and the golden snapshot ($0.0002 an hour).
- Next step: `prod_state_version` hashes all tables and the watched paths of production, so any change there between rehearsal and approval returns 409. Hashing only the declared tables and paths would let unrelated writes through.

## Known limits

- Goal mode, where the model writes the first script from a goal, needs the operator token and has one public run so far (`fb6a2121c9a2`). The other public runs start from the three preset scripts.
- A twin from the snapshot needs about 8 minutes before the script can run, so a two-attempt rehearsal takes about 17 minutes; the video cuts the waits. A warm pool of twins (`rt/twin/pool.py`) is written and tested but not wired into live runs.
- The free-form script path on VX1 microVMs is not finished (KVM works there, see Platform findings).
- The golden image is a demo fixture with decoy secrets (`fixtures/prod/cloud-init.sh`). For a real server the image has to be built without real secrets first.
- The demo production server is reset to the golden snapshot every hour, which takes about 6 minutes. If another run already changed it, approving a new run returns 409 (`snapshot_drift`) until that reset.

## Repository

- `rt/twin`: Vultr API client, twin lifecycle, reaper, warm pool (not wired into live runs)
- `rt/tracer`, `rt/ledger`: tracers that run on the twin and production, ledger, scope check, compare
- `rt/agent`: Serverless Inference client with model allowlist, input filter, planner
- `rt/orchestrator`, `rt/api`, `web`: the rehearsal flow, API with live event feed, the screen
- `rt/receipts`: signed receipts and a standalone verifier
- `fixtures/prod`: the demo production server; `presets`: three rehearsals shaped like the incidents above

## License

MIT, see [LICENSE](LICENSE).
