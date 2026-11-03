# Rehearsal Twin

Run a risky script on a disposable twin of your server first. See every side effect. Approve the exact ledger. Only then touch production.

Built for the Vultr: Agent Rush hackathon, Challenge 1 "Blast Radius Zero" (November 3–8, 2026).

## What it does

1. An agent gets a goal (or a script) and a declared scope: the paths, tables and hosts it may touch.
2. Rehearsal Twin snapshots the production server and creates a twin from that snapshot through the Vultr API. The twin lives in a private VPC, has no public IP and holds no keys.
3. The script runs on the twin under tracers: file changes, database rows and SQL, outbound network calls (recorded, never delivered), exit code, resource limits.
4. The result is a side-effect ledger. Scope is checked by code, line by line. The agent explains the ledger and proposes a safer variant, which is rehearsed again on a fresh twin.
5. A human approves the ledger by its hash. A narrow executor applies the script to production with the same tracers and compares predicted against actual.
6. The twin is deleted. A signed receipt is stored in Vultr Object Storage.

## Status

Work in progress. Built from scratch during the hackathon window. This README grows with the code: evidence table, architecture, how to run, and platform findings.

## License

MIT, see [LICENSE](LICENSE).
