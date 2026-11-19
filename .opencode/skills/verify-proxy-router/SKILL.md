---
name: verify-proxy-router
description: Prove a running proxy-router instance is healthy in one command and rebuild that instance from a fresh clone. Use when connectivity, the tray, egress, or a proxy-router service looks wrong, or after repointing services.
---

# Verify proxy-router

Surface: a deployed local service stack (HTTP/SOCKS proxy on `127.0.0.1:2080`,
`router.py` CLI) plus an optional macOS menu-bar dashboard. One instance owns
the port and the tray; do not run a second side by side.

## Doctor

Run this first whenever anything looks off:

```bash
./.opencode/skills/verify-proxy-router/verify.sh
```

The script is read-only and exits 0 only when every applicable check passes. It
checks the listener, a real fetch through the proxy, config parsing, egress
health, the configured fallback chain, and on macOS the dashboard env and
launchd paths. Evidence is written to a timestamped dir under
`.verify-evidence/` (override with `PROXY_ROUTER_EVIDENCE`).

Settings, all optional:

| Variable | Default | Purpose |
|---|---|---|
| `PROXY_ROUTER_ROOT` | repo root | install dir to inspect |
| `PROXY_ROUTER_PYTHON` | `python3` | interpreter for `router.py` |
| `PROXY_ROUTER_PORT` | `2080` | proxy listener port |
| `PROXY_ROUTER_FETCH_URL` | Cloudflare trace | URL for the live fetch |
| `PROXY_ROUTER_EXPECT_PROVIDERS` | `cloudflare,proton` | providers that should be healthy |
| `PROXY_ROUTER_EXPECT_FALLBACK` | `cloudflare:proton` | configured fallback to assert; empty disables |
| `PROXY_ROUTER_SKIP_MACOS` | `0` | set `1` to skip launchd/tray checks |

## Drive

- Health gate: `verify.sh` — require 0 failures (skips are informational).
- Detailed egress: `python3 router.py egress check --json`.
- Failover state: `python3 router.py failover <provider> status --json`.
- Provider validity: `python3 router.py providers check --json`.
- WARP (if used): `warp-cli status` and WarpProxy mode on the SOCKS port.

## Evidence

The helper writes `results.txt`, `listener.txt`, `fetch-body.txt`, `status.json`,
`egress.txt`, `fallback.json`, and process/env captures into the run dir. A
health claim requires a real HTTP 200 fetch and egress health, not just a
listening port. Capture the command, output, and exit code for anything you run
manually. Never claim health from a process list alone.

## Rebuild from a fresh clone

The full ordered procedure, including which files are gitignored and how to
restore them, is in [RUNBOOK.md](RUNBOOK.md). Read it before any repair.

## Cleanup

`verify.sh` creates no processes and never tears down the stack. It reads only.
Keep evidence runs; remove old ones only when asked. Never kill by process name.

## Feature map

[`features/README.md`](features/README.md) indexes the user-facing behaviors
and their recipes.

## Maintenance

`/maintain-verification-skill` keeps the feature map honest as the app changes.
