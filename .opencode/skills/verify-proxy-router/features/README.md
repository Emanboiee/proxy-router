# proxy-router verification map

Maintained source for verifying the user-facing behavior of a running
proxy-router instance. Read this index, then the matching feature file.

## Baseline preconditions

- One instance owns the proxy port and the menu-bar item; never double-drive.
- Run `verify.sh` and require zero failures before any feature run.
- The stack may carry real traffic. Repairs must be reversible and leave the
  working path intact.

## Driving conventions

- Treat commands as literal; keep quoted paths and flags unchanged.
- Capture command, output, and exit code for each step.
- Prefer `router.py` and launchd over killing processes by name.
- Mutation steps need a read-only second view confirming the result.

## Proof and skip reporting

- Health requires a real fetch returning 200 plus egress health, not a port.
- Failover requires the runtime marker changed AND traffic kept flowing.
- Record the feature id with every artifact.
- Report an unreachable path with the attempted command and unmet precondition.
- Never report a skip as a verified pass.

## Feature entry contract

Each feature file has an H1 and intro paragraph, then exactly four H2s in order:
`Sub-features`, `How to get to it (user POV)`, `Driving it with <harness>`,
`Gotchas`.

## Features

- [Stack health](stack-health.md) — listener, live fetch, egress, config.
- [Failover](failover.md) — fallback chain and traffic continuity.
- [Dashboard tray](dashboard-tray.md) — menu-bar connection state.
