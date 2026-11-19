# Failover

When a primary provider dies, routed domains should keep working through its
configured fallback. The chain lives in `router.json`; the runtime marker
records when failover is active.

## Sub-features

- `fallback-configured` — the primary declares its fallback target.
- `fallback-activate` — `failover <primary> on --to <target>` writes the marker.
- `fallback-traffic` — routed domains still return 200 while failed over.
- `fallback-clear` — `failover <primary> off` restores the primary.

## How to get to it (user POV)

- A routed site loads while the primary is degraded.
- `router.py status` shows the primary as fallback (target).
- `python3 router.py failover <primary> status --json` reports active fallback.

## Driving it with the CLI

Preconditions:

- Baseline `verify.sh` passes.
- A reversible way to degrade the primary exists, with a restore step.
- A trap or manual step restores the primary and clears the marker on exit.

- **Read chain.** Run `python3 router.py failover <primary> status --json`.
  Expect the target in `configured` and `active: null`.
- **Degrade primary.** Use the provider's own control and confirm status changed.
- **Activate.** Run `python3 router.py failover <primary> on --to <target> --reason test`.
  Expect rc 0 and `active: <target>`.
- **Prove traffic.** Fetch a primary-routed domain through the proxy. Expect 200
  and egress showing `primary: fallback (target)`.
- **Restore.** Re-enable the primary, run `failover <primary> off`, re-run
  `verify.sh`. Expect zero failures and no active marker.

## Gotchas

- A soft WARP disconnect leaves its SOCKS port up: proves manual failover only.
- Automatic failover needs several dead strikes and a truly dead relay.
- A parked fallback is sticky; always clear it after the primary recovers.
- Never force a failure that strands the operator's own traffic.
