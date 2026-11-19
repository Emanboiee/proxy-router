# Dashboard tray

The user reads connection state from the menu-bar item. It must reflect the real
stack, not a stale checkout.

## Sub-features

- `tray-connected` — the item shows connected when the proxy is up.
- `tray-root` — the dashboard reads the right root via `PROXY_ROUTER_ROOT`.
- `tray-no-errors` — the dashboard log stops emitting controller errors.

## How to get to it (user POV)

- Look at the menu-bar icon.
- Read the dashboard stderr log.

## Driving it with the CLI and shell

Preconditions:

- One dashboard instance owns the tray.

- **Check env.** Find the PID with `ps auxww | grep proxy-router-dashboard`.
  Run `ps -wwE -p <pid> | tr ' ' '\n' | grep PROXY_ROUTER_ROOT`. Expect the
  correct root.
- **Check what it sees.** Run `python3 router.py status --json --fast` from the
  correct root. Expect the proxy reported up.
- **Check errors.** Truncate the dashboard stderr log, wait one poll window, and
  read again. Expect no new controller-failed lines.
- **Fix stale instance.** If env is wrong or unset, quit the orphan with
  `osascript -e 'tell application "..." to quit'`, then bootout/bootstrap the
  dashboard plist so it inherits the env.

## Gotchas

- The app defaults to `~/proxy-router` when `PROXY_ROUTER_ROOT` is unset.
- A stale orphan predating the plist edit keeps the old env.
- The binary's built-in python default may be stale; set `PROXY_ROUTER_PYTHON`.
- A clean log over one poll window is stronger proof than a screenshot.
