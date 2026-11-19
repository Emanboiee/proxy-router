# Stack health

The user browses through the local proxy and expects a working connection: the
port listens, real traffic returns, and egress is healthy.

## Sub-features

- `health-listener` — the proxy port has a LISTEN socket.
- `health-fetch` — a real fetch through the proxy returns HTTP 200.
- `health-config` — `router.py status --json` parses.
- `health-egress` — expected providers are alive, none dead.

## How to get to it (user POV)

- Load a page in a browser configured for the system proxy.
- Run `verify.sh` in a terminal.
- Run `python3 router.py status` and `python3 router.py egress check`.

## Driving it with verify.sh

Preconditions:

- Stack is up; `verify.sh` is executable.

- **Full check.** Run `verify.sh`. Expect zero failures and a fresh evidence dir.
- **Listener.** Read `listener.txt`: a listener row on the configured port.
- **Live fetch.** Read `fetch-body.txt` and `results.txt`: HTTP 200 and a real body.
- **Egress.** Read `egress.txt`: expected providers alive, no `dead` lanes.
- **Config.** Read `status.json`: valid JSON with a state field.

## Gotchas

- A listening port alone is not health; the upstream SOCKS relay can be down.
- An upstream app can report Connected while its relay briefly refuses connects.
- A copied `state/` dir can hold stale tracebacks; live checks are the proof.
- Run `verify.sh` before claiming any feature verified.
