# Official WARP Proxy Mode — SOCKS5 Integration Contract

> How proxy-router consumes the official Cloudflare WARP client's SOCKS5
> endpoint. **Documentation only** — this changes no production behavior, no
> ports, no TUN, no system proxy. All examples use **non-production test
> ports** (`2180` router-test listener, `2181` mock/upstream) and never touch
> the live `127.0.0.1:2080` listener.

Verified against `warp-cli 2026.4.1390.0` (`/usr/local/bin/warp-cli`) and
`sing-box 1.13.16`. Verified commands (all read-only, none alter connection
state):

```sh
warp-cli --help
warp-cli mode --help
warp-cli proxy help
```

## The contract (two independent knobs)

WARP proxy mode is configured with **two separate subcommands** — tunnel
behavior and listener port are independent:

- `warp-cli mode proxy` — *"Establish a tunnel for use in a SOCKS5 proxy"*
  (exact `mode --help` text). This decides *what the tunnel is for*.
- `warp-cli proxy port <PORT>` — *"Override the listening port for proxy
  mode (`127.0.0.1:{port}`)"* (exact `proxy help` text). This decides *where
  the local SOCKS5 listener binds*. Loopback-only by design.

Setting the mode does **not** pick the port; setting the port does **not**
pick the mode. An operator must configure both, then `connect` out of band
(not covered here — this lane never changes connection state).

> **Terminology trap:** proxy-router's own *"proxy mode"* (local mixed
> HTTP/SOCKS listener, no TUN) is unrelated to WARP's *"proxy"* connection
> mode. When both appear together, say which one you mean.

## How proxy-router should consume it

Treat the WARP listener as one **upstream SOCKS5 endpoint** for selected
routes — alongside, not instead of, the WireGuard providers proxy-router
already manages. The engine accepts a SOCKS outbound pointing at loopback
(schema verified with `sing-box check`, exit 0):

```json
{
  "type": "socks",
  "tag": "warp-official",
  "server": "127.0.0.1",
  "server_port": 2181,
  "version": "5"
}
```

(Illustrative sketch — `2181` is the mock port used below, not a live value.)

Consumption rules:

1. **Pin by route, not by default.** Only explicitly listed domains egress
   via `warp-official`; everything else keeps its current provider or
   `direct`. No fail-open onto it, no global default through it.
2. **The official client owns the tunnel.** proxy-router must not rotate,
   re-key, reconnect, or otherwise manage it — no `.conf`, no key handling,
   no cooldown bookkeeping. If the listener is down, the route is `dead`
   like any other failed egress.
3. **Keep it loopback-only.** Both ends stay on `127.0.0.1`. Never expose
   the WARP listener or the router listener on LAN interfaces.

## Isolation

- **Separate ports, always.** Live router listener is `127.0.0.1:2080`
  (`README.md`); tests and mocks use `2180`/`2181` (the CI contract forbids
  `2080` in loopback harnesses). Never point a test at `2080`, never set a
  system-wide HTTP/HTTPS proxy, never touch TUN.
- **Loopback stays direct.** `router.py` already pins `localhost` and
  `127.0.0.0/8`/`::1/128` to `direct` — health checks against `127.0.0.1`
  must resolve through that pin, never through an upstream.
- **One direction.** Traffic flows app → router listener → WARP listener →
  Cloudflare. The WARP listener must never forward back into the router.

## Health-check

Probe *through* the endpoint with remote DNS (`socks5h`, so names resolve
at the far end) against the same trace URL the egress prober uses:

```sh
# NON-PRODUCTION example — 2181 is the mock/upstream port, not live state
curl --max-time 10 -x socks5h://127.0.0.1:2181 \
  https://www.cloudflare.com/cdn-cgi/trace
```

Healthy = HTTP 200 with `warp=on` in the body. Connection-refused on
`127.0.0.1:<port>` means the listener isn't up (mode not `proxy`, port
mismatch, or client disconnected) — check the two knobs independently
before assuming the tunnel is down.

## Avoiding proxy loops

A loop looks like: requests hang, latency climbs, logs show the router's
own listener as both inbound and upstream. Prevent it by construction:

- The `socks` outbound's `server_port` must **never** equal the router's
  own listener port (`2080` live; `2180` in tests).
- Keep the loopback→`direct` pin; do not add routes covering `127.0.0.0/8`.
- When testing, run exactly one mock on `2181` and one router-test
  listener on `2180` — if either port is already bound, stop and inspect
  (`lsof -i :2180 -i :2181`) instead of picking a third port.

## What it cannot handle

- **UDP, including Discord voice.** SOCKS5 `CONNECT` carries TCP; UDP
  needs `UDP ASSOCIATE`, which this path does not provide. Expect voice,
  game traffic, and QUIC-over-UDP to fail or fall back — keep them on
  WireGuard/TUN routes, never on the WARP SOCKS endpoint.
- **Applications that ignore proxies.** Anything that doesn't honor
  `*_proxy` env or explicit proxy settings bypasses this entirely (there
  is no TUN capture in this design). Each app must be pointed at the
  router listener individually.
- **DNS unless resolved remotely.** Bare `socks5://` leaks local DNS;
  always use `socks5h://` (or equivalent remote-resolve option) so names
  resolve through the tunnel.
- **Rotation/failover inside WARP.** One listener, one exit, no profile
  pool. Treat it as a single non-rotating egress with standard
  dead/alive probing.

## Safe end-to-end sketch (non-production)

```sh
# 1. Confirm the contract on the installed client (read-only, no state change)
warp-cli mode --help      # look for: proxy: Establish a tunnel for use in a SOCKS5 proxy
warp-cli proxy help       # look for: port — Override the listening port (127.0.0.1:{port})

# 2. NON-PRODUCTION: router-test listener on 2180, mock upstream on 2181.
#    Never 2080. Never set a system proxy. Never enable TUN for this test.
curl --max-time 10 -x socks5h://127.0.0.1:2181 \
  https://www.cloudflare.com/cdn-cgi/trace
# Expect: HTTP 200 once a mock occupies 2181; connection-refused otherwise.
```

## Security notes

- Proxy mode involves **no keys, accounts, or `.conf` files** — there is
  nothing to paste, commit, or chmod. If a step asks for a private key or
  license string, it is not this integration.
- Generated `sing-box.json` may inline secrets for WireGuard providers;
  it stays mode `0600` and uncommitted, as with existing providers.
- This document contains no credentials by construction; keep it that way.

## Troubleshooting

- **`mode` set but nothing listens:** the port knob is separate — confirm
  which port the listener should be on and that the client is connected.
  `mode --help` and `proxy help` describe different things; both must agree
  with the operator's intent.
- **Connection-refused on the expected port:** wrong port (stale override),
  client disconnected, or MDM policy blocking mode switch
  (`settings mode-switch-allowed`). None of these are proxy-router bugs.
- **Voice/UDP app broken after moving to this route:** expected (see
  above) — move UDP-dependent apps back to a WireGuard/TUN route.
- **Suspected loop:** verify the outbound port ≠ the router listener port
  and that no route covers `127.0.0.0/8`.
