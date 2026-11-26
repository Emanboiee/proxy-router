# One traffic port, model-only exit switching

The optional model selector sends explicit model domains through a sing-box
selector on the existing mixed proxy port. Model retries change that selector
through an authenticated loopback control API instead of reloading the shared
engine. Existing inbound connections keep their selected exit.

```json
{
  "vpn": {
    "model_selector": {
      "providers": ["proton", "proton2", "warp-proxy"],
      "domains": ["opencode.ai"],
      "control_port": 2084,
      "cooldown_seconds": 900
    }
  }
}
```

Use your configured provider names. At least two of those providers must already
be loaded in the generated engine configuration. The selector adds no WireGuard
tunnels: it does not preload profiles or establish additional account sessions.
It currently supports proxy mode only. An unavailable control API fails closed;
model recovery does not fall back to global rotation.

There is one traffic proxy listener (normally 2080) and a separate private control
listener (normally 2084). Stock sing-box requires the control API to change a
selector. OC2API and the model relay retain their existing API listeners.
The control credential is stored in `state/model-selector.secret` with mode 0600.

Enabling this requires one planned engine reload. Subsequent model selector
changes do not reload it. Ordinary router operations can still reload the engine.
Model failure cooldowns apply only to the model selector, not browsing provider
health. Switching happens among loaded providers, not every profile in their
pools. Cooldowns are in memory and reset when the relay restarts.

This isolates model exit changes from browsing; it does not guarantee upstream
availability, unlimited quota, or uninterrupted 24/7 service. sing-box documents
that internal connections can still be interrupted on selector changes, even
when established inbound connections are preserved.

Verification: `python3 test-results/model_selector_isolation.py` uses local fake
SOCKS exits and the installed sing-box, without touching production configuration.
It checks authenticated control, new exit selection, existing connection survival,
and an unchanged engine PID across 20 switches.
