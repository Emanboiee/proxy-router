# Routed dependency autodetection

Proxy mode can learn exact dependency hostnames for every configured domain route
without decrypting TLS. With `autodetect.auto_sources` enabled (the default),
routes without an explicit source automatically use their first domain as the
seed and all configured route domains as trusted roots. Explicit entries under
`autodetect.sources` override the generated source when a site needs a custom
seed or additional owned asset roots.

```json
{
  "autodetect": {
    "enabled": true,
    "auto_sources": true,
    "interval_seconds": 300,
    "timeout_seconds": 12,
    "sources": {
      "twitch": {
        "seed": "https://www.twitch.tv/",
        "route_id": "school",
        "provider": "cloudflare",
        "roots": ["twitch.tv", "jtvnw.net", "ttvnw.net"],
        "ttl_seconds": 1800
      }
    }
  }
}
```

`router.py autodetect <source>` fetches the seed through the local proxy, extracts
URLs under the trusted roots, and stores exact hosts in
`state/autodetect/<source>.json`. The keepalive agent uses
`router.py autodetect --all --quiet` to refresh every explicit and generated
source under one controller lock. Individual scans save state without reloading;
after the batch, effective route/DNS rules are compared with the generated
engine configuration. Timestamp-only refreshes and already-covered hosts cause
no reload; changed effective routing causes at most one. `--no-reload` persists
state without applying it, and a later batch still detects unapplied changes.
Stopped, manually disconnected, TUN, and unknown-mode engines are not started
or reloaded by this background entry point. Failed sources retain their last
atomic state; successful sources can still be applied, with a failing exit code
for the partial refresh. A required reload can still interrupt established
connections; this batching does not make SIGHUP seamless or fix speculative
fallback restoration. Non-expired learned hosts are keyed by
`route_id`, so they follow that route's active provider and any fallback or
rotation.

The roots are both an allowlist and the route suffixes used while the source is
configured. Use `extra_roots` for a cross-origin asset CDN that the application
owns or requires; those suffixes are learned and added to the same route. Shared
roots such as `cloudfront.net` are not added automatically because they can serve
unrelated sites. Set `auto_sources` to `false` to require explicit sources, and
use `router.py status --json` to inspect generated sources, roots, and learned
hosts.
