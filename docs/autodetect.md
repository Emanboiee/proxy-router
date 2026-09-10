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
        "extra_roots": ["cdn.prod.example-cdn.com"],
        "ttl_seconds": 1800
      }
    }
  }
}
```

`router.py autodetect <source>` fetches the seed through the local proxy, extracts
URLs under the trusted roots, and stores exact hosts in
`state/autodetect/<source>.json`. The keepalive agent refreshes every explicit
and generated source at the configured interval. The next reload adds only
non-expired learned hosts to the configured route. Learned hosts are keyed by
`route_id`, so they follow that route's active provider and any fallback or
rotation.

The roots are both an allowlist and the route suffixes used while the source is
configured. Use `extra_roots` for a cross-origin asset CDN that the application
owns or requires; those suffixes are learned and routed through the same
provider. Use the narrowest owned suffix possible: shared roots such as
`cloudfront.net` or `website-files.com` can serve unrelated tenants and would
route their traffic too. Set `auto_sources` to `false` to require explicit
sources, and use `router.py status --json` to inspect generated sources, roots,
and learned hosts.
