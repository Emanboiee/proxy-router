# Routed dependency autodetection

Proxy mode can learn exact dependency hostnames for a routed web application
without decrypting TLS. Configure a source under `autodetect.sources`:

```json
{
  "autodetect": {
    "enabled": true,
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

`router.py autodetect twitch` fetches the seed through the local proxy, extracts
URLs under the trusted roots, and stores exact hosts in
`state/autodetect/twitch.json`. The next reload adds only non-expired learned
hosts to the configured route. Learned hosts are keyed by `route_id`, so they
follow that route's active provider and any fallback or rotation; the provider
in the source entry identifies the discovery policy and does not pin the
learned hosts to one egress. The keepalive agent refreshes the source at the
configured interval and reloads only when the routed hostname set changes.

The roots are an allowlist. Shared CDN roots such as `cloudfront.net` are not
learned automatically because they can serve unrelated sites. Use
`router.py status --json` to inspect learned hosts and their source route.
