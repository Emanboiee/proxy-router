# Mac dashboard performance audit — 2026-10-13

Five sequential read-only samples on the current Mac/router, using Python CLI
subprocesses; timings include interpreter startup. These are local samples,
not cross-platform guarantees or end-to-end webview measurements.

| Command | Median | Range |
| --- | ---: | ---: |
| status --json --fast | 299 ms | 268–353 ms |
| dashboard state | 144 ms | 122–623 ms |
| network-preset show | 178 ms | 165–207 ms |

## Findings and changes

- Unchanged background markup preserves page DOM, scroll, disclosures, and
  focused controls. Existing regression tests verify this behavior.
- Five-second UI ticks could overlap slow reads and invalidate earlier results.
  Polls now run one at a time; explicit user actions still proceed immediately.
- Hidden webviews skip UI polling. The Rust tray/status poller and Wi-Fi observer
  continue independently, so automatic switching does not depend on visibility.
- Native refreshes no longer request static preview-status fixture IPC.
- Config discovery runs every 15 seconds and reads inventory/network sequentially.
  This bounds routine process count but may delay freshness during slow commands.
- Backend fast status avoids elevation/launchd probes. Cached status serves UI
  polls; network checks are coalesced and paced by NetworkRefresh.
- Rust controller commands are synchronous and some spawn Python. A future
  blocking-worker migration should measure UI responsiveness under timeout first.
- Wi-Fi identity observation starts a controller every 10 seconds even when the
  identity is unchanged. Do not suppress heartbeats without checking observation
  expiry and network-transition semantics.

## Verification

Production TypeScript/Vite build passed. 32 control/import/network tests passed;
an additional delayed-read regression passed and verifies that a 12-second read
does not overlap later ticks or request fixture status. Earlier native acceptance
verified real configuration and profile inventory. New polling changes have not
yet been installed or timed in the native webview. Physical Wi-Fi transitions,
WARP restart, Windows performance, and 24-hour reliability remain unverified.

## Reproducible action-cache benchmark — 2026-10-21

Start a separate development server after `npm ci` and `npx playwright install chromium`:

```sh
npm run dev -- --port 24327 --strictPort
# In another terminal, from dashboard/:
node scripts/benchmark-refresh.mjs http://127.0.0.1:24327
```

The script installs the existing desktop bridge mock before loading the page.
It compares the cache change against the same page with only the previous
`force: !options?.poll` expression restored. A forced status read costs 110ms
by injection; other controller calls are immediate. Twelve alternating
Connect/Disconnect actions are timed until both the heading and rail settle;
DOM clicks exclude Playwright's actionability wait. The script rejects an
unmatched baseline rewrite or unexpected forced-read counts.

One Chromium run on the PR branch measured median 215.8ms before / 13.5ms after,
maximum 256.3ms / 28.7ms, and 13 / 0 forced reads including startup. These small,
sequential samples demonstrate removal of duplicate bridge work under controlled
delay. They are not native/production latency, a confidence interval, or a
guarantee for another machine. No native RAM reduction is established.
