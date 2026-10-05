# proxy-router improvement and implementation plan

Date: 6 September 2026. Scope: the working tree audited in [the accompanying report](../AUDIT_2026-09-06.md). This is an implementation-ready plan, not a claim that the changes have been made.

## Outcome and order

First make installation reproducible and runtime changes truthful. Next unify configuration and routing decisions. Then extract modules behind proven interfaces and add operational visibility. Avoid a simultaneous package reorganization, engine upgrade, and behavior change: failures would become difficult to attribute or roll back.

Recommended sequence for one experienced maintainer: roughly **25–40 engineering days**, with uncertainty concentrated in real TUN integration and native Windows support. These are planning estimates, not measured delivery commitments. A narrower macOS-only scope can reduce work, but must be reflected in the README and release matrix. Each PR below should be independently reviewable, with its own regression tests and a clear rollback path.

| PR | Work package | Findings | Effort | Dependencies |
|---|---|---|---|---|
| 01 | Reproducible test and audit baseline | F15 | 0.5–1 day | None |
| 02 | Repair Unix installation and state-root layout | F01 | 2–3 days | 01 |
| 03 | Make release validation execute actual artifacts | F02, F15 | 1–2 days | 02 |
| 04 | Make lifecycle outcomes and state commits truthful | F04, F10 | 3–5 days | 01 |
| 05 | Stop background TUN changes and fix disconnect errors | F07, F12, F13 | 2–3 days | 01; integrate 04 outcome type |
| 06 | Introduce canonical configuration transactions | F08, F11 | 3–4 days | 01, 04 |
| 07 | Compile one effective routing policy | F05, F06, F11 | 3–5 days | 06 |
| 08 | Bind probe security and budgets to actual transport | F09, F14 | 2–4 days | 01; integrate 07 policy |
| 09 | Unify worker lifecycle and observation | F07, F14 | 2–3 days | 04, 05, 06 |
| 10 | Deliver or explicitly narrow platform support | F03, F15 | 2–4 days | 02, 03, 06 |
| 11 | Extract tested services and shared UI contracts | F16 | 3–4 days | 04, 06, 07, 09 |
| 12 | Finish observability, performance budgets, runbooks | F13–F16 | 1–2 days | 08, 09, 11 |

The first useful milestone is PRs 01–05: an installable release with accurate state-change results and safer operator controls. Small urgent fixes such as adding the watcher operation-origin flag need not wait for the full configuration refactor.

## Invariants that every PR must preserve

1. A failed requested change is not success merely because the old service recovered.
2. Active profile, fallback, applied config generation, and health attribution refer to the same engine state.
3. Stop/manual-off intent prevents automatic resurrection or shared-TUN changes, including when the request waits for a lock.
4. Only an identified owned engine/worker is signaled. Ambiguous identity is an explicit error.
5. The root helper executes only root-owned pinned code/binaries using its exact system-interpreter policy. Unprivileged package refactoring never weakens that boundary.
6. Config writers preserve unrelated/concurrent changes or return an explicit conflict.
7. Routing policy, DNS policy, capture coverage, and observer inference agree—or the configuration is rejected as unsupported.
8. The default direct-fallback contract is explicit. A future strict policy must be separately specified and enforced, never implied by a UI label.
9. Tests use disposable roots and reviewed transports; no tests manage production tunnels, system proxies, login agents, or unrelated PIDs.
10. An installation/release gate tests the exact files being published and fails on missing evidence.

## PR 01 — Establish a repeatable baseline

**Implementation steps**

1. Record the baseline commit and existing worktree diff without stashing/reverting it. Separate intended application changes from personal backups and benchmark outputs through review, not automatic deletion.
2. Give repository test helpers an unambiguous import identity, for example a `tests/__init__.py` or a distinct support package; verify behavior when another installed package is named `tests`.
3. Document a fresh virtual environment and `python -m pytest tests -q --randomly-seed=58` as the primary developer path. Keep the socket plugin, strict markers, ResourceWarning checks, and process cleanup active.
4. Update README's unittest/dependency-free guidance. Include `pyproject.toml` and `requirements-dev.txt` in the source-artifact manifest.
5. Add a regression inventory mapping each F-number to a behavioral test target. Do not create dozens of tests that merely assert the current source text.
6. Add precise ignore patterns for local config backups, while keeping published example configs visible. Add a secret scan over versioned/release inputs; do not upload local private profiles to an external service.

**Validation and exit criteria**

- Both prescribed seeds run in the clean environment. Preserve any pre-existing failures as explicit issues until fixed; do not rewrite assertions merely to obtain green output.
- Test collection works with and without a foreign `tests` package.
- A source tarball contains enough metadata to install test dependencies and execute its tests.
- The documented command activates the safety fixtures/plugins.

**Rollback:** docs/test-support changes can be reverted independently. No runtime state migration.

## PR 02 — Repair installation as a real transaction

**Implementation steps**

1. Define the installed layout before editing shell code:

   ```text
   prefix/
     current -> releases/<version>
     previous -> releases/<previous-successful-version>
     releases/<version>/       immutable code, bundled engine, resources
     router.json              mutable operator configuration
     providers/ presets/      operator-owned data
     state/ logs/             mutable runtime state
   user-bin/proxy-router      launcher with explicit prefix/state root
   ```

2. Introduce a `Paths` value separating code/resource root from state root. Preserve `PROXY_ROUTER_ROOT` compatibility for checkouts; define exact behavior for installed launchers and workers. Resolve resources from the release and mutable files from the prefix.
3. Stage the complete runtime manifest, including all examples, guides, rulesets, helper modules, and release manifest. Verify required files before publication.
4. Use a temporary config/fixture for an offline smoke. Separate “the program starts and emits valid JSON” from “a live production engine is healthy.” Never run `ensure` or enable a system proxy from an install smoke.
5. Rename the actual stage directory into a previously absent release directory. On an existing version, either verify identical content and no-op or reject an ambiguous replacement; do not silently mix files.
6. Create a temporary relative symlink beside `current`, then atomically replace `current`. Update a recorded previous-successful target. Sync file/directory state where crash durability is required.
7. Create the command launcher and all compatibility links from one manifest. Make cleanup remove only the current attempt's staging area. Validate the launcher with an explicit temporary USER_BIN.
8. Roll back to the recorded previous target, not lexical version order. Preserve live configuration and handle explicit schema compatibility failures without editing it silently.

**Validation and exit criteria**

- Real shell integration: clean install, repeated version, version A→B upgrade, B→A rollback, paths containing spaces and XML/shell-special characters, missing engine, missing resources, and injected copy/rename/smoke failures.
- At each injected failure, either A still works or B is completely installed. No broken `current` target and no mixed release.
- Config, provider file hashes, permissions, and custom presets are unchanged by upgrade/rollback.
- Launching from user-bin, prefix compatibility path, and current resolves the same state root. Worker commands retain that root.

**Rollback:** use the last known-good current target; preserve state-root data. Test rollback before shipping the installer.

## PR 03 — Make release gates enforce artifact correctness

**Implementation steps**

1. Create a checked manifest for every engine platform/architecture, with version, asset name, archive digest, expected binary identity, and provenance. Reject missing entries.
2. Require workflow input version to match the manifest, or explicitly generate/review a new manifest before the build. No “skip verification” branch.
3. Assemble → archive → extract into a unique temp directory → install from that extraction → smoke the installed CLI → calculate/publish artifact checksums.
4. Run native executable checks on matching runners. For cross-built assets, separate file-header validation from a native smoke job; do not assume cross-architecture execution.
5. Exercise Windows extraction and installed CLI. Confirm source bundle test metadata and resources with the same manifest-driven checker.
6. Use read-only workflow defaults; restrict write permissions to publish. Pin test-workflow actions consistently with release-workflow practice.
7. Replace textual release tests with failure-injection tests for missing archive, invalid digest, absent resource, broken launcher, and bad installer exit status.

**Exit criteria:** the currently reproduced installer defect would fail the gate, and every shipped platform has an integrity check and documented executable smoke evidence.

**Rollback:** disable publication of a failing target rather than bypass a validation step. Existing installed copies are unaffected by this PR.

## PR 04 — Model reload, recovery, and applied state explicitly

**Implementation steps**

1. Introduce an outcome type, initially inside the current module to keep the diff reviewable:

   ```text
   ChangeResult
     operation_id
     requested_generation
     applied_generation
     requested_applied: bool
     service_restored: bool
     state: applied | recovered | failed | cancelled
     error_code / diagnostic
   ```

2. Generate and validate a candidate without replacing the committed good state. Store candidate config and selected-profile metadata as one operation record.
3. Apply the candidate. Prove readiness with a bounded observation window; distinguish identity, listener readiness, route readiness, and generation evidence.
4. Commit active/fallback/rotation records and last-good only after the candidate is confirmed. Use a generation-tagged state snapshot or manifest so a crash cannot leave unrelated marker generations masquerading as one state.
5. On failure, restore the prior committed snapshot and confirm it. Return `recovered` with a nonzero requested-change CLI result; include service availability separately.
6. Update rotate/fallback/sweep/ensure callers and tray parsing to consume the outcome. Attribute probe results to applied generation and profile, not the intended candidate.
7. Apply the same semantics to the root helper without adding arbitrary execution or network-target capabilities. Preserve the previous root config during staging, and make helper readiness stronger than `process_matches` alone.
8. Reconcile incomplete operation records at startup: prefer an identified applied generation or report unknown state; do not invent success from files left by an interrupted command.

**Validation and exit criteria**

- Candidate check failure with successful recovery; SIGHUP failure; process survives but candidate does not apply; delayed fatal; startup failure; rollback failure; and crash after each persistent-write step.
- On every path: CLI result, UI result, engine generation, profile marker, fallback marker, and last-good agree.
- Root-helper tests never signal a host engine. Real signal/reload semantics are exercised only against a disposable controlled process or isolated engine harness.

**Rollback:** keep backward-reading support for old markers during migration and retain the prior complete state snapshot. Do not delete the compatibility reader in the same PR.

## PR 05 — Restore operator control over background work

**Implementation steps**

1. Add `--automatic` to watcher-triggered rotations immediately. Replace guessed providers with an explicit unknown-route result.
2. Centralize operation origin (`user`, `watcher`, `keepalive`, `bridge`) and evaluate mode/manual-off under the controller lock immediately before mutation. Decide whether the bridge is an automatic source; document and test the choice consistently.
3. Make automatic actions require positive proxy-mode evidence. Unknown/generated-config mismatch is not permission to change the TUN.
4. Track proxy ownership per network service and HTTP/HTTPS/PAC slot. Use stored ownership to clear a non-default-port endpoint during emergency teardown.
5. Return a list of cleanup successes/failures. Keep the engine available when an owned service still points to it, with a retryable partial-disconnect status. Preserve foreign settings independently for each protocol.
6. Use operation-specific tray deadlines immediately, then integrate PR 04 operation IDs for progress and timeout reconciliation. Poll cancellation/manual-off while settling; keep critical commit sections short and non-interruptible.

**Validation and exit criteria**

- Race tests: mode changes after watcher observation; Stop while rotation waits for lock; Stop during probe/settle; network service changes during disconnect.
- No automatic shared-TUN reload; no false disconnect success after stale service cleanup failure; no clearing a foreign HTTPS setting merely because HTTP is owned.
- A slow valid action is not killed by the former universal 20-second timeout. Quit/drain reaches a bounded, truthful result.

**Rollback:** preserve the safer automatic gate even if UI progress work is reverted. Retain old state readers for proxy ownership migration.

## PR 06 — One validated configuration model and transaction API

**Implementation steps**

1. Define immutable dataclasses or equivalent validated values for Provider, Route, RoutingPolicy, VpnCapture, ProbePolicy, RotationPolicy, Monitor, and Keepalive. Keep the core stdlib-only unless a new dependency has a clear benefit.
2. Normalize fallback aliases/string/list forms into a single ordered list before graph validation. Use linear-time visited/visiting traversal; bound config size, provider count, and nesting.
3. Validate actual intent: nonempty matchers, valid CIDRs/domains, no boolean-as-integer surprises, finite bounded times/MTUs/ports, known references, reserved tag collisions, and helper-compatible bounds for privileged modes.
4. Add `config.load(path) -> Config` and `config.update(path, mutation, expected_generation=None) -> Config`. The update owns lock → fresh read → mutation → validation → durable atomic write.
5. Move all CLI, preset, routing-list, TUI-setting, and profile-registration writers to this API. Remove earlier loads from write-critical decisions. Keep network work outside the config lock.
6. Replace workers' independent default-on-error readers with a shared read result distinguishing missing optional settings, invalid config, last-known-good config, and unavailable config. Report invalid input without silently probing a replacement endpoint.
7. Make `setup --check` validate the complete schema and provider files through the same service. Introduce a schema version and explicit migrations; preserve backwards compatibility for current supported encodings.

**Validation and exit criteria**

- Table-driven valid/invalid fixtures shared by CLI/setup/workers; all fallback encodings and cycles; malformed top-level values; blank matchers; invalid addresses; NaN/infinity; port/mode incompatibilities.
- Real multi-process temporary-file writers preserve both concurrent updates or return a conflict. Test add/add, add/remove, preset/routing, and config/reload races with barriers rather than probabilistic sleeps.
- Fault injection at write/flush/replace/sync boundaries leaves a parseable prior or new snapshot and no secret-readable temporary files.

**Rollback:** retain old schema reading and a private pre-migration backup; never automatically downgrade a configuration that the prior program cannot interpret.

## PR 07 — Compile and explain the effective route once

**Implementation steps**

1. Create a pure compiler `compile_policy(config, provider_state) -> EffectivePolicy` with normalized domain suffixes, IP rules, precedence, effective fallback providers, and explicit final action.
2. Calculate domain intersections correctly. Reuse the resulting matcher set for DNS, data-plane routing, capture planning, watcher inference, status, and bridge/provider inference.
3. Define and publish the compatibility table below. Reject unsupported combinations rather than emit a policy that only partially enforces its description.

   | Mode | Required guarantee |
   |---|---|
   | Mixed proxy, default/VPN-list | Only traffic sent to the proxy is controlled; explicit direct fallback remains visible |
   | Full-capture TUN, safe-list | Traffic outside the direct list reaches the configured default provider, subject to explicit platform exceptions |
   | Selective IP TUN | Only captured destination IPs are controlled; no claim of exhaustive wildcard-domain capture |
   | Safe-list plus selective snapshot capture | Reject or describe as captured-traffic-only; never imply all-system coverage |

4. Choose the DNS/capture strategy deliberately. If maintaining dynamic capture, record TTL/source and handle changed answers, subdomains, IPv6, and shared CDN IPs; avoid a background change mechanism that reintroduces TUN churn.
5. Add a read-only `explain-route HOST_OR_IP --json` showing matcher, effective provider, fallback reason, DNS path, capture coverage, and policy generation. Keep any live DNS resolution an explicit option.
6. Keep current direct fallback by default if preserving the product contract. If adding strict block-on-provider-loss, treat it as a separately tested opt-in feature with precise DNS and TUN guarantees.

**Validation and exit criteria**

- Golden cases cover parent/subdomain intersections, rule overlap/precedence, active fallback chains, invalid/dead providers, safe-list pins, IPv4/IPv6, and ruleset capture.
- Compare compiler, watcher, bridge, and explain outputs for the same fixture.
- Isolated actual-routing tests prove packet/request path across DNS changes and unmatched destinations. No production provider credentials in CI.

**Rollback:** version policy output and retain the previous committed policy/config generation. Avoid making a new privacy guarantee until its integration tests pass.

## PR 08 — Secure and bound the probe transport

**Implementation steps**

1. Specify one transport interface taking validated target policy, total deadline, maximum bytes, maximum redirects, and explicit proxy path. Return structured transport/HTTP/TLS/DNS evidence.
2. Reject private/loopback/link-local/metadata/reserved targets at the actual dialing boundary. Validate all candidate addresses and fail closed on unresolved identity. Preserve Host and TLS hostname verification when connecting to a validated address.
3. Disable redirects for probes by default; if required, revalidate every hop and cap count. Address proxy-side DNS separately: a local preflight lookup cannot authorize an independently resolved CONNECT destination.
4. Replace unbounded curl capture with streaming and a hard body cap. Apply a total deadline spanning resolution, connection, body reads, and retries.
5. Unify watcher/controller health classification. A received HTTP error, DNS failure, inner TLS failure, and connection failure carry different evidence; keep policy separate from measurement.
6. Specify the private-target override narrowly and make its presence visible in diagnostics. Do not let it silently disable unrelated URL credential/scheme validation.

**Validation and exit criteria:** hermetic redirect/rebinding/mixed-answer tests; DNS timeout; proxy-side different answers; huge/slow body; malformed HTTP; TLS error; byte/elapsed budget exhaustion. Resource use remains bounded and error classification does not trigger inappropriate rotation.

**Rollback:** keep the old transport only behind a temporary explicit development switch, not an automatic fallback that bypasses the new safety checks.

## PR 09 — Consolidate worker ownership and observation

**Implementation steps**

1. Build a shared user-worker manager with a per-worker cross-process lock, PID plus launch identity, generation, start handshake, and stop acknowledgement.
2. Publish intent and ownership in a defined order. The child must not recreate an enable marker after a completed Stop. Confirm startup before reporting running.
3. Reuse bounded stop/wait/escalation behavior from the safer existing paths, preserving protection against PID reuse and unrelated processes.
4. Read logs incrementally with byte/line budgets and inode identity. Expire host caches, handle partial final lines, and rotate bounded worker logs.
5. Decide the observation source: intentionally enable suitable connection events, use an engine event API, or reduce the watcher contract. Expose `running`, `observing`, last event time, and dropped-event count separately.
6. Keep sampling failures visible without retrying a failing log append recursively; degrade cleanly on full/read-only disks.

**Exit criteria:** one worker under concurrent starts; stop waits for confirmed termination; restart races cannot resurrect disabled workers; replaced logs and burst input remain bounded; a quiet/unavailable observation source is visible in status.

**Rollback:** maintain compatibility with old PID records for detection/cleanup only; never assume a legacy PID is owned without checking it.

## PR 10 — Match platform claims to executable support

**Implementation steps**

1. Create narrow adapters for user identity, file permissions, process identity/signals, locking, and system proxy operations. Avoid unconditional Unix imports in shared entrypoints.
2. Add native Linux and Windows help/config/fixture/status tests before enabling tunnel tests. Evolve the CI contract to assert required coverage, not an exact macOS-only job set.
3. Repair PowerShell optional-directory handling, runtime manifest copying, command launcher/PATH behavior, and upgrade transaction.
4. Classify commands as portable, macOS-only, or unsupported. Return a clear unsupported result before touching state on another platform.
5. Test installation from actual ZIP/tar artifacts and keep platform-specific integration in disposable CI VMs.

**Exit criteria:** every advertised command has native evidence or explicit scope wording. Simulated `sys.platform` tests supplement, not replace, native tests.

**Rollback:** remove a failing platform asset/claim from the next release rather than publish a known-broken artifact.

## PR 11 — Extract along the established service boundaries

Refine the older [refactor plan](../REFACTOR_PLAN.md) after correctness fixes. Suggested package name: `proxy_router`; keep `router.py` as a compatible launcher while existing integrations depend on it.

```text
proxy_router/
  paths.py                 code/resource/state roots
  models.py                immutable values and result contracts
  config.py                schema, normalization, transactions
  state.py                 generation snapshots and private storage
  routing.py               pure effective-policy compiler
  singbox.py               engine-config rendering and validation adapter
  probes.py                bounded measurement, no rotation policy
  health.py                classification and selection policy
  engine.py                candidate/apply/verify/recover orchestration
  workers.py               user-worker ownership/lifecycle
  platforms/               macOS/Linux/Windows capabilities
  cli.py                   argument parsing and presentation
```

**Implementation steps**

1. Extract Paths/models/state first, then config and routing, then probes/health, then engine/platforms/CLI. Each extraction should preserve already-tested behavior and be independently reviewable.
2. Pass immutable snapshots explicitly. Do not emulate module-global properties; Python modules do not provide the ordinary instance-property behavior assumed by such a facade. Use an explicit compatibility object or re-export wrapper with a clear removal plan.
3. Inject filesystem/process/network/time interfaces at unsafe boundaries. Keep pure policy functions free of subprocess calls and host state.
4. Let tray/TUI consume the same versioned status/change API. Remove duplicated PID/provider inference only after parity tests pass.
5. Keep privileged_helper independently root-installed and restrictive. Share a versioned protocol/schema artifact only when the installer verifies it; do not import user-writable application modules into root execution.
6. Add dependency-direction checks and focused lint/type checks. Increase strictness gradually in extracted modules; avoid unrelated formatting churn.

**Exit criteria:** CLI flags and intended exit codes remain compatible, package dependency graph is acyclic, state is explicit, and each UI observes the same applied generation.

**Rollback:** the compatibility launcher and old-state reader remain until at least one release has exercised the new package layout.

## PR 12 — Add useful operational evidence and performance budgets

**Implementation steps**

1. Version status JSON and add operation ID, desired/applied generation, recovery result, mode evidence, worker observation freshness, and partial proxy-cleanup details.
2. Emit bounded structured events for connect/stop/reload/rotation/fallback/recovery. Redact private keys, URL credentials, sensitive query parameters, and raw profile contents.
3. Measure controller wall time, subprocess count, lock wait/hold time, probe bytes, worker RSS, event backlog, and disconnect latency in reproducible fixtures.
4. Establish budgets from that baseline. Suggested initial goals for hermetic tests: offline help/check under one second, uncontended state-lock work under 100 ms, Stop acknowledgement under five seconds except explicit cleanup failure, and probe body memory bounded by configuration. These are goals to calibrate, not claims about current performance or external VPN latency.
5. Replace repeated full-file scans/status subprocesses only when measurements identify them as a cost. Keep read-only status free of surprise egress probes or mutation.
6. Write runbooks for install/upgrade/rollback, bad config, helper migration, failed reload, stale proxy, worker failure, DNS/capture limitations, and direct versus strict routing behavior. Document expected JSON/exit codes.

**Exit criteria:** an operator can distinguish down, recovering, applied, old-generation-serving, partial-disconnect, and unknown state without reading source or guessing from a generic error. A benchmark result includes commit, fixture, platform, engine version, sample count, and method.

## Test layers and release acceptance

| Layer | What it proves | Environment |
|---|---|---|
| Pure unit/property tests | Schema, suffix intersection, fallback graph, classifications | No sockets/process effects |
| Temporary-filesystem tests | Transactions, permissions, rollback, migration | Per-test disposable roots |
| Controlled subprocess tests | Lock races, cancellation, identity, worker ownership | Registered dummy children only |
| Actual installer/artifact tests | Published layout, resources, launchers, state root | Temporary HOME/prefix/USER_BIN |
| Native-platform smoke | Real import/API/PowerShell portability | CI platform runners |
| Actual engine proxy tests | Generated-config compatibility and request path | Loopback-only fixtures and isolated engine |
| TUN/system-proxy tests | Capture/teardown behavior and routing guarantees | Disposable VM, synthetic credentials, explicit OS isolation |

Release only when all high-priority findings for the advertised modes/platforms are fixed or those capabilities are explicitly excluded from the release; actual artifacts pass their checks; both deterministic suite seeds pass; rollback is demonstrated; and documentation matches the enforced routing/automatic-maintenance contract.

## Decisions to record during implementation

These decisions do not block the audit or immediate fixes:

- Is the supported release scope macOS-first or all three advertised OSes?
- Does safe-list mean all-system routing, or only traffic reaching the proxy/captured TUN?
- Should direct fallback remain the only supported policy, or should a separately specified strict policy be added later?
- Is log-based watcher observation a supported operational feature, or should the engine expose structured events?
- How long must legacy state and helper protocol readers remain supported?

Default implementation assumptions: preserve the existing stdlib core, keep intentional direct fallback visible, preserve the root-helper trust boundary, retain CLI compatibility, and land correctness repairs before architectural extraction.
