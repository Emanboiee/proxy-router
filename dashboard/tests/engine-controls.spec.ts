import { test, expect } from '@playwright/test';

/** Desktop app: the window's engine controls must reach the real controller. */
test('desktop connect and disconnect drive the engine, not local state', async ({ page }) => {
  await page.addInitScript(() => {
    const state = window as unknown as { __invoke: { command: string; payload?: unknown }[] };
    state.__invoke = [];
    Object.defineProperty(window, 'isTauri', { value: true });
    let connected = false;
    Object.defineProperty(window, '__TAURI_INTERNALS__', { value: {
      invoke: (command: unknown, payload?: unknown) => {
        state.__invoke.push({ command: String(command), payload });
        if (String(command) === 'get_live_status') {
          return Promise.resolve({
            state: connected ? 'connected' : 'disconnected',
            status: { up: connected, mode: 'proxy', port: 2080, degraded_lanes: [], error: null },
          });
        }
        if (String(command) === 'run_router_action') {
          const action = (payload as { action?: string } | undefined)?.action;
          connected = action === 'connect';
          return Promise.resolve('ok');
        }
        return Promise.resolve();
      },
    }, configurable: true });
  });

  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Disconnected', exact: true })).toBeVisible();

  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page.getByRole('heading', { name: 'Connected', exact: true })).toBeVisible();
  let actions = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: unknown }[] }).__invoke
    .filter(entry => entry.command === 'run_router_action')
    .map(entry => (entry.payload as { action: string }).action));
  expect(actions).toContain('connect');

  await page.getByRole('button', { name: 'Disconnect' }).click();
  await expect(page.getByRole('heading', { name: 'Disconnected', exact: true })).toBeVisible();
  actions = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: unknown }[] }).__invoke
    .filter(entry => entry.command === 'run_router_action')
    .map(entry => (entry.payload as { action: string }).action));
  expect(actions).toContain('disconnect');
});

test('desktop Home reflects the engine preset and routes', async ({ page }) => {
  await page.addInitScript(desktopMock);
  await page.goto('/');
  await expect(page.locator('#active-preset')).toHaveText('opencode');
  await expect(page.locator('#home-engine-routes')).toContainText('opencode-zen');
  await expect(page.locator('#home-engine-routes')).toContainText('proton');
  await expect(page.locator('#main')).toContainText('Routes: 2 routes · 6 domains');
  await expect(page.locator('#main')).toContainText('Latency: Unknown');
  await expect(page.locator('#home-profile')).toHaveCount(0);
  await expect(page.locator('#rail-status')).toHaveText('Connected');

  await page.getByRole('link', { name: 'Profiles', exact: true }).click();
  await page.getByRole('button', { name: 'Apply roblox', exact: true }).click();
  const presets = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: unknown }[] }).__invoke
    .filter(entry => entry.command === 'apply_preset')
    .map(entry => (entry.payload as { name: string }).name));
  expect(presets).toContain('roblox');
});

test('failed preset apply keeps the confirmed preset and outside changes refresh Home', async ({ page }) => {
  await page.addInitScript(() => {
    const state = window as unknown as {
      __invoke: { command: string; payload?: unknown }[];
      __engineConfig: Record<string, unknown>;
      __rejectPreset: boolean;
    };
    state.__invoke = [];
    state.__rejectPreset = true;
    state.__engineConfig = {
      port: 2080,
      preset: 'opencode',
      providers: { proton: { fallback_providers: ['proton2'] }, cloudflare: {} },
      routes: [{ id: 'opencode-zen', provider: 'proton', domains: ['opencode.ai'] }],
    };
    Object.defineProperty(window, 'isTauri', { value: true });
    Object.defineProperty(window, '__TAURI_INTERNALS__', { value: {
      invoke: (command: unknown, payload?: unknown) => {
        const name = String(command);
        state.__invoke.push({ command: name, payload });
        if (name === 'get_cached_live_status' || name === 'get_live_status') {
          return Promise.resolve({ state: 'connected', status: { up: true, mode: 'proxy', port: 2080, degraded_lanes: [], error: null }, age_ms: 0 });
        }
        if (name === 'get_config') return Promise.resolve(state.__engineConfig);
        if (name === 'apply_preset') {
          if (state.__rejectPreset) return Promise.reject(new Error('preset rejected'));
          const preset = (payload as { name: string }).name;
          state.__engineConfig.preset = preset;
          state.__engineConfig.routes = [{
            id: `${preset}-games`, provider: 'cloudflare', domains: [`${preset}.example`],
          }];
          return Promise.resolve('ok');
        }
        if (name === 'get_network') return Promise.resolve({ status: {}, presets: {} });
        if (name === 'get_routing') return Promise.resolve({ mode: 'default' });
        return Promise.resolve('ok');
      },
    }, configurable: true });
  });

  await page.goto('/');
  await expect(page.locator('#active-preset')).toHaveText('opencode');
  await page.getByRole('link', { name: 'Profiles', exact: true }).click();
  await page.getByRole('button', { name: 'Apply roblox', exact: true }).click();
  await expect(page.locator('button[data-preset="opencode"]')).toContainText('active');

  await page.evaluate(() => {
    (window as unknown as { __rejectPreset: boolean }).__rejectPreset = false;
  });
  await page.getByRole('button', { name: 'Apply roblox', exact: true }).click();
  await expect(page.getByRole('button', { name: 'roblox ✓ active', exact: true })).toBeVisible();
  await page.getByRole('link', { name: 'Home', exact: true }).click();
  await expect(page.locator('#active-preset')).toHaveText('roblox');

  await page.evaluate(() => {
    const state = window as unknown as { __engineConfig: Record<string, unknown> };
    state.__engineConfig.preset = 'school-warp';
    state.__engineConfig.routes = [{ id: 'school-lane', provider: 'proton', domains: ['school.example'] }];
    const actualNow = Date.now.bind(Date);
    Date.now = () => actualNow() + 20000;
  });
  await expect(page.locator('#active-preset')).toHaveText('school-warp', { timeout: 8000 });
  await expect(page.locator('#home-engine-routes')).toContainText('school-lane');
  await expect(page.locator('#rail-status')).toHaveText('Connected');
});


/** A Tauri mock that serves live status, engine config and network detection. */
const desktopMock = () => {
  const state = window as unknown as { __invoke: { command: string; payload?: unknown }[] };
  state.__invoke = [];
  Object.defineProperty(window, 'isTauri', { value: true });
  Object.defineProperty(window, '__TAURI_INTERNALS__', { value: {
    invoke: (command: unknown, payload?: unknown) => {
      state.__invoke.push({ command: String(command), payload });
      const name = String(command);
      if (name === 'get_live_status') {
        return Promise.resolve({
          state: 'connected',
          status: { up: true, mode: 'proxy', port: 2080, degraded_lanes: [], error: null },
        });
      }
      if (name === 'get_config') {
        return Promise.resolve({
          port: 2080,
          preset: 'opencode',
          providers: {
            proton: { directory: 'providers/proton', fallback_providers: ['proton2'] },
            cloudflare: { socks5: { host: '127.0.0.1', port: 2181 } },
          },
          routes: [
            { id: 'opencode-zen', provider: 'proton', domains: ['opencode.ai'] },
            { id: 'school', provider: 'cloudflare', domains: ['twitch.tv', 'x.com', 'youtube.com', 'discord.com', 'extra.example'] },
          ],
        });
      }
      if (name === 'get_routing') {
        return Promise.resolve({
          mode: 'default', default_provider: null,
          direct_domains: [], vpn_domains: [], health_order: false,
        });
      }
      if (name === 'get_network') {
        return Promise.resolve({
          status: { connected: true, ssid: 'SchoolWiFi' },
          presets: {
            ssid: 'SchoolWiFi', connected: true, auto: true,
            mapped_preset: 'school-warp',
            presets: { SchoolWiFi: 'school-warp' },
            last_applied: { ssid: 'SchoolWiFi', preset: 'school-warp', at: 1789487390 },
          },
        });
      }
      if (name === 'set_network_preset') {
        return Promise.resolve({
          ssid: 'SchoolWiFi', connected: true, auto: true,
          mapped_preset: 'opencode', presets: { SchoolWiFi: 'opencode' }, last_applied: {},
        });
      }
      if (name === 'set_network_auto') {
        return Promise.resolve({
          ssid: 'SchoolWiFi', connected: true, auto: false,
          mapped_preset: 'school-warp', presets: { SchoolWiFi: 'school-warp' }, last_applied: {},
        });
      }
      if (name === 'remove_network_preset') {
        return Promise.resolve({
          ssid: 'SchoolWiFi', connected: true, auto: true,
          mapped_preset: null, presets: {}, last_applied: {},
        });
      }
      return Promise.resolve();
    },
  }, configurable: true });
};

test('desktop Connectivity shows the detected network and its preset', async ({ page }) => {
  await page.addInitScript(desktopMock);
  await page.goto('/#connectivity');

  await expect(page.locator('#network-panel')).toBeVisible();
  await expect(page.locator('#network-panel')).toContainText('SchoolWiFi');
  await expect(page.locator('#network-panel')).toContainText('school-warp');
  // Real engine routes/providers, not the fixture's demo profiles.
  await expect(page.locator('#engine-routes')).toContainText('opencode-zen');
  await expect(page.locator('#engine-providers')).toContainText('cloudflare');
});

test('desktop Network card saves, toggles and removes the mapping', async ({ page }) => {
  await page.addInitScript(desktopMock);
  await page.goto('/#connectivity');

  await page.locator('#network-preset-select').selectOption('opencode');
  await page.getByRole('button', { name: 'Save mapping', exact: true }).click();
  let saved = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: unknown }[] }).__invoke
    .filter(entry => entry.command === 'set_network_preset')
    .map(entry => entry.payload));
  expect(saved).toContainEqual({ ssid: 'SchoolWiFi', preset: 'opencode' });

  await page.getByRole('button', { name: 'Turn auto-switch off', exact: true }).click();
  const toggles = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: unknown }[] }).__invoke
    .filter(entry => entry.command === 'set_network_auto')
    .map(entry => entry.payload));
  expect(toggles).toContainEqual({ state: 'off' });

  await page.getByRole('button', { name: 'Check network', exact: true }).click();
  const actions = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: unknown }[] }).__invoke
    .filter(entry => entry.command === 'run_router_action')
    .map(entry => (entry.payload as { action: string }).action));
  expect(actions).toContain('network-check');
});


test('desktop Profiles shows the engine routes and mutates them', async ({ page }) => {
  await page.addInitScript(desktopMock);
  await page.goto('/#profiles');

  // Real routes from router.json, not demo profiles.
  await expect(page.locator('#engine-route-rows')).toContainText('opencode-zen');
  await expect(page.locator('#engine-provider-list')).toContainText('proton');

  // Removing a route calls the engine.
  await page.locator('#engine-route-rows button[data-route-id="opencode-zen"]').click();
  const removed = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: unknown }[] }).__invoke
    .filter(entry => entry.command === 'remove_route')
    .map(entry => (entry.payload as { id: string }).id));
  expect(removed).toContain('opencode-zen');

  // Adding a route calls the engine with the entered domain + provider.
  await page.locator('#route-domain').fill('example.com');
  await page.locator('#route-provider').selectOption('cloudflare');
  await page.getByRole('button', { name: 'Add route', exact: true }).click();
  const added = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: unknown }[] }).__invoke
    .filter(entry => entry.command === 'add_route')
    .map(entry => entry.payload));
  expect(added).toContainEqual({ domain: 'example.com', provider: 'cloudflare', id: null });

  // Presets are switchable from this page too.
  await page.locator('button[data-preset="roblox"]').first().click();
  const presets = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: unknown }[] }).__invoke
    .filter(entry => entry.command === 'apply_preset')
    .map(entry => (entry.payload as { name: string }).name));
  expect(presets).toContain('roblox');
});

test('desktop Settings shows engine values and switches routing mode', async ({ page }) => {
  await page.addInitScript(desktopMock);
  await page.goto('/#settings');

  await expect(page.locator('#main')).toContainText('from router.json');
  await expect(page.locator('#main')).toContainText('Proxy port');
  await expect(page.locator('#main')).toContainText('2080');

  await page.locator('button[data-mode="vpn-list"]').click();
  const modes = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: unknown }[] }).__invoke
    .filter(entry => entry.command === 'set_routing_mode')
    .map(entry => (entry.payload as { mode: string }).mode));
  expect(modes).toContain('vpn-list');
});
