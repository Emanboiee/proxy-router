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

test('desktop profile switch applies the matching preset preset', async ({ page }) => {
  await page.addInitScript(() => {
    const state = window as unknown as { __invoke: { command: string; payload?: unknown }[] };
    state.__invoke = [];
    Object.defineProperty(window, 'isTauri', { value: true });
    Object.defineProperty(window, '__TAURI_INTERNALS__', { value: {
      invoke: (command: unknown, payload?: unknown) => {
        state.__invoke.push({ command: String(command), payload });
        if (String(command) === 'get_live_status') {
          return Promise.resolve({ state: 'connected', status: { up: true, mode: 'proxy', port: 2080, degraded_lanes: [], error: null } });
        }
        return Promise.resolve('ok');
      },
    }, configurable: true });
  });
  await page.goto('/');
  await page.locator('#home-profile').click();
  await page.getByRole('option', { name: 'OpenCode only', exact: true }).click();
  const presets = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: unknown }[] }).__invoke
    .filter(entry => entry.command === 'apply_preset')
    .map(entry => (entry.payload as { name: string }).name));
  expect(presets).toContain('opencode');
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
