import { test, expect } from '@playwright/test';

// Mirrors engine-controls.spec.ts's desktop mock, with a controllable live
// mode and a deferred run_router_action so we can observe in-flight state.
const desktopMock = ({ mode = 'proxy', startConnected = true } = {}) => {
  const state = window as unknown as {
    __invoke: { command: string; payload?: unknown }[];
    __actionGate?: (release: () => void) => void;
    __failAction?: boolean;
    __dashboard?: unknown;
  };
  state.__invoke = [];
  Object.defineProperty(window, 'isTauri', { value: true });
  let connected = startConnected;
  const dashboard = {
    profiles: [{ id: 'a', name: 'Profile A', description: '', providerId: 'p', fallbackProviderId: '', routeMode: 'selective', domains: ['example.com'], autoSubdomains: false, fallback: 'direct', updatedAt: 1 }],
    providers: [{ id: 'p', name: 'Provider', kind: 'custom', status: 'offline', latency: null, server: 'x:1', servers: ['x:1'], connection: { kind: 'wireguard', fileName: 'p.conf', endpoint: 'x:1' } }],
    activeProfileId: 'a',
  };
  state.__dashboard = dashboard;
  Object.defineProperty(window, '__TAURI_INTERNALS__', { value: {
    invoke: (command: unknown, payload?: unknown) => {
      state.__invoke.push({ command: String(command), payload });
      const name = String(command);
      if (name === 'get_dashboard_state') return Promise.resolve(dashboard);
      if (name === 'get_config') return Promise.resolve({ port: 2080, preset: 'opencode', routes: [], vpn: { default_mode: 'proxy' } });
      if (name === 'get_live_status' || name === 'cached_live_status') {
        return Promise.resolve({ state: connected ? 'connected' : 'disconnected',
          status: { up: connected, mode, port: 2080, degraded_lanes: [], error: null }, age_ms: 100 });
      }
      if (name === 'run_router_action') {
        if (state.__actionGate) return new Promise((resolve, reject) => {
          state.__actionGate!(() => state.__failAction ? reject(new Error('Verb failed')) : (connected = (payload as { action: string }).action === 'connect', resolve('ok')));
        });
        connected = (payload as { action: string }).action === 'connect';
        return Promise.resolve('ok');
      }
      return Promise.resolve(null);
    },
  } });
};

test('#240 Home shows the LIVE mode and Settings distinguishes the default', async ({ page }) => {
  await page.addInitScript(desktopMock, { mode: 'tun' });
  await page.goto('/');
  await expect(page.locator('#live-vpn-mode')).toHaveText('TUN');
  await expect(page.locator('.connection-hero .lead')).not.toContainText('proxied');
  await expect(page.locator('.connection-hero .lead')).toContainText('All traffic is captured');
  await page.getByRole('link', { name: /Settings/ }).first().click();
  await expect(page.getByText('Live VPN mode')).toBeVisible();
  await expect(page.getByText('Configured default mode')).toBeVisible();
});

test('#240 a mode change from the CLI updates the readout on the next poll', async ({ page }) => {
  await page.addInitScript(desktopMock, { mode: 'proxy' });
  await page.goto('/');
  await expect(page.locator('#live-vpn-mode')).toContainText('Proxy');
  await page.evaluate(() => {
    const s = window as unknown as { __TAURI_INTERNALS__: { invoke: (c: string, p?: unknown) => Promise<unknown> } };
    const original = s.__TAURI_INTERNALS__.invoke;
    s.__TAURI_INTERNALS__.invoke = (c, p) => (c === 'get_live_status' || c === 'cached_live_status')
      ? Promise.resolve({ state: 'connected', status: { up: true, mode: 'tun', port: 2080, degraded_lanes: [], error: null }, age_ms: 100 })
      : original(c, p);
  });
  await page.clock.install();
  await page.clock.runFor(6000);
  await expect(page.locator('#live-vpn-mode')).toHaveText('TUN', { timeout: 10000 });
});

test('#241 Connect is disabled and labelled in-flight until the verb resolves', async ({ page }) => {
  await page.addInitScript(desktopMock, { mode: 'proxy', startConnected: false });
  await page.goto('/');
  await page.evaluate(() => {
    const s = window as unknown as { __actionGate?: (release: () => void) => void };
    s.__actionGate = release => { (window as unknown as { __release: () => void }).__release = release; };
  });
  const connect = page.getByRole('button', { name: 'Connect', exact: true });
  await connect.click();
  await expect(page.getByText('Connecting…')).toBeVisible();
  await expect(page.getByRole('button', { name: /Connect/ })).toBeDisabled();
  // A second click while in flight must not queue a second verb.
  await connect.click({ force: true }).catch(() => {});
  expect((await page.evaluate(() => (window as unknown as { __invoke: { command: string }[] }).__invoke.filter(e => e.command === 'run_router_action').length))).toBe(1);
  await page.evaluate(() => (window as unknown as { __release: () => void }).__release());
  await expect(page.getByText('Connecting…')).toHaveCount(0);
});

test('#241 a failing verb leaves a persistent error in the hero', async ({ page }) => {
  await page.addInitScript(desktopMock, { mode: 'proxy', startConnected: false });
  await page.goto('/');
  await page.evaluate(() => {
    const s = window as unknown as { __actionGate?: (release: () => void) => void; __failAction?: boolean };
    s.__failAction = true;
    s.__actionGate = release => { (window as unknown as { __release: () => void }).__release = release; };
  });
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await page.evaluate(() => (window as unknown as { __release: () => void }).__release());
  await expect(page.locator('#engine-action-error')).toContainText('Verb failed');
  await expect(page.getByRole('button', { name: 'Connect', exact: true })).toBeEnabled();
});
