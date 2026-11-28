import { test, expect } from '@playwright/test';

// Desktop mock with a controllable live mode so the Proxy/TUN switch can be
// observed without a real engine. Mirrors live-mode-inflight.spec.ts.
const desktopMock = ({ mode = 'proxy', startConnected = true } = {}) => {
  const state = window as unknown as {
    __invoke: { command: string; payload?: unknown }[];
    __failAction?: boolean;
  };
  state.__invoke = [];
  Object.defineProperty(window, 'isTauri', { value: true });
  let connected = startConnected;
  let currentMode = mode;
  const dashboard = {
    profiles: [{ id: 'a', name: 'Profile A', description: '', providerId: 'p', fallbackProviderId: '', routeMode: 'selective', domains: ['example.com'], autoSubdomains: false, fallback: 'direct', updatedAt: 1 }],
    providers: [{ id: 'p', name: 'Provider', kind: 'custom', status: 'offline', latency: null, server: 'x:1', servers: ['x:1'], connection: { kind: 'wireguard', fileName: 'p.conf', endpoint: 'x:1' } }],
    activeProfileId: 'a',
  };
  Object.defineProperty(window, '__TAURI_INTERNALS__', { value: {
    invoke: (command: unknown, payload?: unknown) => {
      state.__invoke.push({ command: String(command), payload });
      const name = String(command);
      if (name === 'get_dashboard_state') return Promise.resolve(dashboard);
      if (name === 'get_config') return Promise.resolve({ port: 2080, preset: 'opencode', routes: [], vpn: { default_mode: 'proxy' } });
      if (name === 'get_live_status' || name === 'cached_live_status') {
        return Promise.resolve({ state: connected ? 'connected' : 'disconnected',
          status: { up: connected, mode: currentMode, port: 2080, degraded_lanes: [], error: null }, age_ms: 100 });
      }
      if (name === 'run_router_action') {
        const action = (payload as { action: string }).action;
        if (state.__failAction) return Promise.reject('controller exited 1: verb failed');
        if (action === 'vpn-on' || action === 'vpn-off') {
          currentMode = action === 'vpn-on' ? 'tun' : 'proxy';
          connected = true;
        } else {
          connected = action === 'connect';
        }
        return Promise.resolve('ok');
      }
      return Promise.resolve(null);
    },
  } });
};

test('Home exposes a Proxy/TUN switch that reflects the live mode', async ({ page }) => {
  await page.addInitScript(desktopMock, { mode: 'proxy' });
  await page.goto('/');
  const toggle = page.getByRole('button', { name: /switch to TUN/i });
  await expect(toggle).toBeVisible();
  await expect(page.locator('#live-vpn-mode')).toContainText('Proxy');

  await toggle.click();
  await expect(page.locator('#live-vpn-mode')).toContainText('TUN');
  await expect(page.getByRole('button', { name: /switch to Proxy/i })).toBeVisible();
  const calls = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: { action: string } }[] }).__invoke
    .filter(e => e.command === 'run_router_action').map(e => e.payload?.action));
  expect(calls).toContain('vpn-on');
});

test('switching from TUN back to Proxy runs vpn-off', async ({ page }) => {
  await page.addInitScript(desktopMock, { mode: 'tun' });
  await page.goto('/');
  await expect(page.locator('#live-vpn-mode')).toContainText('TUN');
  await page.getByRole('button', { name: /switch to Proxy/i }).click();
  await expect(page.locator('#live-vpn-mode')).toContainText('Proxy');
  const calls = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: { action: string } }[] }).__invoke
    .filter(e => e.command === 'run_router_action').map(e => e.payload?.action));
  expect(calls).toContain('vpn-off');
});

test('a failed mode switch surfaces the controller error and stays operable', async ({ page }) => {
  await page.addInitScript(desktopMock, { mode: 'proxy' });
  await page.goto('/');
  await page.evaluate(() => { (window as unknown as { __failAction: boolean }).__failAction = true; });
  await page.getByRole('button', { name: /switch to TUN/i }).click();
  await expect(page.locator('#engine-action-error')).toContainText('verb failed');
  await expect(page.getByRole('button', { name: /switch to TUN/i })).toBeEnabled();
});

test('Settings no longer shows the dead Full tunnel mode toggle', async ({ page }) => {
  await page.addInitScript(desktopMock, { mode: 'proxy' });
  await page.goto('/');
  await page.getByRole('link', { name: /Settings/ }).first().click();
  await expect(page.getByText('Full tunnel mode', { exact: true })).toHaveCount(0);
});
