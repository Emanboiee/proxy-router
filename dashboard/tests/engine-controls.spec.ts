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
