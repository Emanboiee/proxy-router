import { test, expect } from '@playwright/test';

/**
 * The controller already refreshes its snapshot before an action returns
 * (run_router_action/apply_preset call refresh_live_status), and
 * get_live_status returns that snapshot while it is younger than
 * CACHE_FRESH_MS. A forced read therefore repeats a CLI spawn the action
 * just paid for; it measured 110ms on main and 220-330ms on the tree the
 * app was running, per dashboard click.
 */
test('actions reuse the snapshot the controller just refreshed', async ({ page }) => {
  await page.addInitScript(() => {
    const state = window as unknown as {
      __invoke: { command: string; payload?: unknown }[];
      __connected: boolean;
    };
    state.__invoke = [];
    state.__connected = false;
    Object.defineProperty(window, 'isTauri', { value: true });
    Object.defineProperty(window, '__TAURI_INTERNALS__', {
      value: {
        invoke: (command: unknown, payload?: unknown) => {
          const name = String(command);
          state.__invoke.push({ command: name, payload });
          if (name === 'cached_live_status') {
            return Promise.resolve({ status: null, age_ms: null });
          }
          if (name === 'get_live_status') {
            return Promise.resolve({
              state: state.__connected ? 'connected' : 'disconnected',
              status: {
                up: state.__connected,
                mode: 'proxy',
                port: 2080,
                degraded_lanes: [],
                error: null,
              },
            });
          }
          if (name === 'run_router_action') {
            const action = (payload as { action?: string } | undefined)?.action;
            state.__connected = action === 'connect';
            return Promise.resolve('ok');
          }
          return Promise.resolve();
        },
      },
      configurable: true,
    });
  });

  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Disconnected', exact: true })).toBeVisible();

  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page.getByRole('heading', { name: 'Connected', exact: true })).toBeVisible();

  const forced = await page.evaluate(() =>
    (window as unknown as { __invoke: { command: string; payload?: unknown }[] }).__invoke
      .filter(entry => entry.command === 'get_live_status')
      .map(entry => Boolean((entry.payload as { force?: boolean } | undefined)?.force)),
  );
  expect(forced).not.toContain(true);
});
