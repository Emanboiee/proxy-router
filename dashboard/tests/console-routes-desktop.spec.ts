import {test, expect} from '@playwright/test';

/**
 * Council C2 R1 P0/P1 regression: in the real desktop app the Console Routes
 * screen must drive the engine, not the browser's localStorage profile. The
 * provider picker must be honored on the write, and Remove must target the
 * engine route id.
 */
test('console Routes add/remove drive the engine and honor the provider', async ({page}) => {
  await page.setViewportSize({width: 1440, height: 900});
  await page.addInitScript(() => {
    const state = window as unknown as {
      __invoke: {command: string; payload?: unknown}[];
      __routes: Array<{id: string; provider: string; domains: string[]}>;
    };
    state.__invoke = [];
    state.__routes = [{id: 'r1', provider: 'warp', domains: ['discord.com']}];
    Object.defineProperty(window, 'isTauri', {value: true});
    Object.defineProperty(window, '__TAURI_INTERNALS__', {value: {
      invoke: (command: unknown, payload?: unknown) => {
        const name = String(command);
        state.__invoke.push({command: name, payload});
        if (name === 'get_config') return Promise.resolve({
          routes: state.__routes.map(route => ({...route, domains: [...route.domains]})),
          providers: {warp: {}, proton: {}},
          routing: {mode: 'safe-list'},
          vpn: {},
        });
        if (name === 'get_live_status') return Promise.resolve({
          state: 'disconnected',
          status: {up: false, mode: 'proxy', port: 2080, degraded_lanes: [], error: null},
        });
        if (name === 'get_routing') return Promise.resolve({mode: 'safe-list'});
        if (name === 'get_dashboard_state') return Promise.resolve({profiles: [], providers: [], activeProfileId: null});
        if (name === 'add_route') {
          const {domain} = payload as {domain: string};
          state.__routes.push({id: `r${state.__routes.length + 1}`, provider: (payload as {provider: string}).provider, domains: [domain]});
          return Promise.resolve();
        }
        if (name === 'remove_route') {
          const {id} = payload as {id: string};
          state.__routes = state.__routes.filter(route => route.id !== id);
          return Promise.resolve();
        }
        return Promise.resolve();
      },
    }, configurable: true});
  });

  await page.goto('/');
  await page.getByRole('link', {name: 'Appearance', exact: true}).click();
  await page.getByRole('button', {name: /^Console/}).click();
  await page.locator('#nav').getByRole('link', {name: 'Routes', exact: true}).click();

  const rows = page.locator('.console-route-rows .row');
  await expect(rows.first()).toBeVisible();
  await expect(rows.first()).toContainText('discord.com');
  await expect(page.locator('.console-foot')).toContainText('ENGINE ROUTES');

  await page.locator('#route-domain').fill('desktop.example.test');
  await page.getByRole('combobox', {name: 'Provider', exact: true}).click();
  await page.getByRole('option', {name: 'proton', exact: true}).click();
  await page.getByRole('button', {name: 'Add route', exact: true}).click();

  const invoked = await page.evaluate(() => (window as unknown as {__invoke: {command: string; payload?: unknown}[]}).__invoke);
  expect(invoked.some(entry => entry.command === 'add_route'
    && (entry.payload as {domain?: string})?.domain === 'desktop.example.test'
    && (entry.payload as {provider?: string})?.provider === 'proton')).toBe(true);
  await expect(rows.filter({hasText: 'desktop.example.test'})).toHaveCount(1);

  await rows.filter({hasText: 'desktop.example.test'}).getByRole('button', {name: /Remove/}).click();
  const after = await page.evaluate(() => (window as unknown as {__invoke: {command: string; payload?: unknown}[]}).__invoke);
  expect(after.some(entry => entry.command === 'remove_route'
    && (entry.payload as {id?: string})?.id === 'r2')).toBe(true);
  await expect(rows.filter({hasText: 'desktop.example.test'})).toHaveCount(0);
});
