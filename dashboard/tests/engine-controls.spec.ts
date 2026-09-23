import { test, expect } from '@playwright/test';

/** A Tauri mock that serves live status, engine config and network detection. */
const desktopMock = (seedCurrentSetup = false) => {
  const state = window as unknown as { __invoke: { command: string; payload?: unknown }[]; __failApply?: boolean; __dashboard?: unknown };
  state.__invoke = [];
  Object.defineProperty(window, 'isTauri', { value: true });
  let connected = false;
  let profileSequence = 0;
  type MockProfile = { id: string; name: string; description: string; providerId: string; fallbackProviderId: string; routeMode: string; domains: string[]; autoSubdomains: boolean; fallback: string; updatedAt: number };
  const dashboard: { profiles: MockProfile[]; providers: Record<string, unknown>[]; activeProfileId: string | null } = {
    profiles: [
      { id: 'school', name: 'School access', description: 'Blocked sites', providerId: 'warp', fallbackProviderId: 'proton', routeMode: 'selective', domains: ['twitch.tv', 'discord.com'], autoSubdomains: true, fallback: 'retry', updatedAt: 1 },
      { id: 'opencode', name: 'OpenCode only', description: 'Keep the rest direct', providerId: 'proton', fallbackProviderId: '', routeMode: 'selective', domains: ['opencode.ai'], autoSubdomains: false, fallback: 'direct', updatedAt: 2 },
    ],
    providers: [
      { id: 'warp', name: 'WARP', kind: 'custom', status: 'offline', latency: null, server: 'warp.example.test:51820', servers: ['warp.example.test:51820'], connection: { kind: 'wireguard', fileName: 'warp.conf', endpoint: 'warp.example.test:51820' } },
      { id: 'proton', name: 'Proton custom VPN', kind: 'custom', status: 'offline', latency: null, server: 'proton.example.test:51820', servers: ['proton.example.test:51820'], connection: { kind: 'wireguard', fileName: 'proton.conf', endpoint: 'proton.example.test:51820' } },
    ],
    activeProfileId: 'school',
  };
  if (seedCurrentSetup) {
    dashboard.profiles = [{ ...dashboard.profiles[0], id: 'current-setup', name: 'Current setup' }];
    dashboard.activeProfileId = 'current-setup';
  }
  state.__dashboard = dashboard;
  const copyDashboard = () => JSON.parse(JSON.stringify(dashboard));
  Object.defineProperty(window, '__TAURI_INTERNALS__', { value: {
    invoke: (command: unknown, payload?: unknown) => {
      state.__invoke.push({ command: String(command), payload });
      const name = String(command);
      if (name === 'get_dashboard_state') return Promise.resolve(copyDashboard());
      if (name === 'apply_dashboard_profile') {
        if (state.__failApply) return Promise.reject(new Error('Profile apply rejected'));
        dashboard.activeProfileId = (payload as { profileId: string }).profileId;
        return Promise.resolve(copyDashboard());
      }
      if (name === 'save_dashboard_profile') {
        const request = payload as { profile: Record<string, unknown>; profileId?: string | null };
        if (request.profileId) {
          dashboard.profiles = dashboard.profiles.map(profile => profile.id === request.profileId ? { ...profile, ...request.profile } : profile);
          if (request.profileId === 'current-setup') dashboard.activeProfileId = null;
        } else {
          const profile = { ...request.profile, id: `created-${++profileSequence}`, updatedAt: 3 } as unknown as MockProfile;
          dashboard.profiles.push(profile);
        }
        return Promise.resolve(copyDashboard());
      }
      if (name === 'delete_dashboard_profile') {
        const profileId = (payload as { profileId: string }).profileId;
        dashboard.profiles = dashboard.profiles.filter(profile => profile.id !== profileId);
        if (dashboard.activeProfileId === profileId) dashboard.activeProfileId = dashboard.profiles[0]?.id ?? null;
        return Promise.resolve(copyDashboard());
      }
      if (name === 'plugin:dialog|open') return Promise.resolve('/tmp/proton-home.conf');
      if (name === 'save_dashboard_provider') {
        const request = payload as { provider: { name: string; kind: string }; providerId?: string | null; sourcePath?: string | null };
        if (request.providerId) {
          dashboard.providers = dashboard.providers.map(provider => provider.id === request.providerId ? { ...provider, name: request.provider.name, kind: request.provider.kind } : provider);
        } else {
          dashboard.providers.push({ id: `provider-${++profileSequence}`, name: request.provider.name, kind: request.provider.kind, status: 'offline', latency: null, server: 'proton.example.test:51820', servers: ['proton.example.test:51820'], connection: { kind: 'wireguard', fileName: 'proton-home.conf', endpoint: 'proton.example.test:51820' } });
        }
        return Promise.resolve(copyDashboard());
      }
      if (name === 'delete_dashboard_provider') {
        const providerId = (payload as { providerId: string }).providerId;
        dashboard.providers = dashboard.providers.filter(provider => provider.id !== providerId);
        return Promise.resolve(copyDashboard());
      }
      if (name === 'get_live_status') {
        return Promise.resolve({
          state: connected ? 'connected' : 'disconnected',
          status: { up: connected, mode: 'proxy', port: 2080, degraded_lanes: [], error: null },
        });
      }
      if (name === 'cached_live_status') return Promise.resolve({ state: connected ? 'connected' : 'disconnected', status: { up: connected, mode: 'proxy', port: 2080, degraded_lanes: [], error: null }, age_ms: 100 });
      if (name === 'run_router_action') { connected = (payload as { action: string }).action === 'connect'; return Promise.resolve('ok'); }
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

test('desktop stays disconnected on launch and profile selection only saves routing', async ({ page }) => {
  await page.addInitScript(desktopMock);
  await page.goto('/#home');

  await expect(page.getByRole('heading', { name: 'Disconnected', exact: true })).toBeVisible();
  let actions = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: unknown }[] }).__invoke
    .filter(entry => entry.command === 'run_router_action'));
  expect(actions).toEqual([]);

  await page.locator('#home-profile').click();
  await page.getByRole('option', { name: 'OpenCode only', exact: true }).click();
  const profileSelections = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: unknown }[] }).__invoke
    .filter(entry => entry.command === 'apply_dashboard_profile')
    .map(entry => entry.payload));
  expect(profileSelections).toContainEqual({ profileId: 'opencode' });
  actions = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: unknown }[] }).__invoke
    .filter(entry => entry.command === 'run_router_action'));
  expect(actions).toEqual([]);
});

test('desktop Connect and Disconnect are explicit engine actions', async ({ page }) => {
  await page.addInitScript(desktopMock);
  await page.goto('/#home');
  await expect(page.getByRole('heading', { name: 'Disconnected', exact: true })).toBeVisible();

  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page.getByRole('heading', { name: 'Connected', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Disconnect' }).click();
  await expect(page.getByRole('heading', { name: 'Disconnected', exact: true })).toBeVisible();

  const actions = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: unknown }[] }).__invoke
    .filter(entry => entry.command === 'run_router_action')
    .map(entry => (entry.payload as { action: string }).action));
  expect(actions).toEqual(['connect', 'disconnect']);
});

test('desktop profile GUI creates, edits, duplicates and deletes saved profiles', async ({ page }) => {
  await page.addInitScript(desktopMock);
  await page.goto('/#profiles');

  await page.getByRole('button', { name: 'Create profile', exact: true }).click();
  const dialog = page.locator('#profile-dialog');
  await dialog.locator('[name="name"]').fill('Home setup');
  await dialog.locator('[name="providerId"]').selectOption('warp');
  await dialog.locator('[name="routeMode"]').selectOption('selective');
  await dialog.locator('[name="domains"]').fill('example.com\napi.example.com');
  await dialog.locator('[name="autoSubdomains"]').check();
  await dialog.getByRole('button', { name: 'Create profile', exact: true }).click();
  await expect(dialog).not.toBeVisible();
  const createdCard = page.locator('.profile-card').filter({ hasText: 'Home setup' });
  await expect(createdCard).toBeVisible();

  const saveCalls = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: unknown }[] }).__invoke
    .filter(entry => entry.command === 'save_dashboard_profile')
    .map(entry => entry.payload as { profile: Record<string, unknown>; profileId: string | null }));
  expect(saveCalls.at(-1)?.profile).toMatchObject({
    name: 'Home setup', routeMode: 'selective', domains: ['example.com', 'api.example.com'], autoSubdomains: true,
  });
  const applyCalls = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: unknown }[] }).__invoke
    .filter(entry => entry.command === 'apply_dashboard_profile'));
  expect(applyCalls.length).toBeGreaterThan(0);

  const card = page.locator('.profile-card').filter({ hasText: 'Home setup' });
  await card.getByRole('button', { name: 'Edit', exact: true }).click();
  await dialog.locator('[name="description"]').fill('A profile edited in the GUI');
  await dialog.locator('[name="fallback"]').selectOption('retry');
  await dialog.locator('[name="fallbackProviderId"]').selectOption('proton');
  await dialog.locator('[name="providerId"]').selectOption('proton');
  await expect(dialog.locator('[name="fallbackProviderId"]')).toHaveValue('warp');
  await dialog.getByRole('button', { name: 'Save changes', exact: true }).click();
  await expect(card).toContainText('Retry another provider');

  const edited = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: unknown }[] }).__invoke
    .filter(entry => entry.command === 'save_dashboard_profile')
    .map(entry => entry.payload as { profile: Record<string, unknown>; profileId: string | null }));
  expect(edited.at(-1)?.profile).toMatchObject({ description: 'A profile edited in the GUI', providerId: 'proton', fallback: 'retry', fallbackProviderId: 'warp' });
  expect(edited.at(-1)?.profileId).toMatch(/^created-/);

  await card.getByRole('button', { name: 'Duplicate', exact: true }).click();
  await expect(page.locator('.profile-card').filter({ hasText: 'Home setup copy' })).toBeVisible();
  const duplicate = page.locator('.profile-card').filter({ hasText: 'Home setup copy' });
  page.on('dialog', dialogEvent => dialogEvent.accept());
  await duplicate.getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(page.locator('.profile-card').filter({ hasText: 'Home setup copy' })).toHaveCount(0);
  const deletions = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: unknown }[] }).__invoke
    .filter(entry => entry.command === 'delete_dashboard_profile'));
  expect(deletions).toHaveLength(1);

  const engineActions = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: unknown }[] }).__invoke
    .filter(entry => entry.command === 'run_router_action'));
  expect(engineActions).toEqual([]);
});

test('desktop profile apply failure leaves the previous selection intact', async ({ page }) => {
  await page.addInitScript(desktopMock);
  await page.goto('/#profiles');
  await page.evaluate(() => { (window as unknown as { __failApply: boolean }).__failApply = true; });

  await page.getByRole('button', { name: 'Create profile', exact: true }).click();
  const dialog = page.locator('#profile-dialog');
  await dialog.locator('[name="name"]').fill('Needs review');
  await dialog.locator('[name="providerId"]').selectOption('warp');
  await dialog.locator('[name="domains"]').fill('example.com');
  await dialog.getByRole('button', { name: 'Create profile', exact: true }).click();

  await expect(page.locator('#toast')).toHaveText('Profile apply rejected');
  const previous = page.locator('.profile-card').filter({ hasText: 'School access' });
  const pending = page.locator('.profile-card').filter({ hasText: 'Needs review' });
  await expect(previous.locator('.label')).toHaveText('Active profile');
  await expect(pending.locator('.label')).toHaveText('Profile');
  const dashboard = await page.evaluate(() => (window as unknown as { __dashboard: { activeProfileId: string; profiles: { name: string }[] } }).__dashboard);
  expect(dashboard.activeProfileId).toBe('school');
  expect(dashboard.profiles.some(profile => profile.name === 'Needs review')).toBe(true);
  const engineActions = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: unknown }[] }).__invoke
    .filter(entry => entry.command === 'run_router_action'));
  expect(engineActions).toEqual([]);
});
test('desktop editing the imported current setup applies its updated routing', async ({ page }) => {
  await page.addInitScript(desktopMock, true);
  await page.goto('/#profiles');

  const card = page.locator('.profile-card').filter({ hasText: 'Current setup' });
  await card.getByRole('button', { name: 'Edit', exact: true }).click();
  const dialog = page.locator('#profile-dialog');
  await dialog.locator('[name="domains"]').fill('updated.example');
  await dialog.getByRole('button', { name: 'Save changes', exact: true }).click();

  const applied = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: unknown }[] }).__invoke
    .filter(entry => entry.command === 'apply_dashboard_profile')
    .map(entry => entry.payload));
  expect(applied).toContainEqual({ profileId: 'current-setup' });
  const dashboard = await page.evaluate(() => (window as unknown as { __dashboard: { activeProfileId: string } }).__dashboard);
  expect(dashboard.activeProfileId).toBe('current-setup');
});


test('desktop provider GUI picks a local config, edits metadata, and deletes a saved connection', async ({ page }) => {
  await page.addInitScript(desktopMock);
  await page.goto('/#providers');

  await page.getByRole('button', { name: 'Add provider', exact: true }).click();
  const dialog = page.locator('#provider-dialog');
  await dialog.locator('[name="name"]').fill('Proton home');
  await dialog.locator('[name="kind"]').selectOption('custom');
  await dialog.getByRole('button', { name: 'Choose WireGuard config', exact: true }).click();
  await expect(dialog.locator('#wireguard-file-label')).toHaveText('proton-home.conf');
  await dialog.getByRole('button', { name: 'Add provider', exact: true }).click();
  const providerCard = page.locator('.provider-card').filter({ hasText: 'Proton home' });
  await expect(providerCard).toBeVisible();

  const saves = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: unknown }[] }).__invoke
    .filter(entry => entry.command === 'save_dashboard_provider')
    .map(entry => entry.payload as { provider: { name: string; kind: string }; providerId: string | null; sourcePath: string | null }));
  expect(saves[0]).toMatchObject({ provider: { name: 'Proton home', kind: 'custom' }, providerId: null, sourcePath: '/tmp/proton-home.conf' });
  expect(JSON.stringify(saves)).not.toContain('PRIVATE-KEY');

  page.on('dialog', dialogEvent => dialogEvent.accept());
  await providerCard.getByRole('button', { name: 'Edit', exact: true }).click();
  await dialog.locator('[name="name"]').fill('Proton personal');
  await dialog.getByRole('button', { name: 'Save connection', exact: true }).click();
  await expect(page.locator('.provider-card').filter({ hasText: 'Proton personal' })).toBeVisible();
  await page.locator('.provider-card').filter({ hasText: 'Proton personal' }).getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(page.locator('.provider-card').filter({ hasText: 'Proton personal' })).toHaveCount(0);
  const deletes = await page.evaluate(() => (window as unknown as { __invoke: { command: string; payload?: unknown }[] }).__invoke
    .filter(entry => entry.command === 'delete_dashboard_provider'));
  expect(deletes).toHaveLength(1);
});

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


test('desktop Profiles displays saved profiles instead of exposing raw engine routes', async ({ page }) => {
  await page.addInitScript(desktopMock);
  await page.goto('/#profiles');

  const schoolCard = page.locator('.profile-card').filter({ hasText: 'School access' });
  await expect(schoolCard).toContainText('Subdomains on');
  await expect(schoolCard).toContainText('Proton custom VPN');
  await expect(page.locator('#engine-route-rows')).toHaveCount(0);
  await expect(page.locator('.setting-note')).toContainText('next explicit Connect');
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
