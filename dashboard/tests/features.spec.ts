import { test, expect } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Disconnected', exact: true })).toBeVisible();
});

test('home profile mode uses an in-app picker', async ({ page }) => {
  const trigger = page.locator('#home-profile');
  await expect(trigger).toHaveAttribute('role', 'combobox');
  await trigger.click();
  await expect(page.getByRole('listbox', { name: 'Mode' })).toBeVisible();
  await page.getByRole('option', { name: 'OpenCode only', exact: true }).click();
  await expect(trigger).toHaveAttribute('aria-expanded', 'false');
  await expect(trigger).toContainText('OpenCode only');
  await expect(page.getByRole('status')).toHaveText('Profile “OpenCode only” selected');
});

test('profiles support create, edit, duplicate, import, export, select, and delete', async ({ page }) => {
  await page.getByRole('link', { name: 'Profiles', exact: true }).click();
  await page.getByRole('button', { name: 'Create profile', exact: true }).click();
  await expect(page.locator('#profile-dialog')).toBeVisible();
  await expect(page.getByRole('button', { name: '← Back', exact: true })).toBeVisible();
  await page.getByLabel('Name').fill('Launch profile');
  await page.getByLabel('Description').fill('A profile created in the UI');
  await page.getByLabel('Domains one per line').fill('launch.example\ncdn.launch.example');
  await page.locator('#profile-form').getByRole('button', { name: 'Create profile', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Launch profile', exact: true })).toBeVisible();
  const card = page.getByRole('article').filter({ hasText: 'Launch profile' });
  await card.getByRole('button', { name: 'Export' }).click();
  await expect(page.getByRole('status')).toHaveText('Profile export ready');
  await card.getByRole('button', { name: 'Edit' }).click();
  await page.getByLabel('Name').fill('Launch profile edited');
  await page.locator('#profile-form').getByRole('button', { name: 'Save changes' }).click();
  await expect(page.getByRole('heading', { name: 'Launch profile edited', exact: true })).toBeVisible();
  const edited = page.getByRole('article').filter({ hasText: 'Launch profile edited' });
  await edited.getByRole('button', { name: 'Duplicate' }).click();
  await expect(page.getByRole('heading', { name: 'Launch profile edited copy', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Import', exact: true }).click();
  await page.getByLabel('Profile JSON').fill(JSON.stringify({ proxyRouterProfile: 1, profile: { name: 'Imported profile', domains: ['imported.example'] } }));
  await page.getByRole('button', { name: 'Import profile', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Imported profile', exact: true })).toBeVisible();
  await page.getByRole('article').filter({ hasText: 'Launch profile edited copy' }).getByRole('button', { name: 'Delete' }).click();
  await expect(page.getByRole('heading', { name: 'Launch profile edited copy', exact: true })).toHaveCount(0);
});

test('profiles can add WireGuard files and SOCKS5 gateways from the GUI', async ({ page }) => {
  await page.getByRole('link', { name: 'Profiles', exact: true }).click();
  await page.getByRole('button', { name: 'Create profile', exact: true }).click();
  await page.getByLabel('Name', { exact: true }).fill('WireGuard profile');
  await page.getByRole('button', { name: 'Add connection', exact: true }).click();
  await expect(page.locator('#provider-dialog')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Add a connection to this profile', exact: true })).toBeVisible();
  await page.getByRole('button', { name: '← Back', exact: true }).click();
  await expect(page.locator('#provider-dialog')).toBeHidden();
  await page.getByRole('button', { name: 'Add connection', exact: true }).click();
  const providerForm = page.locator('#provider-form');
  await providerForm.locator('input[name="name"]').fill('Home WireGuard');
  await providerForm.locator('select[name="kind"]').selectOption('wireguard');
  await providerForm.locator('input[name="wireguardConfig"]').setInputFiles({
    name: 'home.conf',
    mimeType: 'text/plain',
    buffer: Buffer.from('[Interface]\nPrivateKey = private-key\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = public-key\nEndpoint = vpn.example.test:51820\n'),
  });
  await providerForm.getByRole('button', { name: 'Add connection', exact: true }).click();
  await expect(page.locator('#profile-form select[name="providerId"] option:checked')).toHaveText('Home WireGuard');
  await page.locator('#profile-form').getByRole('button', { name: 'Create profile', exact: true }).click();
  await expect(page.getByRole('article').filter({ hasText: 'WireGuard profile' })).toContainText('Home WireGuard');

  await page.getByRole('button', { name: 'Create profile', exact: true }).click();
  await page.getByLabel('Name', { exact: true }).fill('Proton custom profile');
  await page.getByRole('button', { name: 'Add connection', exact: true }).click();
  const customForm = page.locator('#provider-form');
  await customForm.locator('input[name="name"]').fill('Proton config (custom)');
  await customForm.locator('select[name="kind"]').selectOption('custom');
  await customForm.locator('input[name="wireguardConfig"]').setInputFiles({
    name: 'proton-free.conf',
    mimeType: 'text/plain',
    buffer: Buffer.from('[Interface]\nPrivateKey = private-key\nAddress = 10.0.0.3/32\n\n[Peer]\nPublicKey = public-key\nEndpoint = proton.example.test:51820\n'),
  });
  await customForm.getByRole('button', { name: 'Add connection', exact: true }).click();
  await expect(page.locator('#profile-form select[name="providerId"] option:checked')).toHaveText('Proton config (custom)');
  await page.locator('#profile-form').getByRole('button', { name: 'Create profile', exact: true }).click();
  await expect(page.getByRole('article').filter({ hasText: 'Proton custom profile' })).toContainText('Proton config (custom)');

  await page.getByRole('button', { name: 'Create profile', exact: true }).click();
  await page.getByLabel('Name', { exact: true }).fill('Windscribe profile');
  await page.getByRole('button', { name: 'Add connection', exact: true }).click();
  const socksForm = page.locator('#provider-form');
  await expect(socksForm).toBeVisible();
  await socksForm.locator('input[name="name"]').fill('Windscribe Gateway');
  await socksForm.locator('select[name="kind"]').selectOption('socks5');
  await page.waitForTimeout(25);
  await expect(socksForm.locator('input[name="socksHost"]')).toBeVisible();
  await socksForm.locator('input[name="socksHost"]').fill('127.0.0.1');
  await socksForm.locator('input[name="socksPort"]').fill('10473');
  await socksForm.getByRole('button', { name: 'Add connection', exact: true }).click();
  await expect(page.locator('#profile-form select[name="providerId"] option:checked')).toHaveText('Windscribe Gateway');
  await page.locator('#profile-form').getByRole('button', { name: 'Create profile', exact: true }).click();
  await expect(page.getByRole('article').filter({ hasText: 'Windscribe profile' })).toContainText('Windscribe Gateway');

  await page.getByRole('button', { name: 'Create profile', exact: true }).click();
  await page.getByLabel('Name', { exact: true }).fill('Linux exit profile');
  await page.getByRole('button', { name: 'Add connection', exact: true }).click();
  const tailscaleForm = page.locator('#provider-form');
  await tailscaleForm.locator('input[name="name"]').fill('Linux box exit node');
  await tailscaleForm.locator('select[name="kind"]').selectOption('tailscale');
  await expect(tailscaleForm.locator('input[name="tailscaleExitNode"]')).toBeVisible();
  await expect(tailscaleForm.locator('input[name="server"]')).toBeHidden();
  await tailscaleForm.locator('input[name="tailscaleExitNode"]').fill('linux-box');
  await tailscaleForm.getByRole('button', { name: 'Add connection', exact: true }).click();
  await expect(page.locator('#profile-form select[name="providerId"] option:checked')).toHaveText('Linux box exit node');
  await page.locator('#profile-form').getByRole('button', { name: 'Create profile', exact: true }).click();
  await expect(page.getByRole('article').filter({ hasText: 'Linux exit profile' })).toContainText('Linux box exit node');
});

test('profiles own routing, fallback, and subdomain preference', async ({ page }) => {
  await page.getByRole('link', { name: 'Profiles', exact: true }).click();
  await page.getByRole('button', { name: 'Create profile', exact: true }).click();
  await page.getByLabel('Name').fill('Routing profile');
  await page.getByLabel('Routing mode').selectOption('selective');
  await page.getByLabel('Fallback').selectOption('retry');
  await page.getByLabel('Domains one per line').fill('media.example');
  await expect(page.getByText('Suggested assets', { exact: true })).toHaveCount(0);
  await page.getByLabel(/Auto-detect subdomains/).check();
  await page.locator('#profile-form').getByRole('button', { name: 'Create profile', exact: true }).click();
  const profileCard = page.getByRole('article').filter({ hasText: 'Routing profile' });
  await expect(profileCard).toContainText('Retry another provider');
  await expect(profileCard).toContainText('Subdomains on');
  await expect(profileCard).toContainText('routed sites');
  await profileCard.getByRole('button', { name: 'Edit', exact: true }).click();
  await expect(page.getByLabel(/Auto-detect subdomains/)).toBeChecked();
  await page.getByRole('button', { name: '← Back', exact: true }).click();
  await page.getByRole('link', { name: 'Providers', exact: true }).click();
  await page.getByRole('button', { name: 'Add provider', exact: true }).click();
  await expect(page.locator('#provider-dialog')).toBeVisible();
  await expect(page.getByRole('button', { name: '← Back', exact: true })).toBeVisible();
  await page.getByLabel('Name').fill('Test VPN');
  await page.getByLabel('Type').selectOption('custom');
  await page.getByLabel('Server or endpoint').fill('nyc.test-vpn.example');
  await page.locator('#provider-form').getByRole('button', { name: 'Add provider', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Test VPN', exact: true })).toBeVisible();
  await expect(page.getByLabel('Simulate Tailscale running')).toHaveCount(0);
  await page.getByLabel('When a VPN connects').selectOption('keep-running');
  await expect(page.getByText('Current policy: Keep Tailscale running', { exact: true })).toBeVisible();
  await page.getByRole('link', { name: 'Connectivity', exact: true }).click();
  await page.getByRole('button', { name: 'Use provider', exact: true }).first().click();
  await expect(page.getByRole('status')).toHaveText('Proton VPN selected');
  await page.getByLabel('Proton VPN server').selectOption('22-SG-FREE-15');
  await expect(page.getByRole('button', { name: 'Simulate outage' })).toHaveCount(0);
});

test('connection actions, settings, themes, and diagnostics persist', async ({ page }) => {
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Connected', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Disconnect', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Disconnected', exact: true })).toBeVisible();
  await expect(page.locator('#app')).toHaveAttribute('data-state', 'disconnected');
  await expect(page.locator('.rail-status .status-dot')).toHaveCSS('background-color', 'rgb(180, 180, 189)');
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Connected', exact: true })).toBeVisible();
  await page.getByRole('link', { name: 'Settings', exact: true }).click();
  const tray = page.getByLabel(/Close to tray/);
  await tray.setChecked(false);
  await page.getByLabel('Proxy port').fill('2090');
  await page.getByLabel('Proxy port').press('Tab');
  await page.getByLabel('Switch after TLS errors').selectOption('3');
  await page.getByRole('link', { name: 'Appearance', exact: true }).click();
  await expect(page.locator('[data-action="theme-layout"]')).toHaveCount(2);
  await page.getByRole('button', { name: /^Vertical/ }).click();
  await expect(page.locator('html')).toHaveAttribute('data-layout', 'vertical');
  const verticalShell = await page.locator('#app').evaluate(element => {
    const style = getComputedStyle(element);
    return { columns: style.gridTemplateColumns.trim().split(/\s+/).length, rows: style.gridTemplateRows.trim().split(/\s+/).length };
  });
  expect(verticalShell).toEqual({ columns: 2, rows: 1 });
  await page.getByRole('button', { name: /^Horizontal/ }).click();
  const horizontalShell = await page.locator('#app').evaluate(element => {
    const style = getComputedStyle(element);
    return { columns: style.gridTemplateColumns.trim().split(/\s+/).length, rows: style.gridTemplateRows.trim().split(/\s+/).length };
  });
  expect(horizontalShell).toEqual({ columns: 1, rows: 2 });
  await page.getByLabel('Colour scheme').selectOption('light');
  await page.getByLabel('Accent').selectOption('ocean');
  await page.getByLabel('Density').selectOption('comfortable');
  await page.getByLabel('Contrast').selectOption('high');
  await page.locator('#animation-speed').selectOption('fast');
  await page.getByLabel(/Reduce motion/).check();
  await expect(page.locator('html')).toHaveAttribute('data-scheme', 'light');
  await expect(page.locator('html')).toHaveAttribute('data-accent', 'ocean');
  await expect(page.locator('html')).toHaveAttribute('data-layout', 'horizontal');
  await expect(page.locator('html')).toHaveAttribute('data-density', 'comfortable');
  await expect(page.locator('html')).toHaveAttribute('data-contrast', 'high');
  await expect(page.locator('html')).toHaveAttribute('data-motion-speed', 'fast');
  await page.getByRole('link', { name: 'About', exact: true }).click();
  await expect(page.getByText('Runtime map', { exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Export', exact: true }).click();
  await expect(page.getByRole('status')).toHaveText('Log export ready');
  await page.reload();
  await page.getByRole('link', { name: 'Home', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Disconnected', exact: true })).toBeVisible();
  await page.getByRole('link', { name: 'Settings', exact: true }).click();
  await expect(page.getByLabel('Proxy port')).toHaveValue('2090');
  await page.getByRole('link', { name: 'Appearance', exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('data-accent', 'ocean');
  await expect(page.locator('#animation-speed')).toHaveValue('fast');
});
