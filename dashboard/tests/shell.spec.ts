import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { mkdirSync, writeFileSync } from 'node:fs';
import { parseStatus, parseWireGuardConfig } from '../src/controller';

const evidence = 'evidence';
mkdirSync(evidence, { recursive: true });

test('rejects malformed and live-looking fixture payloads', () => {
  for (const value of [null, {}, { version: 1, source: 'router', connection: 'connected' }]) {
    expect(() => parseStatus(value)).toThrow();
  }
});

test('validates imported VPN configuration without returning key material', () => {
  const parsed = parseWireGuardConfig('[Interface]\nPrivateKey = secret\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = peer\nEndpoint = vpn.example:51820\n', 'proton.conf');
  expect(parsed).toEqual({ kind: 'wireguard', fileName: 'proton.conf', endpoint: 'vpn.example:51820', interfaceAddress: '10.0.0.2/32' });
  expect(JSON.stringify(parsed)).not.toContain('secret');
  expect(() => parseWireGuardConfig('[Interface]\nPrivateKey = secret\n')).toThrow();
});

test('startup reads the real controller but never performs engine actions', async ({ page }) => {
  await page.addInitScript(() => {
    const state = window as unknown as { __invokeCommands: string[] };
    state.__invokeCommands = [];
    Object.defineProperty(window, 'isTauri', { value: true });
    Object.defineProperty(window, '__TAURI_INTERNALS__', { value: {
      invoke: (command: unknown, payload?: unknown) => {
        state.__invokeCommands.push(String(command));
        if (String(command) === 'get_live_status') {
          return Promise.resolve({
            state: 'connected',
            status: { up: true, mode: 'proxy', port: 2080, degraded_lanes: [], error: null },
          });
        }
        return Promise.resolve();
      },
    }, configurable: true });
  });
  await page.goto('/');
  // The hero follows the real controller payload, not the prototype fixture.
  await expect(page.getByRole('heading', { name: 'Connected', exact: true })).toBeVisible();
  // Startup is read-only: status reads are fine, engine mutations are not.
  const commands = await page.evaluate(() => (window as unknown as { __invokeCommands: string[] }).__invokeCommands);
  expect(commands).toContain('get_live_status');
  expect(commands).not.toContain('run_router_action');
  // getPreviewStatus also fires; it is read-only browser-preview plumbing.
});

test('navigation resets the content scroll before showing Home', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/#profiles');
  const main = page.locator('#main');
  await main.evaluate(node => {
    const element = node as HTMLElement;
    element.style.height = '120px';
    element.style.overflow = 'auto';
    element.scrollTop = element.scrollHeight;
  });
  expect(await main.evaluate(node => (node as HTMLElement).scrollTop)).toBeGreaterThan(0);
  await page.getByRole('link', { name: 'Home', exact: true }).click();
  await expect(main.evaluate(node => (node as HTMLElement).scrollTop)).resolves.toBe(0);
});
for (const [width, height] of [[1440, 900], [390, 844]]) {
  test(`states, navigation, dialog and accessibility at ${width}`, async ({ page }) => {
    await page.setViewportSize({ width, height });
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Disconnected', exact: true })).toBeVisible();
    await expect(page.getByRole('navigation').getByRole('link', { name: 'Routing', exact: true })).toHaveCount(0);
    await expect(page.getByText('Your routes.', { exact: true })).toHaveCount(0);
    await expect(page.locator('#home-profile')).toBeVisible();
    for (const [value, title] of Object.entries({ connected: 'Connected', degraded: 'Needs attention', offline: 'Network unavailable', stale: 'Status is out of date', failed: 'Couldn’t read status', empty: 'Make it yours', disconnected: 'Disconnected', loading: 'Checking status' })) {
      await page.getByRole('button', { name: 'Preview states' }).click();
      await expect(page.getByRole('button', { name: 'Cancel', exact: true })).toBeFocused();
      if (value === 'connected') {
        await page.screenshot({ path: `${evidence}/dialog-${width}.png` });
        expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
      }
      await page.getByLabel('Connection state', { exact: true }).selectOption(value);
      await page.getByRole('button', { name: 'Show preview' }).click();
      await expect(page.getByRole('heading', { name: title, exact: true })).toBeVisible();
      await expect(page.getByRole('button', { name: 'Preview states' })).toBeFocused();
      await page.evaluate(() => scrollTo(0, 0));
      await page.screenshot({ path: `${evidence}/${value}-${width}.png` });
      if (value !== 'loading') {
        expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
      }
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
    }
    await expect(page.getByRole('heading', { name: 'Couldn’t read status', exact: true })).toHaveCount(0);
    await page.getByRole('button', { name: 'Preview states' }).click();
    await page.getByLabel('Connection state', { exact: true }).selectOption('connected');
    await page.getByRole('button', { name: 'Show preview' }).click();
    await expect(page.getByRole('heading', { name: 'Connected', exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Preview states' }).click();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('button', { name: 'Preview states' })).toBeFocused();
    for (const name of ['Profiles', 'Providers', 'Connectivity', 'Settings', 'About', 'Home']) {
      if (width === 390) await page.getByRole('button', { name: 'Menu', exact: true }).click();
      const navLink = page.getByRole('navigation').getByRole('link', { name, exact: true });
      await navLink.focus();
      await navLink.press('Enter');
      await expect(page).toHaveURL(new RegExp(`#${name.toLowerCase()}$`));
      await expect(page.locator('h1')).toBeFocused();
      expect(await page.title()).toContain(name);
    }
    await page.goBack();
    await expect(page.getByRole('heading', { name: 'About', exact: true })).toBeVisible();
    await page.emulateMedia({ reducedMotion: 'reduce' });
    const styles = await page.evaluate(() => ({
      fonts: [...new Set([...document.querySelectorAll('*')].map(e => getComputedStyle(e).fontSize))],
      radii: [...new Set([...document.querySelectorAll('*')].map(e => getComputedStyle(e).borderRadius))],
      paint: performance.getEntriesByType('paint').map(p => ({name: p.name, ms: p.startTime})),
      targets: [...document.querySelectorAll('button, nav a, select')].filter(e => e.getBoundingClientRect().width > 0).map(e => ({ text: e.textContent, height: e.getBoundingClientRect().height })),
    }));
    writeFileSync(`${evidence}/metrics-${width}.json`, JSON.stringify(styles, null, 2));
    expect(styles.targets.every(t => t.height >= 44)).toBeTruthy();
    expect(errors).toEqual([]);
  });
}

test('minimum desktop sizes and large text reflow', async ({ page }) => {
  await page.goto('/');
  for (const [width, height] of [[1024, 720], [760, 560], [390, 844]]) {
    await page.setViewportSize({ width, height });
    await page.evaluate(() => { document.documentElement.style.fontSize = '200%'; });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
    await page.getByRole('button', { name: 'Preview states' }).click();
    await expect(page.getByRole('button', { name: 'Cancel', exact: true })).toBeVisible();
    await page.keyboard.press('Escape');
  }
});
