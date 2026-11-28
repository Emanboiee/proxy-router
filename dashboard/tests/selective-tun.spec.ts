import { test, expect, type Page } from '@playwright/test';
import { selectWeb } from './select-web';

type Invoke = { command: string; payload?: unknown };

// Desktop mock with a controllable live mode and an engine-advertised ruleset
// list. Mirrors vpn-mode-switch.spec.ts: no real engine, no signed-app changes.
const desktopMock = ({ mode = 'tun', failSelect = false } = {}) => {
  const state = window as unknown as { __invoke: Invoke[]; __failSelect: boolean };
  state.__invoke = [];
  state.__failSelect = failSelect;
  Object.defineProperty(window, 'isTauri', { value: true });
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
      if (name === 'get_config') return Promise.resolve({
        port: 2080, preset: 'roblox', routes: [],
        vpn: {
          default_mode: 'tun',
          capture: 'ruleset',
          selective: 'roblox',
          selective_provider: 'cloudflare',
          rulesets: [
            { name: 'roblox', usable: true, provider: 'cloudflare', description: 'Roblox destinations' },
            { name: 'school', usable: false, provider: 'warp', description: 'School destinations' },
          ],
        },
      });
      if (name === 'get_live_status' || name === 'cached_live_status') {
        return Promise.resolve({ state: 'connected',
          status: { up: true, mode: currentMode, port: 2080, degraded_lanes: [], error: null }, age_ms: 100 });
      }
      if (name === 'select_ruleset') {
        if (state.__failSelect) return Promise.reject('controller exited 1: ruleset failed');
        return Promise.resolve('vpn: ruleset=roblox');
      }
      if (name === 'run_router_action') {
        const action = (payload as { action: string }).action;
        if (action === 'vpn-on' || action === 'vpn-off') currentMode = action === 'vpn-on' ? 'tun' : 'proxy';
        return Promise.resolve('ok');
      }
      return Promise.resolve(null);
    },
  } });
};

const settingsPanel = (page: Page) => page.locator('#selective-tun-panel');
const rulesetRow = (page: Page) => settingsPanel(page).locator('.selective-tun-row');
const rulesetTrigger = (page: Page) => rulesetRow(page).getByRole('combobox', { name: /destination ruleset/i });
const nativeSelect = (page: Page) => settingsPanel(page).locator('#selective-ruleset');
const applyButton = (page: Page) => settingsPanel(page).getByRole('button', { name: /^Apply$/ });
const selectCalls = (page: Page) => page.evaluate(() => (window as unknown as { __invoke: Invoke[] }).__invoke
  .filter(entry => entry.command === 'select_ruleset').map(entry => entry.payload));

async function openSettings(page: Page): Promise<void> {
  await page.goto('/');
  await page.getByRole('link', { name: /Settings/ }).first().click();
  await expect(settingsPanel(page)).toBeVisible();
}

test('Settings shows the current ruleset and disables unusable ones', async ({ page }) => {
  await page.addInitScript(desktopMock, { mode: 'tun' });
  await openSettings(page);
  await expect(settingsPanel(page)).toContainText('ruleset');
  await expect(rulesetTrigger(page)).toHaveAccessibleName(/destination ruleset/i);
  await expect(nativeSelect(page)).toHaveValue('roblox');
  await expect(nativeSelect(page).locator('option[value="school"]')).toBeDisabled();
  await expect(settingsPanel(page).getByText(/destination-based, not per-app/i)).toBeVisible();
});

test('Apply selects a usable destination ruleset', async ({ page }) => {
  await page.addInitScript(desktopMock, { mode: 'tun' });
  await openSettings(page);
  await selectWeb(nativeSelect(page), 'roblox');
  await applyButton(page).click();
  expect(await selectCalls(page)).toEqual([{ name: 'roblox' }]);
});

test('a failed selection surfaces the error and stays operable', async ({ page }) => {
  await page.addInitScript(desktopMock, { mode: 'tun', failSelect: true });
  await openSettings(page);
  await applyButton(page).click();
  await expect(settingsPanel(page).locator('#selective-ruleset-error')).toContainText('ruleset failed');
  await expect(applyButton(page)).toBeEnabled();
});

test('the ruleset control is disabled in proxy mode', async ({ page }) => {
  await page.addInitScript(desktopMock, { mode: 'proxy' });
  await openSettings(page);
  await expect(rulesetTrigger(page)).toBeDisabled();
  await expect(applyButton(page)).toBeDisabled();
});
