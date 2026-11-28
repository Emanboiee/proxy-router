import {test, expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

/**
 * New task — port the isolated "Signal Console" redesign into the real app as
 * an opt-in `console` layout. Iteration 1 proves the shell + Overview identity:
 * lime-on-ink frame, PR breadcrumb + mono status line, connection power ring,
 * throughput sparkline, top routed sites and a timestamped activity log.
 * Real actions (connect/disconnect) and navigation must keep working.
 */
async function chooseConsoleLayout(page: import('@playwright/test').Page): Promise<void> {
  await page.getByRole('link', {name: 'Appearance', exact: true}).click();
  await page.getByRole('button', {name: /^Console/}).click();
  await expect(page.locator('html')).toHaveAttribute('data-layout', 'console');
  await page.getByRole('link', {name: 'Home', exact: true}).click();
}

test('console Overview shows the Signal Console identity and keeps real connection controls', async ({page}) => {
  await page.setViewportSize({width: 1440, height: 900});
  await page.goto('/');
  await chooseConsoleLayout(page);

  // Lime-on-ink frame.
  expect(await page.evaluate(() => getComputedStyle(document.body).backgroundColor)).toBe('rgb(0, 0, 0)');

  // Breadcrumb: small PR badge + "Proxy Router / Overview", then a mono status line.
  const crumb = page.locator('.console-crumb');
  await expect(crumb).toBeVisible();
  await expect(crumb.locator('.crumb-badge')).toHaveText('PR');
  await expect(crumb).toContainText('Proxy Router');
  await expect(crumb.locator('#crumb-page')).toHaveText('Overview');
  await expect(page.locator('.console-title')).not.toHaveText('');

  // Connection hero ring + throughput sparkline.
  await expect(page.locator('.power')).toBeVisible();
  await expect(page.locator('svg.spark')).toBeVisible();
  await expect(page.getByRole('heading', {name: 'Throughput'})).toBeVisible();

  // Top routed sites + activity log, with the sample-data honesty footer.
  await expect(page.getByRole('heading', {name: 'Top routed sites'})).toBeVisible();
  await expect(page.getByRole('heading', {name: 'Activity'})).toBeVisible();
  await expect(page.locator('.event-log li').first()).toBeVisible();
  await expect(page.locator('.console-foot')).toContainText('SAMPLE DATA');

  // Real connect/disconnect still work from the ported ring/controls.
  await page.getByRole('button', {name: 'Connect', exact: true}).click();
  await expect(page.getByRole('heading', {name: 'Connected', exact: true})).toBeVisible();
  await page.getByRole('button', {name: 'Disconnect', exact: true}).click();
  await expect(page.getByRole('heading', {name: 'Disconnected', exact: true})).toBeVisible();
});

test('console shell is accessible and reflows on mobile without horizontal overflow', async ({page}) => {
  await page.setViewportSize({width: 1440, height: 900});
  await page.goto('/');
  await chooseConsoleLayout(page);
  expect((await new AxeBuilder({page}).analyze()).violations).toEqual([]);

  await page.setViewportSize({width: 390, height: 844});
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
});

test('console layout is remembered across a reload', async ({page}) => {
  await page.setViewportSize({width: 1440, height: 900});
  await page.goto('/');
  await chooseConsoleLayout(page);
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-layout', 'console');
});

test('console stays readable when the light scheme is selected', async ({page}) => {
  await page.setViewportSize({width: 1440, height: 900});
  await page.goto('/');
  await chooseConsoleLayout(page);
  // The scheme is independently selectable and persisted; Console must stay
  // legible with it, not paint light-scheme text on a forced-black canvas.
  await page.getByRole('link', {name: 'Appearance', exact: true}).click();
  await page.locator('.schemes').getByRole('button', {name: 'Light', exact: true}).click();
  await expect(page.locator('html')).toHaveAttribute('data-scheme', 'light');
  for (const name of ['Home', 'Profiles', 'Providers', 'Connectivity', 'Settings', 'Appearance']) {
    await page.getByRole('link', {name, exact: true}).click();
    expect((await new AxeBuilder({page}).analyze()).violations).toEqual([]);
  }
});
