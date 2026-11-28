import {test, expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

/**
 * Iteration C2 — port the Signal Console "Routes" screen and relabel the rail
 * to the prototype's Overview / Routes / Providers / Network / Settings.
 * Hrefs, ids and real actions stay intact; other layouts keep their labels.
 */
async function chooseConsoleLayout(page: import('@playwright/test').Page): Promise<void> {
  await page.getByRole('link', {name: 'Appearance', exact: true}).click();
  await page.getByRole('button', {name: /^Console/}).click();
  await expect(page.locator('html')).toHaveAttribute('data-layout', 'console');
}

test('console rail uses the prototype labels but keeps real navigation targets', async ({page}) => {
  await page.setViewportSize({width: 1440, height: 900});
  await page.goto('/');
  await chooseConsoleLayout(page);

  const nav = page.locator('#nav');
  const expected: Array<[string, string]> = [
    ['Overview', '#home'], ['Routes', '#profiles'], ['Providers', '#providers'],
    ['Network', '#connectivity'], ['Settings', '#settings'],
  ];
  for (const [label, href] of expected) {
    await expect(nav.getByRole('link', {name: label, exact: true})).toHaveAttribute('href', href);
  }
  // The theme switcher remains available so the preset can be exited.
  await expect(nav.getByRole('link', {name: 'Appearance', exact: true})).toBeVisible();
});

test('console Routes screen ports the mode control, add form and domain list', async ({page}) => {
  await page.setViewportSize({width: 1440, height: 900});
  await page.goto('/');
  await chooseConsoleLayout(page);
  await page.locator('#nav').getByRole('link', {name: 'Routes', exact: true}).click();

  await expect(page.locator('#crumb-page')).toHaveText('Routes');
  await expect(page.locator('.console-title')).toHaveText('Routes');

  // Segmented routing-mode control with exactly one active choice.
  const modes = page.locator('.seg [data-action="routing-mode"]');
  await expect(modes).toHaveCount(3);
  await expect(page.locator('.seg [aria-pressed="true"]')).toHaveCount(1);

  // Add form + routed domains, reusing the real app's field ids.
  await expect(page.locator('#route-domain')).toBeVisible();
  // The app enhances native selects into an accessible custom combobox.
  await expect(page.locator('.console-route-add .select-trigger')).toBeVisible();
  await expect(page.getByRole('button', {name: 'Add route', exact: true})).toBeVisible();
  await expect(page.locator('.console-route-rows .row').first()).toBeVisible();
  await expect(page.locator('.console-route-rows [data-action="console-domain-remove"]').first()).toBeVisible();
});

test('console Routes add and remove change the real profile domain list', async ({page}) => {
  await page.setViewportSize({width: 1440, height: 900});
  await page.goto('/');
  await chooseConsoleLayout(page);
  await page.locator('#nav').getByRole('link', {name: 'Routes', exact: true}).click();

  const rows = page.locator('.console-route-rows .row');
  await expect(rows.first()).toBeVisible();
  const before = await rows.count();
  await page.locator('#route-domain').fill('console.example.test');
  await page.getByRole('button', {name: 'Add route', exact: true}).click();
  await expect(rows).toHaveCount(before + 1);
  await expect(rows.filter({hasText: 'console.example.test'})).toHaveCount(1);

  await rows.filter({hasText: 'console.example.test'}).getByRole('button', {name: /Remove/}).click();
  await expect(rows).toHaveCount(before);
});

test('console Routes screen is accessible and other layouts keep their labels', async ({page}) => {
  await page.setViewportSize({width: 1440, height: 900});
  await page.goto('/');
  await chooseConsoleLayout(page);
  await page.locator('#nav').getByRole('link', {name: 'Routes', exact: true}).click();
  expect((await new AxeBuilder({page}).analyze()).violations).toEqual([]);

  await page.locator('#nav').getByRole('link', {name: 'Appearance', exact: true}).click();
  await page.getByRole('button', {name: /^Horizontal/}).click();
  await expect(page.locator('#nav').getByRole('link', {name: 'Home', exact: true})).toBeVisible();
  await expect(page.locator('#nav').getByRole('link', {name: 'Overview', exact: true})).toHaveCount(0);
});
