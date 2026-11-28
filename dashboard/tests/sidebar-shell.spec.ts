import {test, expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

/**
 * Iteration 1 — port the frozen prototype's strongest screen: the persistent
 * side-nav shell + focused Overview. The shell is a new `sidebar` layout preset
 * that reuses the real nav links, page ids and actions (no broken behavior).
 */
async function chooseSidebarLayout(page: import('@playwright/test').Page): Promise<void> {
  await page.getByRole('link', {name: 'Appearance', exact: true}).click();
  await page.getByRole('button', {name: /^Sidebar/}).click();
  await expect(page.locator('html')).toHaveAttribute('data-layout', 'sidebar');
  await page.getByRole('link', {name: 'Home', exact: true}).click();
}

test('sidebar preset shows a persistent side nav with icons, labels and a connection card', async ({page}) => {
  await page.setViewportSize({width: 1440, height: 900});
  await page.goto('/');
  await chooseSidebarLayout(page);

  const shell = page.locator('#app');
  expect(await shell.evaluate(el => getComputedStyle(el).gridTemplateColumns.trim().split(/\s+/).length)).toBe(2);

  const nav = page.getByRole('navigation', {name: 'Primary'});
  await expect(nav.getByRole('link', {name: 'Home', exact: true})).toBeVisible();
  await expect(nav.getByRole('link', {name: 'Settings', exact: true})).toBeVisible();
  // Prototype nav links carry an inline icon; the shell keeps label text intact.
  expect(await nav.locator('a svg').count()).toBeGreaterThanOrEqual(5);

  const status = page.locator('.rail-status');
  await expect(status).toBeVisible();
  await expect(status.locator('.status-dot')).toBeVisible();
  await expect(status.locator('#rail-status')).not.toHaveText('');

  // Rail stays visible across navigation — it is the shell, not page content.
  await page.getByRole('link', {name: 'Providers', exact: true}).click();
  await expect(nav).toBeVisible();
  expect(await shell.evaluate(el => getComputedStyle(el).gridTemplateColumns.trim().split(/\s+/).length)).toBe(2);
});

test('sidebar Overview shows a breadcrumb, title and connection context with working controls', async ({page}) => {
  await page.setViewportSize({width: 1440, height: 900});
  await page.goto('/');
  await chooseSidebarLayout(page);

  await expect(page.locator('#view-breadcrumb')).toHaveText('Overview');
  await expect(page.locator('#view-title')).toHaveText('Home');
  // Real connection controls still work inside the ported shell.
  await expect(page.getByRole('heading', {name: 'Disconnected', exact: true})).toBeVisible();
  await page.getByRole('button', {name: 'Connect', exact: true}).click();
  await expect(page.getByRole('heading', {name: 'Connected', exact: true})).toBeVisible();
  await page.getByRole('button', {name: 'Disconnect', exact: true}).click();
  await expect(page.getByRole('heading', {name: 'Disconnected', exact: true})).toBeVisible();
});

test('sidebar shell is accessible and reflows on mobile', async ({page}) => {
  await page.setViewportSize({width: 1440, height: 900});
  await page.goto('/');
  await chooseSidebarLayout(page);
  expect((await new AxeBuilder({page}).analyze()).violations).toEqual([]);

  await page.setViewportSize({width: 390, height: 844});
  await expect(page.getByRole('navigation', {name: 'Primary'})).toBeHidden();
  await page.getByRole('button', {name: 'Menu', exact: true}).click();
  await expect(page.getByRole('navigation', {name: 'Primary'})).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
});
