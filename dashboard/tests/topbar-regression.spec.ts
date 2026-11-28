import {test, expect} from '@playwright/test';

/**
 * Iteration 1 fix — the breadcrumb/title heading belongs to the sidebar preset
 * only, at every viewport. All other presets keep the original single-line
 * topbar with a visible page label, not a stacked double-height bar.
 */
async function chooseLayout(page: import('@playwright/test').Page, name: 'Vertical' | 'Horizontal'): Promise<void> {
  await page.getByRole('link', {name: 'Appearance', exact: true}).click();
  await page.getByRole('button', {name: new RegExp(`^${name}`)}).click();
  await expect(page.locator('html')).toHaveAttribute('data-layout', name.toLowerCase());
  await page.getByRole('link', {name: 'Home', exact: true}).click();
}

async function expectSingleLineTopbar(page: import('@playwright/test').Page): Promise<void> {
  const height = await page.locator('.topbar').evaluate(el => el.getBoundingClientRect().height);
  // A single-line bar is ~56px desktop / ~49px mobile; the leaked heading ~100/84px.
  expect(height).toBeLessThan(72);
  const label = page.locator('#page-label');
  await expect(label).toHaveText('Home');
  expect(await label.evaluate(el => getComputedStyle(el).position)).not.toBe('absolute');
  expect(await page.locator('.view-heading').evaluate(el => getComputedStyle(el).display)).toBe('none');
}

for (const layout of ['Horizontal', 'Vertical'] as const) {
  test(`${layout} preset keeps a single-line topbar with a visible page label`, async ({page}) => {
    await page.setViewportSize({width: 1440, height: 900});
    await page.goto('/');
    await chooseLayout(page, layout);
    await expectSingleLineTopbar(page);
  });
}

// The default layout at mobile width must not regress either — the global
// .view-heading hide was previously scoped inside a min-width:651px query.
test('default layout keeps a single-line topbar at mobile width', async ({page}) => {
  await page.setViewportSize({width: 390, height: 844});
  await page.goto('/');
  await expect(page.locator('#page-label')).toHaveText('Home');
  await expectSingleLineTopbar(page);
});
