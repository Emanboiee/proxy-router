import {test, expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

/**
 * Cleanup iteration — drop the spaced-uppercase mono microcopy the operator
 * flagged (the "CONNECT" caption under the power ring and the status-line
 * subtitles). Honesty footers stay, but in plain small type.
 */
async function chooseConsole(page: import('@playwright/test').Page): Promise<void> {
  await page.getByRole('link', {name: 'Appearance', exact: true}).click();
  await page.getByRole('button', {name: /^Console/}).click();
  await expect(page.locator('html')).toHaveAttribute('data-layout', 'console');
  await page.getByRole('link', {name: 'Overview', exact: true}).click();
}

test('console has no spaced captions or mono subtitles and stays usable', async ({page}) => {
  await page.setViewportSize({width: 1440, height: 900});
  await page.goto('/');
  await chooseConsole(page);
  await expect(page.locator('.console-title')).toHaveText('Disconnected');

  await expect(page.locator('.power-caption')).toHaveCount(0);
  await expect(page.locator('.console-status-line')).toHaveCount(0);

  // The ring remains a real, labelled control without the printed caption.
  await expect(page.getByRole('button', {name: 'Connect', exact: true})).toBeVisible();
  await page.getByRole('button', {name: 'Connect', exact: true}).click();
  await expect(page.getByRole('heading', {name: 'Connected', exact: true})).toBeVisible();

  // Honesty markers remain, but not in the hated wide-tracked mono font.
  const foot = page.locator('.console-foot').first();
  const style = await foot.evaluate(element => ({
    letterSpacing: getComputedStyle(element).letterSpacing,
    fontFamily: getComputedStyle(element).fontFamily,
  }));
  expect(style.letterSpacing).toBe('normal');
  expect(style.fontFamily).not.toContain('Mono');
  await expect(foot).toContainText('SAMPLE DATA');
  expect((await new AxeBuilder({page}).analyze()).violations).toEqual([]);

  // The same cleanup applies to the ported Routes screen.
  await page.locator('#nav').getByRole('link', {name: 'Routes', exact: true}).click();
  await expect(page.locator('.console-title')).toHaveText('Routes');
  await expect(page.locator('.console-status-line')).toHaveCount(0);
  expect((await new AxeBuilder({page}).analyze()).violations).toEqual([]);
});
