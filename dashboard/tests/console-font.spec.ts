import {test, expect} from '@playwright/test';

/**
 * Iteration C4 — the console layout must use one font stack everywhere.
 * The prototype uses DM Sans for UI text and reserves mono for nothing on
 * screen; leftover utility classes were still painting SF Mono on chips,
 * timestamps, favourite letters and base-rule details.
 */
async function chooseConsole(page: import('@playwright/test').Page): Promise<void> {
  await page.getByRole('link', {name: 'Appearance', exact: true}).click();
  await page.getByRole('button', {name: /^Console/}).click();
  await expect(page.locator('html')).toHaveAttribute('data-layout', 'console');
}

test('console uses one sans stack for every visible text element on every page', async ({page}) => {
  await page.setViewportSize({width: 1440, height: 900});
  await page.goto('/');
  await chooseConsole(page);

  for (const name of ['Overview', 'Routes', 'Providers', 'Network', 'Settings', 'Appearance']) {
    await page.getByRole('link', {name, exact: true}).click();
    await expect(page.locator('#crumb-page')).toHaveText(name);
    const mono = await page.evaluate(() => {
      const offenders: string[] = [];
      for (const el of document.querySelectorAll('#app *')) {
        if (!el.getClientRects().length) continue;
        const ownsText = Array.from(el.childNodes).some(node => node.nodeType === Node.TEXT_NODE && node.textContent!.trim());
        if (!ownsText) continue;
        const family = getComputedStyle(el).fontFamily;
        if (/mono/i.test(family)) offenders.push(`${el.tagName.toLowerCase()}.${el.className} :: ${family}`);
      }
      return offenders;
    });
    expect(mono, `${name} still uses a mono font:\n${mono.join('\n')}`).toEqual([]);
  }
});

test('console keeps code and pre blocks on the same sans stack', async ({page}) => {
  await page.setViewportSize({width: 1440, height: 900});
  await page.goto('/');
  await chooseConsole(page);
  // The WARP provider form renders bare <pre>/<code> command snippets; the
  // console palette must not let those fall back to the browser mono stack.
  await page.evaluate(() => {
    const host = document.createElement('div');
    host.className = 'font-probe';
    host.innerHTML = '<pre><code>warp-cli connect</code></pre>';
    document.querySelector('#main')!.append(host);
  });
  const families = await page.evaluate(() => Array.from(document.querySelectorAll('.font-probe, .font-probe pre, .font-probe code'))
    .map(el => getComputedStyle(el).fontFamily));
  expect(families.every(family => /^"DM Sans Variable"/.test(family) && !/mono/i.test(family)), families.join(' | ')).toBeTruthy();
});
