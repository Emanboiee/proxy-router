import {expect, type Locator} from '@playwright/test';

/** Drive the visible web control while keeping test choices in domain values. */
export async function selectWeb(locator: Locator, value: string): Promise<void> {
  const source = locator.and(locator.page().locator('select'));
  const index = await source.evaluate((element, selected) => [...(element as HTMLSelectElement).options].findIndex(option => option.value === selected), value);
  expect(index).toBeGreaterThanOrEqual(0);
  const label = await source.evaluate((element, selected) => (element as HTMLSelectElement).options[selected].text, index);
  if (await source.getAttribute('data-provider-kind') !== null) {
    await source.locator('xpath=ancestor::form').locator('.connection-choices').getByRole('button', {name:label, exact:true}).click();
    return;
  }
  for (const [attribute, group] of [['data-theme-scheme', 'schemes'], ['data-theme-accent', 'themes']]) {
    if (await source.getAttribute(attribute) !== null) {
      await locator.page().locator(`.${group}`).getByRole('button', {name:label, exact:true}).click();
      return;
    }
  }
  const trigger = source.locator('..').getByRole('combobox');
  await trigger.click();
  const menu = await trigger.getAttribute('aria-controls');
  await locator.page().locator(`#${menu}`).locator(`[data-index="${index}"]`).click();
}
