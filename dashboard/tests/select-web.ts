import {expect, type Locator} from '@playwright/test';

/** Drive the visible web control while keeping test choices in domain values. */
export async function selectWeb(locator: Locator, value: string): Promise<void> {
  const source = locator.and(locator.page().locator('select'));
  const index = await source.evaluate((element, selected) => [...(element as HTMLSelectElement).options].findIndex(option => option.value === selected), value);
  expect(index).toBeGreaterThanOrEqual(0);
  const trigger = source.locator('..').getByRole('combobox');
  await trigger.click();
  const menu = await trigger.getAttribute('aria-controls');
  await locator.page().locator(`#${menu}`).locator(`[data-index="${index}"]`).click();
}
