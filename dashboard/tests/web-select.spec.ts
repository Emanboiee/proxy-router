import {test, expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test('every page and editor uses visible web dropdowns', async ({page}) => {
  for (const name of ['home', 'profiles', 'providers', 'connectivity', 'settings', 'appearance']) {
    await page.goto(`/#${name}`);
    await expect(page.locator('select:visible')).toHaveCount(0);
    await expect.poll(() => page.locator('select:not([aria-hidden="true"])').count()).toBe(0);
  }
  await page.goto('/#providers');
  await page.getByRole('button', {name:'Add provider', exact:true}).click();
  await expect(page.getByRole('combobox', {name:'Type',exact:true})).toBeVisible();
  await expect(page.locator('select:visible')).toHaveCount(0);
});

test('required values, disabled options, keyboard, reset and FormData still work', async ({page}) => {
  await page.goto('/#settings');
  await page.evaluate(() => {
    const form = document.createElement('form');
    form.id = 'validation-test';
    form.innerHTML = '<label>Test connection<select name="connection" required><option value="" selected disabled>Choose connection</option><option value="alpha">Alpha</option><option value="beta" disabled>Beta</option><option value="gamma">Gamma</option></select></label><button type="submit">Save test</button><button type="reset">Reset test</button>';
    form.addEventListener('submit', event => {event.preventDefault(); (window as any).__submitted = new FormData(form).get('connection');});
    document.querySelector('#app')!.append(form);
  });
  const trigger = page.getByRole('combobox', {name:'Test connection',exact:true});
  await expect(trigger).toBeVisible();
  await page.getByRole('button', {name:'Save test',exact:true}).click();
  await expect(trigger).toBeFocused();
  await expect(trigger).toHaveAttribute('aria-invalid', 'true');
  await expect(page.locator('#validation-test [role="alert"]')).not.toBeEmpty();
  await trigger.press('ArrowDown');
  await expect(page.getByRole('option', {name:'Alpha',exact:true})).toBeFocused();
  await page.keyboard.press('ArrowDown');
  await expect(page.getByRole('option', {name:'Gamma',exact:true})).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(trigger).toContainText('Choose connection');
  await trigger.press('g');
  await expect(page.getByRole('option', {name:'Gamma',exact:true})).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(trigger).toContainText('Gamma');
  await expect(page.locator('#validation-test [role="alert"]')).toBeEmpty();
  await page.getByRole('button', {name:'Save test',exact:true}).click();
  expect(await page.evaluate(() => (window as any).__submitted)).toBe('gamma');
  await page.getByRole('button', {name:'Reset test',exact:true}).click();
  await expect(trigger).toContainText('Choose connection');
  await page.locator('#validation-test select').evaluate((select: HTMLSelectElement) => {select.disabled = true;});
  await expect(trigger).toBeDisabled();
});

test('long web menus fit viewport and remain inside dialog focus scope', async ({page}) => {
  await page.setViewportSize({width:390,height:700});
  await page.goto('/#appearance');
  await page.evaluate(() => {
    const dialog = document.createElement('dialog'); dialog.id = 'edge-test';
    dialog.setAttribute('aria-label','Menu test');
    dialog.style.cssText = 'position:fixed;inset:auto 8px 8px;width:calc(100% - 16px);margin:0;padding:16px;';
    dialog.innerHTML = '<label>Edge server<select>' + Array.from({length:23},(_,i) => `<option>Server ${i}</option>`).join('') + '</select></label>';
    document.querySelector('#app')!.append(dialog); dialog.showModal();
  });
  const trigger = page.getByRole('combobox', {name:'Edge server',exact:true});
  await trigger.click();
  const list = page.getByRole('listbox',{name:'Edge server',exact:true});
  await expect(list).not.toHaveAttribute('popover');
  await expect(page.locator('#edge-test .web-select-menu')).toBeVisible();
  const box = await list.boundingBox();
  expect(box).not.toBeNull();
  expect(box!.y).toBeGreaterThanOrEqual(0);
  expect(box!.y + box!.height).toBeLessThanOrEqual(700);
  expect(await list.evaluate(element => element.scrollHeight > element.clientHeight)).toBe(true);
  await page.keyboard.press('End');
  await expect(page.getByRole('option',{name:'Server 22',exact:true})).toBeFocused();
  expect((await new AxeBuilder({page}).analyze()).violations).toEqual([]);
  await page.keyboard.press('Escape');
  await expect(trigger).toBeFocused();
  await expect(page.locator('#edge-test')).toHaveAttribute('open','');
});
