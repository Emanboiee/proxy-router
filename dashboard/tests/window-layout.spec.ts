import {test, expect} from '@playwright/test';
import {fitWindowLayout} from '../src/window-layout';

test('native presets account for Retina scaling, window frame, and usable display area', () => {
  const area = {x: -2560, y: 48, width: 2560, height: 1392};
  const current = {x: -2500, y: 80, width: 1800, height: 1200};
  const frame = {width: 0, height: 56};
  const horizontal = fitWindowLayout('horizontal', area, 2, frame, current);
  const vertical = fitWindowLayout('vertical', area, 2, frame, current);
  expect(horizontal).toMatchObject({width: 1280, height: 668});
  expect(vertical).toMatchObject({width: 560, height: 668});
  for (const rect of [horizontal, vertical]) {
    expect(rect.x).toBeGreaterThanOrEqual(area.x);
    expect(rect.y).toBeGreaterThanOrEqual(area.y);
    expect(rect.x + rect.width * 2 + frame.width).toBeLessThanOrEqual(area.x + area.width);
    expect(rect.y + rect.height * 2 + frame.height).toBeLessThanOrEqual(area.y + area.height);
  }
});

test('large displays use distinct promised sizes; invalid monitor data fails before resizing', () => {
  const area = {x: 0, y: 0, width: 2560, height: 1440};
  expect(fitWindowLayout('vertical', area, 1, {width: 0, height: 28}, area)).toMatchObject({width: 560, height: 820});
  expect(fitWindowLayout('horizontal', area, 1, {width: 0, height: 28}, area)).toMatchObject({width: 1440, height: 900});
  expect(() => fitWindowLayout('vertical', area, 0, {width: 0, height: 28}, area)).toThrow();
  const small = {x: 0, y: 24, width: 1281, height: 781};
  const fractional = fitWindowLayout('horizontal', small, 1.25, {width: 2, height: 31}, area);
  expect(fractional.x + Math.ceil(fractional.width * 1.25) + 2).toBeLessThanOrEqual(1281);
  expect(fractional.y + Math.ceil(fractional.height * 1.25) + 31).toBeLessThanOrEqual(805);
});

test('desktop startup and persisted preset changes resize the native window once per change', async ({page}) => {
  await page.addInitScript(() => {
    const state = window as unknown as {__sizes: unknown[]; __TAURI_INTERNALS__: unknown};
    state.__sizes = [];
    Object.defineProperty(window, 'isTauri', {value: true});
    state.__TAURI_INTERNALS__ = {
      metadata: {currentWindow: {label: 'main'}},
      invoke: async (command: string, payload: Record<string, unknown>) => {
        if (command === 'plugin:window|current_monitor') return {name:'Test display',size:{width:3200,height:2000},position:{x:0,y:0},workArea:{position:{x:0,y:48},size:{width:3200,height:1896}},scaleFactor:2};
        if (command === 'plugin:window|is_maximized') return false;
        if (command === 'plugin:window|inner_size') return {width:2000,height:1400};
        if (command === 'plugin:window|outer_size') return {width:2000,height:1456};
        if (command === 'plugin:window|outer_position') return {x:100,y:100};
        if (command === 'plugin:window|set_size') state.__sizes.push(payload.value);
        if (command === 'get_dashboard_state') return {profiles:[],providers:[],activeProfileId:null};
        if (command === 'get_live_status' || command === 'cached_live_status') return {state:'disconnected',status:{up:false},age_ms:0};
        return null;
      },
    };
  });
  await page.goto('/#appearance');
  await expect.poll(() => page.evaluate(() => (window as unknown as {__sizes: unknown[]}).__sizes.length)).toBe(1);
  await page.locator('[data-layout="vertical"]').click();
  await expect.poll(() => page.evaluate(() => (window as unknown as {__sizes: unknown[]}).__sizes.length)).toBe(2);
  expect(await page.evaluate(() => (window as unknown as {__sizes: unknown[]}).__sizes.at(-1))).toMatchObject({size:{type:'Logical',width:560,height:820}});
  await page.reload();
  await expect.poll(() => page.evaluate(() => (window as unknown as {__sizes: unknown[]}).__sizes.length)).toBe(1);
  expect(await page.evaluate(() => (window as unknown as {__sizes: unknown[]}).__sizes[0])).toMatchObject({size:{type:'Logical',width:560,height:820}});
  await page.locator('[data-layout="horizontal"]').click();
  await expect.poll(() => page.evaluate(() => (window as unknown as {__sizes: unknown[]}).__sizes.length)).toBe(2);
  expect(await page.evaluate(() => (window as unknown as {__sizes: unknown[]}).__sizes.at(-1))).toMatchObject({size:{type:'Logical',width:1440,height:900}});
});
