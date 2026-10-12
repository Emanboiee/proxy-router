import {test, expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test.beforeEach(async ({page}) => {
  await page.addInitScript(() => {
    const win = window as any;
    win.__calls = [];
    win.__identityDenied = false;
    const network = {
      connected: true, supported: true, ssid: 'Home WiFi', identity: 'available', auto: false,
      disconnect_on_loss: true, mapped_preset: null, presets: {}, last_applied: {},
      recent: ['Home WiFi', 'School WiFi', 'Cafe', 'Phone hotspot', 'Office'].map((ssid, i) => ({ssid, last_seen: 100-i})),
    };
    Object.defineProperty(window, 'isTauri', {value: true});
    Object.defineProperty(window, '__TAURI_INTERNALS__', {value: {
      invoke: (command: string, payload: any) => {
        win.__calls.push({command, payload});
        if (command === 'get_live_status' || command === 'cached_live_status') return Promise.resolve({state:'connected', status:{up:true, mode:'proxy', degraded_lanes:[]}});
        if (command === 'get_dashboard_state') return Promise.resolve({activeProfileId:'home', providers:[], profiles:[
          {id:'home', name:'Home custom', domains:[], routeMode:'direct', providerId:'direct', fallback:'direct', updatedAt:1},
          {id:'preset-school-warp-open', name:'School WARP + Proton', presetName:'school-warp-open', domains:[], routeMode:'selective', providerId:'cloudflare', fallback:'retry', updatedAt:1},
        ]});
        if (command === 'get_network' || command === 'reveal_network') {
          return Promise.resolve({status:network, presets:win.__identityDenied ? {...network, ssid:null, identity:'permission', recent:[]} : structuredClone(network)});
        }
        if (command === 'get_config') return Promise.resolve({routes:[], providers:{}});
        if (command === 'get_routing') return Promise.resolve({});
        if (command === 'set_network_disconnect') {network.disconnect_on_loss = payload.state === 'on'; return Promise.resolve(structuredClone(network));}
        if (command === 'set_network_preset') {(network.presets as any)[payload.ssid] = payload.preset; return Promise.resolve(structuredClone(network));}
        if (command === 'remove_network_preset') {delete (network.presets as any)[payload.ssid]; return Promise.resolve(structuredClone(network));}
        if (command === 'set_network_auto') {network.auto = payload.state === 'on'; return Promise.resolve(structuredClone(network));}
        return Promise.resolve();
      },
    }});
  });
});

test('reveals and hides all names, maps a recent network, and separates loss protection', async ({page}) => {
  await page.goto('/#connectivity');
  await expect(page.locator('.network-history-row')).toHaveCount(5);
  await expect(page.locator('#network-panel')).not.toContainText('Home WiFi');
  await page.getByRole('button', {name:'Show names', exact:true}).click();
  await expect(page.locator('#network-panel')).toContainText('Home WiFi');
  await expect(page.locator('#network-panel')).toContainText('School WiFi');
  await page.locator('#recent-network-1').selectOption('profile:preset-school-warp-open');
  await page.locator('.network-history-row').nth(1).getByRole('button', {name:'Save', exact:true}).click();
  await expect.poll(() => page.evaluate(() => (window as any).__calls)).toContainEqual({
    command:'set_network_preset', payload:{ssid:'School WiFi', preset:'profile:preset-school-warp-open'},
  });
  await page.getByRole('checkbox', {name:'Disconnect when the network is lost'}).uncheck();
  await expect.poll(() => page.evaluate(() => (window as any).__calls)).toContainEqual({
    command:'set_network_disconnect', payload:{state:'off'},
  });
  await expect(page.getByRole('button', {name:'Turn auto-switch on', exact:true})).toBeVisible();
  await page.getByRole('button', {name:'Hide names', exact:true}).click();
  await expect(page.locator('#network-panel')).not.toContainText('Home WiFi');
  await expect(page.locator('#network-panel')).not.toContainText('School WiFi');
  await expect(page.locator('.network-history-row')).toHaveCount(5);
  for (const width of [1440, 390]) {
    await page.setViewportSize({width, height:900});
    await page.locator("#main").evaluate(node => {node.scrollTop=0;});
    await page.screenshot({path:`/tmp/proxy-router-network-${width}.png`, fullPage:true});
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    const results = await new AxeBuilder({page}).analyze();
    expect(results.violations).toEqual([]);
  }
});

test('permission failure offers recovery and never maps a redaction placeholder', async ({page}) => {
  await page.goto('/#connectivity');
  await page.evaluate(() => {(window as any).__identityDenied = true;});
  await page.getByRole('button', {name:'Show names', exact:true}).click();
  await expect(page.locator('#network-panel')).toContainText('Location Services');
  await expect(page.locator('#network-panel')).not.toContainText('<redacted>');
  await expect(page.locator('#network-preset-select')).toHaveCount(0);
  await expect(page.getByRole('button', {name:'Check network', exact:true})).toBeVisible();
});
