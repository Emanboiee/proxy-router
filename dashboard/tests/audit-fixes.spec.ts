import {test, expect} from '@playwright/test';

test('missing provider config shows feedback inside the open editor', async ({page}) => {
  await page.goto('/#providers');
  await page.locator('.provider-instances').getByRole('button', {name:/Proton VPN/}).click();
  await page.getByRole('button', {name:'Add WireGuard configs',exact:true}).click();
  await page.getByRole('button', {name:'Add server',exact:true}).click();
  await expect(page.locator('#provider-dialog')).toBeVisible();
  await expect(page.locator('#provider-dialog .provider-feedback')).toHaveText('Choose at least one WireGuard .conf file');
});

test('desktop import preserves rules and remains open after a save failure', async ({page}) => {
  await page.addInitScript(() => {
    const state = window as unknown as {saved:unknown[]}; state.saved = [];
    Object.defineProperty(window, 'isTauri', {value:true});
    Object.defineProperty(window, '__TAURI_INTERNALS__', {value:{invoke:(command:string, payload?:{profile:unknown}) => {
      if (command === 'save_dashboard_profile') {
        state.saved.push(payload?.profile);
        if (state.saved.length === 1) return Promise.reject(new Error('Could not write profile. Try again.'));
      }
      if (command === 'save_dashboard_profile' || command === 'get_dashboard_state') return Promise.resolve({profiles:[],providers:[],activeProfileId:null});
      if (command === 'cached_live_status' || command === 'get_live_status') return Promise.resolve({state:'disconnected',status:{up:false,degraded_lanes:[]}});
      return Promise.resolve({});
    }}});
  });
  await page.goto('/#profiles');
  await page.getByRole('button', {name:'Import',exact:true}).click();
  const profile = {name:'Advanced import',providerId:'proton',fallbackProviderId:'warp',fallback:'retry',routeRules:[{id:'models',providerId:'proton',domains:['opencode.ai'],autoSubdomains:true,fallback:'block',enabled:false}]};
  const raw = JSON.stringify({proxyRouterProfile:1,profile});
  await page.getByLabel('Profile JSON').fill(raw);
  const submit = page.getByRole('button', {name:'Import profile',exact:true});
  await submit.click();
  await expect(page.locator('#import-dialog')).toBeVisible();
  await expect(page.locator('#import-feedback')).toHaveText('Could not write profile. Try again.');
  await expect(page.getByLabel('Profile JSON')).toHaveValue(raw);
  await submit.click();
  await expect(page.locator('#import-dialog')).toBeHidden();
  const saved = await page.evaluate(() => (window as unknown as {saved:unknown[]}).saved);
  expect(saved).toHaveLength(2);
  expect(saved[1]).toMatchObject(profile);
});

test('failed imports retain input; advanced routing survives import', async ({page}) => {
  await page.goto('/#profiles');
  await page.getByRole('button', {name:'Import', exact:true}).click();
  const dialog = page.locator('#import-dialog');
  const input = page.getByLabel('Profile JSON');
  await input.fill('{');
  await dialog.getByRole('button', {name:'Import profile', exact:true}).click();
  await expect(dialog).toBeVisible();
  await expect(input).toHaveValue('{');
  await expect(dialog.getByRole('alert')).toHaveText('Invalid JSON. Check the pasted export and try again.');
  await expect(input).toHaveAttribute('aria-invalid', 'true');
  await dialog.getByRole('button', {name:'Cancel', exact:true}).click();
  await page.getByRole('button', {name:'Import', exact:true}).click();
  await expect(input).toHaveValue('{');
  await input.fill(JSON.stringify({proxyRouterProfile:1, profile:{name:'Mixed routes', providerId:'warp', fallbackProviderId:'proton', fallback:'retry', routeRules:[
    {id:'social',providerId:'warp',domains:['discord.com'],autoSubdomains:true,fallback:'block',enabled:false},
    {id:'models',providerId:'proton',domains:['opencode.ai'],autoSubdomains:false,fallback:'direct'},
  ]}}));
  await dialog.getByRole('button', {name:'Import profile', exact:true}).click();
  await expect(dialog).toBeHidden();
  await page.locator('.profile-card').filter({hasText:'Mixed routes'}).getByRole('button', {name:'Edit',exact:true}).click();
  const rules = page.locator('[data-route-rule]');
  await expect(rules).toHaveCount(2);
  await expect(rules.first().locator('[name="route-provider"]')).toHaveValue('warp');
  await expect(rules.first().locator('[name="route-enabled"]')).not.toBeChecked();
  await expect(rules.last().locator('[name="route-domains"]')).toHaveValue('opencode.ai');
});

test('delete requires explicit in-app confirmation and cancellation retains profile', async ({page}) => {
  await page.goto('/#profiles');
  const card = page.locator('.profile-card').filter({hasText:'OpenCode only'});
  await card.locator('.profile-more summary').click();
  await card.getByRole('button', {name:'Delete',exact:true}).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByRole('heading')).toHaveText('Delete profile “OpenCode only”?');
  await expect(dialog.getByRole('button', {name:'Cancel',exact:true})).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(card).toBeVisible();
  await expect(card.locator('.profile-more summary')).toBeFocused();
});

test('desktop theme updates preserve live data while dashboard refresh is pending', async ({page}) => {
  await page.addInitScript(() => {
    let reads = 0;
    Object.defineProperty(window, 'isTauri', {value:true});
    Object.defineProperty(window, '__TAURI_INTERNALS__', {value:{invoke:(command:string) => {
      if (command === 'get_dashboard_state') {
        if (++reads > 1) return new Promise(() => {});
        return Promise.resolve({activeProfileId:'real', profiles:[{id:'real',name:'Real saved profile',description:'',providerId:'direct',routeMode:'direct',domains:[],fallback:'direct',autoSubdomains:false,updatedAt:1}],providers:[]});
      }
      if (command === 'cached_live_status' || command === 'get_live_status') return Promise.resolve({state:'connected',status:{up:true,degraded_lanes:[]}});
      if (command === 'get_network') return Promise.resolve({presets:{connected:true,ssid:null,auto:true,presets:{},recent:[]}});
      return Promise.reject(new Error('Audit mock unavailable'));
    }}});
  });
  await page.goto('/#profiles');
  await expect(page.getByRole('heading', {name:'Real saved profile',exact:true})).toBeVisible();
  await page.getByRole('link', {name:'Appearance',exact:true}).click();
  await page.locator('.themes').getByRole('button', {name:'Iris',exact:true}).click();
  await expect(page.locator('html')).toHaveAttribute('data-accent', 'iris');
  await page.getByRole('link', {name:'Profiles',exact:true}).click();
  await expect(page.getByRole('heading', {name:'Real saved profile',exact:true})).toBeVisible();
  await expect(page.locator('#main')).not.toContainText('School access');
});
