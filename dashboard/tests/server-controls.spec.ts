import {selectWeb} from './select-web';
import {test,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test('desktop discovers installed servers and separates preference from switching',async({page})=>{
 await page.addInitScript(()=>{
  Object.defineProperty(window,'isTauri',{value:true});
  const providers=[
   {id:'proton',name:'Proton',kind:'wireguard',status:'unknown',latency:null,server:'server-00',servers:Array.from({length:23},(_,i)=>'server-'+String(i).padStart(2,'0')),preferredServer:null,capabilities:{serverSelection:true,reconnect:false}},
   {id:'warp',name:'Cloudflare WARP',kind:'custom',status:'unknown',latency:null,server:'Automatic endpoint',servers:[],preferredServer:null,capabilities:{serverSelection:false,reconnect:true}}
  ];
  let failSwitch=true;
  const state={profiles:[{id:'school',name:'School',providerId:'proton',routeMode:'selective',domains:['ai.example'],autoSubdomains:false,fallback:'direct'}],providers,activeProfileId:'school'};
  Object.defineProperty(window,'__TAURI_INTERNALS__',{value:{invoke:(command:string,args:any)=>{
   if(command==='get_dashboard_state')return Promise.resolve(structuredClone(state));
   if(command==='get_config')return Promise.resolve({preset:'school',providers:{proton:{directory:true},warp:{socks5:true}},routes:[{id:'ai',provider:'proton',domains:['ai.example']},{id:'chat',provider:'warp',domains:['chat.example']}]});
   if(['get_live_status','cached_live_status'].includes(command))return Promise.resolve({state:'connected',status:{up:true},age_ms:0});
   if(command==='save_server_preference'){providers[0].preferredServer=args.server;return Promise.resolve(structuredClone(state));}
   if(command==='switch_dashboard_server'){
    if(failSwitch){failSwitch=false;return Promise.reject(new Error('Server check failed; previous connection restored'));}
    providers[0].server=args.server;return Promise.resolve('ok');
   }
   return Promise.resolve({});
  }}});
 });
 await page.goto('/');
 await expect(page.locator('#preferred-server option')).toHaveCount(24);
 await selectWeb(page.locator('#preferred-server'), 'server-22');
 await expect(page.locator('.server-current')).toContainText('server-00');
 await page.getByRole('button',{name:'Switch now',exact:true}).click();
 await expect(page.locator('#announcement')).toContainText('previous connection restored');
 await expect(page.locator('.server-current')).toContainText('server-00');
 await page.getByRole('button',{name:'Switch now',exact:true}).click();
 await expect(page.locator('.server-current')).toContainText('server-22');
 await page.getByRole('button',{name:'Browse 23 installed servers →'}).click();
 await expect(page.locator('#server-inventory tbody tr')).toHaveCount(23);
 await page.screenshot({path:'test-results/server-dialog-desktop.png'});
 await page.setViewportSize({width:390,height:844});
 await page.screenshot({path:'test-results/server-dialog-mobile.png'});
 expect((await new AxeBuilder({page}).analyze()).violations).toEqual([]);
 expect(await page.evaluate(()=>document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
 await page.setViewportSize({width:1280,height:720});
 const scrolling=page.locator('.server-inventory-scroll');
 expect(await scrolling.evaluate(el=>el.scrollHeight>el.clientHeight)).toBe(true);
 await page.locator('#server-search').fill('server-17');
 await expect(page.locator('#server-inventory tbody tr')).toHaveCount(1);
 await page.getByRole('button',{name:'Prefer',exact:true}).click();
 await page.keyboard.press('Escape');
 await expect(page.getByRole('button',{name:'Browse 23 installed servers →'})).toBeFocused();
 await expect(page.locator('#preferred-server')).toHaveValue('server-17');
 await selectWeb(page.locator('#server-provider'), 'warp');
 await expect(page.locator('#preferred-server')).toHaveCount(0);
 await expect(page.locator('#main')).toContainText('chooses its endpoint automatically');
 await expect(page.locator('#main')).not.toContainText('DEMO-');
});
