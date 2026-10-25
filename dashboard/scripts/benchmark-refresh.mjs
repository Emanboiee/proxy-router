// Run against `npm run dev -- --port 1420`; all controller calls are mocked.
import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import ts from 'typescript';
import {chromium} from '@playwright/test';

const base = new URL(process.argv[2] ?? 'http://127.0.0.1:1420');
if (base.protocol !== 'http:' || !['127.0.0.1', 'localhost'].includes(base.hostname)) {
  throw new Error('Use an isolated local Vite development server');
}
const source = fs.readFileSync(fileURLToPath(new URL('../tests/engine-controls.spec.ts', import.meta.url)), 'utf8');
const ast = ts.createSourceFile('fixture.ts', source, ts.ScriptTarget.Latest, true);
const fixture = ast.statements.find(node => ts.isVariableStatement(node)
  && node.declarationList.declarations.some(declaration => declaration.name.getText(ast) === 'desktopMock'));
if (!fixture) throw new Error('Desktop bridge fixture missing');
const mock = ts.transpileModule(fixture.getText(ast), {compilerOptions: {target: ts.ScriptTarget.ES2022}}).outputText;
const browser = await chromium.launch();
const results = {};
try {
  for (const before of [true, false]) {
    const page = await browser.newPage({viewport: {width: 1440, height: 900}});
    let replacements = 0;
    if (before) await page.route('**/src/main.ts', async route => {
      const response = await route.fetch();
      const body = (await response.text()).replace(/getLiveStatus\(\{\s*force:\s*false\s*\}\)/g, () => {
        replacements++;
        return 'getLiveStatus({ force: !options?.poll })';
      });
      await route.fulfill({response, body});
    });
    await page.addInitScript({content: mock + `
      desktopMock();
      const original = window.__TAURI_INTERNALS__.invoke;
      window.__forcedReads = 0;
      window.__TAURI_INTERNALS__.invoke = async (command, payload) => {
        if (command === 'get_live_status' && payload?.force) {
          window.__forcedReads++;
          await new Promise(resolve => setTimeout(resolve, 110));
        }
        return original(command, payload);
      };
    `});
    await page.goto(base.href);
    await page.getByRole('heading', {name: 'Disconnected', exact: true}).waitFor();
    const samples = [];
    for (let index = 0; index < 12; index++) {
      const connected = index % 2 === 0;
      const started = performance.now();
      await page.getByRole('button', {name: connected ? 'Connect' : 'Disconnect', exact: true})
        .evaluate(button => button.click());
      await page.getByRole('heading', {name: connected ? 'Connected' : 'Disconnected', exact: true}).waitFor();
      await page.locator('#rail-status').filter({hasText: connected ? 'Connected' : 'Disconnected'}).waitFor();
      samples.push(performance.now() - started);
    }
    if (before && replacements !== 1) throw new Error(`Baseline rewrite must match exactly once, matched ${replacements}`);
    samples.sort((a, b) => a - b);
    results[before ? 'before' : 'after'] = {
      samples_ms: samples, median_ms: (samples[5] + samples[6]) / 2, max_ms: samples[11],
      forced_reads: await page.evaluate(() => window.__forcedReads),
    };
    await page.close();
  }
  if (results.before.forced_reads !== 13 || results.after.forced_reads !== 0) {
    throw new Error('Unexpected bridge calls: benchmark did not exercise the expected path');
  }
  console.log(JSON.stringify({
    scope: 'Controlled Chromium bridge: forced status reads cost 110ms by injection; other bridge calls are immediate. Reverts only the cache flag. Not production/native latency or a statistical performance guarantee.',
    ...results,
  }, null, 2));
} finally {
  await browser.close();
}
