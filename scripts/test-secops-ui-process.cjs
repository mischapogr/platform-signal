#!/usr/bin/env node
'use strict';
// Real binary + browser + WAL/Parquet/findings, with an owned temporary data root.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {spawn} = require('node:child_process');
const args = {};
for (let i = 2; i < process.argv.length; i += 2) {
  assert.ok(['--binary', '--output-dir', '--playwright-path', '--browser-path'].includes(process.argv[i]) && process.argv[i + 1], 'Expected named path arguments');
  args[process.argv[i].slice(2)] = process.argv[i + 1];
}
assert.ok(args.binary && args['output-dir'], '--binary and --output-dir required');
const root = path.resolve(args['output-dir']);
assert.ok(!fs.existsSync(root), 'Output directory must be fresh');
fs.mkdirSync(root, {recursive: true, mode: 0o700});
const {chromium} = require(args['playwright-path'] || process.env.SIGNAL_PLAYWRIGHT_PATH || 'playwright-core');
const binary = path.resolve(args.binary);
const token = 'ui-process-fixture-token';
const eventId = '40000000-0000-4000-8000-000000000001';
const rawInteger = '9007199254740993';
fs.mkdirSync(path.join(root, 'rules'));
fs.writeFileSync(path.join(root, 'rules', 'fixture.yaml'), 'apiVersion: signal.dev/v1\nkind: Rule\nmetadata:\n  id: fixture.ui\n  name: UI fixture\nspec:\n  severity: high\n  match:\n    all:\n      - field: source.type\n        eq: fixture.ui\n  finding:\n    title: UI process finding\n');
fs.writeFileSync(path.join(root, 'server.yaml'), `schema_version: 1\nrules:\n  directories:\n    - ${JSON.stringify(path.join(root, 'rules'))}\n`);
const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('SIGNAL_')));
Object.assign(env, {SIGNAL_LISTEN: '127.0.0.1:0', SIGNAL_API_TOKEN: token, SIGNAL_WAL_DIR: path.join(root, 'wal'), SIGNAL_STORAGE_DIR: path.join(root, 'events'), SIGNAL_FINDINGS_DIR: path.join(root, 'findings'), SIGNAL_CONFIG: path.join(root, 'server.yaml'), SIGNAL_STORAGE_FLUSH_MS: '10'});
let child, browser, origin;
const checks = [];
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const log = fs.createWriteStream(path.join(root, 'server.log'), {flags: 'wx', mode: 0o600});
async function start() {
  origin = undefined;
  let pending = '';
  child = spawn(binary, [], {env, stdio: ['ignore', 'ignore', 'pipe']});
  child.stderr.on('data', chunk => {
    log.write(chunk); pending += chunk.toString();
    assert.ok(pending.length < 1024 * 1024, 'Startup log line exceeds bound');
    let newline;
    while ((newline = pending.indexOf('\n')) >= 0) {
      const line = pending.slice(0, newline); pending = pending.slice(newline + 1);
      try { const address = JSON.parse(line).fields?.listen; if (address) origin = `http://${address}`; } catch {}
    }
  });
  child.on('error', error => { pending = error.message; });
  const deadline = Date.now() + 15000;
  while (!origin && child.exitCode === null && Date.now() < deadline) await sleep(20);
  assert.ok(origin, `Server startup failed; inspect ${path.join(root, 'server.log')}`);
  assert.equal((await fetch(`${origin}/readyz`, {signal: AbortSignal.timeout(5000)})).status, 200);
}
async function stop() {
  if (!child || child.exitCode !== null) return;
  const current = child;
  current.kill('SIGTERM');
  const deadline = Date.now() + 10000;
  while (current.exitCode === null && Date.now() < deadline) await sleep(20);
  if (current.exitCode === null) { current.kill('SIGKILL'); await new Promise(resolve => current.once('exit', resolve)); }
  assert.equal(current.exitCode, 0, 'Graceful process exit failed');
}
async function api(endpoint) {
  const response = await fetch(`${origin}/v1/${endpoint}`, {headers: {Authorization: `Bearer ${token}`}, signal: AbortSignal.timeout(5000)});
  assert.equal(response.status, 200); return response.json();
}
async function main() {
  try {
    await start();
    const observed = new Date(Date.now() - 600000).toISOString();
    const stamp = new Date(Date.now() - 10 * 86400000).toISOString();
    const event = JSON.stringify({schema_version: 1, id: eventId, timestamp: stamp, observed_at: observed, source: {type: 'fixture.ui'}, severity: 'info', message: '<img src=x onerror=globalThis.UI_XSS=true>', attributes: {large: '__INTEGER__'}, tags: []}).replace('"__INTEGER__"', rawInteger);
    const unrelated = JSON.stringify({schema_version: 1, id: '40000000-0000-4000-8000-000000000002', timestamp: stamp, observed_at: observed, source: {type: 'fixture.other'}, severity: 'info', message: eventId, attributes: {}, tags: []});
    for (const body of [event, event, unrelated]) {
      const admitted = await fetch(`${origin}/v1/events`, {method: 'POST', headers: {Authorization: `Bearer ${token}`, 'Content-Type': 'application/json'}, body, signal: AbortSignal.timeout(5000)});
      assert.equal(admitted.status, 202);
    }
    const deadline = Date.now() + 15000;
    while ((await api('findings')).findings.length !== 1 && Date.now() < deadline) await sleep(30);
    assert.equal((await api('findings')).findings.length, 1);
    while ((await api(`events?event_id=${eventId}`)).events.length !== 2 && Date.now() < deadline) await sleep(30);
    assert.equal((await api(`events?event_id=${eventId}`)).events.length, 2);
    checks.push('actual HTTP admissions retain duplicate identities and exclude message-only UUID');
    browser = await chromium.launch({executablePath: args['browser-path'] || process.env.SIGNAL_BROWSER_PATH, headless: true, args: ['--no-sandbox']});
    const context = await browser.newContext();
    const page = await context.newPage(); page.setDefaultTimeout(10000);
    const errors = []; page.on('pageerror', error => errors.push(error.message));
    async function inspect() {
      const shell = await page.goto(`${origin}/ui`);
      assert.equal(shell.status(), 200);
      assert.ok(shell.headers()['content-security-policy'].includes("form-action 'none'"));
      for (const [file, route] of [['index.html', '/ui'], ['app.js', '/ui/app.js'], ['style.css', '/ui/style.css']]) {
        const asset = await fetch(origin + route, {signal: AbortSignal.timeout(5000)});
        assert.equal(asset.status, 200);
        assert.equal(await asset.text(), fs.readFileSync(path.resolve(__dirname, '../apps/signal-server/ui', file), 'utf8'), 'Binary embeds the reviewed current asset');
      }
      await page.locator('#api-token').fill(token); await page.locator('#connect-button').click();
      await page.waitForFunction(() => document.querySelectorAll('#findings-results .select-row').length === 1);
      await page.locator('#findings-results .select-row').click();
      assert.ok((await page.locator('#finding-detail').textContent()).includes(eventId));
      await page.locator('.evidence-link').click();
      await page.waitForFunction(() => document.querySelectorAll('#events-results .select-row').length === 2);
      assert.equal(await page.locator('#events-id').inputValue(), eventId);
      assert.equal(await page.locator('#events-from').inputValue(), '');
      assert.equal(await page.locator('#events-to').inputValue(), '');
      await page.locator('#events-results .select-row').first().click();
      const detail = await page.locator('#event-detail').textContent();
      assert.ok(detail.includes(eventId)); assert.ok(detail.includes(rawInteger));
      assert.equal(await page.evaluate(() => Boolean(globalThis.UI_XSS)), false);
      await page.locator('#events-id').fill('40000000-0000-4000-8000-000000000099');
      await page.locator('#events-form button[type=submit]').click();
      await page.waitForFunction(() => document.querySelector('#events-status').textContent.includes('does not prove it never existed'));
      assert.equal(await page.locator('#events-results .select-row').count(), 0);
    }
    await inspect(); checks.push('real browser exact-ID link finds delayed duplicate evidence with lossless detail and scoped absence');
    await page.locator('#disconnect-button').click();
    assert.equal(await page.locator('.select-row').count(), 0);
    await page.locator('#api-token').fill('wrong-token'); await page.locator('#connect-button').click();
    await page.waitForFunction(() => document.querySelector('#connection-status').textContent.includes('Access denied'));
    checks.push('real API rejects wrong token and disconnect clears data');
    await stop(); await start(); await inspect();
    checks.push('process restart preserves queryable finding/event for browser');
    assert.deepEqual(errors, []);
    const report = {status: 'passed', scope: 'Real local AMD64 signal-server + Chromium; WAL/Parquet/findings restart; not container/ARM64/EKS', checks, binary_sha256: crypto.createHash('sha256').update(fs.readFileSync(binary)).digest('hex'), assets_sha256: Object.fromEntries(['index.html','app.js','style.css'].map(file => [file,crypto.createHash('sha256').update(fs.readFileSync(path.resolve(__dirname,'../apps/signal-server/ui',file))).digest('hex')])), captured_at: new Date().toISOString()};
    fs.writeFileSync(path.join(root, 'report.json'), JSON.stringify(report, null, 2) + '\n'); console.log(JSON.stringify(report));
  } finally {
    if (browser) await browser.close();
    await stop(); log.end();
  }
}
main().catch(error => { console.error(error.stack); process.exitCode = 1; });
