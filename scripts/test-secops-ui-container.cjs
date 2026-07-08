#!/usr/bin/env node
'use strict';
// Browser stage for test-secops-ui-container.py. Real container API, no mocks.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const args = {};
for (let i = 2; i < process.argv.length; i += 2) {
  assert.ok(['--base-url', '--fixture', '--output', '--playwright-path', '--browser-path'].includes(process.argv[i]) && process.argv[i + 1], 'Expected named arguments');
  args[process.argv[i].slice(2)] = process.argv[i + 1];
}
assert.ok(args['base-url'] && args.fixture && args.output, 'base URL, fixture and output required');
const origin = new URL(args['base-url']).origin;
assert.ok(['http:', 'https:'].includes(new URL(origin).protocol), 'HTTP(S) origin required');
assert.ok(fs.statSync(args.fixture).size <= 1024 * 1024, 'Fixture bound');
assert.ok(!fs.existsSync(args.output), 'Output must be fresh');
const fixture = JSON.parse(fs.readFileSync(args.fixture, 'utf8'));
const token = process.env.SIGNAL_UI_GATE_TOKEN;
assert.ok(token, 'Token must be provided through environment');
const { chromium } = require(args['playwright-path'] || process.env.SIGNAL_PLAYWRIGHT_PATH || 'playwright-core');
const checks = [];
let browser;
async function check(name, action) { await action(); checks.push(name); console.log(`PASS ${name}`); }
async function main() {
  try {
    browser = await chromium.launch({ executablePath: args['browser-path'] || process.env.SIGNAL_BROWSER_PATH, headless: true, timeout: 15_000, args: ['--no-sandbox'] });
    const context = await browser.newContext({ timezoneId: 'Europe/Berlin' });
    const page = await context.newPage();
    page.setDefaultTimeout(10_000);
    const errors = [], external = [], queries = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => {
      const url = new URL(request.url());
      if (url.origin !== origin) external.push(url.origin);
      if (url.pathname === '/v1/events') queries.push(Object.fromEntries(url.searchParams));
    });
    const shell = await page.goto(origin + '/ui', { waitUntil: 'networkidle', timeout: 15_000 });
    await check('container serves reviewed embedded assets with restrictive security headers', async () => {
      assert.equal(shell.status(), 200);
      assert.ok(shell.headers()['content-security-policy'].includes("form-action 'none'"));
      assert.ok(shell.headers()['content-security-policy'].includes("connect-src 'self'"));
      assert.equal(shell.headers()['x-content-type-options'], 'nosniff');
      assert.equal(shell.headers()['cache-control'], 'no-store');
      for (const [name, route] of [['index.html', '/ui'], ['app.js', '/ui/app.js'], ['style.css', '/ui/style.css']]) {
        const response = await fetch(origin + route, { signal: AbortSignal.timeout(5000) });
        assert.equal(response.status, 200);
        const bytes = Buffer.from(await response.arrayBuffer());
        assert.deepEqual(bytes, fs.readFileSync(path.resolve(__dirname, '../apps/signal-server/ui', name)), 'Container asset differs from reviewed source');
        assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), fixture.assets_sha256[name], 'Asset differs from pinned stage input');
      }
    });
    await check('authenticated browser finds persisted example-rule finding', async () => {
      await page.locator('#api-token').fill(token);
      await page.locator('#connect-button').click();
      await page.waitForFunction(() => document.querySelectorAll('#findings-results .select-row').length === 1);
      assert.equal(await page.locator('#api-token').inputValue(), '');
      await page.locator('#findings-results .select-row').click();
      const detail = await page.locator('#finding-detail').textContent();
      assert.ok(detail.includes(fixture.finding_id));
      assert.ok(detail.includes('auth.login-failure'));
      assert.ok(detail.includes(fixture.event_id));
    });
    await check('finding link performs exact-ID query and returns both delayed retained copies', async () => {
      await page.locator('.evidence-link').filter({ hasText: fixture.event_id }).click();
      await page.waitForFunction(() => document.querySelectorAll('#events-results .select-row').length === 2);
      assert.equal(await page.locator('#events-id').inputValue(), fixture.event_id);
      assert.equal(await page.locator('#events-from').inputValue(), '');
      assert.equal(await page.locator('#events-to').inputValue(), '');
      assert.equal(queries.at(-1).event_id, fixture.event_id);
      assert.equal(queries.at(-1).from, undefined);
      assert.equal(queries.at(-1).to, undefined);
      assert.equal(queries.at(-1).order, 'desc');
      assert.equal(queries.at(-1).limit, '100');
      assert.equal((await page.locator('#events-results').textContent()).includes(fixture.unrelated_id), false);
      for (const index of [0, 1]) {
        await page.locator('#events-results .select-row').nth(index).click();
        const detail = await page.locator('#event-detail').textContent();
        assert.ok(detail.includes(fixture.event_id));
        assert.ok(detail.includes(fixture.event_timestamp));
        assert.ok(detail.includes(fixture.raw_integer));
        assert.ok(!detail.includes(fixture.unrelated_id));
      }
    });
    await check('hostile payload stays text and token is absent from rendered/persisted state', async () => {
      assert.equal(await page.evaluate(() => Boolean(globalThis.UI_CONTAINER_XSS)), false);
      assert.equal(await page.locator('#events-results img,#event-detail img').count(), 0);
      const state = await page.evaluate(() => ({ local: { ...localStorage }, session: { ...sessionStorage }, cookie: document.cookie, url: location.href, text: [...document.querySelectorAll('#findings-results,#events-results,#finding-detail,#event-detail')].map(node => node.textContent).join('') }));
      assert.ok(!JSON.stringify(state).includes(token));
      assert.deepEqual(state.local, {});
      assert.deepEqual(state.session, {});
    });
    await check('missing exact identity reports scoped retained-evidence absence', async () => {
      await page.locator('#events-id').fill(fixture.missing_id);
      await page.locator('#events-form button[type=submit]').click();
      await page.waitForFunction(() => document.querySelector('#events-status').textContent.includes('does not prove it never existed'));
      assert.equal(await page.locator('#events-results .select-row').count(), 0);
      assert.equal(queries.at(-1).event_id, fixture.missing_id);
    });
    await check('disconnect and wrong-token real 401 clear prior data and credentials', async () => {
      await page.locator('#disconnect-button').click();
      assert.equal(await page.locator('.select-row').count(), 0);
      assert.equal(await page.locator('.evidence-link').count(), 0);
      await page.locator('#api-token').fill('wrong-ui-container-token');
      await page.locator('#connect-button').click();
      await page.waitForFunction(() => document.querySelector('#connection-status').textContent.includes('Access denied'));
      assert.equal(await page.locator('#api-token').inputValue(), '');
      assert.equal(await page.locator('.select-row').count(), 0);
    });
    await check('real browser has no third-party traffic or uncaught errors', async () => {
      assert.deepEqual(external, []);
      assert.deepEqual(errors, []);
    });
    const report = { schema_version: 1, status: 'passed', scope: 'Real Chromium, immutable-container assets and authenticated WAL/Parquet/findings API; no mock API', checks, passed: checks.length, browser_version: browser.version(), assets_sha256: fixture.assets_sha256, captured_at: new Date().toISOString() };
    fs.writeFileSync(args.output, JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    console.log(JSON.stringify(report));
  } finally { if (browser) await browser.close(); }
}
const timer = setTimeout(() => { console.error('Browser container stage exceeded 55 seconds'); process.exit(1); }, 55_000);
main().catch(error => { console.error(error.stack); process.exitCode = 1; }).finally(() => clearTimeout(timer));
