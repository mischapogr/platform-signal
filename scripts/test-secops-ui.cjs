#!/usr/bin/env node
'use strict';

// Bounded browser acceptance: real Chromium, real embedded assets, mock API.
// This is not live pipeline, identity-provider, or production qualification.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

const defaults = {
  playwrightPath: process.env.SIGNAL_PLAYWRIGHT_PATH || 'playwright-core',
  browserPath: process.env.SIGNAL_BROWSER_PATH || undefined,
};
const options = { ...defaults };
for (let i = 2; i < process.argv.length; i += 2) {
  const key = { '--playwright-path': 'playwrightPath', '--browser-path': 'browserPath', '--output': 'output', '--base-url': 'baseUrl' }[process.argv[i]];
  if (!key || !process.argv[i + 1]) throw new Error('Usage: node scripts/test-secops-ui.cjs [--playwright-path PATH] [--browser-path PATH] [--output FILE] [--base-url URL]');
  options[key] = process.argv[i + 1];
}
if (options.baseUrl && !/^https?:\/\/[^/]+(?:\/)?$/.test(options.baseUrl)) throw new Error('--base-url must be an HTTP(S) origin');
const { chromium } = require(options.playwrightPath);
const uiRoot = path.resolve(__dirname, '../apps/signal-server/ui');
const assets = Object.fromEntries(['index.html', 'app.js', 'style.css'].map(name => [name, fs.readFileSync(path.join(uiRoot, name))]));
const assetHashes = Object.fromEntries(Object.entries(assets).map(([name, bytes]) => [name, crypto.createHash('sha256').update(bytes).digest('hex')]));
const token = 'browser-fixture-token-do-not-persist';
const hostile = '<img src=x onerror="globalThis.SIGNAL_XSS=true"><script>globalThis.SIGNAL_XSS=true</script>';
const eventId = '20000000-0000-4000-8000-000000000001';
const finding = {
  schema_version: 1, id: '30000000-0000-4000-8000-000000000001',
  rule_id: 'fixture.browser.rule', created_at: '2026-10-07T10:00:00Z',
  severity: 'high', title: hostile, event_ids: [eventId],
  attributes: { counter: '__RAW_INTEGER__', nested: { retained: true } },
};
const event = {
  schema_version: 1, id: eventId, timestamp: '2026-10-07T09:59:00Z',
  observed_at: '2026-10-07T10:00:00Z', source: { type: 'fixture.browser', name: 'fixture' },
  severity: 'error', message: hostile, attributes: { counter: '__RAW_INTEGER__' },
  resource: { kind: 'fixture', id: 'fixture-resource', account_id: '000000000000', region: 'eu-central-1' },
  tags: [],
};
const encode = value => JSON.stringify(value).replaceAll('"__RAW_INTEGER__"', '9007199254740993');
const headers = {
  'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff', 'cache-control': 'no-store',
  'referrer-policy': 'no-referrer',
};
let mode = 'normal';
const requests = [];
let pendingClosed = false;
const pending = new Set();
const response = endpoint => encode(endpoint === '/v1/findings'
  ? { schema_version: 1, findings: [finding] }
  : { schema_version: 1, events: [event], metadata: { scanned_partitions: 1, returned: 1, truncated: false } });
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  if (url.pathname.startsWith('/v1/')) {
    requests.push({ path: url.pathname, query: Object.fromEntries(url.searchParams), authorization: req.headers.authorization });
    res.setHeader('content-type', 'application/json');
    res.setHeader('cache-control', 'no-store');
    if (mode === 'pending') {
      pending.add(res);
      res.on('close', () => { pendingClosed = true; pending.delete(res); });
      return;
    }
    if (mode === 'unauthorized' || req.headers.authorization !== `Bearer ${token}`) {
      res.writeHead(401);
      res.end(encode({ schema_version: 1, error: { code: 'unauthorized', message: 'valid bearer token required' } }));
      return;
    }
    if (mode === 'rows') {
      res.end(encode(url.pathname === '/v1/findings'
        ? { schema_version: 1, findings: Array(101).fill(finding) }
        : { schema_version: 1, events: Array(101).fill(event), metadata: {} }));
      return;
    }
    if (mode === 'bytes' || mode === 'stream-bytes') {
      // Valid JSON exceeding the decoded bound. Chunked mode has no content length.
      const body = encode({ schema_version: 1, findings: [finding], padding: 'x'.repeat(8 * 1024 * 1024 + 1) });
      if (mode === 'bytes') res.setHeader('content-length', Buffer.byteLength(body));
      else res.write(body.slice(0, 4096));
      res.end(mode === 'bytes' ? body : body.slice(4096));
      return;
    }
    if (mode === 'malformed') { res.end('{"schema_version":1,'); return; }
    if (mode === 'whitespace') { res.end(' \n\t\r' + response(url.pathname) + '\n\t '); return; }
    res.end(response(url.pathname));
    return;
  }
  const asset = { '/ui': ['index.html', 'text/html; charset=utf-8'], '/ui/': ['index.html', 'text/html; charset=utf-8'], '/ui/app.js': ['app.js', 'application/javascript; charset=utf-8'], '/ui/style.css': ['style.css', 'text/css; charset=utf-8'] }[url.pathname];
  if (!asset) { res.writeHead(404); res.end(); return; }
  const body = assets[asset[0]];
  res.writeHead(200, { ...headers, 'content-type': asset[1] });
  res.end(body);
});

async function main() {
  let browser;
  const checks = [];
  const errors = [];
  const externalRequests = [];
  async function check(name, action) {
    await action();
    checks.push(name);
    process.stdout.write(`PASS ${name}\n`);
  }
  try {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    const fixtureOrigin = `http://127.0.0.1:${server.address().port}`;
    const origin = options.baseUrl ? options.baseUrl.replace(/\/$/, '') : fixtureOrigin;
    browser = await chromium.launch({ executablePath: options.browserPath, headless: true, timeout: 15_000, args: ['--no-sandbox'] });
    const context = await browser.newContext({ viewport: { width: 1280, height: 800 }, timezoneId: 'Europe/Berlin' });
    // --base-url qualifies real asset delivery only. API remains explicitly mocked.
    if (options.baseUrl) {
      await context.route(`${origin}/v1/**`, async route => {
        const upstream = new URL(route.request().url());
        const fetched = await context.request.get(fixtureOrigin + upstream.pathname + upstream.search, { headers: route.request().headers(), timeout: 10_000 });
        await route.fulfill({ response: fetched });
      });
    }
    const page = await context.newPage();
    page.setDefaultTimeout(10_000);
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => {
      if (new URL(request.url()).origin !== origin) externalRequests.push(request.url());
    });
    const navigate = await page.goto(`${origin}/ui`, { waitUntil: 'networkidle', timeout: 15_000 });
    assert.equal(navigate.status(), 200);
    const rows = kind => page.locator(`#${kind}-results tr`);
    const search = async kind => {
      if (kind === 'events') await page.locator('#events-tab').click();
      else await page.locator('#findings-tab').click();
      await page.locator(`#${kind}-form button[type="submit"]`).click();
    };
    const connect = async () => {
      await page.locator('#api-token').fill(token);
      await page.locator('#connect-button').click();
      await page.waitForFunction(() => !document.querySelector('#api-token').value);
    };
    const waitRow = kind => page.waitForFunction(k => document.querySelectorAll(`#${k}-results .select-row`).length === 1, kind);
    const waitError = kind => page.waitForFunction(k => /exceed|limit|large|invalid|failed|error|disconnect|unauthoriz|unable/i.test(document.querySelector(`#${k}-status`).textContent), kind);

    await check('disconnected state sends no API request and conceals credentials', async () => {
      assert.equal(requests.length, 0);
      assert.equal(await page.locator('#api-token').getAttribute('type'), 'password');
      assert.equal(await page.locator('#api-token').getAttribute('autocomplete'), 'off');
    });
    await check('connection authenticates same-origin findings and clears token input', async () => {
      await connect();
      await waitRow('findings');
      assert.equal(requests.at(-1).path, '/v1/findings');
      assert.equal(requests.at(-1).authorization, `Bearer ${token}`);
      assert.equal(requests.filter(r => r.path === '/v1/events').length, 0);
    });
    await check('hostile finding text remains text and raw large integers survive detail', async () => {
      assert.ok((await rows('findings').innerText()).includes('<img'));
      await page.locator('#findings-results .select-row').click();
      const detail = await page.locator('#finding-detail').textContent();
      assert.ok(detail.includes('9007199254740993'));
      assert.ok(detail.includes('nested'));
      assert.equal(await page.evaluate(() => Boolean(globalThis.SIGNAL_XSS)), false);
      assert.equal(await page.locator('#findings-results img, #finding-detail img').count(), 0);
    });
    await check('findings filters and local time inputs encode independently as UTC', async () => {
      await page.locator('#findings-severity').selectOption('high');
      await page.locator('#findings-rule').fill('fixture&rule=admin + unicode Ω');
      await page.locator('#findings-from').fill('2026-10-07T09:00');
      await page.locator('#findings-to').fill('2026-10-07T11:00');
      await page.locator('#findings-limit').fill('5');
      const before = requests.length;
      await search('findings');
      await page.waitForFunction(() => !document.querySelector('#findings-form button[type="submit"]').disabled);
      assert.ok(requests.length > before);
      const query = requests.at(-1).query;
      assert.equal(query.rule_id, 'fixture&rule=admin + unicode Ω');
      assert.equal(query.severity, 'high');
      assert.equal(query.limit, '5');
      assert.equal(new Date(query.from).toISOString(), '2026-10-07T07:00:00.000Z');
      assert.equal(new Date(query.to).toISOString(), '2026-10-07T09:00:00.000Z');
    });
    await check('explicit events search encodes source/account/resource/content filters', async () => {
      await page.locator('#events-tab').click();
      await page.locator('#events-from').fill('2026-10-07T09:00');
      await page.locator('#events-to').fill('2026-10-07T11:00');
      await page.locator('#events-severity').selectOption('error');
      await page.locator('#events-source').fill('fixture.browser');
      await page.locator('#events-account').fill('000000000000');
      await page.locator('#events-resource').fill('resource&other=x');
      await page.locator('#events-contains').fill('needle & + Ω');
      await page.locator('#events-limit').fill('3');
      await search('events');
      await waitRow('events');
      const query = requests.at(-1).query;
      assert.equal(query.source_type, 'fixture.browser');
      assert.equal(query.account, '000000000000');
      assert.equal(query.resource_id, 'resource&other=x');
      assert.equal(query.contains, 'needle & + Ω');
      assert.equal(query.limit, '3');
      assert.equal(query.severity, 'error');
    });
    await check('event detail preserves source/resource/raw numbers without executing message', async () => {
      await page.locator('#events-results .select-row').click();
      const detail = await page.locator('#event-detail').textContent();
      assert.ok(detail.includes('9007199254740993'));
      assert.ok(detail.includes('000000000000'));
      assert.ok(detail.includes('fixture.browser'));
      assert.equal(await page.evaluate(() => Boolean(globalThis.SIGNAL_XSS)), false);
    });
    await check('credentials absent from storage, URL, tables and detail', async () => {
      const persisted = await page.evaluate(() => ({ local: { ...localStorage }, session: { ...sessionStorage }, cookie: document.cookie, url: location.href, results: [...document.querySelectorAll('#findings-results,#events-results,#finding-detail,#event-detail')].map(e => e.textContent).join('') }));
      assert.equal(JSON.stringify(persisted).includes(token), false);
      assert.deepEqual(persisted.local, {});
      assert.deepEqual(persisted.session, {});
    });
    await check('401 disconnects and clears previous rows/detail before reconnection', async () => {
      mode = 'unauthorized';
      await search('events');
      await page.waitForFunction(() => /unauthoriz|disconnect|connect/i.test(document.querySelector('#connection-status').textContent) && document.querySelectorAll('.select-row').length === 0);
      assert.equal((await page.locator('#finding-detail').textContent()).includes('9007199254740993'), false);
      assert.equal((await page.locator('#event-detail').textContent()).includes(eventId), false);
      mode = 'normal';
      await connect();
      await waitRow('findings');
    });
    await check('result count limit rejects oversized response without stale rows', async () => {
      mode = 'rows';
      await search('findings');
      await waitError('findings');
      assert.equal(await page.locator('#findings-results .select-row').count(), 0);
      mode = 'normal';
    });
    for (const scenario of ['bytes', 'stream-bytes']) {
      await check(`${scenario} response enforces 8 MiB client bound`, async () => {
        mode = scenario;
        await search('findings');
        await waitError('findings');
        assert.equal(await page.locator('#findings-results .select-row').count(), 0);
        mode = 'normal';
      });
    }
    await check('malformed response reports bounded error and no results', async () => {
      mode = 'malformed';
      await search('findings');
      await waitError('findings');
      assert.equal(await page.locator('#findings-results .select-row').count(), 0);
      mode = 'normal';
    });
    await check('valid JSON with blank lines and leading whitespace retains exact row detail', async () => {
      mode = 'whitespace';
      await search('findings');
      await waitRow('findings');
      await page.locator('#findings-results .select-row').click();
      assert.ok((await page.locator('#finding-detail').textContent()).includes('9007199254740993'));
      mode = 'normal';
    });
    for (const kind of ['findings', 'events']) {
      await check(`${kind} pane cancel aborts pending request and keeps connection`, async () => {
        mode = 'pending';
        pendingClosed = false;
        const before = requests.length;
        await search(kind);
        const deadline = Date.now() + 3000;
        while (requests.length === before && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 20));
        assert.ok(requests.length > before);
        await page.locator(`#${kind}-cancel`).click();
        await page.waitForFunction(k => /cancel/i.test(document.querySelector(`#${k}-status`).textContent), kind);
        if (!options.baseUrl) {
          const closedDeadline = Date.now() + 3000;
          while (!pendingClosed && Date.now() < closedDeadline) await new Promise(resolve => setTimeout(resolve, 20));
          assert.equal(pendingClosed, true);
        }
        assert.equal(await page.locator('#disconnect-button').isEnabled(), true);
        assert.equal(await page.locator(`#${kind}-results .select-row`).count(), 0);
        mode = 'normal';
        await search(kind);
        await waitRow(kind);
      });
    }
    await check('controlled cancelled-fetch 401 cannot clear fresh results or disconnect', async () => {
      // The one controlled race fixture intentionally ignores AbortSignal: this
      // models an already-resolved response queued after a newer request starts.
      await page.evaluate(() => {
        const original = globalThis.fetch;
        let first = true;
        globalThis.fetch = (...args) => {
          if (first && String(args[0]).startsWith('/v1/findings?')) {
            first = false;
            return new Promise(resolve => { globalThis.fixtureResolveStale = resolve; });
          }
          return original(...args);
        };
        globalThis.fixtureRestoreFetch = () => { globalThis.fetch = original; };
      });
      await search('findings');
      await page.waitForFunction(() => typeof globalThis.fixtureResolveStale === 'function');
      await page.locator('#findings-cancel').click();
      // A normally aborted native fetch settles immediately. The controlled
      // promise above deliberately does not, so submit programmatically to
      // exercise the controller identity guard without enabling UI controls.
      await page.evaluate(() => document.querySelector('#findings-form').requestSubmit());
      await waitRow('findings');
      await page.evaluate(() => {
        globalThis.fixtureResolveStale(new Response('', { status: 401 }));
        globalThis.fixtureRestoreFetch();
        delete globalThis.fixtureRestoreFetch;
        delete globalThis.fixtureResolveStale;
      });
      await page.waitForTimeout(100);
      assert.equal(await page.locator('#connection-status').textContent(), 'Connected');
      assert.equal(await page.locator('#findings-results .select-row').count(), 1);
    });
    await check('actual 30-second request deadline aborts stalled response', async () => {
      mode = 'pending';
      pendingClosed = false;
      const started = Date.now();
      await search('findings');
      await page.waitForFunction(() => /timed out/i.test(document.querySelector('#findings-status').textContent), null, { timeout: 35_000 });
      const elapsed = Date.now() - started;
      assert.ok(elapsed >= 29_000 && elapsed < 35_000, `actual deadline elapsed ${elapsed}ms`);
      assert.equal(await page.locator('#findings-results .select-row').count(), 0);
      assert.equal(await page.locator('#disconnect-button').isEnabled(), true);
      mode = 'normal';
    });
    await check('disconnect aborts inflight request and clears result/detail state', async () => {
      // Pending-close assertion is direct only in local fixture mode.
      mode = 'pending';
      const before = requests.length;
      await search('findings');
      await page.waitForFunction(() => document.querySelector('#findings-form button[type="submit"]').disabled);
      const observedDeadline = Date.now() + 3000;
      while (requests.length === before && Date.now() < observedDeadline) await new Promise(resolve => setTimeout(resolve, 20));
      assert.ok(requests.length > before, 'pending request reached the fixture server');
      await page.locator('#disconnect-button').click();
      if (!options.baseUrl) {
        const deadline = Date.now() + 3000;
        while ((!pendingClosed || requests.length === before) && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 20));
        assert.equal(pendingClosed, true);
      }
      assert.equal(await page.locator('.select-row').count(), 0);
      assert.equal(await page.locator('#api-token').inputValue(), '');
      mode = 'normal';
    });
    await check('keyboard tabs switch panels and keyboard search selects a row', async () => {
      await connect();
      await waitRow('findings');
      await page.locator('#events-tab').focus();
      await page.keyboard.press('Enter');
      assert.equal(await page.locator('#events-pane').isVisible(), true);
      await page.locator('#events-form button[type="submit"]').focus();
      await page.keyboard.press('Enter');
      await waitRow('events');
      await page.locator('#events-results .select-row').focus();
      await page.keyboard.press('Enter');
      assert.ok((await page.locator('#event-detail').textContent()).includes(eventId));
    });
    await check('phone width keeps page within viewport while tables scroll locally', async () => {
      await page.setViewportSize({ width: 390, height: 844 });
      await page.waitForTimeout(100);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true);
      assert.equal(await page.locator('#disconnect-button').isVisible(), true);
    });
    await check('no third-party traffic or uncaught browser errors', async () => {
      assert.deepEqual(externalRequests, []);
      assert.deepEqual(errors, []);
    });
    const report = { schema_version: 1, scope: 'real Chromium / embedded UI assets / deterministic mock API; not pipeline or production qualification', controlled_race_fixture: 'one fetch promise ignores AbortSignal to exercise a stale 401 response; other API fixtures use loopback HTTP', passed: checks.length, checks, actual_timestamp: new Date().toISOString(), asset_origin: options.baseUrl ? 'provided server origin' : 'local fixture server', local_asset_sha256: assetHashes, client_limits: { rows: 100, decoded_response_bytes: 8 * 1024 * 1024 } };
    if (options.output) { fs.mkdirSync(path.dirname(options.output), { recursive: true }); fs.writeFileSync(options.output, JSON.stringify(report, null, 2) + '\n'); }
    process.stdout.write(JSON.stringify(report) + '\n');
  } finally {
    if (browser) await browser.close();
    for (const res of pending) res.destroy();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
}

const overallDeadline = setTimeout(() => {
  process.stderr.write('Browser acceptance exceeded its 180-second wall-clock bound\n');
  process.exit(1);
}, 180_000);
main().catch(error => { process.stderr.write(`${error.stack}\n`); process.exitCode = 1; }).finally(() => clearTimeout(overallDeadline));
