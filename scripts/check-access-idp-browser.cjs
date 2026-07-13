#!/usr/bin/env node
'use strict';
// Actual established OIDC client + owned Chromium + monolith. Test tooling only.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const tls = require('node:tls');
const crypto = require('node:crypto');
const {Agent, fetch: tlsFetch} = require('../tools/identity/node_modules/undici');
const {chromium} = require('../tools/identity/node_modules/playwright-core');
let stage = 'prepare';

function localOrigin(value, protocol) {
  const url = new URL(value);
  assert.equal(url.protocol, protocol);
  assert.equal(url.hostname, '127.0.0.1');
  assert.ok(url.port && !url.username && !url.password);
  return url.origin;
}
async function boundedBytes(response, capacity) {
  const reader = response.body?.getReader();
  const chunks = [];
  let size = 0;
  if (reader) {
    try {
      for (;;) {
        const {done, value} = await reader.read();
        if (done) break;
        size += value.length;
        assert.ok(size <= capacity, 'finite response byte capacity');
        chunks.push(value);
      }
    } catch (error) { await reader.cancel(); throw error; }
  }
  return Buffer.concat(chunks, size);
}

async function main() {
  assert.deepEqual(process.argv.slice(2, 3), ['--config']);
  assert.equal(process.argv.length, 4);
  assert.ok(fs.statSync(process.argv[3]).size <= 65536);
  const configBytes = fs.readFileSync(process.argv[3]);
  assert.ok(configBytes.length <= 65536);
  const wire = JSON.parse(configBytes);
  if (wire.mode !== undefined) assert.equal(wire.mode, 'audit-composition');
  const issuerOrigin = localOrigin(wire.issuer, 'https:');
  const callbackOrigin = localOrigin(wire.callback, 'https:');
  const serverOrigin = localOrigin(wire.server_origin, 'http:');
  localOrigin(wire.debug_url, 'http:');
  const oidc = await import('../tools/identity/node_modules/openid-client/build/index.js');
  const checks = [];
  const ca = fs.readFileSync(path.join(wire.certs, 'root.pem'));
  const dispatcher = new Agent({connections: 4, pipelining: 1, maxHeaderSize: 16384,
    headersTimeout: 5000, bodyTimeout: 5000, connect: {ca, timeout: 5000}});
  let networkCalls = 0, browser, callbackServer, pendingCallback;
  // Parent owns this process group and its 100-second deadline. This earlier
  // hard exit leaves cleanup to that owner; it cannot create a passing report.
  const timer = setTimeout(() => { console.error('OIDC client finite deadline'); process.exit(1); }, 90000);
  timer.unref();

  async function providerFetch(input, options = {}) {
    const url = new URL(input instanceof Request ? input.url : input);
    assert.equal(url.origin, issuerOrigin);
    assert.ok(url.pathname.startsWith('/realms/signal-fixture/'));
    assert.ok(++networkCalls <= 128);
    const signal = options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(5000)]) : AbortSignal.timeout(5000);
    const reply = await tlsFetch(input, {...options, dispatcher, signal, redirect: 'error'});
    const bytes = await boundedBytes(reply, 65536);
    return new Response(bytes, {status: reply.status, statusText: reply.statusText, headers: reply.headers});
  }
  async function sdk(name) {
    const config = await oidc.discovery(new URL(wire.issuer), name, wire.secrets[name],
      oidc.ClientSecretBasic(), {[oidc.customFetch]: providerFetch, timeout: 5,
        execute: [oidc.enableNonRepudiationChecks]});
    for (const field of ['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'introspection_endpoint', 'revocation_endpoint']) {
      const endpoint = new URL(config.serverMetadata()[field]);
      assert.equal(endpoint.origin, issuerOrigin);
      assert.ok(endpoint.pathname.startsWith('/realms/signal-fixture/'));
    }
    return config;
  }
  async function context() {
    const ctx = await browser.newContext({serviceWorkers: 'block', acceptDownloads: false});
    await ctx.route('**/*', route => {
      const origin = new URL(route.request().url()).origin;
      return [issuerOrigin, callbackOrigin, serverOrigin].includes(origin) ? route.continue() : route.abort();
    });
    return ctx;
  }
  async function authorize(config, account) {
    assert.ok(!pendingCallback, 'one finite login at a time');
    const verifier = oidc.randomPKCECodeVerifier();
    const challenge = await oidc.calculatePKCECodeChallenge(verifier);
    const state = oidc.randomState(), nonce = oidc.randomNonce();
    let resolveCallback;
    const callback = new Promise(resolve => { resolveCallback = resolve; });
    pendingCallback = resolveCallback;
    const ctx = await context();
    try {
      const page = await ctx.newPage();
      page.setDefaultTimeout(15000);
      const url = oidc.buildAuthorizationUrl(config, {redirect_uri: wire.callback, scope: 'openid',
        code_challenge: challenge, code_challenge_method: 'S256', state, nonce, prompt: 'login'});
      await page.goto(url.href, {waitUntil: 'domcontentloaded', timeout: 15000});
      await page.locator('#username').fill('fixture-' + account);
      await page.locator('#password').fill(wire.secrets.password);
      await page.locator('#kc-login').click();
      const current = await Promise.race([callback, new Promise((_, reject) => {
        const handle = setTimeout(() => reject(new Error('finite authorization callback')), 15000); handle.unref();
      })]);
      return {url: current, checks: {pkceCodeVerifier: verifier, expectedState: state, expectedNonce: nonce}};
    } finally {
      pendingCallback = undefined;
      await ctx.close();
    }
  }
  async function login(config, account) {
    const response = await authorize(config, account);
    const tokens = await oidc.authorizationCodeGrant(config, response.url, response.checks);
    assert.equal(tokens.claims()?.iss, wire.issuer);
    assert.equal(tokens.claims()?.sub, wire.subjects[account]);
    assert.ok(tokens.access_token && tokens.access_token.length <= 4096);
    assert.ok(tokens.id_token && tokens.refresh_token);
    return {tokens, response};
  }
  async function api(method, endpoint, token, body, extra = {}) {
    assert.ok(endpoint.startsWith('/v1/'));
    const headers = {'Content-Type': 'application/json', ...extra};
    if (token) headers.Authorization = 'Bearer ' + token;
    const response = await fetch(serverOrigin + endpoint, {method, headers,
      body: body === undefined ? undefined : JSON.stringify(body), redirect: 'error',
      signal: AbortSignal.timeout(3000)});
    const bytes = await boundedBytes(response, 1024 * 1024);
    return {status: response.status, body: response.headers.get('content-type')?.startsWith('application/json') ? JSON.parse(bytes) : undefined};
  }
  async function control(operation) {
    assert.ok(['pause', 'unpause'].includes(operation));
    fs.writeFileSync(path.join(wire.scratch, 'control-' + operation), '', {flag: 'wx', mode: 0o600});
    const deadline = Date.now() + 15000;
    while (!fs.existsSync(path.join(wire.scratch, 'ack-' + operation))) {
      assert.ok(Date.now() < deadline, 'bounded provider control');
      await new Promise(resolve => setTimeout(resolve, 20));
    }
  }


  async function compositionPhase(name, result = {}) {
    assert.ok(['login', 'ingested', 'granted', 'denied', 'unverified', 'provider-pause',
      'provider-denied', 'provider-recovered', 'receiver-stop', 'receiver-denied',
      'recovered', 'observability-stop', 'final'].includes(name));
    const index = compositionIndex++;
    assert.ok(index < 16);
    const prefix = path.join(wire.scratch, 'composition-' + index);
    fs.writeFileSync(prefix + '.request.tmp', JSON.stringify({generation: wire.generation, index, phase: name, result}),
      {flag: 'wx', mode: 0o600});
    fs.renameSync(prefix + '.request.tmp', prefix + '.request');
    const until = Date.now() + 20000;
    while (!fs.existsSync(prefix + '.ack')) {
      assert.ok(Date.now() < until, 'finite composition phase');
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.ok(fs.statSync(prefix + '.ack').size <= 1024);
    assert.deepEqual(JSON.parse(fs.readFileSync(prefix + '.ack')),
      {generation: wire.generation, index, phase: name});
  }
  let compositionIndex = 0;
  async function composition() {
    stage = 'composition-login';
    const config = await sdk('signal-fixture');
    const a = await login(config, 'a'), admin = await login(config, 'admin');
    // Secrets stay in this child. Only digests are used by the parent's log scanner.
    const sensitive = [a.tokens.access_token, a.tokens.refresh_token, a.tokens.id_token,
      admin.tokens.access_token, admin.tokens.refresh_token, admin.tokens.id_token];
    await compositionPhase('login', {secret_digests: sensitive.map(v => crypto.createHash('sha256').update(v).digest('hex'))});
    const event = wire.event;
    stage = 'composition-ingest';
    let response = await api('POST', '/v1/events/batch', a.tokens.access_token, {events: [event]});
    assert.equal(response.status, 202); assert.equal(response.body.accepted, 1);
    assert.equal(response.body.schema_version, 1); assert.equal(response.body.rejected, 0);
    assert.deepEqual(response.body.event_ids, [event.id]); assert.equal(response.body.error, undefined);
    await compositionPhase('ingested', {status: response.status});
    async function query(token = a.tokens.access_token) {
      const res = await api('GET', '/v1/events', token);
      assert.equal(res.status, 200); assert.deepEqual(res.body.events, [event]);
      return {status: res.status};
    }
    stage = 'composition-granted'; await compositionPhase('granted', await query());
    stage = 'composition-denied'; response = await api('GET', '/v1/events', admin.tokens.access_token);
    assert.equal(response.status, 403); assert.ok(!response.body.events);
    await compositionPhase('denied', {status: response.status});
    stage = 'composition-unverified'; response = await api('GET', '/v1/events', a.tokens.id_token,
      undefined, {'x-forwarded-user': wire.subjects.a});
    assert.equal(response.status, 403); assert.ok(!response.body.events);
    await compositionPhase('unverified', {status: response.status});
    stage = 'composition-provider-outage'; await compositionPhase('provider-pause');
    const began = Date.now(); response = await api('GET', '/v1/events', a.tokens.access_token);
    assert.equal(response.status, 408); assert.ok(!response.body.events); assert.ok(Date.now() - began < 3000);
    await compositionPhase('provider-denied', {status: response.status});
    stage = 'composition-provider-recovered'; await compositionPhase('provider-recovered', await query());
    stage = 'composition-receiver-outage'; await compositionPhase('receiver-stop');
    response = await api('GET', '/v1/events', a.tokens.access_token);
    assert.equal(response.status, 503); assert.ok(!response.body.events);
    await compositionPhase('receiver-denied', {status: response.status});
    stage = 'composition-exact-recovery'; await compositionPhase('recovered', await query());
    await compositionPhase('observability-stop');
    stage = 'composition-final'; await compositionPhase('final', await query());
    // Check log exposure inside the secret-owning child; no tokens leave memory.
    assert.ok(fs.statSync(wire.log_scan).size <= 8 * 1024 * 1024);
    const logText = fs.readFileSync(wire.log_scan, 'utf8');
    assert.ok(!sensitive.some(v => logText.includes(v)));
    fs.writeFileSync(wire.report, JSON.stringify({schema_version: 1, status: 'passed_simulated',
      mode: 'audit-composition', phases: compositionIndex, browser: browser.version(),
      protocol_client: 'openid-client 6.8.8', network_calls: networkCalls}), {flag: 'wx', mode: 0o600});
  }

  try {
    callbackServer = https.createServer({key: fs.readFileSync(path.join(wire.certs, 'leaf.key')),
      cert: fs.readFileSync(path.join(wire.certs, 'leaf.pem')), maxHeaderSize: 8192,
      handshakeTimeout: 2000, headersTimeout: 2000, requestTimeout: 2000, keepAliveTimeout: 1000}, (req, res) => {
      let url;
      try {
        if (req.method !== 'GET' || !req.url || req.url.length > 4096) throw new Error('callback bounds');
        url = new URL(req.url, wire.callback);
        if (url.origin !== callbackOrigin || req.headers.host !== new URL(wire.callback).host) throw new Error('callback origin');
      } catch {
        res.writeHead(400); res.end(); return;
      }
      if (url.pathname !== '/callback' || !pendingCallback) {
        res.writeHead(400); res.end(); return;
      }
      const resolve = pendingCallback; pendingCallback = undefined;
      res.writeHead(200, {'Content-Type': 'text/html', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer'});
      res.end('<!doctype html><title>Local sign-in callback</title>Local sign-in completed.');
      resolve(url);
    });
    callbackServer.maxConnections = 8;
    callbackServer.on('clientError', (_error, socket) => {
      if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
      else socket.destroy();
    });
    await new Promise((resolve, reject) => {
      callbackServer.once('error', reject);
      callbackServer.listen(Number(new URL(wire.callback).port), '127.0.0.1', resolve);
    });
    browser = await chromium.connectOverCDP(wire.debug_url, {timeout: 10000});
    if (wire.mode === 'audit-composition') { await composition(); return; }
    stage = 'malformed-callback';
    await new Promise((resolve, reject) => {
      const socket = tls.connect({host: '127.0.0.1', port: Number(new URL(wire.callback).port), ca});
      const deadline = setTimeout(() => { socket.destroy(); reject(new Error('callback deadline')); }, 2000);
      let bytes = Buffer.alloc(0);
      socket.once('secureConnect', () => socket.write('GET http://[?synthetic-private-value HTTP/1.1\r\nHost: ' +
        new URL(wire.callback).host + '\r\nConnection: close\r\n\r\n'));
      socket.on('data', chunk => {
        bytes = Buffer.concat([bytes, chunk]);
        if (bytes.length > 8192) { socket.destroy(); reject(new Error('callback byte capacity')); }
      });
      socket.once('error', reject);
      socket.once('close', () => {
        clearTimeout(deadline);
        try { assert.ok(bytes.toString().startsWith('HTTP/1.1 400')); resolve(); } catch (error) { reject(error); }
      });
    });
    checks.push('malformed callback target returns bounded400 without credential diagnostics');
    stage = 'discovery';
    const config = await sdk('signal-fixture');
    checks.push('fixed authenticated HTTPS discovery and signed ID-token validation');
    stage = 'browser-sign-in';
    const replayProbe = await login(config, 'a');
    checks.push('actual isolated browser authorization-code PKCE/state/nonce sign-in');
    stage = 'state-and-replay';
    const wrongState = await authorize(config, 'a');
    await assert.rejects(oidc.authorizationCodeGrant(config, wrongState.url,
      {...wrongState.checks, expectedState: oidc.randomState()}));
    // A rejected state does not consume the code; its correct checks still work.
    await oidc.authorizationCodeGrant(config, wrongState.url, wrongState.checks);
    await assert.rejects(oidc.authorizationCodeGrant(config, replayProbe.response.url, replayProbe.response.checks));
    const wrongVerifier = await authorize(config, 'a');
    await assert.rejects(oidc.authorizationCodeGrant(config, wrongVerifier.url,
      {...wrongVerifier.checks, pkceCodeVerifier: oidc.randomPKCECodeVerifier()}));
    checks.push('state mismatch, code replay and wrong PKCE verifier rejection');
    // Real providers may revoke the replayed code's session. Scope acceptance
    // deliberately uses fresh sessions after the hostile protocol probes.
    const a = await login(config, 'a');
    const b = await login(config, 'b');
    stage = 'provider-token-profile';
    const introspection = await oidc.tokenIntrospection(config, b.tokens.access_token);
    for (const [field, expected] of Object.entries({active: true, iss: wire.issuer,
      sub: wire.subjects.b, token_type: 'Bearer'})) {
      stage = 'provider-token-profile-' + field;
      assert.equal(introspection[field], expected);
    }
    stage = 'provider-token-profile-audience';
    assert.ok([introspection.aud].flat().includes('signal'));
    stage = 'canonical-scopes';
    const events = ['b', 'a'].map(account => ({schema_version: 1, id: crypto.randomUUID(),
      timestamp: new Date().toISOString(), observed_at: new Date().toISOString(),
      source: {type: 'synthetic-idp'}, severity: 'info', message: 'synthetic-idp-event-' + account,
      resource: {kind: 'host', id: 'resource-' + account, account_id: account},
      attributes: {account_id: 'a', roles: ['forged-global']}, tags: []}));
    let response = await api('POST', '/v1/events/batch', a.tokens.access_token, {events});
    assert.equal(response.status, 403); assert.equal(response.body.accepted, 0);
    for (const [token, event] of [[b.tokens.access_token, events[0]], [a.tokens.access_token, events[1]]]) {
      stage = 'canonical-scopes-admit-' + event.resource.account_id;
      response = await api('POST', '/v1/events/batch', token, {events: [event]});
      assert.equal(response.status, 202, 'admission HTTP status ' + response.status);
    }
    stage = 'canonical-scopes-query';
    const until = Date.now() + 5000;
    for (;;) {
      response = await api('GET', '/v1/events?limit=1', a.tokens.access_token);
      assert.equal(response.status, 200);
      if (response.body.events.length) { assert.deepEqual(response.body.events, [events[1]]); break; }
      assert.ok(Date.now() < until); await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.deepEqual((await api('GET', '/v1/events?account=b', a.tokens.access_token)).body.events, []);
    assert.deepEqual((await api('GET', '/v1/events?limit=1', b.tokens.access_token)).body.events, [events[0]]);
    stage = 'canonical-scopes-findings';
    do {
      response = await api('GET', '/v1/findings?limit=1', a.tokens.access_token);
      assert.equal(response.status, 200);
      if (response.body.findings.length) break;
      assert.ok(Date.now() < until); await new Promise(resolve => setTimeout(resolve, 20));
    } while (true);
    assert.equal(response.status, 200); assert.deepEqual(response.body.findings.map(row => row.event_ids), [[events[1].id]]);
    checks.push('synced admission and persisted event/finding complete scopes before limits; roles/attributes cannot bypass');
    stage = 'denial-and-admin';
    assert.equal((await api('GET', '/v1/events?limit=bad', undefined, undefined, {'x-forwarded-user': 'admin'})).status, 401);
    assert.equal((await api('GET', '/v1/events', a.tokens.id_token)).status, 403);
    const unbound = await login(config, 'unbound');
    assert.equal((await api('GET', '/v1/events', unbound.tokens.access_token)).status, 403);
    const admin = await login(config, 'admin');
    assert.equal((await api('GET', '/v1/events', admin.tokens.access_token)).status, 403);
    assert.equal((await api('GET', '/v1/findings/feed?after=begin', a.tokens.access_token)).status, 403);
    assert.equal((await api('GET', '/v1/findings/feed?after=begin', admin.tokens.access_token)).status, 200);
    for (const endpoint of ['/v1/evidence', '/v1/admin', '/v1/rules', '/v1/audit']) {
      assert.equal((await api('GET', endpoint, admin.tokens.access_token)).status, 404);
    }
    checks.push('ID token, unbound identity, forwarded headers and implicit admin denial; separate global feed authority');
    stage = 'wrong-audience';
    const wrong = await login(await sdk('wrong-audience'), 'a');
    assert.equal((await api('GET', '/v1/events', wrong.tokens.access_token)).status, 403);
    checks.push('real wrong-resource access token denial');
    stage = 'console';
    const ctx = await context();
    try {
      const page = await ctx.newPage(); page.setDefaultTimeout(5000);
      await page.goto(serverOrigin + '/ui/', {waitUntil: 'domcontentloaded'});
      await page.locator('#api-token').fill(a.tokens.access_token);
      await page.locator('#connect-button').click();
      await page.waitForFunction(() => document.querySelectorAll('#findings-results tr').length === 1);
      assert.ok((await page.locator('#findings-results').textContent()).includes('Synthetic identity security event'));
      const persisted = await page.evaluate(() => [localStorage.length, sessionStorage.length]);
      assert.deepEqual(persisted, [0, 0]);
      await page.locator('#disconnect-button').click();
      assert.equal(await page.locator('#api-token').inputValue(), '');
    } finally { await ctx.close(); }
    checks.push('existing SecOps console with IdP-issued token, scoped finding and no browser token persistence');
    stage = 'revocation';
    await oidc.tokenRevocation(config, a.tokens.refresh_token, {token_type_hint: 'refresh_token'});
    assert.equal((await api('GET', '/v1/events', a.tokens.access_token)).status, 403);
    checks.push('real session revocation denies subsequent fresh introspection');
    stage = 'expiry';
    const short = await login(await sdk('short-lease'), 'a');
    assert.equal((await api('GET', '/v1/events', short.tokens.access_token)).status, 200);
    const end = Date.now() + 6000;
    while ((await api('GET', '/v1/events', short.tokens.access_token)).status !== 403) {
      assert.ok(Date.now() < end); await new Promise(resolve => setTimeout(resolve, 100));
    }
    checks.push('real token expiry denies subsequent request');
    stage = 'provider-outage';
    await control('pause');
    const began = Date.now();
    assert.equal((await api('GET', '/v1/events', b.tokens.access_token)).status, 408);
    assert.ok(Date.now() - began < 1500);
    await control('unpause');
    await new Promise(resolve => setTimeout(resolve, 150));
    assert.equal((await api('GET', '/v1/events', b.tokens.access_token)).status, 200);
    checks.push('actual paused provider causes bounded denial and recovers without credential cache');
    fs.writeFileSync(wire.report, JSON.stringify({schema_version: 1, status: 'passed_simulated', checks,
      browser: browser.version(), protocol_client: 'openid-client 6.8.8', network_calls: networkCalls}), {flag: 'wx', mode: 0o600});
    stage = 'passed';
    console.log('Established local IdP browser checks passed');
  } finally {
    clearTimeout(timer);
    if (browser) await browser.close();
    if (callbackServer) {
      callbackServer.closeAllConnections();
      await new Promise(resolve => callbackServer.close(resolve));
    }
    await dispatcher.destroy();
  }
}

main().catch(() => { console.error('Established local IdP check failed at: ' + stage); process.exitCode = 1; });
