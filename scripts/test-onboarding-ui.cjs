'use strict';
// Real Chromium with owned synthetic HTTP; native identity is qualified separately.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const {chromium} = require('../tools/identity/node_modules/playwright-core');
const root = path.resolve(__dirname, '..');
let mode = 'blocked';
let selectedScope;
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname.startsWith('/ui')) {
    const name = url.pathname === '/ui' ? 'index.html' : path.basename(url.pathname);
    if (!['index.html','app.js','style.css'].includes(name)) {res.writeHead(404).end();return;}
    res.setHeader('content-type', name.endsWith('.js') ? 'application/javascript' : name.endsWith('.css') ? 'text/css' : 'text/html');
    res.end(fs.readFileSync(path.join(root,'apps/signal-server/ui',name)));return;
  }
  res.setHeader('content-type','application/json');res.setHeader('cache-control','no-store');
  if (url.pathname === '/v1/findings') {res.end(JSON.stringify({schema_version:1,findings:[]}));return;}
  if (url.pathname !== '/v1/coverage/onboarding') {res.writeHead(404).end('{}');return;}
  selectedScope = req.headers['x-signal-coverage-scope'];
  assert.equal(req.headers.authorization,'Bearer fixture-ui-token');
  if (mode === 'pending') return;
  if (mode === 'denied') {res.writeHead(403).end('{}');return;}
  const active = mode === 'active';
  res.end(JSON.stringify({schema_version:1,stage:active?'detections_active':'coverage_verified',coverage:{status:'verified',reason_codes:[]},assessed_at:new Date().toISOString(),valid_until:active?new Date(Date.now()+800).toISOString():null,detections:[{id:'fixture.rule',active,blockers:active?[]:[{code:'missing_permission',requirement:'read-audit'},{code:'missing_category',requirement:'audit'},{code:'unknown_state',requirement:'baseline<script>window.XSS=true</script>'}]}]}));
});
const deadline = setTimeout(()=>{process.stderr.write('onboarding browser deadline\n');process.exit(1);},45000);
(async()=>{
  let browser;
  const checks=[];
  try {
    await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
    browser=await chromium.launch({headless:true,executablePath:process.env.SIGNAL_BROWSER_PATH || path.join(root,'target/idp-browsers/chromium-1248/chrome-linux64/chrome')});
    const page=await browser.newPage();
    await page.goto(`http://127.0.0.1:${server.address().port}/ui`,{timeout:10000});
    await page.fill('#api-token','fixture-ui-token');await page.click('#connect-button');
    await page.waitForFunction(()=>!document.querySelector('#findings-form button').disabled);
    await page.click('#onboarding-tab');
    assert.match(await page.textContent('#onboarding-status'),/unassessed/);
    checks.push('token entry does not verify source readiness');
    await page.fill('#onboarding-scope','fixture-scope');await page.click('#onboarding-form button');
    await page.waitForSelector('#onboarding-results tr');
    assert.equal(selectedScope,'fixture-scope');
    const blocked=await page.textContent('#onboarding-results');
    assert.match(blocked,/Blocked/);assert.match(blocked,/missing permission: read-audit/);assert.match(blocked,/missing category: audit/);assert.match(blocked,/unknown state: baseline/);
    assert.equal(await page.evaluate(()=>window.XSS),undefined);
    checks.push('scoped request displays permission/category/state blockers as inert text');
    mode='active';await page.click('#onboarding-form button');
    await page.waitForFunction(()=>document.querySelector('#onboarding-status').textContent.includes('Supported detections active'));
    await page.waitForFunction(()=>document.querySelector('#onboarding-status').textContent.includes('Assessment expired'));
    assert.equal(await page.locator('#onboarding-results tr').count(),0);
    checks.push('active readiness disappears on attestation expiry');
    mode='pending';await page.click('#onboarding-form button');await page.click('#onboarding-cancel');
    await page.waitForFunction(()=>document.querySelector('#onboarding-status').textContent.includes('cancelled'));
    checks.push('cancelled request leaves coverage unassessed');
    mode='denied';await page.click('#onboarding-form button');
    await page.waitForFunction(()=>document.querySelector('#connection-status').textContent.includes('Access denied'));
    assert.equal(await page.locator('#onboarding-results tr').count(),0);
    assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
    checks.push('denial disconnects and clears readiness without token persistence');
    const result={status:'passed_simulated',scope:'real Chromium / owned mock HTTP; not native host or production evidence',passed:checks.length,checks,actual_timestamp:new Date().toISOString()};
    const output=process.argv[2];if(output){fs.mkdirSync(path.dirname(output),{recursive:true});fs.writeFileSync(output,JSON.stringify(result,null,2)+'\n');}
    process.stdout.write(JSON.stringify(result)+'\n');
  } finally {
    clearTimeout(deadline);if(browser)await browser.close();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));
  }
})().catch(error=>{process.stderr.write(`${error.name}: ${error.message}\n`);process.exitCode=1;});
