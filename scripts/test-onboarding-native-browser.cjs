'use strict';
// Browser -> owned loopback relay -> real Standard endpoint with verified mTLS.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const http=require('node:http');
const https=require('node:https');
const crypto=require('node:crypto');
const {chromium}=require('../tools/identity/node_modules/playwright-core');
const config=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const agent=new https.Agent({cert:fs.readFileSync(config.cert),key:fs.readFileSync(config.key),ca:fs.readFileSync(config.ca),rejectUnauthorized:true,maxSockets:2});
let browser,closing;
let upstreamCount=0;
const server=http.createServer((req,res)=>{
  if(req.method!=='GET'||!/^\/(ui(?:\/[^?]*)?|v1\/(findings|coverage\/onboarding))(?:\?|$)/.test(req.url)){res.writeHead(404).end();return;}
  if(++upstreamCount>64){res.writeHead(429).end();return;}
  const upstream=https.request({hostname:'127.0.0.1',port:config.port,path:req.url,method:'GET',agent,
    headers:Object.fromEntries(['authorization','x-signal-coverage-scope'].filter(k=>req.headers[k]).map(k=>[k,req.headers[k]])),timeout:2000},reply=>{
    assert.equal(reply.socket.authorized,true);
    let bytes=0;res.writeHead(reply.statusCode,{'content-type':reply.headers['content-type']||'application/octet-stream','cache-control':'no-store'});
    reply.on('data',chunk=>{bytes+=chunk.length;if(bytes>524288){reply.destroy();res.destroy();}else res.write(chunk);});reply.on('end',()=>res.end());
  });
  upstream.on('timeout',()=>upstream.destroy());upstream.on('error',()=>{if(!res.headersSent)res.writeHead(503);res.end();});
  res.on('close',()=>upstream.destroy());upstream.end();
});
async function cleanup(){if(closing)return closing;closing=(async()=>{if(browser)await browser.close();server.closeAllConnections();if(server.listening)await new Promise(resolve=>server.close(resolve));agent.destroy();})();return closing;}
for(const sig of ['SIGTERM','SIGINT'])process.on(sig,()=>{const force=setTimeout(()=>process.exit(1),4000);cleanup().finally(()=>{clearTimeout(force);process.exit(1);});});
const timeout=setTimeout(()=>{cleanup().finally(()=>process.exit(1));},45000);
function publish(changes={},ttl=20000){
  const observed=Date.parse(config.payload.observed_at),now=Date.now();
  function shift(value){if(Array.isArray(value))return value.map(shift);if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,shift(v)]));if(typeof value==='string'&&/^\d{4}-\d{2}-\d{2}T.*Z$/.test(value)){const at=Date.parse(value);if(Number.isFinite(at))return new Date(at+now-observed).toISOString();}return value;}
  const payload=Object.assign(shift(config.payload),changes,{observed_at:new Date(now).toISOString(),expires_at:new Date(now+ttl).toISOString()});
  const body=Buffer.from(JSON.stringify(payload));const signature=crypto.sign(null,Buffer.concat([Buffer.from('PLATFORM::SIGNAL/onboarding/v1\0'),body]),fs.readFileSync(config.signing_key));
  const temp=config.report_path+'.browser.tmp';fs.writeFileSync(temp,JSON.stringify({schema_version:1,payload_base64:body.toString('base64'),signature_base64:signature.toString('base64')}));fs.renameSync(temp,config.report_path);
}
(async()=>{
  const checks=[];
  try{
    await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
    browser=await chromium.launch({headless:true,executablePath:process.env.SIGNAL_BROWSER_PATH||path.resolve('target/idp-browsers/chromium-1248/chrome-linux64/chrome')});
    const page=await browser.newPage();await page.goto(`http://127.0.0.1:${server.address().port}/ui`,{timeout:10000});
    await page.fill('#api-token','global');await page.click('#connect-button');await page.waitForFunction(()=>!document.querySelector('#findings-form button').disabled);
    await page.click('#onboarding-tab');assert.match(await page.textContent('#onboarding-status'),/unassessed/);
    await page.fill('#onboarding-scope',config.scope);
    async function refresh(){await page.click('#onboarding-form button');await page.waitForFunction(()=>!document.querySelector('#onboarding-form button').disabled);}
    if(config.unsupported){
      publish();await refresh();const text=await page.textContent('#onboarding-results');
      assert.match(await page.textContent('#onboarding-status'),/Coverage verified/);assert.match(text,/Blocked/);assert.match(text,/unsupported detection/);
      const result={status:'passed_simulated',scope:'actual native Standard unsupported loaded rule in real Chromium over verified backend mTLS',passed:1,checks:['verified source coverage still shows unsupported loaded detection blocked'],backend_tls_verified:true,actual_timestamp:new Date().toISOString()};
      fs.writeFileSync(process.argv[3],JSON.stringify(result,null,2)+'\n');process.stdout.write(JSON.stringify(result)+'\n');return;
    }
    publish();await refresh();assert.match(await page.textContent('#onboarding-status'),/Supported detections active/);
    checks.push('real native verified mTLS readiness reaches actual console; login alone unassessed');
    for(const [category,id,label]of [['permissions','read-audit','missing permission'],['categories','audit','missing category'],['state','baseline','missing state']]){
      publish({[category]:{[id]:'missing'}});await refresh();const text=await page.textContent('#onboarding-results');assert.match(text,/Blocked/);assert.ok(text.includes(label+': '+id));
      checks.push('actual native '+category+' blocker is visible');
    }
    publish({},2000);await refresh();assert.match(await page.textContent('#onboarding-status'),/Supported detections active/);
    await page.waitForFunction(()=>document.querySelector('#onboarding-status').textContent.includes('Assessment expired'));
    assert.equal(await page.locator('#onboarding-results tr').count(),0);checks.push('actual native attestation expiry clears active browser rows');
    await page.click('#disconnect-button');await page.fill('#api-token','read-a');await page.click('#connect-button');await page.waitForFunction(()=>!document.querySelector('#findings-form button').disabled);
    await refresh();await page.waitForFunction(()=>document.querySelector('#connection-status').textContent.includes('Access denied'));
    assert.equal(await page.locator('#onboarding-results tr').count(),0);checks.push('actual native read permission denial clears connection and readiness');
    assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
    const result={status:'passed_simulated',scope:'actual embedded console -> owned loopback relay -> verified mTLS Standard/native identity; signed synthetic source checks',passed:checks.length,checks,upstream_requests:upstreamCount,backend_tls_verified:true,actual_timestamp:new Date().toISOString()};
    fs.writeFileSync(process.argv[3],JSON.stringify(result,null,2)+'\n');process.stdout.write(JSON.stringify(result)+'\n');
  }finally{clearTimeout(timeout);await cleanup();}
})().catch(error=>{process.stderr.write(`${error.name}: ${error.message}\n`);process.exitCode=1;});
