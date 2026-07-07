#!/usr/bin/env python3
"""Render the shared deck into offline HTML, Markdown notes and editable PPTX.

HTML/Markdown use Python and the shared cost engine uses Node.js at build time.
Run from any directory: python3 build.py. Earlier PPTX/PDF exports are historical.
"""
import argparse
import csv
import html
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO_BLOB = "https://github.com/mischapogr/platform-signal/blob/main"
DATA = json.loads((ROOT / "deck.json").read_text())
MODEL = json.loads((ROOT / "cost-model.json").read_text())
BASELINE = json.loads(subprocess.check_output([
    "node", "-e", "const m=require(process.argv[1]);const c=require(process.argv[2]);console.log(JSON.stringify(c.evaluate(m)));",
    str(ROOT / "cost-model.json"), str(ROOT / "cost-model.js")
], text=True))


def usd(value):
    return f'${value:,.0f}'


def model_table(name):
    scenarios = BASELINE
    headings = ['Assumption / monthly USD'] + [f'{s["accounts"]:,} account' + ('s' if s['accounts'] != 1 else '') for s in scenarios]
    inventory = {
        'inventory': [('EC2 hosts (outside EKS)', 'ec2'), ('EKS clusters', 'eks'), ('EKS worker nodes', 'nodes'), ('Selected running pods', 'pods'), ('Aurora clusters / instances', None), ('Other RDS instances', 'rdsInstances')],
        'inventory-other': [('Lambda functions', 'lambda'), ('Selected S3 buckets', 'buckets'), ('Workload load balancers', 'loadbalancers'), ('SIGNAL servers / collectors', None), ('SIGNAL control DB deployments', 'controlDBs'), ('SIGNAL EBS GiB', 'ebsGiB')]
    }
    if name in inventory:
        headings[0] = 'Illustrative inventory'
        rows = []
        for label, key in inventory[name]:
            values = [f'{s[key]:,}' for s in scenarios] if key else ([f'{s["auroraClusters"]:,} / {s["auroraInstances"]:,}' for s in scenarios] if name == 'inventory' else [f'{s["servers"]} / {s["collectors"]}' for s in scenarios])
            rows.append([label] + values)
    elif name == 'traffic':
        headings[0] = 'Selected traffic / 30-day month'
        rows = [
            ['Canonical GB/day'] + [f'{s["gbDay"]:,.2f}' for s in scenarios],
            ['Messages/day (millions)'] + [f'{s["messagesDay"]/1e6:,.2f}' for s in scenarios],
            ['Mean canonical bytes/message'] + [f'{s["meanBytes"]:,.0f}' for s in scenarios],
            ['Average EPS / 5× burst EPS'] + [f'{s["eps"]:,.0f} / {s["burstEPS"]:,.0f}' for s in scenarios],
            ['Stored normalized / original TiB'] + [f'{s["normalizedGiB"]/1024:,.2f} / {s["originalGiB"]/1024:,.2f}' for s in scenarios]
        ]
    elif name == 'cost':
        rows = [
            ['EC2 + EBS/snapshots + control DB'] + [usd(sum(s['components'][k] for k in ['compute', 'disks', 'control'])) for s in scenarios],
            ['S3 retained telemetry + originals'] + [usd(s['components']['s3']) for s in scenarios],
            ['Network/API + requests/security + monitoring'] + [usd(sum(s['components'][k] for k in ['network','requests','security','transport','monitoring'])) for s in scenarios],
            ['Direct SIGNAL AWS subtotal'] + [usd(s['directAWS']) for s in scenarios],
            ['Selected CloudWatch source delivery'] + [usd(s['sourceDelivery']) for s in scenarios],
            ['AWS baseline / +40% planning reserve'] + [f'{usd(s["totalAWS"])} / {usd(s["budgetAWS"])}' for s in scenarios]
        ]
    elif name == 'hours':
        headings[0] = 'Scheduled person-hours / month'
        labels = ['Health / capacity / failed retries','Release and dependency maintenance','Backup / restore exercises','Source / identity configuration','Cost / retention review']
        rows = [[label] + [f'{s["operationBands"][i][0]}–{s["operationBands"][i][1]}' for s in scenarios] for i,label in enumerate(labels)]
        rows.append(['Platform operations subtotal'] + [f'{s["platformHours"][0]}–{s["platformHours"][1]}' for s in scenarios])
    elif name == 'staffing':
        headings[0] = 'Post-stable-release estimate'
        rows = [
            ['Platform operations hours/month'] + [f'{s["platformHours"][0]}–{s["platformHours"][1]}' for s in scenarios],
            ['Detection / policy tuning hours/month'] + [f'{s["detectionHours"][0]}–{s["detectionHours"][1]}' for s in scenarios],
            ['Total scheduled hours/month'] + [f'{s["laborHours"][0]}–{s["laborHours"][1]}' for s in scenarios],
            ['FTE effort (160 hours/month)'] + [f'{s["fte"][0]:.2f}–{s["fte"][1]:.2f}' for s in scenarios],
            ['Labor USD/month at assumed $100/hour'] + [f'{usd(s["laborUSD"][0])}–{usd(s["laborUSD"][1])}' for s in scenarios],
            ['AWS + labor USD/month (no reserve)'] + [f'{usd(s["fullyLoaded"][0])}–{usd(s["fullyLoaded"][1])}' for s in scenarios]
        ]
    else:
        raise ValueError(name)
    return {'headers': headings, 'rows': rows}


DIAGRAMS = ROOT.parent.parent / "diagrams"


def check_diagrams():
    """Fail the build when diagram sources, renders and the architecture doc disagree."""
    doc = (ROOT.parent.parent / "logical-architecture.md").read_text()
    fence = re.search(r"```mermaid\n(.*?)```", doc, re.S).group(1)
    if fence != (DIAGRAMS / "02-logical-architecture.mmd").read_text():
        raise SystemExit("docs/logical-architecture.md and docs/diagrams/02-logical-architecture.mmd differ; keep one copy")
    missing = [f.name for f in DIAGRAMS.glob("[0-9][0-9]-*.mmd") if not (DIAGRAMS / "dist" / (f.stem + ".svg")).exists()]
    if missing:
        raise SystemExit(f"run docs/diagrams/render.sh: no SVG for {missing}")


def diagram_block(d):
    """Embed a pre-rendered Mermaid SVG; keep its source for copy/export in the browser."""
    name = d["mermaid"]
    svg = (DIAGRAMS / "dist" / f"{name}.svg").read_text()
    source = (DIAGRAMS / f"{name}.mmd").read_text()
    root = re.match(r'<svg\b[^>]*>', svg).group(0)
    tag = re.sub(r'\s(width|height|class|role|aria-roledescription)="[^"]*"', '', root)
    tag = tag[:-1] + f' class="diagram" role="img" aria-label="{html.escape(d["label"], quote=True)}">'
    svg = tag + svg[len(root):]
    link = f'{REPO_BLOB}/docs/diagrams/{name}.mmd'
    return (f'<figure class="figure" data-diagram="{name}"><button class="zoom" type="button" aria-label="Open diagram full size">{svg}</button>'
            f'<script type="text/plain" class="mmd">{html.escape(source)}</script>'
            f'<figcaption>{esc(d["description"])} <a href="{link}" target="_blank" rel="noopener">Mermaid source</a></figcaption></figure>')


def chart_svg(name):
    import math
    volume = name == 'volume'
    field = 'gbDay' if volume else 'totalAWS'
    ticks = [1,10,100,1000,10000] if volume else [100,1000,10000,100000]
    minimum, maximum = math.log10(ticks[0]), math.log10(ticks[-1])
    x = lambda v: 220+(math.log10(v)-minimum)/(maximum-minimum)*720
    svg = ['<svg class="chart" viewBox="0 0 1176 360" role="img" aria-label="Baseline ' + ('daily canonical GB' if volume else 'monthly AWS cost USD') + ', logarithmic scale">']
    for tick in ticks:
        pos = x(tick)
        svg.append(f'<path d="M{pos},20 V295" stroke="#d3dce8"/><text x="{pos}" y="325" text-anchor="middle" fill="#475569" font-size="16">{tick:,}</text>')
    for i,s in enumerate(BASELINE):
        y = 32+i*66
        label = f'{s[field]:,.2f} GB/day' if volume else usd(s[field])+'/month'
        svg.append(f'<text x="5" y="{y+23}" fill="#0f1b2d" font-size="20">{s["accounts"]:,} account{"s" if s["accounts"] != 1 else ""}</text><rect x="220" y="{y}" width="{x(s[field])-220}" height="35" rx="5" fill="#0f766e"/><text x="{x(s[field])+10}" y="{y+23}" fill="#0f1b2d" font-size="18">{label}</text>')
    svg.append('<text x="580" y="355" text-anchor="middle" fill="#475569" font-size="15">LOGARITHMIC SCALE · baseline assumptions · not measured capacity</text></svg>')
    return ''.join(svg)


def esc(value):
    return html.escape(value).replace("\n", "<br>")


def absolute(url):
    if url.startswith("http"):
        return url
    if url.startswith("../../"):
        return f"{REPO_BLOB}/docs/{url[6:]}"
    return f"{REPO_BLOB}/docs/presentations/aws-adoption/{url}"


def source_links(keys):
    return " · ".join(
        f'<a href="{html.escape(absolute(DATA["sources"][key][1]), quote=True)}" target="_blank" rel="noopener">{esc(DATA["sources"][key][0])}</a>'
        for key in keys
    )


CSS = """
:root{color-scheme:light;--bg:#ffffff;--panel:#f4f7fb;--ink:#0f1b2d;--muted:#475569;--accent:#0f766e;--line:#d3dce8;--scale:1}
*{box-sizing:border-box}body{margin:0;background:#e8edf3;color:var(--ink);font-family:Arial,Helvetica,sans-serif;overflow:hidden}
button,a{touch-action:manipulation}button{font:inherit;color:var(--ink);border:1px solid var(--line);background:var(--panel);padding:8px 13px;border-radius:6px;cursor:pointer}
button:hover{border-color:var(--accent)}:focus-visible{outline:3px solid var(--accent);outline-offset:3px}a{color:#0b5f58;text-underline-offset:3px}
.toolbar{height:56px;display:flex;gap:8px;align-items:center;padding:8px 20px;border-bottom:1px solid var(--line)}.brand{font-size:14px;letter-spacing:2px;margin-right:auto}.toolbar output{min-width:68px;text-align:center;color:var(--muted);font-size:14px}
#stage{position:absolute;inset:56px 0 0}.slide{display:none;position:absolute;left:50%;top:50%;width:1280px;height:720px;transform:translate(-50%,-50%) scale(var(--scale));padding:42px 52px 30px;background:var(--bg);border-top:5px solid var(--accent);grid-template-rows:auto auto auto 1fr auto auto;gap:15px;overflow:hidden}
.slide.active{display:grid}.eyebrow{font-size:14px;letter-spacing:2.2px;text-transform:uppercase;color:var(--accent)}h1{font-size:43px;line-height:1.08;letter-spacing:-1.4px;margin:0;max-width:1150px}.subtitle{font-size:21px;color:var(--muted);line-height:1.4;margin:0;max-width:1120px}
.body{min-height:0;display:flex;flex-direction:column;justify-content:center;gap:20px}.cards{display:grid;grid-template-columns:repeat(var(--cols),1fr);gap:18px}.card{border:1px solid var(--line);background:var(--panel);padding:23px 24px;border-radius:9px}.card h2{font-size:22px;color:var(--accent);margin:0 0 16px}.card ul{margin:0;padding-left:20px}.card li{font-size:20px;line-height:1.34;margin-bottom:13px}.card li:last-child{margin-bottom:0}
.callout{font-size:19px;line-height:1.35;border-left:4px solid var(--accent);padding:10px 15px;background:#e6f4f1;margin:0}.footer{font-size:10.5px;color:var(--muted);display:flex;gap:16px;align-items:end;line-height:1.45}.footer .citations{flex:1}.footer .page{white-space:nowrap;font-size:12px}
.hero{--bg:#0b1f33;--ink:#f2f6fb;--muted:#c3d2e3;--accent:#5eead4;color:var(--ink);background:radial-gradient(ellipse at 90% 30%,#134e4a 0,transparent 55%),var(--bg)}.hero h1{font-size:78px;letter-spacing:-3px;line-height:1.03;margin:10px 0}.hero .subtitle{max-width:830px;font-size:25px}.hero .body{justify-content:end}.hero-mark{font-size:15px;letter-spacing:5px;color:var(--muted)}.hero .callout{background:#0f2f3a;color:var(--ink)}.zoom::after{content:"Click to enlarge · copy Mermaid / SVG / PNG";display:block;font-size:12px;color:var(--muted);text-align:right}.callout:empty,.subtitle:empty{display:none}.figure figcaption{max-height:2.8em;overflow:hidden}.hero .footer a{color:#99f6e4}.hero .footer{color:var(--muted)}
.flow{display:grid;grid-template-columns:repeat(4,1fr);gap:24px}.node{position:relative;background:#eaf2fb;border:1px solid #bcd0e6;border-radius:9px;padding:20px;min-height:116px}.node h2{font-size:20px;margin:0 0 12px;color:var(--accent)}.node p{font-size:17px;line-height:1.4;margin:0;color:var(--ink)}.node:not(:last-child)::after{content:'→';position:absolute;right:-23px;top:42px;font-size:27px;color:var(--accent)}.accounts .node::after{display:none}.flow-slide .card{padding:18px}.flow-slide .card h2{font-size:19px;margin-bottom:12px}.flow-slide .card li{font-size:18px}
table{width:100%;border-collapse:collapse;table-layout:fixed;font-size:18px;line-height:1.3}th{text-align:left;color:var(--accent);background:#eaf2fb;padding:13px 15px;border-bottom:2px solid #9fb3c8}td{vertical-align:top;padding:15px;border-bottom:1px solid var(--line)}tbody tr:nth-child(even){background:#f8fafc}td:first-child{font-weight:bold}table.cols-4 th:first-child{width:20%}table.cols-3 th:first-child{width:22%}
.refs{display:grid;grid-template-columns:1fr 1fr;gap:9px 28px}.ref{font-size:16px;line-height:1.2;padding:5px 0;border-bottom:1px solid var(--line)}.ref small{display:block;font-size:10px;color:var(--muted);overflow-wrap:anywhere;margin-top:5px}
.diagram,.chart{width:100%;max-height:380px;display:block}.dense table{font-size:16px}.dense th,.dense td{padding:10px 12px}.cols-5 th:first-child{width:31%}.calculator{display:grid;gap:12px}.calc-controls{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.calc-controls label{font-size:13px;color:var(--muted);display:grid;gap:5px}.calc-controls select{font-size:16px;padding:7px;background:var(--panel);color:var(--ink);border:1px solid #9fb3c8;border-radius:4px;min-width:0}.calc-controls .check{display:flex;align-items:center;gap:8px}.calc-controls input{width:18px;height:18px}.calc-results{display:grid;grid-template-columns:repeat(4,1fr);gap:15px}.calc-result{background:var(--panel);padding:15px;border:1px solid var(--line);border-radius:8px}.calc-result h2{font-size:17px;margin:0 0 12px;color:var(--accent)}.calc-result strong{font-size:26px;display:block;margin-bottom:9px}.calc-result p{font-size:14px;line-height:1.4;margin:6px 0;color:var(--muted)}.calc-result .total{color:var(--ink)}.calc-context{font-size:14px;color:var(--muted);line-height:1.4;margin:0}.calc-controls button{font-size:13px}.diagram-desc{font-size:14px;line-height:1.4;color:var(--muted);margin:0}
.figure{margin:0;display:grid;gap:8px;min-height:0}.zoom{border:1px solid var(--line);background:#fff;padding:8px;border-radius:9px;cursor:zoom-in;display:block;width:100%}.zoom .diagram{width:100%;height:auto;max-height:372px;display:block;margin:0 auto}.figure figcaption{font-size:13px;line-height:1.4;color:var(--muted)}
#zoom{width:min(96vw,1700px);max-height:94vh}#zoom .zoom-bar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center}#zoom .zoom-view{overflow:auto;background:#fff;border:1px solid var(--line);border-radius:8px;padding:12px;max-height:74vh}#zoom .zoom-view svg{display:block;width:100%;min-width:900px;height:auto}#zoom-status{font-size:13px;color:var(--muted)}
.notice{font-size:12px;line-height:1.45;color:var(--muted);margin:0}
#notes{position:absolute;right:0;top:56px;bottom:0;width:370px;overflow:auto;padding:26px;background:var(--panel);border-left:1px solid var(--line);font-size:17px;line-height:1.6}#notes h2{color:var(--accent);font-size:20px}body.with-notes #stage{right:370px}[hidden]{display:none!important}dialog{width:min(720px,90vw);max-height:85vh;overflow:auto;background:var(--panel);color:var(--ink);border:1px solid var(--line);border-radius:12px;padding:28px}dialog::backdrop{background:#000b}.outline{display:grid;gap:8px}.outline button{text-align:left}#help{font-size:13px;color:var(--muted)}
@media(max-width:700px){body{overflow:auto}.brand{display:none}.toolbar{position:sticky;top:0;z-index:2;background:var(--bg);padding:7px;gap:4px}.toolbar button{font-size:12px;padding:8px}#stage{position:relative;inset:auto}.slide{position:relative;left:auto;top:auto;width:100%;height:auto;min-height:calc(100dvh - 56px);transform:none;padding:25px 20px;overflow:visible;gap:18px}h1{font-size:32px}.hero h1{font-size:49px}.hero .subtitle,.subtitle{font-size:18px}.cards,.flow,.refs{grid-template-columns:1fr}.card li{font-size:18px}.node:not(:last-child)::after{display:none}.body{overflow-x:auto}table{min-width:780px;font-size:16px}.footer{font-size:10px}.callout{font-size:17px}body.with-notes #stage{right:auto}#notes{position:relative;inset:auto;width:100%}.toolbar output{min-width:42px;font-size:12px}}
@media(max-width:700px){.calc-controls,.calc-results{grid-template-columns:1fr 1fr}.chart{min-width:950px}.zoom .diagram{min-width:700px}.calc-result strong{font-size:21px}.calc-result{padding:12px}.calc-context{font-size:13px}}
@media print{@page{size:13.333333in 7.5in;margin:0}html,body{margin:0;padding:0;overflow:visible;background:var(--bg);print-color-adjust:exact;-webkit-print-color-adjust:exact}.toolbar,#notes,dialog{display:none!important}#stage,body.with-notes #stage{position:static;inset:auto}.slide,.slide.active{display:grid!important;position:relative;left:auto;top:auto;transform:none;width:1280px;height:720px;min-height:0;break-after:page;break-inside:avoid;margin:0}.slide:last-child{break-after:auto}.cards{grid-template-columns:repeat(var(--cols),1fr)}.flow{grid-template-columns:repeat(4,1fr)}.refs{grid-template-columns:1fr 1fr}}
"""

JS = """
const slides=[...document.querySelectorAll('.slide')];let index=0;
const stage=document.querySelector('#stage'),notes=document.querySelector('#notes'),dialog=document.querySelector('#contents');
function resize(){document.documentElement.style.setProperty('--scale',Math.min(stage.clientWidth/1280,(stage.clientHeight-12)/720));}
function show(n){index=Math.max(0,Math.min(slides.length-1,n));slides.forEach((s,i)=>{s.classList.toggle('active',i===index);s.setAttribute('aria-hidden',i===index?'false':'true');});document.querySelector('#counter').value=`${index+1} / ${slides.length}`;document.querySelector('#note-text').textContent=slides[index].dataset.notes;document.querySelector('#prev').disabled=index===0;document.querySelector('#next').disabled=index===slides.length-1;history.replaceState(null,'',`#slide-${index+1}`);resize();}
document.querySelector('#prev').onclick=()=>show(index-1);document.querySelector('#next').onclick=()=>show(index+1);
function toggleNotes(){const open=notes.hidden;notes.hidden=!open;document.body.classList.toggle('with-notes',open);document.querySelector('#toggle-notes').setAttribute('aria-expanded',String(open));resize();}
document.querySelector('#toggle-notes').onclick=toggleNotes;document.querySelector('#open-contents').onclick=()=>dialog.showModal();document.querySelector('#close-contents').onclick=()=>dialog.close();
document.querySelector('#print').onclick=()=>window.print();document.querySelector('#fullscreen').onclick=async()=>{try{if(document.fullscreenElement)await document.exitFullscreen();else await document.documentElement.requestFullscreen();}catch{document.querySelector('#help').textContent='Fullscreen is unavailable in this browser. Use its presentation or fullscreen command.';}};
document.querySelectorAll('[data-slide]').forEach(b=>b.onclick=()=>{show(Number(b.dataset.slide));dialog.close();});
window.addEventListener('keydown',e=>{if(dialog.open||zoomDialog.open||/INPUT|TEXTAREA|SELECT|BUTTON|A/.test(e.target.tagName)||e.ctrlKey||e.altKey||e.metaKey)return;if(['ArrowRight','PageDown',' '].includes(e.key)){e.preventDefault();show(index+1);}else if(['ArrowLeft','PageUp'].includes(e.key)){e.preventDefault();show(index-1);}else if(e.key==='Home')show(0);else if(e.key==='End')show(slides.length-1);else if(e.key.toLowerCase()==='n')toggleNotes();});
window.addEventListener('resize',resize);window.addEventListener('hashchange',()=>{const n=Number(location.hash.replace('#slide-',''));if(n>0&&n<=slides.length)show(n-1);});
const initial=Number(location.hash.replace('#slide-',''));show(Number.isInteger(initial)&&initial>0?initial-1:0);

const zoomDialog=document.querySelector('#zoom'),zoomView=document.querySelector('#zoom-view'),zoomStatus=document.querySelector('#zoom-status');let zoomFigure=null;
document.querySelectorAll('.figure .zoom').forEach(b=>b.onclick=()=>{zoomFigure=b.closest('.figure');zoomView.replaceChildren(b.querySelector('svg').cloneNode(true));zoomStatus.textContent=zoomFigure.dataset.diagram;zoomDialog.showModal();});
document.querySelector('#zoom-close').onclick=()=>zoomDialog.close();
const mmd=()=>zoomFigure.querySelector('.mmd').textContent;
const svgText=()=>{const n=zoomView.querySelector('svg').cloneNode(true);n.setAttribute('xmlns','http://www.w3.org/2000/svg');return new XMLSerializer().serializeToString(n);};
function save(blob,name){const u=URL.createObjectURL(blob),a=document.createElement('a');a.href=u;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(u),1000);}
document.querySelector('#zoom-copy').onclick=async()=>{try{await navigator.clipboard.writeText(mmd());zoomStatus.textContent='Mermaid copied. Paste it into Miro, FigJam, draw.io, Slack canvas or a Markdown fence.';}catch{zoomStatus.textContent='Clipboard blocked by this browser. Use the Mermaid source link.';}};
document.querySelector('#zoom-svg').onclick=()=>save(new Blob([svgText()],{type:'image/svg+xml'}),zoomFigure.dataset.diagram+'.svg');
document.querySelector('#zoom-png').onclick=()=>{const svg=zoomView.querySelector('svg'),vb=svg.viewBox.baseVal,k=3,img=new Image();img.onload=()=>{const c=document.createElement('canvas');c.width=vb.width*k;c.height=vb.height*k;const x=c.getContext('2d');x.fillStyle='#fff';x.fillRect(0,0,c.width,c.height);x.drawImage(img,0,0,c.width,c.height);c.toBlob(b=>save(b,zoomFigure.dataset.diagram+'.png'));};img.onerror=()=>{zoomStatus.textContent='PNG export failed. Download the SVG instead.';};img.src='data:image/svg+xml;charset=utf-8,'+encodeURIComponent(svgText().replace('<svg ',`<svg width="${vb.width}" height="${vb.height}" `));};
const costInputs=document.querySelectorAll('[data-cost-option]');
const money=n=>new Intl.NumberFormat('en-US',{style:'currency',currency:'USD',maximumFractionDigits:0}).format(n);
function updateCosts(){const settings={};costInputs.forEach(e=>settings[e.dataset.costOption]=e.type==='checkbox'?e.checked:Number(e.value));const result=SignalCostModel.evaluate(signalCostInput,settings);document.querySelectorAll('.calc-result').forEach((e,i)=>{const s=result[i];e.querySelector('.aws-value').textContent=money(s.totalAWS)+'/mo';e.querySelector('.direct-value').textContent='Direct SIGNAL AWS: '+money(s.directAWS);e.querySelector('.source-value').textContent='Source delivery: '+money(s.sourceDelivery);e.querySelector('.budget-value').textContent='+40% AWS reserve: '+money(s.budgetAWS);e.querySelector('.traffic-value').textContent=s.gbDay.toLocaleString('en-US',{maximumFractionDigits:2})+' GB/day · '+Math.round(s.eps).toLocaleString('en-US')+' EPS';e.querySelector('.labor-value').textContent='Labor: '+money(s.laborUSD[0])+'–'+money(s.laborUSD[1])+'/mo';e.querySelector('.loaded-value').textContent='AWS + labor: '+money(s.fullyLoaded[0])+'–'+money(s.fullyLoaded[1]);});globalThis.latestCostResults=result;}
costInputs.forEach(e=>e.addEventListener('change',updateCosts));document.querySelector('#reset-costs').onclick=()=>{costInputs.forEach(e=>{const v=signalCostInput.defaults[e.dataset.costOption];if(e.type==='checkbox')e.checked=v;else e.value=String(v);});updateCosts();};updateCosts();
"""


def build_html():
    check_diagrams()
    (ROOT / 'estimate-baseline.json').write_text(json.dumps(BASELINE, indent=2) + '\n')
    fields = ['accounts', 'gbDay', 'messagesDay', 'meanBytes', 'eps', 'burstEPS', 'normalizedGiB', 'originalGiB', 'directAWS', 'sourceDelivery', 'totalAWS', 'budgetAWS']
    with (ROOT / 'cost-estimates.csv').open('w', newline='') as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(fields + ['scheduled_hours_low', 'scheduled_hours_high', 'fully_loaded_usd_low', 'fully_loaded_usd_high'])
        for s in BASELINE:
            writer.writerow([s[k] for k in fields] + s['laborHours'] + s['fullyLoaded'])
    rendered = []
    outline = []
    markdown = [f'# {DATA["title"]}', f'Source snapshot: {DATA["date"]}. Estimated delivery: 40–45 minutes plus discussion; use Contents to select chapters.', '']
    for i, slide in enumerate(DATA["slides"], 1):
        kind = slide.get("kind", "content")
        slide = dict(slide)
        if "table_model" in slide:
            slide["table"] = model_table(slide["table_model"])
        classes = "slide " + ("hero" if kind == "hero" else "flow-slide" if kind == "flow" else "")
        if slide.get("accounts_view"):
            classes += " accounts"
        if "table" in slide and len(slide["table"]["headers"]) >= 5:
            classes += " dense"
        body = ""
        if kind == "hero":
            body += '<p class="hero-mark">OPEN MECHANISMS / PRIVATE COMPANY POLICY</p>'
        if "nodes" in slide:
            body += '<div class="flow">' + ''.join(f'<div class="node"><h2>{esc(t)}</h2><p>{esc(b)}</p></div>' for t, b in slide["nodes"]) + '</div>'
        if "cards" in slide:
            body += f'<div class="cards" style="--cols:{len(slide["cards"])}">' + ''.join('<article class="card"><h2>' + esc(c["title"]) + '</h2><ul>' + ''.join('<li>' + esc(x) + '</li>' for x in c["items"]) + '</ul></article>' for c in slide["cards"]) + '</div>'
        if "table" in slide:
            table = slide["table"]
            body += f'<table class="cols-{len(table["headers"])}"><thead><tr>' + ''.join(f'<th scope="col">{esc(x)}</th>' for x in table["headers"]) + '</tr></thead><tbody>' + ''.join('<tr>' + ''.join(f'<td>{esc(x)}</td>' for x in row) + '</tr>' for row in table["rows"]) + '</tbody></table>'
        if "references" in slide:
            body += '<div class="refs">' + ''.join(f'<div class="ref"><a href="{html.escape(absolute(DATA["sources"][k][1]), quote=True)}" target="_blank" rel="noopener">{esc(DATA["sources"][k][0])}</a><small>{esc(absolute(DATA["sources"][k][1]))}</small></div>' for k in slide["references"]) + '</div>'
        if "diagram" in slide:
            body += diagram_block(slide['diagram'])
        if "chart" in slide:
            body += chart_svg(slide['chart'])
        if kind == "calculator":
            options = [
                ('traffic', 'Selected traffic', [(0.5,'0.5× baseline'),(1,'1× baseline'),(2,'2× baseline')]),
                ('searchDays', 'Searchable retention', [(30,'30 days'),(90,'90 days'),(180,'180 days')]),
                ('originalDays', 'Protected-original retention', [(30,'30 days'),(365,'365 days'),(730,'730 days')]),
                ('compression', 'Normalized stored/input ratio', [(0.1,'10%'),(0.25,'25%'),(0.5,'50%')]),
                ('hourlyLabor', 'Assumed loaded labor USD/hour', [(50,'$50'),(100,'$100'),(150,'$150')]),
                ('computeMultiplier', 'EC2 + disk allocation', [(1,'1× illustrative allocation'),(2,'2× allocation'),(4,'4× allocation')])
            ]
            controls=''
            for key,label,choices in options:
                controls+=f'<label>{label}<select data-cost-option="{key}">' + ''.join(f'<option value="{v}"{" selected" if v==MODEL["defaults"][key] else ""}>{label}</option>' for v,label in choices) + '</select></label>'
            controls+='<label class="check"><input type="checkbox" checked data-cost-option="sourceDelivery">Include CloudWatch source delivery</label><button id="reset-costs">Reset baseline</button>'
            results=''.join(f'<article class="calc-result"><h2>{s["accounts"]:,} AWS account{"s" if s["accounts"] != 1 else ""}</h2><strong class="aws-value"></strong><p class="direct-value"></p><p class="source-value"></p><p class="budget-value"></p><p class="traffic-value"></p><p class="labor-value"></p><p class="loaded-value total"></p></article>' for s in BASELINE)
            body+='<div class="calculator"><div class="calc-controls">'+controls+'</div><div class="calc-results" aria-live="polite">'+results+'</div><p class="calc-context">US East (N. Virginia) · no discounts/tax. AWS + labor excludes the 40% reserve. Traffic controls do not auto-size workers or labor. Other slides show the frozen baseline; reset before comparing them.</p></div>'
        rendered.append(f'<section id="slide-{i}" class="{classes}" aria-label="Slide {i}: {html.escape(slide["title"], quote=True)}" data-notes="{html.escape(slide["notes"], quote=True)}"><div class="eyebrow">{esc(slide["eyebrow"])}</div><h1>{esc(slide["title"])}</h1><p class="subtitle">{esc(slide.get("subtitle", ""))}</p><div class="body">{body}</div><p class="callout">{esc(slide.get("callout", ""))}</p><footer class="footer"><div class="citations">{source_links(slide.get("sources", []))}</div><span class="page">SIGNAL · 07 JUL 2026 · {i:02d}/{len(DATA["slides"])}</span></footer></section>')
        outline.append(f'<button data-slide="{i-1}">{i:02d} · {esc(slide["title"].replace(chr(10), " "))}</button>')
        markdown += [f'## {i:02d}. {slide["title"].replace(chr(10), " ")}', '', slide.get("subtitle", ""), '']
        for c in slide.get("cards", []):
            markdown += [f'**{c["title"]}**', ''] + [f'- {x}' for x in c["items"]] + ['']
        if "nodes" in slide:
            markdown += [' → '.join(t for t, _ in slide["nodes"]), '']
        if 'diagram' in slide:
            markdown += [slide['diagram']['description'], '']
        if "table" in slide:
            t = slide["table"]
            markdown += ['| ' + ' | '.join(t["headers"]) + ' |', '| ' + ' | '.join('---' for _ in t["headers"]) + ' |']
            markdown += ['| ' + ' | '.join(row) + ' |' for row in t["rows"]] + ['']
        markdown += [slide.get("callout", ""), '', '**Speaker notes**', '', slide["notes"], '', '**Sources**', '']
        markdown += [f'- [{DATA["sources"][k][0]}]({DATA["sources"][k][1]})' for k in slide.get("sources", slide.get("references", []))] + ['']
    document = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(DATA["title"])}</title><style>{CSS}</style></head><body>
<nav class="toolbar" aria-label="Presentation controls"><span class="brand">PLATFORM::SIGNAL</span><button id="prev" aria-label="Previous slide">←</button><output id="counter" aria-live="polite"></output><button id="next" aria-label="Next slide">→</button><button id="open-contents">Contents</button><button id="toggle-notes" aria-controls="notes" aria-expanded="false">Notes</button><button id="fullscreen">Fullscreen</button><button id="print">Print</button></nav>
<main id="stage">{''.join(rendered)}</main><aside id="notes" hidden><h2>Speaker notes</h2><p id="note-text"></p><p id="help">Arrow keys / Page Up / Page Down: navigate. Home / End: first / last. N: notes.</p></aside><dialog id="contents" aria-labelledby="contents-title"><h2 id="contents-title">Presentation contents</h2><button id="close-contents">Close</button><div class="outline">{''.join(outline)}</div></dialog><dialog id="zoom" aria-label="Diagram full size"><div class="zoom-bar"><button id="zoom-close">Close</button><button id="zoom-copy">Copy Mermaid</button><button id="zoom-svg">Download SVG</button><button id="zoom-png">Download PNG</button><span id="zoom-status" aria-live="polite"></span></div><div class="zoom-view" id="zoom-view"></div></dialog><script>const signalCostInput={json.dumps(MODEL).replace('<', chr(92)+'u003c')};</script><script>{(ROOT/'cost-model.js').read_text()}</script><script>{JS}</script></body></html>'''
    (ROOT / "index.html").write_text(document)
    (ROOT / "speaker-notes.md").write_text('\n'.join(markdown))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    args = parser.parse_args()
    build_html()
    print(f'Generated {len(DATA["slides"])} slides in {ROOT}')
