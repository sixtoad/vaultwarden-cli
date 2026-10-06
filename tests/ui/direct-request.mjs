// Run: VW_UI_DEPS=/tmp/vw-story14-browser/node_modules node tests/ui/direct-request.mjs
// Dependencies: puppeteer-core, axe-core, Firefox, NSS certutil. No production account.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {spawn,execFileSync} from 'node:child_process';
import assert from 'node:assert/strict';
const repo=path.resolve(new URL('../..',import.meta.url).pathname);
const deps=process.env.VW_UI_DEPS || path.join(repo,'tests/ui/node_modules');
const puppetPackage=JSON.parse(fs.readFileSync(path.join(deps,'puppeteer-core/package.json')));
const {default:puppeteer}=await import(pathToFileURL(path.join(deps,'puppeteer-core',puppetPackage.main)));
const axe=fs.readFileSync(path.join(deps,'axe-core/axe.min.js'),'utf8');
const control=fs.mkdtempSync(path.join(os.tmpdir(),'vw-story15-browser-'));fs.chmodSync(control,0o700);
const profile=path.join(control,'profile');fs.mkdirSync(profile,{mode:0o700});
const certutil=process.env.CERTUTIL || '/tmp/vw-story13-nss/extracted/usr/bin/certutil';
execFileSync(certutil,['-N','--empty-password','-d',`sql:${profile}`]);
execFileSync(certutil,['-A','-n','Story 1.5 synthetic CA','-t','C,,','-i',path.join(repo,'tests/fixtures/provider-tls/ca.pem'),'-d',`sql:${profile}`]);
const child=spawn('cargo',['test','--offline','--locked','--lib','adapters::loopback_ui::tests::direct_request_browser_fixture','--','--ignored','--exact'],{cwd:repo,env:{...process.env,VW_UI_TEST_CONTROL:control},stdio:['ignore','pipe','pipe']});
let childOutput='';child.stdout.on('data',b=>childOutput+=b);child.stderr.on('data',b=>childOutput+=b);
const closed=new Promise(resolve=>child.on('close',resolve));let browser;
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
try{
  for(let i=0;i<3000&&!fs.existsSync(path.join(control,'ready.json'));i++){if(child.exitCode!==null)throw Error('Fixture failed: '+childOutput);await sleep(20);}
  assert(fs.existsSync(path.join(control,'ready.json')),'fixture startup timeout');
  const ready=JSON.parse(fs.readFileSync(path.join(control,'ready.json')));
  browser=await puppeteer.launch({browser:'firefox',executablePath:process.env.FIREFOX || '/usr/bin/firefox',userDataDir:profile,headless:true,acceptInsecureCerts:false});
  const page=await browser.newPage();const errors=[];page.on('pageerror',e=>errors.push(String(e)));
  await page.goto(pathToFileURL(ready.artifact).href);await page.click('a');
  await page.waitForFunction(()=>location.protocol==='https:'&&sessionStorage.getItem('vw_proof'));
  const origin=await page.evaluate(()=>location.origin);
  await page.waitForFunction(()=>document.querySelector('#history-status').textContent==='No operation history.');
  assert.equal(await page.$$eval('#history-events > li',events=>events.length),0);
  // Keyboard-only unlock, with an explicit nonvisual confirmation.
  await page.focus('#password');await page.keyboard.type('synthetic-browser-password');await page.keyboard.press('Tab');
  const focus=await page.evaluate(()=>({name:document.activeElement.textContent,style:getComputedStyle(document.activeElement).outlineStyle,width:getComputedStyle(document.activeElement).outlineWidth}));assert.match(focus.name,/Unlock/);assert.equal(focus.style,'solid');assert.equal(focus.width,'3px');
  await page.keyboard.press('Enter');await page.waitForFunction(()=>document.querySelector('#result').textContent.includes('Provider unlocked'));
  assert.equal(await page.$eval('#password',e=>e.value),'');
  const run=(args)=>JSON.parse(execFileSync(path.join(path.resolve(repo,process.env.CARGO_TARGET_DIR || 'target'),'debug/vw-access'),['--state-root',ready.root,...args],{encoding:'utf8',stdio:'pipe'}));
  // Valid fixture creation may contend with UI polling. Retry only the explicit
  // unavailable rejection, never a transport/delivery error or another rejection.
  const submit=async(values)=>{
    for(let attempt=0;;attempt++){
      try{return run(['request','deploy','--no-wait','--',...values]).receipt;}
      catch(error){
        if(attempt>=9||error.status!==1||error.signal!==null||error.stdout!==''||error.stderr!=='vw-access: provider unavailable\n')throw error;
        await sleep(50);
      }
    }
  };
  const receipt=await submit(['staging','safe|\"quoted\"','+0003']);assert.equal(receipt.status.status,'pending');
  const artifact=path.join(ready.root,`review-${receipt.id}.html`);assert.equal(fs.statSync(artifact).mode&0o777,0o600);
  const launchHtml=fs.readFileSync(artifact,'utf8');const link=launchHtml.match(/href="([^"]+)"/)[1];const capability=new URL(link).hash.slice(1).split(':')[0];
  const review=await browser.newPage();
  await review.evaluateOnNewDocument(()=>{const actual=window.fetch.bind(window);window.fetch=async(url,options)=>{const response=await actual(url,options);if(url==='/history'&&!window.initialHistoryHeld){window.initialHistoryHeld=true;await new Promise(resolve=>window.releaseInitialHistory=resolve);}return response;};});
  let dialogs=0;review.on('dialog',async dialog=>{dialogs++;await dialog.dismiss();});review.on('pageerror',e=>errors.push(String(e)));await review.goto(pathToFileURL(artifact).href); // automatic artifact navigation
  await review.waitForFunction(()=>document.querySelector('#review-status')?.textContent==='Request status: pending');
  await review.waitForFunction(()=>window.initialHistoryHeld);
  assert.equal(await review.$eval('#history-status',e=>e.textContent),'Loading history');
  assert(await review.$$eval('#deny,#begin-approval',controls=>controls.every(control=>!control.disabled)),'held initial history must not block decisions');
  await review.evaluate(()=>window.releaseInitialHistory());
  assert.equal(await review.evaluate(()=>location.hash),'');assert.equal(await review.$eval('#details',e=>e.querySelectorAll('img,script').length),0);assert.equal(dialogs,0);
  const detail=await review.$eval('#details',e=>e.textContent);for(const expected of ['local human terminal','Deploy <img src=x onerror=alert(1)>','staging','safe','Deployment <login>','Request ID','Policy digest','Executable digest','Arguments digest','One-time meaning'])assert(detail.includes(expected),expected);
  for(const forbidden of ['11111111-1111-1111-1111-111111111111','DEPLOY_PASSWORD','synthetic-browser-password'])assert(!detail.includes(forbidden));
  assert.equal(await review.$eval('#review-status',e=>e.getAttribute('aria-atomic')),'true');
  assert.deepEqual(await review.$$eval('#arguments > li',items=>items.map(item=>({text:item.textContent,name:item.getAttribute('aria-label')}))),[{text:'staging',name:'Argument 1'},{text:'safe|"quoted"',name:'Argument 2'},{text:'3',name:'Argument 3'}]);
  // Real provider history is readable through both authenticated human transports.
  await review.waitForFunction(()=>document.querySelector('#history-status').textContent==='1 history events shown.');
  const cliHistory=run(['history','--limit','1']);assert.equal(cliHistory.result,'history');assert.equal(cliHistory.events.length,1);assert.equal(cliHistory.events[0].request_id,receipt.id);assert.equal(cliHistory.events[0].outcome,'submitted');
  const historyText=await review.$eval('#history-events',e=>e.textContent);
  assert(historyText.includes('Deployment <login>')&&historyText.includes(receipt.id),'successful history capture must contain known record fields');
  assert.equal(await review.$eval('#history-events',e=>e.querySelectorAll('img,script').length),0);
  for(const forbidden of ['11111111-1111-1111-1111-111111111111','DEPLOY_PASSWORD','synthetic-browser-password','safe|"quoted"',capability,'binding','record_seal'])assert(!JSON.stringify(cliHistory).includes(forbidden)&&!historyText.includes(forbidden));
  await submit(['staging','safe','3']);
  await submit(['staging','safe','3']);
  const newestHistory=run(['history','--limit','1']).events[0];
  const refreshHistory=async limit=>{
    await review.$eval('#history-limit',(element,value)=>{element.value=String(value);},limit);
    await review.evaluate(()=>{window.historyRefreshFinished=false;const actual=window.fetch.bind(window);window.fetch=async(url,options)=>{if(url!=='/history')return actual(url,options);window.fetch=actual;const response=await actual(url,options);const json=response.json.bind(response);response.json=async()=>{const value=await json();window.historyRefreshFinished=true;return value;};return response;};document.querySelector('#history-refresh').click();});
    await review.waitForFunction(()=>window.historyRefreshFinished&&!document.querySelector('#history-refresh').disabled);
  };
  await refreshHistory(1);
  assert.equal(await review.$$eval('#history-events > li',events=>events.length),1);
  assert((await review.$eval('#history-events',element=>element.textContent)).includes(newestHistory.request_id));
  await refreshHistory(3);
  assert.equal(await review.$$eval('#history-events > li',events=>events.length),3);
  await refreshHistory(1);
  const historyGuards=await review.evaluate(async()=>{
    const post=(headers,body)=>fetch('/history',{method:'POST',headers,body}).then(r=>r.status),headers={'Content-Type':'application/json','X-CSRF-Token':sessionStorage.getItem('vw_proof')};
    return {noProof:await post({'Content-Type':'application/json'},'{}'),wrongProof:await post({...headers,'X-CSRF-Token':'wrong'},'{}'),zero:await post(headers,'{"limit":0}'),oversized:await post(headers,'{"limit":201}'),overflow:await post(headers,'{"limit":4294967296}'),unknown:await post(headers,'{"agent":"private-sentinel"}')};
  });assert.deepEqual(historyGuards,{noProof:403,wrongProof:403,zero:403,oversized:403,overflow:403,unknown:403});
  // An internal rendering fixture covers agent attribution and invisible controls;
  // the provider receives no agent insertion API or authority-bearing fields.
  await review.evaluate(event=>{
    const fetchActual=window.fetch.bind(window);window.fetch=async(url,options)=>{if(url==='/history'){window.fetch=fetchActual;return new Response(JSON.stringify([event]),{status:200});}return fetchActual(url,options);};
    document.querySelector('#history-refresh').click();
  },{...cliHistory.events[0],requester:{kind:'agent',label:'Agent <img src=x>\n\x1b]2;title\x07\x7f\u0085\u009b\u061c\u200e\u200f\u202e\u2066\u2069',fingerprint:'b'.repeat(64)},at_unix_seconds:null,outcome:'legacy_unknown',status:null});
  await review.waitForFunction(()=>document.querySelector('#history-events').textContent.includes('Unknown (legacy record)'));
  const syntheticHistory=await review.$eval('#history-events',e=>e.textContent);
  for(const escaped of String.raw`\u000a \u001b \u0007 \u007f \u0085 \u009b \u061c \u200e \u200f \u202e \u2066 \u2069`.split(' '))assert(syntheticHistory.includes(escaped),escaped);
  assert(syntheticHistory.includes('b'.repeat(64)));assert.equal(await review.$eval('#history-events',e=>e.querySelectorAll('img,script').length),0);
  await review.focus('#history-refresh');await review.keyboard.press('Enter');
  await review.waitForFunction(()=>!document.querySelector('#history-refresh').disabled&&!document.querySelector('#history-events').textContent.includes('Unknown (legacy record)'));
  // A static 403 cannot distinguish authentication, storage and output failures.
  await review.evaluate(()=>{const actual=window.fetch.bind(window);window.fetch=async(url,options)=>{if(url==='/history'){window.fetch=actual;return new Response('private-history-error-sentinel',{status:403});}return actual(url,options);};document.querySelector('#history-refresh').click();});
  await review.waitForFunction(()=>document.querySelector('#history-status').textContent.includes('Try fewer events'));
  const historyGuidance=await review.$eval('#history-status',e=>e.textContent);
  for(const guidance of ['fewer events','fresh provider launch','provider availability'])assert(historyGuidance.includes(guidance));
  assert(!historyGuidance.includes('private-history-error-sentinel'));
  await review.evaluate(()=>document.querySelector('#history-refresh').click());
  await review.waitForFunction(()=>document.querySelector('#history-status').textContent==='1 history events shown.');
  // Each additional invisible separator must be escaped independently.
  for(const character of ['\u200b','\u2060','\ufeff']){
    await review.evaluate(({event,character})=>{const actual=window.fetch.bind(window);window.fetch=async(url,options)=>{if(url!=='/history')return actual(url,options);window.fetch=actual;return new Response(JSON.stringify([{...event,requester:{...event.requester,label:'label'+character+'end'}}]),{status:200});};document.querySelector('#history-refresh').click();},{event:cliHistory.events[0],character});
    const escaped='\\u'+character.codePointAt(0).toString(16).padStart(4,'0');
    await review.waitForFunction(escaped=>document.querySelector('#history-events').textContent.includes(escaped),{},escaped);
    assert(!(await review.$eval('#history-events',element=>element.textContent)).includes(character));
  }
  // Trigger the real deadline deterministically for both an unresolved fetch and body.
  for(const phase of ['fetch','body']){
    await review.evaluate(phase=>{
      const actual=window.fetch.bind(window),schedule=window.setTimeout.bind(window),cancel=window.clearTimeout.bind(window);
      window.historyDeadlineCleared=false;window.historyDeadlineHeld=false;
      window.setTimeout=(callback,delay,...args)=>{const timer=schedule(callback,delay,...args);if(delay===15000){window.historyDeadlineTimer=timer;window.triggerHistoryDeadline=()=>callback(...args);}return timer;};
      window.clearTimeout=timer=>{if(timer===window.historyDeadlineTimer)window.historyDeadlineCleared=true;return cancel(timer);};
      window.fetch=async(url,options)=>{if(url!=='/history')return actual(url,options);window.fetch=actual;window.historyAbortSignal=options.signal;const response=await actual(url,options);const hold=()=>new Promise(resolve=>{window.releaseTimedHistory=resolve;window.historyDeadlineHeld=true;});if(phase==='fetch'){await hold();return response;}return {ok:true,json:async()=>{await hold();return response.json();}};};
      window.restoreDeadlineHooks=()=>{window.setTimeout=schedule;window.clearTimeout=cancel;};document.querySelector('#history-refresh').click();
    },phase);
    await review.waitForFunction(()=>window.historyDeadlineHeld);
    await review.evaluate(()=>window.triggerHistoryDeadline());
    await review.waitForFunction(()=>document.querySelector('#history-status').textContent.includes('Try fewer events')&&!document.querySelector('#history-refresh').disabled);
    assert.equal(await review.$$eval('#history-events > li',events=>events.length),0);
    assert(await review.evaluate(()=>window.historyAbortSignal.aborted&&window.historyDeadlineCleared));
    await review.evaluate(()=>{window.releaseTimedHistory();window.restoreDeadlineHooks();});
    await refreshHistory(1);
    assert.equal(await review.$$eval('#history-events > li',events=>events.length),1);
  }
  // Ordinary polls must preserve immutable nodes and avoid repeated live announcements.
  await review.evaluate(()=>{
    window.detailNodes=Array.from(document.querySelector('#details').childNodes);window.detailMutations=0;window.statusMutations=0;window.reviewPolls=0;window.transientFailures=0;
    new MutationObserver(records=>window.detailMutations+=records.length).observe(document.querySelector('#details'),{subtree:true,childList:true,characterData:true});
    new MutationObserver(records=>window.statusMutations+=records.length).observe(document.querySelector('#review-status'),{subtree:true,childList:true,characterData:true});
    const original=window.fetch.bind(window);window.fetch=async(url,options)=>{if(url==='/review'){window.reviewPolls++;if(window.failNextReview){window.failNextReview=false;window.transientFailures++;throw new TypeError('synthetic transient network failure');}}return original(url,options);};
  });
  await review.waitForFunction(()=>window.reviewPolls>=2);
  assert.deepEqual(await review.evaluate(()=>({sameNodes:window.detailNodes.every((node,index)=>node===document.querySelector('#details').childNodes[index]),details:window.detailMutations,status:window.statusMutations})),{sameNodes:true,details:0,status:0});
  await review.evaluate(()=>{window.failNextReview=true;});
  await review.waitForFunction(()=>document.querySelector('#review-status').textContent==='Request status unavailable; retrying');
  await review.waitForFunction(()=>window.transientFailures===1&&document.querySelector('#review-status').textContent==='Request status: pending');
  assert.equal(await review.evaluate(()=>window.detailMutations),0);
  // Two simultaneous fresh-cookie tabs must serialize before either exchange fetch.
  const concurrentReceipts=[await submit(['staging','safe','3']),await submit(['staging','safe','3'])];
  const fresh=await browser.createBrowserContext();assert.equal((await fresh.cookies()).length,0);
  const tabs=await Promise.all([fresh.newPage(),fresh.newPage()]);
  for(const tab of tabs)await tab.evaluateOnNewDocument(()=>{const lockRequest=navigator.locks.request.bind(navigator.locks);navigator.locks.request=(name,...args)=>{if(name==='vw-launch')window.launchLockQueued=true;return lockRequest(name,...args);};const original=window.fetch.bind(window);window.fetch=async(url,options)=>{if(url==='/launch'){window.launchFetchStarted=true;await new Promise(resolve=>window.releaseLaunch=resolve);}return original(url,options);};});
  await Promise.all(tabs.map((tab,index)=>tab.goto(pathToFileURL(path.join(ready.root,`review-${concurrentReceipts[index].id}.html`)).href)));
  await Promise.all(tabs.map(tab=>tab.waitForFunction(()=>location.protocol==='https:'&&window.launchLockQueued===true)));
  const started=await Promise.all(tabs.map(tab=>tab.evaluate(()=>Boolean(window.launchFetchStarted))));assert.equal(started.filter(Boolean).length,1,'only one launch fetch may start before the first cookie is installed');
  const first=started.findIndex(Boolean),second=1-first;
  await tabs[first].evaluate(()=>window.releaseLaunch());await tabs[first].waitForFunction(()=>document.querySelector('#review-status').textContent==='Request status: pending');
  await tabs[second].waitForFunction(()=>window.launchFetchStarted===true);await tabs[second].evaluate(()=>window.releaseLaunch());
  await tabs[second].waitForFunction(()=>document.querySelector('#review-status').textContent==='Request status: pending');
  const proofs=await Promise.all(tabs.map(tab=>tab.evaluate(()=>sessionStorage.getItem('vw_proof'))));assert(proofs[0]);assert.equal(proofs[0],proofs[1]);
  for(let index=0;index<tabs.length;index++){const status=await tabs[index].evaluate(async id=>(await fetch('/review',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':sessionStorage.getItem('vw_proof')},body:JSON.stringify({request_id:id})})).status,concurrentReceipts[index].id);assert.equal(status,200);}
  await fresh.close();

  // Keyboard cancellation clears password without submitting or changing Pending.
  await review.focus('#begin-approval');await review.keyboard.press('Enter');await review.keyboard.type('cancelled-password-sentinel');
  await review.keyboard.press('Tab');await review.keyboard.press('Tab');assert.equal(await review.evaluate(()=>document.activeElement.id),'cancel-approval');await review.keyboard.press('Enter');
  assert.equal(await review.$eval('#approval-password',e=>e.value),'');assert.equal(await review.evaluate(()=>document.activeElement.id),'begin-approval');assert.equal(run(['status',receipt.id]).state.status,'pending');
  await review.focus('#refresh');await review.keyboard.press('Enter');
  await review.addScriptTag({content:axe});const audit=await review.evaluate(async()=>{const r=await axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa']}});return {violations:r.violations.map(v=>({id:v.id,impact:v.impact,nodes:v.nodes.length})),passes:r.passes.length};});assert.deepEqual(audit.violations,[]);
  const cookies=await review.cookies();const cookie=cookies.find(c=>c.name==='vw_session');assert(cookie.secure&&cookie.httpOnly&&cookie.sameSite==='Strict');
  const attacks=await review.evaluate(async({capability,id})=>{
    const proof=sessionStorage.getItem('vw_proof');const post=(p,headers,body)=>fetch(p,{method:'POST',headers,body}).then(r=>r.status);
    const replay=await post('/launch',{'Content-Type':'text/plain'},capability);
    const noProof=await post('/review',{'Content-Type':'application/json'},JSON.stringify({request_id:id}));
    const wrongProof=await post('/review',{'Content-Type':'application/json','X-CSRF-Token':'wrong'},JSON.stringify({request_id:id}));
    const page=await fetch('/').then(r=>r.text());return{replay,noProof,wrongProof,publicLeaks:page.includes(proof)||page.includes(id)};
  },{capability,id:receipt.id});assert.deepEqual(attacks,{replay:403,noProof:403,wrongProof:403,publicLeaks:false});
  // Existing browser session still works after the second request launch.
  const proofStillWorks=await page.evaluate(async id=>(await fetch('/review',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':sessionStorage.getItem('vw_proof')},body:JSON.stringify({request_id:id})})).status,receipt.id);assert.equal(proofStillWorks,403); // Pre-unlock session proof was rotated by the new launch.
  // Distinct requests exercise keyboard denial and authenticated approval.
  for(const decision of ['deny','approve']){
    const decided=await submit(['staging','safe','3']);const tab=await browser.newPage();
    await tab.goto(pathToFileURL(path.join(ready.root,`review-${decided.id}.html`)).href);
    await tab.waitForFunction(()=>document.querySelector('#review-status')?.textContent==='Request status: pending');
    if(decision==='deny'){await tab.focus('#deny');await tab.keyboard.press('Enter');}
    else{
      await tab.focus('#begin-approval');await tab.keyboard.press('Enter');
      await tab.keyboard.type('synthetic-browser-password');await tab.keyboard.press('Tab');await tab.keyboard.press('Enter');
    }
    await tab.waitForFunction(expected=>document.querySelector('#review-status').textContent.includes('Request status: '+expected),{},decision==='deny'?'denied':'approved');
    assert.equal(await tab.$eval('#approval-password',e=>e.value),'');
    assert.equal(run(['status',decided.id]).state.status,decision==='deny'?'denied':'approved');
    assert(await tab.$$eval('#decisions button',buttons=>buttons.every(b=>b.disabled)));
    assert.match(await tab.$eval('#review-status',e=>e.textContent),decision==='deny'?/no operation will run/:/approved once; awaiting protected execution/);
    const replay=await tab.evaluate(async({id,decision})=>(await fetch('/'+decision,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':sessionStorage.getItem('vw_proof')},body:JSON.stringify(decision==='approve'?{request_id:id,password:'synthetic-browser-password'}:{request_id:id})})).status,{id:decided.id,decision});assert.equal(replay,403);
    await tab.addScriptTag({content:axe});assert.deepEqual(await tab.evaluate(async()=>(await axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa']}})).violations.map(v=>v.id)),[]);
    await tab.close();
  }
  const openDecision=async()=>{
    const receipt=await submit(['staging','safe','3']);const tab=await browser.newPage();
    tab.on('pageerror',e=>errors.push(String(e)));
    await tab.goto(pathToFileURL(path.join(ready.root,`review-${receipt.id}.html`)).href);
    await tab.waitForFunction(()=>document.querySelector('#review-status')?.textContent==='Request status: pending');
    await tab.evaluate(()=>{
      const send=window.fetch.bind(window);window.sendDirect=send;window.approvalCalls=0;window.approvalOutgoing=0;window.reviewDelivered=0;window.heldReviews=[];
      window.fetch=async(url,options)=>{
        if(url==='/approve'){
          window.approvalCalls++;
          if(window.holdApproval){window.approvalHeld=true;await new Promise(resolve=>window.releaseApproval=resolve);}
          window.approvalOutgoing++;const response=await send(url,options);
          if(window.discardApprovalResponse){window.deliveredApprovalStatus=response.status;throw new TypeError('synthetic discarded approval response');}
          return response;
        }
        if(url==='/review'){
          const hold=window.holdNextReview;window.holdNextReview=false;
          const response=await send(url,options);
          if(hold){const held={state:(await response.clone().json()).status.status,released:false};window.heldReviews.push(held);window.heldReviewState=held.state;await new Promise(resolve=>{held.release=resolve;window.releaseReview=resolve;});held.released=true;window.heldReviewReleased=true;}
          window.reviewDelivered++;return response;
        }
        return send(url,options);
      };
    });
    return {tab,receipt};
  };
  const auditDecision=async tab=>{
    await tab.addScriptTag({content:axe});
    assert.deepEqual(await tab.evaluate(async()=>(await axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa']}})).violations.map(v=>v.id)),[]);
  };
  const typeApproval=async(tab,password='synthetic-browser-password')=>{
    await tab.focus('#begin-approval');await tab.keyboard.press('Enter');await tab.keyboard.type(password);
  };
  const assertUnavailable=async tab=>assert.deepEqual(await tab.evaluate(()=>({password:document.querySelector('#approval-password').value,disabled:['approve','deny','cancel-approval'].every(id=>document.getElementById(id).disabled)})),{password:'',disabled:true});
  // Hold an actual Pending response across submission; a fresh review must complete
  // before that obsolete response is released. Also poll Pending during the hold.
  {
    const {tab,receipt:held}=await openDecision();await typeApproval(tab);await auditDecision(tab);
    await tab.evaluate(()=>{window.holdNextReview=true;window.holdApproval=true;document.querySelector('#refresh').click();});
    await tab.waitForFunction(()=>window.heldReviewState==='pending');
    await tab.focus('#approve');await tab.keyboard.press('Enter');await tab.waitForFunction(()=>window.approvalHeld);
    await assertUnavailable(tab);assert.equal(await tab.evaluate(()=>window.approvalOutgoing),0);await auditDecision(tab);
    const polls=await tab.evaluate(()=>{const n=window.reviewDelivered;document.querySelector('#refresh').click();return n;});
    await tab.waitForFunction(n=>window.reviewDelivered>n,{},polls);await assertUnavailable(tab);
    assert.equal(run(['status',held.id]).state.status,'pending');
    // This second response belongs to the decision epoch and independently proves
    // completion forces a new review even while its current poll is outstanding.
    await tab.evaluate(()=>{window.holdNextReview=true;document.querySelector('#refresh').click();});
    await tab.waitForFunction(()=>window.heldReviews.length===2&&window.heldReviews[1].state==='pending');
    await assertUnavailable(tab);
    await tab.evaluate(()=>window.releaseApproval());
    await tab.waitForFunction(()=>document.querySelector('#review-status').textContent.includes('Request status: approved'));
    await assertUnavailable(tab);
    for(const index of [1,0]){
      await tab.evaluate(index=>window.heldReviews[index].release(),index);await tab.waitForFunction(index=>window.heldReviews[index].released,{},index);
      assert.match(await tab.$eval('#review-status',e=>e.textContent),/Request status: approved/);await assertUnavailable(tab);
    }
    assert.equal(await tab.evaluate(()=>window.approvalOutgoing),1);await tab.close();
  }
  // An explicit rejection remains visible through successful Pending polling.
  {
    const {tab}=await openDecision();await typeApproval(tab,'wrong-password-sentinel');
    await tab.focus('#approve');await tab.keyboard.press('Enter');
    await tab.waitForFunction(()=>document.querySelector('#decision-feedback').textContent.includes('Decision rejected')&&!document.querySelector('#begin-approval').disabled);
    const message=await tab.$eval('#decision-feedback',e=>e.textContent),polls=await tab.evaluate(()=>window.reviewDelivered);
    await tab.waitForFunction(n=>window.reviewDelivered>=n+2,{},polls);
    assert.equal(await tab.$eval('#decision-feedback',e=>e.textContent),message);assert(!message.includes('wrong-password-sentinel'));await tab.close();
  }
  // Forward one real approval, discard only its response, and recover using review.
  {
    const {tab,receipt:uncertain}=await openDecision();await tab.evaluate(()=>window.discardApprovalResponse=true);await typeApproval(tab);
    await tab.focus('#approve');await tab.keyboard.press('Enter');
    await tab.waitForFunction(()=>document.querySelector('#review-status').textContent.includes('Request status: approved'));
    assert.equal(run(['status',uncertain.id]).state.status,'approved');await assertUnavailable(tab);
    const message=await tab.$eval('#decision-feedback',e=>e.textContent);assert.match(message,/response unavailable.*do not resubmit/);
    const polls=await tab.evaluate(()=>window.reviewDelivered);await tab.waitForFunction(n=>window.reviewDelivered>=n+2,{},polls);
    assert.equal(await tab.$eval('#decision-feedback',e=>e.textContent),message);
    assert.deepEqual(await tab.evaluate(()=>({calls:window.approvalCalls,outgoing:window.approvalOutgoing,delivered:window.deliveredApprovalStatus})),{calls:1,outgoing:1,delivered:200});await tab.close();
  }
  // External completion while an input is focused must move focus to Refresh.
  // Cancelling after external completion describes only the local form action.
  for(const cancel of [false,true]){
    const {tab,receipt:external}=await openDecision();await typeApproval(tab,'cancelled-password-sentinel');
    await tab.evaluate(()=>{window.holdNextReview=true;document.querySelector('#refresh').click();});
    await tab.waitForFunction(()=>window.heldReviewState==='pending');
    assert.equal(await tab.evaluate(async id=>(await window.sendDirect('/deny',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':sessionStorage.getItem('vw_proof')},body:JSON.stringify({request_id:id})})).status,external.id),200);
    if(cancel){await tab.focus('#cancel-approval');await tab.keyboard.press('Enter');}
    else await tab.evaluate(()=>window.releaseReview());
    await tab.waitForFunction(()=>document.querySelector('#review-status').textContent.includes('Request status: denied'));
    await assertUnavailable(tab);assert.equal(await tab.evaluate(()=>document.activeElement.id),'refresh');
    if(cancel){assert.equal(await tab.$eval('#decision-feedback',e=>e.textContent),'Authentication form cancelled.');await tab.evaluate(()=>window.releaseReview());await tab.waitForFunction(()=>window.heldReviewReleased);assert.match(await tab.$eval('#review-status',e=>e.textContent),/Request status: denied/);}
    await tab.close();
  }
  fs.writeFileSync(path.join(control,'clock'),'310');await review.waitForFunction(()=>document.querySelector('#review-status').textContent==='Request status: expired');
  await review.evaluate(()=>{const actual=window.fetch.bind(window);window.historyFetches=0;window.heldLocks=[];window.fetch=async(url,options)=>{if(url==='/lock')await new Promise(resolve=>window.heldLocks.push(resolve));if(url==='/history')window.historyFetches++;const response=await actual(url,options);if(url==='/history'&&!window.historyResponseHeld){window.historyResponseHeld=true;await new Promise(resolve=>window.releaseHistory=resolve);}return response;};document.querySelector('#history-refresh').click();});
  await review.waitForFunction(()=>window.historyResponseHeld);
  await review.focus('#lock');await review.keyboard.press('Enter');
  await review.waitForFunction(()=>window.heldLocks.length===1);
  await review.evaluate(()=>{document.querySelector('#lock').click();document.querySelector('#history-form').dispatchEvent(new Event('submit',{cancelable:true}));});
  assert(await review.$$eval('#history-form button,#history-form input',controls=>controls.every(control=>control.disabled)));
  assert.equal(await review.evaluate(()=>window.historyFetches),1,'refresh cannot start after lock was queued');
  await review.evaluate(()=>window.heldLocks[0]());
  await review.waitForFunction(()=>window.heldLocks.length===2);
  await review.evaluate(()=>document.querySelector('#history-form').dispatchEvent(new Event('submit',{cancelable:true})));
  assert(await review.$$eval('#history-form button,#history-form input',controls=>controls.every(control=>control.disabled)));
  assert.equal(await review.evaluate(()=>window.historyFetches),1,'refresh stays blocked across queued mutations');
  await review.evaluate(()=>window.heldLocks[1]());
  await review.waitForFunction(()=>!document.querySelector('#history-refresh').disabled&&document.querySelector('#result').textContent.includes('Provider locked'));assert.equal(run(['status',receipt.id]).state.status,'expired');assert.equal(await review.$eval('#review-status',e=>e.textContent),'Request status: expired');
  await review.evaluate(()=>window.releaseHistory());
  await review.waitForFunction(()=>document.querySelector('#history-status').textContent==='Refresh history to read current events.');
  assert.equal(await review.$$eval('#history-events > li',events=>events.length),0);
  await review.focus('#history-refresh');await review.keyboard.press('Enter');
  await review.waitForFunction(()=>document.querySelector('#history-status').textContent.includes('reopen a fresh provider launch'));
  const lockedHistory=run(['history']);assert(lockedHistory.events.length>0);assert.equal(lockedHistory.events.find(event=>event.request_id===receipt.id).outcome,'expired');
  // A real lock/unlock and new launch rotates the shared cookie. Old tab proof
  // must remain retired, with persistent guidance and no cookie-based recovery.
  {
    assert.equal(await review.evaluate(async()=>(await fetch('/unlock',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':sessionStorage.getItem('vw_proof')},body:JSON.stringify({password:'synthetic-browser-password'})})).status),200);
    const {tab}=await openDecision();await typeApproval(tab,'retired-password-sentinel');
    const oldProof=await tab.evaluate(()=>sessionStorage.getItem('vw_proof'));
    await tab.waitForFunction(()=>document.querySelector('#history-status').textContent.includes('history events shown.'));
    await tab.evaluate(()=>{const actual=window.fetch.bind(window);window.retiringHistoryFetches=0;window.fetch=async(url,options)=>{if(url==='/history')window.retiringHistoryFetches++;const response=await actual(url,options);if(url==='/history'){window.retiringHistoryHeld=true;await new Promise(resolve=>window.releaseRetiringHistory=resolve);window.retiringHistoryReleased=true;}return response;};document.querySelector('#history-refresh').click();});
    await tab.waitForFunction(()=>window.retiringHistoryHeld);
    for(const action of ['lock','unlock'])assert.equal(await tab.evaluate(async action=>(await window.sendDirect('/'+action,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':sessionStorage.getItem('vw_proof')},body:JSON.stringify({password:action==='unlock'?'synthetic-browser-password':''})})).status,action),200);
    const fresh=await openDecision();assert.notEqual(await fresh.tab.evaluate(()=>sessionStorage.getItem('vw_proof')),oldProof);
    await tab.evaluate(()=>document.querySelector('#refresh').click());
    await tab.waitForFunction(()=>document.querySelector('#decision-feedback').textContent.includes('Browser session retired'));
    await assertUnavailable(tab);assert(await tab.$$eval('#unlock input,#unlock button,#lock',controls=>controls.every(c=>c.disabled)));
    await tab.evaluate(()=>window.releaseRetiringHistory());
    await tab.waitForFunction(()=>window.retiringHistoryReleased);
    assert.equal(await tab.$$eval('#history-events > li',events=>events.length),0);
    assert(await tab.$$eval('#history-form input,#history-form button',controls=>controls.every(control=>control.disabled)));
    assert.match(await tab.$eval('#history-status',e=>e.textContent),/retired browser session/);
    await tab.evaluate(()=>document.querySelector('#history-form').dispatchEvent(new Event('submit',{cancelable:true})));
    assert.equal(await tab.evaluate(()=>window.retiringHistoryFetches),1,'retired history cannot refresh or repaint');
    assert.equal(await tab.evaluate(()=>sessionStorage.getItem('vw_proof')),oldProof);
    const message=await tab.$eval('#decision-feedback',e=>e.textContent);assert.match(message,/fresh launch/);
    const polls=await tab.evaluate(()=>{const n=window.reviewDelivered;document.querySelector('#refresh').click();return n;});
    await tab.waitForFunction(n=>window.reviewDelivered>n,{},polls);assert.equal(await tab.$eval('#decision-feedback',e=>e.textContent),message);await assertUnavailable(tab);
    await tab.close();await fresh.tab.close();
  }
  // A real signed admission creates the private launch artifact and complete
  // attributed review. Only its closed acknowledgment crosses the agent boundary.
  fs.writeFileSync(path.join(control,'signed-submit'),'submit');
  for(let attempt=0;attempt<200&&!fs.existsSync(path.join(control,'signed-result.json'));attempt++)await sleep(25);
  const signedResponse=JSON.parse(fs.readFileSync(path.join(control,'signed-result.json'),'utf8'));
  assert.deepEqual(Object.keys(signedResponse).sort(),['protocol_version','request_id','status']);
  assert.equal(signedResponse.protocol_version,1);assert.equal(signedResponse.status,'pending');
  const signedStored=JSON.parse(fs.readFileSync(path.join(ready.root,'provider-state.json'),'utf8')).requests.find(request=>request.id===signedResponse.request_id).direct;
  assert(signedStored.replay_digest);assert.equal(signedStored.agent_owner.binding_id,ready.signed_binding.id);
  const signedTab=await browser.newPage();signedTab.on('pageerror',e=>errors.push(String(e)));
  const signedArtifact=path.join(ready.root,`review-${signedResponse.request_id}.html`);
  assert.equal(fs.statSync(signedArtifact).mode&0o777,0o600);
  await signedTab.goto(pathToFileURL(signedArtifact).href);
  await signedTab.waitForFunction(()=>document.querySelector('#review-status')?.textContent==='Request status: pending');
  const signedDetails=await signedTab.$$eval('#details dt',terms=>Object.fromEntries(terms.map(term=>[term.textContent,term.nextElementSibling.textContent])));
  const expectedReview=signedStored.review;
  for(const [name,value] of Object.entries({'Request ID':signedResponse.request_id,'Requester':`agent ${ready.signed_binding.label} (${ready.signed_binding.fingerprint})`,'Operation':expectedReview.operation,'Effect':expectedReview.effect,'Target':expectedReview.target,'Credentials and use types':expectedReview.credentials.map(credential=>`${credential.label} (${credential.use_type})`).join(' · '),'Executable digest':expectedReview.executable_digest,'Policy digest':ready.signed_revision,'Arguments digest':expectedReview.arguments_digest,'Expires at':new Date(expectedReview.expires_at_unix_seconds*1000).toISOString(),'One-time meaning':expectedReview.one_time}))assert.equal(signedDetails[name],value,name);
  assert.deepEqual(await signedTab.$$eval('#arguments > li',items=>items.map(item=>item.textContent)),['staging','safe|"quoted"','3']);
  assert.equal(await signedTab.$eval('#details',element=>element.querySelectorAll('img,script').length),0);
  for(const excluded of ['capability','https://','synthetic-browser-password','Deployment','seed','private_key'])assert(!JSON.stringify(signedResponse).includes(excluded));
  await signedTab.click('#deny');await signedTab.waitForFunction(()=>document.querySelector('#review-status').textContent==='Request status: denied; no operation will run');
  assert.equal(JSON.parse(fs.readFileSync(path.join(ready.root,'provider-state.json'),'utf8')).requests.find(request=>request.id===signedResponse.request_id).direct.review.status.status,'denied');
  await signedTab.close();
  // A real SSH policy and human admission render the exact fixed authority.
  // The fixture has no private-key resolver or SSH executor.
  const submitSsh=async()=>{for(let attempt=0;;attempt++){
    try{return run(['request','ssh-backup','--revision',ready.ssh_revision,'--no-wait']).receipt;}
    catch(error){if(attempt>=9||error.status!==1||error.signal!==null||error.stdout!==''||error.stderr!=='vw-access: provider unavailable\n')throw error;await sleep(50);}
  }
  };
  const sshReceipt=await submitSsh();
  const sshArtifact=path.join(ready.root,`review-${sshReceipt.id}.html`);
  const sshLink=fs.readFileSync(sshArtifact,'utf8').match(/href="([^"]+)"/)[1];
  const sshCapability=new URL(sshLink).hash.slice(1).split(':')[0];
  const sshTab=await browser.newPage();sshTab.on('pageerror',e=>errors.push(String(e)));
  await sshTab.goto(pathToFileURL(sshArtifact).href);
  await sshTab.waitForFunction(()=>document.querySelector('#review-status')?.textContent==='Request status: pending');
  const sshDetails=await sshTab.$$eval('#details dt',terms=>Object.fromEntries(terms.map(term=>[term.textContent,term.nextElementSibling.textContent])));
  for(const [name,value] of Object.entries({'Target':'backup@backup.example.test:2222/srv/archive','SSH host':'backup.example.test','SSH port':'2222','SSH user':'backup','Resource path':'/srv/archive','Pinned host fingerprint':'SHA256:'+'A'.repeat(43),'Working directory':'/var/empty','Credentials and use types':'Backup SSH (ssh)','Policy digest':ready.ssh_revision,'One-time meaning':'Approval authorizes this request once only. Execution is not available yet.'}))assert.equal(sshDetails[name],value,name);
  assert.deepEqual(await sshTab.$$eval('#arguments > li',items=>items.map(item=>item.textContent)),[]);
  const sshReview=await sshTab.evaluate(async id=>(await fetch('/review',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':sessionStorage.getItem('vw_proof')},body:JSON.stringify({request_id:id})})).json(),sshReceipt.id);
  assert.deepEqual(sshReview.credentials,[{label:'Backup SSH',use_type:'ssh'}]);
  assert.equal(sshReview.ssh.destination.port,2222);assert.equal(sshReview.ssh.working_directory,'/var/empty');
  await sshTab.addScriptTag({content:axe});
  assert.deepEqual(await sshTab.evaluate(async()=>(await axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa']}})).violations.map(v=>v.id)),[]);
  const sshVisible=await sshTab.$eval('body',element=>element.innerText);
  for(const excluded of ['synthetic-private-key-sentinel','synthetic-ssh-agent-capability-sentinel','BEGIN OPENSSH PRIVATE KEY',sshCapability]){
    assert(!sshVisible.includes(excluded));assert(!JSON.stringify(sshReview).includes(excluded));
    assert(!JSON.stringify(sshReceipt).includes(excluded));
    assert(!fs.readFileSync(path.join(ready.root,'provider-state.json'),'utf8').includes(excluded));
  }
  assert(!JSON.stringify(sshReceipt).includes('Backup SSH'));
  await sshTab.focus('#deny');await sshTab.keyboard.press('Enter');
  await sshTab.waitForFunction(()=>document.querySelector('#review-status').textContent==='Request status: denied; no operation will run');
  await sshTab.click('#history-refresh');
  await sshTab.waitForFunction(id=>[...document.querySelectorAll('#history-events > li')].some(row=>row.textContent.includes(id)&&row.textContent.includes('denied')),{},sshReceipt.id);
  const sshHistory=await sshTab.$$eval('#history-events > li',(rows,id)=>rows.filter(row=>row.textContent.includes(id)).map(row=>row.textContent),sshReceipt.id);
  for(const row of sshHistory)for(const field of ['Backup SSH (ssh)','backup.example.test','2222','/srv/archive','/var/empty','SHA256:'+'A'.repeat(43)])assert(row.includes(field),field);
  const sshApproved=await submitSsh();
  const sshApprovalArtifact=path.join(ready.root,`review-${sshApproved.id}.html`);
  const sshApprovalLink=fs.readFileSync(sshApprovalArtifact,'utf8').match(/href="([^"]+)"/)[1];
  const sshApprovalCapability=new URL(sshApprovalLink).hash.slice(1).split(':')[0];
  await sshTab.goto(pathToFileURL(sshApprovalArtifact).href);
  await sshTab.waitForFunction(()=>document.querySelector('#review-status')?.textContent==='Request status: pending');
  await sshTab.click('#begin-approval');await sshTab.type('#approval-password','synthetic-browser-password');
  await sshTab.click('#approve');
  await sshTab.waitForFunction(()=>document.querySelector('#review-status').textContent==='Request status: approved; approved once; SSH execution is unavailable');
  assert.equal(run(['status',sshApproved.id]).state.status,'approved');
  await sshTab.close();
  const knownDiagnostics=errors.filter(e=>e.includes('Permission denied to access property \"__bidi_args\"')||e==='Error: Error: Permission denied to access property \"length\"'||(e.includes('Content-Security-Policy')&&e.includes('/favicon.ico')));
  assert.deepEqual(errors.filter(e=>!knownDiagnostics.includes(e)),[]);
  for(const error of errors)for(const secret of ['synthetic-browser-password','cancelled-password-sentinel','wrong-password-sentinel','retired-password-sentinel','synthetic-private-key-sentinel','synthetic-ssh-agent-capability-sentinel','BEGIN OPENSSH PRIVATE KEY',sshCapability,sshApprovalCapability,capability,receipt.id])assert(!error.includes(secret),'diagnostic reflected protected input');
  const diagnosticCategories=[...new Set(knownDiagnostics.map(e=>e.replace(/https:\/\/127\.0\.0\.1:\d+/g,'https://127.0.0.1:<port>')))];
  console.log(JSON.stringify({browser:await browser.version(),trustedTLS:true,sshFixedTargetReview:true,sshReviewRedaction:true,sshHistoryProjection:true,sshKeyboardDenial:true,signedAgentAdmission:true,signedAgentCompleteReview:true,signedAgentCapabilityIsolation:true,historyEmptyAndRows:true,historyCliAndBrowser:true,historyLimitsAndAuth:true,historyAgentControlEscaping:true,historyStaleSessionRejected:true,historyLateResponseDiscarded:true,historyQueuedMutationBlocked:true,historyRetirementClearsAndDisables:true,historyInitialReadIndependent:true,historyAmbiguousFailureGuidance:true,historyBoundedFetchAndBody:true,historyInvisibleSeparators:true,historyLimitChangesObserved:true,automaticArtifactNavigation:true,keyboardFocus:focus,axe:audit,requestReview:'pending -> expired -> expired while locked',launchReplay:'403',cookieOnly:'403',invalidProof:'403',stalePreUnlockProofRejected:true,terminalInspectionAfterLock:true,keyboardApproveDenyCancel:true,passwordCleared:true,immediateInFlightClearingAndDisabling:true,staleReviewDiscarded:true,activeAndInFlightAxe:true,persistentDecisionFeedback:true,retiredSessionGuidance:true,externalCompletionFocus:true,deliveredApprovalResponseDiscarded:true,exactlyOneApprovalSubmission:true,decisionReplayRejected:true,concurrentFreshCookieTabs:true,transientPollingRecovery:true,immutableDetailsStable:true,unchangedLiveStatusStable:true,argumentBoundariesPreserved:true,screenReaderManual:false,automationDiagnostics:{knownCrossOriginOrBlockedFavicon:knownDiagnostics.length,categories:diagnosticCategories,unexpected:0}},null,2));
  fs.writeFileSync(path.join(control,'stop'),'stop');assert.equal(await closed,0,childOutput);
}finally{fs.writeFileSync(path.join(control,'stop'),'stop');await browser?.close();if(child.exitCode===null)child.kill('SIGTERM');}
