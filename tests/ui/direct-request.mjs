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
const control=fs.mkdtempSync(path.join(os.tmpdir(),'vw-story14-browser-'));fs.chmodSync(control,0o700);
const profile=path.join(control,'profile');fs.mkdirSync(profile,{mode:0o700});
const certutil=process.env.CERTUTIL || '/tmp/vw-story13-nss/extracted/usr/bin/certutil';
execFileSync(certutil,['-N','--empty-password','-d',`sql:${profile}`]);
execFileSync(certutil,['-A','-n','Story 1.4 synthetic CA','-t','C,,','-i',path.join(repo,'tests/fixtures/provider-tls/ca.pem'),'-d',`sql:${profile}`]);
const child=spawn('cargo',['test','--lib','adapters::loopback_ui::tests::direct_request_browser_fixture','--','--ignored','--exact'],{cwd:repo,env:{...process.env,VW_UI_TEST_CONTROL:control},stdio:['ignore','pipe','pipe']});
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
  // Keyboard-only unlock, with an explicit nonvisual confirmation.
  await page.focus('#password');await page.keyboard.type('synthetic-browser-password');await page.keyboard.press('Tab');
  const focus=await page.evaluate(()=>({name:document.activeElement.textContent,style:getComputedStyle(document.activeElement).outlineStyle,width:getComputedStyle(document.activeElement).outlineWidth}));assert.match(focus.name,/Unlock/);assert.equal(focus.style,'solid');assert.equal(focus.width,'3px');
  await page.keyboard.press('Enter');await page.waitForFunction(()=>document.querySelector('#result').textContent.includes('Provider unlocked'));
  assert.equal(await page.$eval('#password',e=>e.value),'');
  const run=(args)=>JSON.parse(execFileSync(path.join(repo,'target/debug/vw-access'),['--state-root',ready.root,...args],{encoding:'utf8',stdio:'pipe'}));
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
  const review=await browser.newPage();let dialogs=0;review.on('dialog',async dialog=>{dialogs++;await dialog.dismiss();});review.on('pageerror',e=>errors.push(String(e)));await review.goto(pathToFileURL(artifact).href); // automatic artifact navigation
  await review.waitForFunction(()=>document.querySelector('#review-status')?.textContent==='Request status: pending');
  assert.equal(await review.evaluate(()=>location.hash),'');assert.equal(await review.$eval('#details',e=>e.querySelectorAll('img,script').length),0);assert.equal(dialogs,0);
  const detail=await review.$eval('#details',e=>e.textContent);for(const expected of ['local human terminal','Deploy <img src=x onerror=alert(1)>','staging','safe','Deployment <login>','Request ID','Policy digest','Executable digest','Arguments digest','One-time meaning'])assert(detail.includes(expected),expected);
  for(const forbidden of ['11111111-1111-1111-1111-111111111111','DEPLOY_PASSWORD','synthetic-browser-password'])assert(!detail.includes(forbidden));
  assert.equal(await review.$eval('#review-status',e=>e.getAttribute('aria-atomic')),'true');
  assert.deepEqual(await review.$$eval('#arguments > li',items=>items.map(item=>({text:item.textContent,name:item.getAttribute('aria-label')}))),[{text:'staging',name:'Argument 1'},{text:'safe|"quoted"',name:'Argument 2'},{text:'3',name:'Argument 3'}]);
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

  const controls=await review.$$eval('button',buttons=>buttons.map(b=>b.textContent));assert(!controls.some(name=>/^(Approve|Deny)$/.test(name)));
  await review.focus('#password');for(let i=0;i<3;i++)await review.keyboard.press('Tab');assert.equal(await review.evaluate(()=>document.activeElement.id),'refresh');await review.keyboard.press('Enter');
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
  const proofStillWorks=await page.evaluate(async id=>(await fetch('/review',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':sessionStorage.getItem('vw_proof')},body:JSON.stringify({request_id:id})})).status,receipt.id);assert.equal(proofStillWorks,200);
  fs.writeFileSync(path.join(control,'clock'),'310');await review.waitForFunction(()=>document.querySelector('#review-status').textContent==='Request status: expired');
  await review.focus('#lock');await review.keyboard.press('Enter');await review.waitForFunction(()=>document.querySelector('#result').textContent.includes('Provider locked'));assert.equal(run(['status',receipt.id]).state.status,'expired');assert.equal(await review.$eval('#review-status',e=>e.textContent),'Request status: expired');
  const knownDiagnostics=errors.filter(e=>e.includes('Permission denied to access property \"__bidi_args\"')||e==='Error: Error: Permission denied to access property \"length\"'||(e.includes('Content-Security-Policy')&&e.includes('/favicon.ico')));
  assert.deepEqual(errors.filter(e=>!knownDiagnostics.includes(e)),[]);
  for(const error of errors)for(const secret of ['synthetic-browser-password',capability,receipt.id])assert(!error.includes(secret),'diagnostic reflected protected input');
  const diagnosticCategories=[...new Set(knownDiagnostics.map(e=>e.replace(/https:\/\/127\.0\.0\.1:\d+/g,'https://127.0.0.1:<port>')))];
  console.log(JSON.stringify({browser:await browser.version(),trustedTLS:true,automaticArtifactNavigation:true,keyboardFocus:focus,axe:audit,requestReview:'pending -> expired -> expired while locked',launchReplay:'403',cookieOnly:'403',invalidProof:'403',priorSessionPreserved:true,concurrentFreshCookieTabs:true,transientPollingRecovery:true,immutableDetailsStable:true,unchangedLiveStatusStable:true,argumentBoundariesPreserved:true,screenReaderManual:false,automationDiagnostics:{knownCrossOriginOrBlockedFavicon:knownDiagnostics.length,categories:diagnosticCategories,unexpected:0}},null,2));
  fs.writeFileSync(path.join(control,'stop'),'stop');assert.equal(await closed,0,childOutput);
}finally{fs.writeFileSync(path.join(control,'stop'),'stop');await browser?.close();if(child.exitCode===null)child.kill('SIGTERM');}
