const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const http = require('node:http');
const {spawn} = require('node:child_process');
const {once} = require('node:events');
const {chromium} = require('playwright');
async function freePort() {
  const s=net.createServer().listen(0,'127.0.0.1'); await once(s,'listening');
  const port=s.address().port; await new Promise(r=>s.close(r)); return port;
}
(async()=>{
  const data=fs.mkdtempSync(path.join(os.tmpdir(),'nullock-recovery-ui-'));
  const port=await freePort(), base=`http://127.0.0.1:${port}`;
  const app=spawn(path.resolve(process.argv[2]),['--headless','--no-update-check',
    `--control-port=${port}`,`--proxy-port=${await freePort()}`,`--oast-port=${await freePort()}`,`--dns-port=${await freePort()}`],
    {windowsHide:true,env:{...process.env,NULLOCK_DATA_DIR:data}});
  const exited=once(app,'exit'); let browser, logs='', shots=0;
  app.stdout.on('data',d=>logs+=d);app.stderr.on('data',d=>logs+=d);
  const fixture=http.createServer((req,res)=>{res.setHeader('X-Sample','captured-'+ ++shots); res.end('ok');});
  fixture.listen(0,'127.0.0.1');await once(fixture,'listening');
  async function api(p,body){return (await fetch(base+p,body===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json','X-Nullock-UI':'1'},body:JSON.stringify(body)})).json();}
  try{
    for(let i=0;i<150;i++){try{await api('/api/snapshot');break;}catch{assert.equal(app.exitCode,null,logs);await new Promise(r=>setTimeout(r,100));}}
    browser=await chromium.launch({headless:true});const page=await browser.newPage({viewport:{width:1440,height:1000}});
    const errors=[];page.on('pageerror',e=>errors.push(e.message));
    await page.goto(base);await page.getByRole('button',{name:/SKIP$/}).click();
    await page.getByRole('tab',{name:/SEQUENCER/i}).click();
    const corpus=page.getByPlaceholder('paste one token per line (session cookies, CSRF tokens, reset-URL tokens, ...)');
    await corpus.fill('manual-a\nmanual-b');
    await page.waitForFunction(()=>NL.sequencerWorkspace?.draft.text==='manual-a\nmanual-b'&&!NL.sequencerError);
    await page.waitForFunction(async()=> (await (await fetch('/api/sequencer/workspace')).json()).draft.text==='manual-a\nmanual-b');
    await page.getByRole('tab',{name:/SCOPE/i}).click();await page.getByRole('tab',{name:/SEQUENCER/i}).click();
    assert.equal(await corpus.inputValue(),'manual-a\nmanual-b');
    await page.reload();await page.getByRole('tab',{name:/SEQUENCER/i}).click();
    await corpus.waitFor();assert.equal(await corpus.inputValue(),'manual-a\nmanual-b');
    await api('/api/scope/in/add',{glob:'127.0.0.1'});
    const capture={host:'127.0.0.1',port:fixture.address().port,tls:false,count:2,
      request:'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n',extract:{from:'header',key:'X-Sample'}};
    for(let run=0;run<2;run++){
      assert.equal((await api('/api/sequencer/capture/start',capture)).ok,true);
      await page.waitForFunction(n=>NL.sequencerWorkspace?.draft.text.endsWith('captured-'+n),2*(run+1));
    }
    const expected='manual-a\nmanual-b\ncaptured-1\ncaptured-2\ncaptured-3\ncaptured-4';
    assert.equal(await corpus.inputValue(),expected);
    await page.reload();await page.getByRole('tab',{name:/SEQUENCER/i}).click();await corpus.waitFor();
    assert.equal(await corpus.inputValue(),expected,'reloading never imports captured tokens twice');
    // Hold a text write after its revision is captured, then append from another client.
    let release, intercepted;
    const held=new Promise(r=>intercepted=r), gate=new Promise(r=>release=r);
    await page.route('**/api/sequencer/workspace/patch',async route=>{intercepted();await gate;await route.continue();});
    await corpus.fill('local unsaved edit');await held;
    await api('/api/sequencer/workspace/append',{text:'peer-token'});release();
    await page.getByRole('alert').filter({hasText:'Unsaved edit'}).waitFor();
    assert.equal(await corpus.inputValue(),'local unsaved edit');
    assert.equal((await api('/api/sequencer/workspace')).draft.text,expected+'\npeer-token');
    await page.unroute('**/api/sequencer/workspace/patch');
    await page.getByRole('button',{name:'RELOAD SAVED CORPUS'}).click();
    await page.waitForFunction(()=>NL.sequencerWorkspace?.draft.text.endsWith('peer-token'));
    if(process.env.RECOVERY_SCREENSHOT)await page.screenshot({path:path.resolve(process.env.RECOVERY_SCREENSHOT)});
    await api('/api/project/create',{name:'recovery-ui-peer'});
    await page.waitForFunction(()=>NL.bootInfo.project==='recovery-ui-peer'&&NL.sequencerWorkspace);
    assert.equal(await corpus.inputValue(),'');
    await page.evaluate(()=>NL.actions.sequencerAppend('send-while-closed'));
    await page.getByRole('tab',{name:/SCOPE/i}).click();await page.getByRole('tab',{name:/SEQUENCER/i}).click();
    assert.equal(await corpus.inputValue(),'send-while-closed');
    assert.deepEqual(errors,[]);
    console.log('PASS: Sequencer drafts survive tab changes/reload, repeated captures append once, conflicts preserve unsaved text, and projects stay isolated');
    await api('/api/app/quit',{});
  }finally{
    if(browser)await browser.close();if(app.exitCode===null)app.kill();await exited;
    await new Promise(r=>fixture.close(r));
    fs.rmSync(data,{recursive:true,force:true,maxRetries:20,retryDelay:100});
  }
})().catch(e=>{console.error(e);process.exitCode=1;});
