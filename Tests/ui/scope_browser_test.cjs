const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const {spawn} = require('node:child_process');
const {once} = require('node:events');
const {chromium} = require('playwright');
async function freePort() {
  const s = net.createServer().listen(0,'127.0.0.1'); await once(s,'listening');
  const port = s.address().port; await new Promise(r=>s.close(r)); return port;
}
(async()=>{
  const data = fs.mkdtempSync(path.join(os.tmpdir(),'nullock-scope-ui-'));
  const project = path.join(data,'projects','invalid-scope'); fs.mkdirSync(project,{recursive:true});
  fs.writeFileSync(path.join(project,'project.json'),JSON.stringify({name:'invalid-scope',advancedScope:[{include:false,host:'['}]}));
  const port = await freePort(), base = `http://127.0.0.1:${port}`;
  const app = spawn(path.resolve(process.argv[2]),['--headless','--no-update-check',`--project=${project}`,
    `--control-port=${port}`,`--proxy-port=${await freePort()}`,`--oast-port=${await freePort()}`,`--dns-port=${await freePort()}`],
    {windowsHide:true,env:{...process.env,NULLOCK_DATA_DIR:data}});
  const exited=once(app,'exit'); let browser, logs='';
  app.stdout.on('data',d=>logs+=d);app.stderr.on('data',d=>logs+=d);
  async function api(p,body){return (await fetch(base+p,body===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json','X-Nullock-UI':'1'},body:JSON.stringify(body)})).json();}
  try {
    for(let i=0;i<150;i++){try{await api('/api/snapshot');break;}catch{assert.equal(app.exitCode,null,logs);await new Promise(r=>setTimeout(r,100));}}
    browser=await chromium.launch({headless:true});
    const page=await browser.newPage({viewport:{width:1440,height:1000}});const errors=[];
    page.on('pageerror',e=>errors.push(e.message)); await page.goto(base);
    await page.getByRole('button',{name:/SKIP$/}).click();
    await page.getByRole('tab',{name:/SCOPE/i}).click();
    await page.getByRole('alert').filter({hasText:'Active traffic is blocked'}).waitFor();
    const host=page.getByPlaceholder('host regex (blank = any)');
    await host.fill('fixture\\.test'); await page.getByRole('button',{name:'SAVE',exact:true}).and(page.locator(':enabled')).click();
    await page.waitForFunction(()=>NL.scope.advanced[0]?.host==='fixture\\.test'&&!NL.scope.validationError);
    assert.equal(await page.getByRole('alert').count(),0);
    await host.fill('['); await page.getByRole('button',{name:'SAVE',exact:true}).and(page.locator(':enabled')).click();
    await page.getByRole('alert').filter({hasText:'invalid regular expression'}).waitFor();
    assert.equal((await api('/api/snapshot')).scope.advanced[0].host,'fixture\\.test');
    assert.equal(await host.inputValue(),'[');
    assert.equal(await page.getByText('unsaved',{exact:true}).count(),1);
    if(process.env.SCOPE_SCREENSHOT) await page.screenshot({path:path.resolve(process.env.SCOPE_SCREENSHOT)});
    assert.equal((await api('/api/project/create',{name:'scope-peer'})).ok,true);
    await page.waitForFunction(()=>NL.bootInfo.project==='scope-peer');
    assert.equal(await host.count(),0);
    assert.equal(await page.getByText('unsaved',{exact:true}).count(),0);
    assert.deepEqual(errors,[]);
    console.log('PASS: invalid saved scope is visible; correction re-enables traffic; rejected edits stay unsaved and preserve effective policy');
    await api('/api/app/quit',{});
  }finally{
    if(browser)await browser.close(); if(app.exitCode===null)app.kill(); await exited;
    fs.rmSync(data,{recursive:true,force:true,maxRetries:20,retryDelay:100});
  }
})().catch(e=>{console.error(e);process.exitCode=1;});
