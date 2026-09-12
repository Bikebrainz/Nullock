const assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),net=require('node:net'),http=require('node:http');
const {spawn}=require('node:child_process'),{once}=require('node:events'),{chromium}=require('playwright');
async function freePort(){const s=net.createServer().listen(0,'127.0.0.1');await once(s,'listening');const p=s.address().port;await new Promise(r=>s.close(r));return p;}
(async()=>{
 const data=fs.mkdtempSync(path.join(os.tmpdir(),'nullock-first-use-')),port=await freePort(),proxy=await freePort(),base=`http://127.0.0.1:${port}`;
 const app=spawn(path.resolve(process.argv[2]),['--headless','--no-update-check',`--control-port=${port}`,`--proxy-port=${proxy}`,`--oast-port=${await freePort()}`,`--dns-port=${await freePort()}`],{windowsHide:true,env:{...process.env,NULLOCK_DATA_DIR:data}});
 const exited=once(app,'exit');let browser,logs='';app.stdout.on('data',d=>logs+=d);app.stderr.on('data',d=>logs+=d);
 const fixture=http.createServer((req,res)=>{res.setHeader('Content-Type','text/plain');res.end('first capture fixture');});fixture.listen(0,'127.0.0.1');await once(fixture,'listening');
 const docs=path.resolve(__dirname,'../../docs');
 const site=http.createServer((req,res)=>{
  const target=path.resolve(docs,'.'+new URL(req.url,'http://localhost').pathname);
  const file=target.endsWith(path.sep)?path.join(target,'index.html'):target;
  try{const actual=fs.statSync(file).isDirectory()?path.join(file,'index.html'):file;
   if(!actual.startsWith(docs+path.sep))throw Error('outside docs');
   const ext=path.extname(actual);res.setHeader('Content-Type',({'.html':'text/html','.css':'text/css','.js':'application/javascript','.svg':'image/svg+xml','.png':'image/png','.woff2':'font/woff2'})[ext]||'application/octet-stream');res.end(fs.readFileSync(actual));
  }catch{res.statusCode=404;res.end('not found');}
 });site.listen(0,'127.0.0.1');await once(site,'listening');
 async function api(p,data){return(await fetch(base+p,data===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json','X-Nullock-UI':'1'},body:JSON.stringify(data)})).json();}
 try{
  for(let i=0;i<150;i++){try{await api('/api/snapshot');break;}catch{assert.equal(app.exitCode,null,logs);await new Promise(r=>setTimeout(r,100));}}
  browser=await chromium.launch({headless:true});const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];
  const scopeWrites=[];page.on('request',r=>{if(r.url().endsWith('/api/scope/in/add'))scopeWrites.push(r.postDataJSON());});
  page.on('pageerror',e=>errors.push(e.message));await page.goto(base);await page.getByRole('button',{name:/SKIP$/}).click();
  const guide=page.getByRole('region',{name:'First capture guide'});await guide.waitFor();
  assert.equal(await page.getByTestId('setup-proxy').innerText(),`127.0.0.1:${proxy}`);
  assert.ok(await guide.getByRole('button',{name:'STAGE FIRST REQUEST'}).isDisabled());
  const ca=await(await fetch(base+'/ca.pem')).text();assert.ok(ca.includes('BEGIN CERTIFICATE')&&!ca.includes('PRIVATE KEY'));
  await guide.getByRole('button',{name:'SET SCOPE'}).click();
  const input=page.getByPlaceholder('e.g. acme.corp, *.acme.corp, or paste a URL').first();
  await input.fill('127.0.0.1');await input.press('Enter');await page.waitForFunction(()=>NL.scope.in.includes('127.0.0.1'));
  assert.equal(scopeWrites[0].historyGeneration,(await api('/api/snapshot')).bootInfo.historyGeneration);
  await page.getByRole('tab',{name:/PROXY/i}).click();await guide.waitFor();
  await new Promise((resolve,reject)=>{
    const req=http.get({host:'127.0.0.1',port:proxy,path:`http://127.0.0.1:${fixture.address().port}/first`,headers:{Host:`127.0.0.1:${fixture.address().port}`}},res=>{let body='';res.on('data',d=>body+=d);res.on('end',()=>{try{assert.equal(body,'first capture fixture');resolve();}catch(e){reject(e);}});});req.on('error',reject);
  });
  await guide.getByRole('status').filter({hasText:/responses? in project history/}).waitFor();
  if(process.env.FIRST_USE_SCREENSHOT)await page.screenshot({path:path.resolve(process.env.FIRST_USE_SCREENSHOT)});
  await guide.getByRole('button',{name:'STAGE FIRST REQUEST'}).click();await page.getByTitle('Ctrl+Space to send').waitFor();
  await page.waitForFunction(()=>NL.repeater.request.includes('/first'));
  assert.ok((await page.getByTitle('Ctrl+Space to send').inputValue()).includes('/first'));
  await page.getByRole('button',{name:'▶ SEND',exact:true}).click();await page.waitForFunction(()=>NL.repeater.response.includes('first capture fixture')&&!NL.repeater.busy);
  await page.getByRole('tab',{name:/PROXY/i}).click();await page.getByRole('button',{name:'FIRST CAPTURE GUIDE',exact:true}).click();
  await guide.getByRole('button',{name:'REPORTS & EXPORT'}).click();await page.getByRole('tab',{name:/REPORTING/i,selected:true}).waitFor();
  await api('/api/project/create',{name:'new-guide-project'});await page.waitForFunction(()=>NL.bootInfo.project==='new-guide-project');
  await page.getByRole('tab',{name:/PROXY/i}).click();await guide.waitFor();
  assert.ok(await guide.getByRole('button',{name:'STAGE FIRST REQUEST'}).isDisabled());
  await page.getByRole('button',{name:'CLOSE SETUP GUIDE'}).click();await page.reload();
  assert.equal(await guide.count(),0,'explicit dismissal survives reload within this project generation');
  await page.getByRole('tab',{name:/LABS/i}).click();
  const labCount=await page.evaluate(()=>window.NULLOCK_LABS.length);
  await page.getByText(`${labCount} intentionally-vulnerable practice targets`,{exact:false}).waitFor();
  const firstLabTitle=await page.evaluate(()=>window.NULLOCK_LABS[0].title);
  await page.getByText(firstLabTitle,{exact:true}).click();
  await page.getByText('Before sending requests, copy labs/',{exact:false}).waitFor();
  if(process.env.LABS_SCREENSHOT)await page.screenshot({path:path.resolve(process.env.LABS_SCREENSHOT)});
  const sitePage=await browser.newPage({viewport:{width:1440,height:1100}});sitePage.on('pageerror',e=>errors.push(e.message));
  await sitePage.goto(`http://127.0.0.1:${site.address().port}/docs/#first-capture`);
  await sitePage.locator('#first-capture').scrollIntoViewIfNeeded();
  assert.ok((await sitePage.locator('#first-capture').innerText()).includes('Stage first request'));
  assert.ok((await sitePage.locator('#getting-started').innerText()).includes('Automatic release checks'));
  if(process.env.FIRST_USE_SITE_SCREENSHOT)await sitePage.screenshot({path:path.resolve(process.env.FIRST_USE_SITE_SCREENSHOT)});
  await sitePage.setViewportSize({width:390,height:844});
  assert.ok(await sitePage.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'docs have no horizontal overflow on a narrow screen');
  await sitePage.goto(`http://127.0.0.1:${site.address().port}/labs/67-graphql-depth-dos.html`);
  const download=sitePage.getByRole('link',{name:'project.json',exact:true});
  assert.equal(await download.getAttribute('download'),'project.json');
  const preset=await(await fetch(new URL(await download.getAttribute('href'),sitePage.url()))).json();
  assert.equal(preset.advancedScope[0].portFrom,5067);
  assert.ok(await sitePage.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'long lab payload wraps on mobile');
  if(process.env.LABS_SITE_SCREENSHOT)await sitePage.screenshot({path:path.resolve(process.env.LABS_SITE_SCREENSHOT),fullPage:true});
  assert.deepEqual(errors,[]);console.log('PASS: first-use guide uses live ports, scope-to-capture-to-Repeater works, projects reset the guide, dismissal persists, the lab catalog shows its actual count, presets download, and site instructions render at desktop/mobile widths');
  await api('/api/app/quit',{});
 }finally{
  if(browser)await browser.close();if(app.exitCode===null)app.kill();await exited;
  await Promise.all([new Promise(r=>fixture.close(r)),new Promise(r=>site.close(r))]);
  fs.rmSync(data,{recursive:true,force:true,maxRetries:20,retryDelay:100});
 }
})().catch(e=>{console.error(e);process.exitCode=1;});
