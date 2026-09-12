const assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),net=require('node:net'),http=require('node:http');
const {spawn}=require('node:child_process'),{once}=require('node:events'),{chromium}=require('playwright');
async function freePort(){const s=net.createServer().listen(0,'127.0.0.1');await once(s,'listening');const p=s.address().port;await new Promise(r=>s.close(r));return p;}
(async()=>{
 const data=fs.mkdtempSync(path.join(os.tmpdir(),'nullock-repeater-ui-')),port=await freePort(),base=`http://127.0.0.1:${port}`;
 const app=spawn(path.resolve(process.argv[2]),['--headless','--no-update-check',`--control-port=${port}`,`--proxy-port=${await freePort()}`,`--oast-port=${await freePort()}`,`--dns-port=${await freePort()}`],{windowsHide:true,env:{...process.env,NULLOCK_DATA_DIR:data}});
 const exited=once(app,'exit');let browser,heldResponse,logs='';app.stdout.on('data',d=>logs+=d);app.stderr.on('data',d=>logs+=d);
 const fixture=http.createServer((req,res)=>{heldResponse=res;});fixture.listen(0,'127.0.0.1');await once(fixture,'listening');
 async function api(p,data){return(await fetch(base+p,data===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json','X-Nullock-UI':'1'},body:JSON.stringify(data)})).json();}
 try{
  for(let i=0;i<150;i++){try{await api('/api/snapshot');break;}catch{assert.equal(app.exitCode,null,logs);await new Promise(r=>setTimeout(r,100));}}
  await api('/api/scope/in/add',{glob:'127.0.0.1'});
  await api('/api/repeater/set',{host:'127.0.0.1',port:fixture.address().port,tls:false,request:'GET /sent HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n'});
  browser=await chromium.launch({headless:true});const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];
  page.on('pageerror',e=>errors.push(e.message));await page.goto(base);await page.getByRole('button',{name:/SKIP$/}).click();
  await page.getByRole('tab',{name:/REPEATER/i}).click();await page.getByRole('button',{name:'▶ SEND',exact:true}).click();
  await page.getByRole('button',{name:'■ STOP',exact:true}).waitFor();
  const started=Date.now();await page.getByRole('tab',{name:/SCOPE/i}).click();await page.getByRole('tab',{name:/REPEATER/i}).click();
  assert.ok(Date.now()-started<2000,'tool navigation stays responsive during the send');
  const input=page.getByTitle('Ctrl+Space to send');await input.fill('GET /next-draft HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n');
  await page.waitForFunction(()=>NL.repeater.request.includes('/next-draft'));
  await page.getByRole('button',{name:'■ STOP',exact:true}).click();await page.getByRole('button',{name:'STOPPING…',exact:true}).waitFor();
  assert.ok(heldResponse);heldResponse.end('owned slow fixture');heldResponse=null;
  await page.waitForFunction(()=>!NL.repeater.busy&&NL.repeater.response.includes('owned slow fixture'));
  assert.ok((await input.inputValue()).includes('/next-draft'));assert.ok((await api('/api/snapshot')).repeater.statusLine.includes('stopped'));
  if(process.env.REPEATER_SCREENSHOT)await page.screenshot({path:path.resolve(process.env.REPEATER_SCREENSHOT)});
  assert.deepEqual(errors,[]);console.log('PASS: Repeater exposes busy/Stop states, other tools remain usable, and a late response preserves the edited draft');
  await api('/api/app/quit',{});
 }finally{
  if(heldResponse)heldResponse.end();if(browser)await browser.close();if(app.exitCode===null)app.kill();await exited;
  await new Promise(r=>fixture.close(r));fs.rmSync(data,{recursive:true,force:true,maxRetries:20,retryDelay:100});
 }
})().catch(e=>{console.error(e);process.exitCode=1;});
