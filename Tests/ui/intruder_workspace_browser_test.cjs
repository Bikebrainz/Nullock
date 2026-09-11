const {chromium} = require('playwright');
const {spawn} = require('node:child_process');
const {once} = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const assert = require('node:assert/strict');
async function freePort() {
  const server = net.createServer().listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}
(async () => {
  const data = fs.mkdtempSync(path.join(os.tmpdir(), 'nullock-intruder-ui-'));
  const control = await freePort(), base = `http://127.0.0.1:${control}`;
  const app = spawn(path.resolve(process.argv[2]), ['--headless', '--no-update-check',
    `--control-port=${control}`, `--proxy-port=${await freePort()}`,
    `--oast-port=${await freePort()}`, `--dns-port=${await freePort()}`],
    {windowsHide:true, env:{...process.env, NULLOCK_DATA_DIR:data}});
  let browser, logs = '';
  app.stdout.on('data', value => { logs += value; });
  app.stderr.on('data', value => { logs += value; });
  const exited = once(app, 'exit');
  async function api(endpoint, body) {
    const response = await fetch(base + endpoint, body === undefined ? {} : {method:'POST',
      headers:{'Content-Type':'application/json', 'X-Nullock-UI':'1'}, body:JSON.stringify(body)});
    return response.json();
  }
  try {
    for (let i = 0; i < 150; ++i) {
      if (app.exitCode !== null) throw new Error(logs);
      try { await api('/api/snapshot'); break; } catch {}
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    assert.equal((await api('/api/project/create', {name:'ui-workspace-a'})).ok, true);
    browser = await chromium.launch({headless:true});
    const page = await browser.newPage({viewport:{width:1440, height:1000}});
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(base);
    await page.getByRole('button', {name:/SKIP$/}).click();
    await page.getByRole('tab', {name:/INTRUDER/i}).click();
    const peer = await browser.newPage();
    peer.on('pageerror', error => errors.push(error.message));
    await peer.goto(base);
    const host = page.locator('.target-row .fld').filter({hasText:'HOST'}).locator('input');
    await host.fill('staged.workspace.test');
    await page.waitForFunction(() => NL.intruder.host === 'staged.workspace.test');
    await peer.waitForFunction(() => NL.intruder.host === 'staged.workspace.test');
    assert.equal((await api('/api/intruder/set', {concurrency:3, throttleMs:75})).ok, true);
    await page.waitForFunction(() => NL.intruder.concurrency === 3 && NL.intruder.throttleMs === 75);
    await peer.waitForFunction(() => NL.intruder.concurrency === 3 && NL.intruder.throttleMs === 75);
    const saved = await api('/api/intruder/export');
    assert.equal((await api('/api/project/create', {name:'ui-workspace-b'})).ok, true);
    await page.waitForFunction(() => NL.bootInfo.project === 'ui-workspace-b');
    await peer.waitForFunction(() => NL.bootInfo.project === 'ui-workspace-b' && NL.intruder.host === '');
    assert.equal(await host.inputValue(), '');
    await host.fill('independent.workspace.test');
    await page.waitForFunction(() => NL.intruder.host === 'independent.workspace.test');
    assert.equal((await api('/api/project/open', {name:'ui-workspace-a'})).ok, true);
    await page.waitForFunction(() => NL.bootInfo.project === 'ui-workspace-a'
      && NL.intruder.host === 'staged.workspace.test');
    assert.equal(await host.inputValue(), 'staged.workspace.test');
    assert.deepEqual(await api('/api/intruder/export'), saved);
    await page.reload();
    await page.getByRole('button', {name:/SKIP$/}).click();
    await page.getByRole('tab', {name:/INTRUDER/i}).click();
    assert.equal(await host.inputValue(), 'staged.workspace.test');
    assert.equal(await page.evaluate(() => NL.intruder.running), false);
    assert.deepEqual(errors, []);
    console.log('PASS: Intruder target and options synchronize between clients; project restoration/reload remains isolated and idle');
    await api('/api/app/quit', {});
  } finally {
    if (browser) await browser.close();
    if (app.exitCode === null) app.kill();
    await exited;
    fs.rmSync(data, {recursive:true, force:true, maxRetries:20, retryDelay:100});
  }
})().catch(error => {console.error(error); process.exitCode = 1;});
