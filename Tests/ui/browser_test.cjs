// Start an isolated local app, open every tool, and verify backend loss is visible.
const { chromium } = require('playwright');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const assert = require('node:assert/strict');
async function freePort() {
  const server = net.createServer(); server.listen(0, '127.0.0.1');
  await once(server, 'listening'); const port = server.address().port;
  await new Promise(resolve => server.close(resolve)); return port;
}
(async () => {
  const appPath = path.resolve(process.argv[2]);
  const data = fs.mkdtempSync(path.join(os.tmpdir(), 'nullock-browser-'));
  const port = await freePort();
  const url = `http://127.0.0.1:${port}`;
  let logs = '', browser;
  const app = spawn(appPath, ['--headless', '--no-update-check', `--control-port=${port}`,
    `--proxy-port=${await freePort()}`, `--oast-port=${await freePort()}`, `--dns-port=${await freePort()}`],
    { windowsHide: true, env: { ...process.env, NULLOCK_DATA_DIR: data } });
  app.stdout.on('data', b => { logs += b; }); app.stderr.on('data', b => { logs += b; });
  const exited = once(app, 'exit');
  try {
    for (let i = 0; i < 150; i++) {
      if (app.exitCode !== null) throw new Error(logs);
      try { const r = await fetch(url + '/api/snapshot'); if (r.ok) break; } catch {}
      await new Promise(r => setTimeout(r, 100));
    }
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    const errors = []; page.on('pageerror', e => errors.push(e.message));
    await page.goto(url);
    await page.getByRole('button', { name: 'SKIP' }).click();
    const tabs = page.getByRole('tab');
    assert.equal(await tabs.count(), 25);
    for (let i = 0; i < 25; i++) {
      await tabs.nth(i).click();
      await page.waitForTimeout(150); // allow the selected tool's asynchronous catalog to render
      assert.deepEqual(errors, [], `tool ${i + 1}`);
      assert.equal(await tabs.nth(i).getAttribute('aria-selected'), 'true');
    }
    await page.request.post(url + '/api/app/quit', { headers: { 'X-Nullock-UI': '1' } });
    await page.waitForFunction(() => document.body.innerText.includes('DISCONNECTED'));
    assert.deepEqual(errors, []);
    console.log('PASS: all 25 tools render, vendored scripts load, disconnection is visible');
  } finally {
    if (browser) await browser.close();
    if (app.exitCode === null) app.kill();
    await exited;
    fs.rmSync(data, { recursive: true, force: true });
  }
})().catch(e => { console.error(e); process.exitCode = 1; });
