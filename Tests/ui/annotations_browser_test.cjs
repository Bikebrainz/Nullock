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
  await once(server, 'listening'); const port = server.address().port;
  await new Promise(resolve => server.close(resolve)); return port;
}
(async () => {
  const data = fs.mkdtempSync(path.join(os.tmpdir(), 'nullock-notes-ui-'));
  const port = await freePort(), base = `http://127.0.0.1:${port}`;
  const app = spawn(path.resolve(process.argv[2]), ['--headless', '--no-update-check',
    `--control-port=${port}`, `--proxy-port=${await freePort()}`,
    `--oast-port=${await freePort()}`, `--dns-port=${await freePort()}`],
    {windowsHide:true, env:{...process.env, NULLOCK_DATA_DIR:data}});
  let logs = '', browser;
  app.stdout.on('data', b => { logs += b; }); app.stderr.on('data', b => { logs += b; });
  const exited = once(app, 'exit');
  try {
    for (let i = 0; i < 150; ++i) {
      if (app.exitCode !== null) throw new Error(logs);
      try { if ((await fetch(base + '/api/snapshot')).ok) break; } catch {}
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    const entries = ['/annotated', '/legacy'].map(p => ({request:{method:'GET',
      url:'http://notes.test' + p, headers:[], httpVersion:'HTTP/1.1'},
      response:{status:200, statusText:'OK', headers:[], httpVersion:'HTTP/1.1', content:{text:'fixture'}}}));
    const imported = await fetch(base + '/api/har/import', {method:'POST',
      headers:{'Content-Type':'application/json', 'X-Nullock-UI':'1'},
      body:JSON.stringify({har:{log:{version:'1.2', entries}}})});
    assert.equal((await imported.json()).ok, true);
    browser = await chromium.launch({headless:true});
    const first = await browser.newContext({viewport:{width:1440, height:1000}});
    const second = await browser.newContext({viewport:{width:1440, height:1000}});
    const page = await first.newPage(), peer = await second.newPage();
    const errors = [];
    for (const p of [page, peer]) {
      p.on('pageerror', error => errors.push(error.message));
      await p.goto(base);
      await p.getByRole('button', {name:/SKIP$/}).click();
      await p.getByRole('tab').first().click();
      await p.waitForFunction(() => NL._annotationsLoadedRevision === NL.bootInfo.annotationsRevision);
    }
    const row = page.locator('table.tbl tbody tr').filter({hasText:'/annotated'});
    await row.click({button:'right'});
    await page.getByRole('button', {name:'Highlight purple', exact:true}).click();
    await peer.waitForFunction(() => NL.historyAnnotations['1']?.color === 'purple');
    assert.match(await row.getAttribute('style'), /inset/);
    const note = '<img src=x onerror=alert(1)>\nUnicode: café 雪';
    await row.click({button:'right'});
    page.once('dialog', dialog => dialog.accept(note));
    await page.getByText('✎ ADD COMMENT', {exact:true}).click();
    await peer.getByTitle(note, {exact:true}).waitFor();
    await page.reload();
    await page.getByTitle(note, {exact:true}).waitFor();
    console.log('PASS: highlight and comment persist on reload and appear in an independent browser client');

    const exports = await page.evaluate(note => {
      const row = {...NL.rows.find(r => r.id === 1), path:'/annotated]]><fake/>', annotation:NL.historyAnnotations['1']};
      const xml = buildSiteMapItemsXml([row], 0);
      const doc = new DOMParser().parseFromString(xml, 'application/xml');
      const savedNote = NL.historyAnnotations['1'];
      NL.historyAnnotations['1'] = {comment:'bad\u0000\u0001\uD800😀'};
      const unusual = buildSiteMapItemsXml([row], 0);
      NL.historyAnnotations['1'] = savedNote;
      const unusualDoc = new DOMParser().parseFromString(unusual, 'application/xml');
      const html = buildBranchIssuesHtml([], 'notes.test', [row]);
      const report = new DOMParser().parseFromString(html, 'text/html');
      return {xmlValid:!doc.querySelector('parsererror'), comment:doc.querySelector('comment')?.textContent,
        unusualValid:!unusualDoc.querySelector('parsererror'), unusualComment:unusualDoc.querySelector('comment')?.textContent,
        highlight:doc.querySelector('highlight')?.textContent, htmlText:report.body.textContent,
        injected:!!report.querySelector('img, script'), note};
    }, note);
    assert.equal(exports.xmlValid, true); assert.equal(exports.comment, note);
    assert.equal(exports.unusualValid, true); assert.equal(exports.unusualComment, 'bad\uFFFD\uFFFD\uFFFD😀');
    assert.equal(exports.highlight, 'purple'); assert.equal(exports.injected, false);
    assert(exports.htmlText.includes(note));
    console.log('PASS: selected-item XML and branch HTML include escaped investigation notes');

    let releaseFirst, releaseSecond, reachedFirst, reachedSecond, writes = 0;
    const firstGate = new Promise(resolve => { releaseFirst = resolve; });
    const secondGate = new Promise(resolve => { releaseSecond = resolve; });
    const firstReached = new Promise(resolve => { reachedFirst = resolve; });
    const secondReached = new Promise(resolve => { reachedSecond = resolve; });
    await page.route('**/api/history/annotation', async route => {
      if (++writes === 1) { reachedFirst(); await firstGate; }
      else { reachedSecond(); await secondGate; }
      await route.continue();
    });
    await row.click({button:'right'});
    await page.getByRole('button', {name:'Highlight green', exact:true}).click();
    await Promise.race([firstReached, new Promise((_, reject) => {
      const timer = setTimeout(() => reject(new Error('First annotation write did not arrive')), 10000);
      firstReached.then(() => clearTimeout(timer));
    })]);
    await row.click({button:'right'});
    await page.getByRole('button', {name:'Highlight purple', exact:true}).click();
    releaseFirst();
    await Promise.race([secondReached, new Promise((_, reject) => {
      const timer = setTimeout(() => reject(new Error('Queued annotation write did not arrive')), 10000);
      secondReached.then(() => clearTimeout(timer));
    })]);
    await page.evaluate(() => new Promise(requestAnimationFrame));
    await page.getByRole('status').filter({hasText:'Saving notes'}).waitFor();
    releaseSecond();
    await page.getByRole('status').filter({hasText:'Saving notes'}).waitFor({state:'hidden'});
    await page.unroute('**/api/history/annotation');
    assert.equal(await page.evaluate(() => NL.historyAnnotations['1'].color), 'purple');
    console.log('PASS: overlapping edits keep the saving indicator until the final write completes');

    await page.evaluate(() => {
      const b = NL.bootInfo;
      const key = 'nl.history.annotations.v2:' + encodeURIComponent(b.projectDir + ':' + b.historyEpoch);
      localStorage.setItem(key, JSON.stringify({'1':{comment:'stale browser note'}, '2':{comment:'Legacy note', color:'green'}}));
    });
    await page.reload();
    await page.waitForFunction(() => NL._annotationsLoadedRevision === NL.bootInfo.annotationsRevision);
    await page.getByRole('button', {name:'SAVE BROWSER NOTES TO PROJECT', exact:true}).click();
    await peer.waitForFunction(() => NL.historyAnnotations['2']?.comment === 'Legacy note');
    assert.equal(await peer.evaluate(() => NL.historyAnnotations['1'].comment), note);
    await page.getByRole('button', {name:'SAVE BROWSER NOTES TO PROJECT', exact:true}).waitFor({state:'hidden'});
    console.log('PASS: legacy browser notes migrate without overwriting existing project notes');

    await page.route('**/api/history/annotation', route => route.fulfill({status:500,
      contentType:'application/json', body:JSON.stringify({ok:false, error:'Fixture save failure'})}));
    await row.click({button:'right'});
    await page.getByRole('button', {name:'Highlight red', exact:true}).click();
    await page.getByRole('alert').filter({hasText:'Fixture save failure'}).waitFor();
    assert.equal(await page.evaluate(() => NL.historyAnnotations['1'].color), 'purple');
    await page.unroute('**/api/history/annotation');
    assert.deepEqual(errors, []);
    console.log('PASS: failed saves are visible and retain the last saved note; no JavaScript errors');
    await page.request.post(base + '/api/app/quit', {headers:{'X-Nullock-UI':'1'}});
  } finally {
    if (browser) await browser.close();
    if (app.exitCode === null) app.kill();
    await exited;
    fs.rmSync(data, {recursive:true, force:true, maxRetries:20, retryDelay:100});
  }
})().catch(error => {console.error(error); process.exitCode = 1;});
