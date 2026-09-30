const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const net = require('node:net'), http = require('node:http'), zlib = require('node:zlib');
const {spawn} = require('node:child_process'), {once} = require('node:events');
const {chromium} = require('playwright');

async function freePort() {
  const server = net.createServer().listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

(async () => {
  const data = fs.mkdtempSync(path.join(os.tmpdir(), 'nullock-repeater-bytes-ui-'));
  const port = await freePort(), base = `http://127.0.0.1:${port}`;
  const body = Buffer.from(Array.from({length: 76806}, (_, i) => i % 256));
  const compressed = zlib.gzipSync(body);
  const fixture = http.createServer((req, res) => {
    res.writeHead(200, {'Content-Length': compressed.length, 'Content-Encoding': 'gzip',
      'Content-Type': 'application/octet-stream', 'Connection': 'close'});
    res.end(compressed);
  }).listen(0, '127.0.0.1');
  await once(fixture, 'listening');
  const app = spawn(path.resolve(process.argv[2]), ['--headless', '--no-update-check',
    `--control-port=${port}`, `--proxy-port=${await freePort()}`,
    `--oast-port=${await freePort()}`, `--dns-port=${await freePort()}`],
    {windowsHide: true, env: {...process.env, NULLOCK_DATA_DIR: data}});
  const exited = once(app, 'exit');
  let browser, logs = '';
  app.stdout.on('data', d => logs += d); app.stderr.on('data', d => logs += d);
  async function api(endpoint, payload) {
    const response = await fetch(base + endpoint, payload === undefined ? {} : {
      method: 'POST', headers: {'Content-Type': 'application/json', 'X-Nullock-UI': '1'},
      body: JSON.stringify(payload)});
    assert.ok(response.ok, `${endpoint}: ${response.status}`);
    return response.json();
  }
  try {
    for (let i = 0; i < 150; i++) {
      try {await api('/api/snapshot'); break;}
      catch {assert.equal(app.exitCode, null, logs); await new Promise(r => setTimeout(r, 100));}
    }
    await api('/api/scope/in/add', {glob: '127.0.0.1'});
    await api('/api/repeater/set', {host: '127.0.0.1', port: fixture.address().port, tls: false,
      request: 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n\u0000\u00ff\u0080A', requestEncoding: 'latin1'});
    browser = await chromium.launch({headless: true});
    const page = await browser.newPage({viewport: {width: 1440, height: 1000}}), errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.goto(base); await page.getByRole('button', {name: /SKIP$/}).click();
    await page.getByRole('tab', {name: /REPEATER/i}).click();
    const requestPane = page.locator('.pane').filter({has: page.getByText('REQUEST · editable', {exact: true})});
    const responsePane = page.locator('.pane').filter({has: page.getByText('RESPONSE · read-only', {exact: true})});
    await requestPane.getByRole('button', {name: 'hex', exact: true}).click();
    assert.match(await requestPane.locator('textarea').inputValue(), /00 ff 80 41/);
    await page.getByRole('combobox', {name: 'Request encoding', exact: true}).selectOption('utf8');
    await page.waitForFunction(() => NL.repeater.requestEncoding === 'utf8');
    assert.match(await requestPane.locator('textarea').inputValue(), /00 c3 bf c2 80 41/);
    console.log('PASS: request Hex respects Latin-1 and UTF-8 for NUL and non-ASCII bytes');
    await page.getByRole('button', {name: '▶ SEND', exact: true}).click();
    await page.waitForFunction(() => !NL.repeater.busy && NL.repeater.responseBodyDecoded);
    await responsePane.getByRole('button', {name: 'hex', exact: true}).click();
    const hex = await responsePane.locator('textarea').inputValue();
    assert.match(hex, /^00000000  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f/);
    assert.match(hex, /000000f0  f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff/);
    assert.match(hex, /0000fff0/); assert.ok(!hex.includes('00010000'));
    assert.match(hex, /truncated at 64 KiB/);
    async function download(expected) {
      const pending = page.waitForEvent('download');
      await responsePane.getByRole('button', {name: '↓ SAVE BYTES', exact: true}).click();
      const item = await pending;
      assert.deepEqual(fs.readFileSync(await item.path()), expected);
    }
    await download(body);
    await page.getByRole('combobox', {name: 'Response byte source', exact: true}).selectOption('wire');
    assert.match(await responsePane.locator('textarea').inputValue(), /^00000000  48 54 54 50 2f/);
    const snapshot = (await api('/api/snapshot')).repeater;
    const wire = Buffer.from(snapshot.responseWireBase64, 'base64');
    assert.deepEqual(wire.subarray(wire.indexOf('\r\n\r\n') + 4), compressed);
    await download(wire);
    await responsePane.getByRole('button', {name: 'body', exact: true}).click();
    assert.ok((await responsePane.locator('textarea').inputValue()).length > 70000, 'CRLF body view is populated');
    assert.deepEqual(errors, []);
    if (process.env.REPEATER_BYTES_SCREENSHOT) await page.screenshot({path: path.resolve(process.env.REPEATER_BYTES_SCREENSHOT)});
    console.log('PASS: response Hex uses exact selected bytes; full body/wire downloads survive preview truncation and gzip');
    await responsePane.getByRole('button', {name: 'hex', exact: true}).click();
    await page.getByRole('button', {name: 'CLEAR', exact: true}).first().click();
    assert.equal(await responsePane.locator('textarea').inputValue(), '');
    assert.ok(await responsePane.getByRole('button', {name: '↓ SAVE BYTES', exact: true}).isDisabled());
    console.log('PASS: clearing the draft immediately clears Hex and disables stale-response downloads');
    await api('/api/app/quit', {});
  } finally {
    if (browser) await browser.close();
    if (app.exitCode === null) app.kill();
    await exited;
    await new Promise(resolve => fixture.close(resolve));
    fs.rmSync(data, {recursive: true, force: true, maxRetries: 20, retryDelay: 100});
  }
})().catch(error => {console.error(error); process.exitCode = 1;});
