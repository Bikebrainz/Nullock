// Compare production header decisions with real loopback HTTP responses.
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { chromium } = require('playwright');
const audit = path.resolve(process.argv[2]);
const xss = path.resolve(process.argv[3]);
const sniffCases = [
  [[], false, false], [['nosniff'], true, true], [['NoSnIfF'], true, true],
  [['\tnosniff\t'], true, true], [['not-nosniff'], false, false],
  [['nosniff-extra'], false, false], [['"nosniff"'], false, false],
  [['nosniff;'], false, false], [['nosniff, invalid'], true, false],
  [['invalid, nosniff'], false, false], [['', 'nosniff'], false, false],
  [[',nosniff'], false, false], [['nosniff', 'invalid'], true, false],
  [['invalid', 'nosniff'], false, false], [['nosniff', 'nosniff'], true, false],
  [['nosniff, nosniff'], true, false], [['\u00a0nosniff\u00a0'], false, false],
];
const referrerCases = [
  [[], ''], [['unsafe-url'], 'unsafe-url'], [['UNSAFE-URL'], 'unsafe-url'],
  [['unsafe-url, future-policy'], 'unsafe-url'], [['unsafe-url, no-referrer'], 'no-referrer'],
  [['no-referrer', 'unsafe-url'], 'unsafe-url'], [['unsafe-url', 'no-referrer'], 'no-referrer'],
  [['unsafe-url', 'future-policy'], 'unsafe-url'], [['"unsafe-url"'], ''],
  [['unsafe-url;'], ''], [['future-policy'], ''], [['never'], ''], [['always'], ''],
  [['unsafe-url, "future,no-referrer"'], ''], [['no-referrer, "future,unsafe-url"'], ''],
  [['unsafe-url,'], 'unsafe-url'], [['unsafe-url', ''], 'unsafe-url'],
  [['unsafe-url, future2'], ''], [['unsafe-url, future_policy'], ''],
  [['unsafe-url, no-referrer;'], ''], [['unsafe-url, \u00a0no-referrer\u00a0'], ''],
  [['no-referrer-when-downgrade'], 'no-referrer-when-downgrade'],
  [['same-origin'], 'same-origin'], [['origin'], 'origin'], [['strict-origin'], 'strict-origin'],
  [['origin-when-cross-origin'], 'origin-when-cross-origin'],
  [['strict-origin-when-cross-origin'], 'strict-origin-when-cross-origin'],
];
function invoke(executable, flag, input) {
  const result = spawnSync(executable, [flag, JSON.stringify(input)], { encoding: 'utf8', timeout: 15000 });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}
function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
}
function close(server) {
  server.closeAllConnections();
  return new Promise(resolve => server.close(resolve));
}
(async () => {
  let active = [], mode, observedReferrer, imageRequests = 0, browser;
  const target = http.createServer((req, res) => {
    observedReferrer = req.headers.referer;
    ++imageRequests;
    res.setHeader('Content-Type', 'image/gif');
    res.end('');
  });
  const server = http.createServer((req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    if (req.url === '/script.js') {
      res.setHeader('Content-Type', 'text/plain');
      if (active.length) res.setHeader('X-Content-Type-Options', active);
      return res.end('window.ran=true;');
    }
    if (mode === 'referrer') {
      res.setHeader('Content-Type', 'text/html');
      if (active.length) res.setHeader('Referrer-Policy', active);
      return res.end(`<img src="http://127.0.0.1:${target.address().port}/image">`);
    }
    if (mode === 'script' || mode === 'html') res.setHeader('Content-Type', 'text/html');
    if (mode === 'plain') res.setHeader('Content-Type', 'text/plain');
    if (mode !== 'script' && active.length) res.setHeader('X-Content-Type-Options', active);
    res.end(mode === 'script' ? '<!doctype html><script src="/script.js"></script>'
      : '<!doctype html><script>window.ran=true</script>');
  });
  let cases = 0;
  try {
    await listen(target);
    await listen(server);
    const origin = `http://127.0.0.1:${server.address().port}`;
    browser = await chromium.launch({ headless: true });
    for (const [values, scriptBlocked, documentBlocked] of sniffCases) {
      active = values;
      const headers = values.map(v => ['X-Content-Type-Options', v]);
      const result = invoke(audit, '--analyze-values', { headers, origin });
      assert.equal(result.scriptNosniff, scriptBlocked, JSON.stringify(values));
      assert.equal(result.documentNosniff, documentBlocked, JSON.stringify(values));
      assert.equal(result.findings.includes('xcto-missing'), !scriptBlocked);
      for (mode of ['script', 'document', 'html', 'plain']) {
        const expected = mode === 'script' ? !scriptBlocked : mode === 'document' ? !documentBlocked : mode === 'html';
        if (mode !== 'script') {
          const responseHeaders = [...headers];
          if (mode !== 'document') responseHeaders.push(['Content-Type', `text/${mode}`]);
          assert.equal(invoke(xss, '--can-execute-html', responseHeaders), expected);
        }
        const page = await browser.newPage();
        await page.goto(origin, { waitUntil: 'load' });
        assert.equal(await page.evaluate(() => window.ran === true), expected, `${mode}: ${JSON.stringify(values)}`);
        await page.close();
        ++cases;
      }
    }
    mode = 'referrer';
    for (const [values, policy] of referrerCases) {
      active = values;
      const result = invoke(audit, '--analyze-values', {
        headers: values.map(v => ['Referrer-Policy', v]), origin,
      });
      assert.equal(result.referrerPolicy, policy, JSON.stringify(values));
      assert.equal(result.findings.includes('referrer-policy-missing'), policy === '');
      assert.equal(result.findings.includes('referrer-policy-unsafe'), policy === 'unsafe-url');
      const fullUrl = `${origin}/referrer?private=marker`;
      const expected = ['no-referrer', 'same-origin'].includes(policy) ? undefined
        : ['unsafe-url', 'no-referrer-when-downgrade'].includes(policy) ? fullUrl : `${origin}/`;
      const before = imageRequests;
      const page = await browser.newPage();
      await page.goto(fullUrl, { waitUntil: 'load' });
      assert.equal(imageRequests, before + 1, 'cross-origin request must reach the fixture');
      assert.equal(observedReferrer, expected, JSON.stringify(values));
      await page.close();
      ++cases;
    }
    console.log(`PASS: ${cases} header-value browser cases (Chromium ${browser.version()})`);
  } finally {
    if (browser) await browser.close();
    await close(server);
    await close(target);
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
