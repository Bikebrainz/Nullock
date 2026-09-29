// Exercise the reflected-XSS HTML gate against CI's pinned Chromium browser.
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { chromium } = require('playwright');
const executable = path.resolve(process.argv[2]);
const cases = [
  [[], true, true], [[''], true, true], [[';'], true, true],
  [['nosuch'], true, true], [['text /html'], true, true],
  [['unknown/unknown'], true, true], [['application/unknown'], true, true],
  [['*/*'], true, true],
  [['text/plain', '*/*'], false, false],
  [['text/plain', '*/*; charset=utf-8'], true, true],
  [['*/*; charset=utf-8'], true, true],
  [['text/html'], true, false], [['TEXT/HTML'], true, false],
  [['\ttext/html '], true, false], [['text/html ; charset=utf-8'], true, false],
  [['text/html(comment)'], true, false], [['text/html extra'], true, false],
  [['application/xhtml+xml'], true, false],
  [['text/plain; note=text/html'], false, false],
  [['application/json; note="text/html"'], false, false],
  [['text/htmlx'], false, false], [['application/xhtml'], false, false],
  [['application/xhtml+xml-extra'], false, false],
  [['application/octet-stream'], false, false],
  [['\u00a0text/html\u00a0'], false, false],
  [['text/plain', 'text/html'], true, false],
  [['text/html', 'text/plain'], false, false],
  [['text/html, text/plain'], false, false],
  [['text/plain, text/html'], true, false],
  [['text/html', ''], true, false], [['', 'text/html'], true, false],
  [['text/html', 'nosuch'], true, false],
  [['text/html', 'text /plain'], true, false],
  [['text/plain; note="a,text/html"'], false, false],
  [['text/html; note="a,text/plain"'], true, false],
  [['text/html; note="a,\\"text/plain"'], true, false],
];
(async () => {
  let values = [], nosniff = false, browser;
  const server = http.createServer((req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    if (values.length) res.setHeader('Content-Type', values);
    if (nosniff) res.setHeader('X-Content-Type-Options', 'nosniff');
    // Well-formed XHTML works under both the HTML and XHTML MIME types.
    res.end('<html xmlns="http://www.w3.org/1999/xhtml"><head><script>window.ran=true;</script></head><body>fixture</body></html>');
  });
  let count = 0;
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    browser = await chromium.launch({ headless: true });
    console.log(`Media-type comparisons: Chromium ${browser.version()}`);
    for (const test of cases) {
      values = test[0];
      for (nosniff of [false, true]) {
        const expected = test[1] && !(nosniff && test[2]);
        const label = JSON.stringify({ values, nosniff });
        const headers = values.map(value => ['Content-Type', value]);
        if (nosniff) headers.push(['X-Content-Type-Options', 'nosniff']);
        const result = spawnSync(executable, ['--can-execute-html', JSON.stringify(headers)],
          { encoding: 'utf8', timeout: 15000 });
        assert.ifError(result.error);
        assert.equal(result.status, 0, result.stderr);
        assert.equal(JSON.parse(result.stdout), expected, `analyzer: ${label}`);
        const page = await browser.newPage();
        let download = false;
        const pendingDownload = page.waitForEvent('download', { timeout: 5000 });
        // Successful document navigation closes the page without a download.
        pendingDownload.catch(() => {});
        try {
          await page.goto(`http://127.0.0.1:${server.address().port}/`, { waitUntil: 'load' });
        } catch (error) {
          // Unsupported MIME types download instead of creating a document.
          // All other navigation errors must still fail the comparison.
          assert.match(error.message, /Download is starting/, label);
          await pendingDownload;
          download = true;
        }
        const executed = !download && await page.evaluate(() => window.ran === true);
        assert.equal(executed, expected, `browser: ${label}`);
        await page.close();
        ++count;
      }
    }
    console.log(`PASS: ${count} media-type browser/analyzer comparisons`);
  } finally {
    if (browser) await browser.close();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
