// Compare the reflected-tag context gate with Chromium's actual HTML parser.
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { chromium } = require('playwright');
const executable = path.resolve(process.argv[2]);
const marker = '<nlk0a1b2c3d>';
const cases = [];
for (const name of ['script', 'style', 'textarea', 'title', 'xmp', 'noscript',
                    'noframes', 'noembed', 'plaintext', 'iframe']) {
  for (const suffix of ['', '-', '-custom', ':x', '_x', '.', '\u00a0', '\u0000']) {
    cases.push([`<${name}${suffix}>${marker}`, suffix !== '']);
  }
  cases.push([`<${name}>inert</${name}>${marker}`, name !== 'plaintext']);
}
for (const prefix of ['<!-->', '<!--->', '<!-- normal -->', '<!-- normal --!>', '<!bogus>']) {
  cases.push([prefix + marker, true]);
}
(async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    console.log(`HTML context comparisons: Chromium ${browser.version()}`);
    const page = await browser.newPage();
    for (const [body, expected] of cases) {
      const result = spawnSync(executable, ['--html-context', JSON.stringify([body])],
        { encoding: 'utf8', timeout: 15000 });
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(JSON.parse(result.stdout), expected, `analyzer: ${JSON.stringify(body)}`);
      await page.setContent(body);
      const parsed = await page.locator('nlk0a1b2c3d').count() > 0;
      assert.equal(parsed, expected, `browser: ${JSON.stringify(body)}`);
    }
    console.log(`PASS: ${cases.length} HTML context browser/analyzer comparisons`);
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
