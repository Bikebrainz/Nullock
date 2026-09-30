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
// Namespace and template cases use the pinned browser as the reference. Keep
// malformed closing tags in the matrix: balanced snippets miss context changes.
for (const prefix of ['', '<template>', '<template><template>', '<div><template>',
    '<template><svg>', '<svg>', '<svg><g>', '<svg><foreignObject>', '<svg><title>',
    '<math>', '<math><mi>', '<math><annotation-xml encoding="text/html">']) {
  for (const middle of ['', '<template>', '<div>', '<p>', '<table>', '<svg><g>',
      '<title>', '<style>', '<script>', '<math><mtext>']) {
    for (const suffix of ['', '</template>', '</svg>', '</math>', '</div>', '</p>',
        '</title>', '</style>', '</script>']) cases.push([prefix + middle + suffix + marker]);
  }
}
for (const encoding of ['text/html', 'application/xhtml+xml', 'TEXT/HTML', 'text&#47;html',
    'text&sol;html', 'application/xhtml&plus;xml', 'text/html ', ' text/html', 'text/plain']) {
  for (const attr of [`encoding="${encoding}"`, `encoding='${encoding}'`, `encoding=${encoding}`,
      `encoding=bogus encoding="${encoding}"`, `encoding="${encoding}" encoding=bogus`])
    cases.push([`<math><annotation-xml ${attr}><title>${marker}`]);
}
for (const prefix of ['<template/>', '<template><!-- </template> -->',
    '<template><div title="</template>">', '<template><textarea></template></textarea>',
    '<template><script></template></script>', '<template><svg><title></template>',
    '<svg><title/ >', '<svg><title a=/>', '<svg><title a="/">', '<svg><title a=x"y>',
    '<script><!--<script/>', '<script><!--<script ></script>', '<script><!--<script></script>-->',
    '<script><!--<script>-->', '<script><!--</script>', '<script></ſcript>',
    '<template><script></script x=">">', '<template><script></script x=',
    '<svg><font color=red><title>', '<svg><font><title>', '<math><mi><mglyph><title>',
    '<math><mi><malignmark><title>', '<svg><![CDATA[>', '<svg><![CDATA[foo]]>',
    '<svg><title><![CDATA[>', '<svg><title><![CDATA[foo]]>',
    '<math><mtext><![CDATA[>', '<math><annotation-xml encoding="text/html"><![CDATA[>',
    '<template><svg><template></template>', '<template><svg><template></template></template>',
    '<template><svg><template></svg></template>', '</!', '</?', '</<', '</>']) cases.push([prefix + marker]);
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
      await page.setContent(body);
      const parsed = await page.locator('nlk0a1b2c3d').count() > 0;
      if (expected !== undefined) assert.equal(parsed, expected, `browser: ${JSON.stringify(body)}`);
      assert.equal(JSON.parse(result.stdout), parsed, `analyzer/browser: ${JSON.stringify(body)}`);
    }
    console.log(`PASS: ${cases.length} HTML context browser/analyzer comparisons`);
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
