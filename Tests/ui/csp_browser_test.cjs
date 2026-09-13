// Compare production CSP verdicts with actual Chromium enforcement. Every
// document and script is fulfilled in memory; unexpected requests are aborted.
// Usage: node Tests/ui/csp_browser_test.cjs <path-to-header_audit_test>
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const { chromium } = require('playwright');

const executable = path.resolve(process.argv[2] || 'build/Tests/header_audit/Release/header_audit_test.exe');
const cases = [
  { name: 'unsafe inline baseline', policy: "script-src 'unsafe-inline'", inline: true, attribute: true },
  { name: 'nonce grammar', policy: "script-src 'unsafe-inline' 'nonce-abc'", inline: false, attribute: false },
  { name: 'invalid nonce character', policy: "script-src 'unsafe-inline' 'nonce-!'", inline: true, attribute: true },
  { name: 'invalid hash character', policy: "script-src 'unsafe-inline' 'sha256-a!b'", inline: true, attribute: true },
  { name: 'embedded padding', policy: "script-src 'unsafe-inline' 'nonce-ab=c'", inline: true, attribute: true },
  { name: 'excess padding', policy: "script-src 'unsafe-inline' 'nonce-ab==='", inline: true, attribute: true },
  { name: 'undecodable one-character hash', policy: "script-src 'unsafe-inline' 'sha256-a'", inline: true, attribute: true },
  { name: 'decodable short hash still suppresses inline', policy: "script-src 'unsafe-inline' 'sha256-ab'", inline: false, attribute: false },
  { name: 'partially padded short hash', policy: "script-src 'unsafe-inline' 'sha256-ab='", inline: false, attribute: false },
  { name: 'overpadded hash', policy: "script-src 'unsafe-inline' 'sha256-abc=='", inline: true, attribute: true },
  { name: 'legacy hyphenated SHA spelling', policy: "script-src 'unsafe-inline' 'sha-256-ab'", inline: false, attribute: false },
  { name: 'base64 and URL-safe nonce characters', policy: "script-src 'unsafe-inline' 'nonce-a_/-+b=='", inline: false, attribute: false },
  { name: 'both inline contexts overridden', policy: "script-src 'unsafe-inline'; script-src-elem 'none'; script-src-attr 'none'", inline: false, attribute: false },
  { name: 'attribute fallback still allows inline', policy: "script-src 'unsafe-inline'; script-src-elem 'none'", inline: false, attribute: true },
  { name: 'invalid nonce on attribute override', policy: "script-src 'self'; script-src-attr 'unsafe-inline' 'nonce-!'", inline: false, attribute: true },
  { name: 'valid nonce on element override', policy: "script-src 'self'; script-src-elem 'unsafe-inline' 'nonce-abc'", inline: false, attribute: false },
  { name: 'strict dynamic suppresses unsafe inline', policy: "script-src 'unsafe-inline' 'strict-dynamic'", inline: false, attribute: false },
  { name: 'element gadget host', policy: "script-src 'self'; script-src-elem https://ajax.googleapis.com", external: true, gadget: true, wildcard: false },
  { name: 'attribute hosts do not authorize external scripts', policy: "script-src 'self'; script-src-attr https://ajax.googleapis.com https:", external: false, gadget: false, wildcard: false },
  { name: 'element override replaces base host list', policy: "script-src https://ajax.googleapis.com; script-src-elem 'self'", external: false, gadget: false, wildcard: false },
  { name: 'strict dynamic ignores parser script hosts', policy: "script-src 'nonce-abc' 'strict-dynamic' https: https://ajax.googleapis.com", external: false, gadget: false, wildcard: false },
  { name: 'element scheme-wide source', policy: "script-src 'self'; script-src-elem https:", external: true, gadget: false, wildcard: true },
  { name: 'element unsafe eval has no effect', policy: "script-src 'self'; script-src-elem 'self' 'unsafe-eval'", eval: false },
  { name: 'attribute unsafe eval has no effect', policy: "script-src 'self'; script-src-attr 'unsafe-eval'", eval: false },
  { name: 'eval is controlled by base script directive', policy: "script-src 'self' 'unsafe-eval'; script-src-elem 'self'; script-src-attr 'none'", eval: true },
];

function analyze(policy) {
  const result = spawnSync(executable, ['--analyze-csp', policy], { encoding: 'utf8', timeout: 15000 });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  const failures = [];
  try {
    for (const test of cases) {
      const context = await browser.newContext({ serviceWorkers: 'block' });
      try {
        await context.route('**/*', async route => {
          const url = new URL(route.request().url());
          if (url.hostname === 'fixture.test' && url.pathname === '/') {
            return route.fulfill({ contentType: 'text/html', headers: { 'Content-Security-Policy': test.policy }, body: `<!doctype html><body>
              <button id="handler" onclick="document.body.dataset.attribute='true'">test</button>
              <script>document.body.dataset.inline='true';</script>
              <script src="https://ajax.googleapis.com/nullock-fixture.js"></script>
              ${test.eval === undefined ? '' : '<script src="/eval.js"></script>'}
            </body>` });
          }
          if (url.hostname === 'fixture.test' && url.pathname === '/eval.js') {
            return route.fulfill({ contentType: 'text/javascript', body: `document.body.dataset.bootstrap='true';
              try { eval("document.body.dataset.evaluated='true'"); } catch { document.body.dataset.evalBlocked='true'; }` });
          }
          if (url.hostname === 'ajax.googleapis.com' && url.pathname === '/nullock-fixture.js') {
            return route.fulfill({ contentType: 'text/javascript', body: "document.body.dataset.external='true';" });
          }
          return route.abort();
        });
        const page = await context.newPage();
        await page.goto('http://fixture.test/', { waitUntil: 'load' });
        await page.locator('#handler').click();
        const actual = await page.locator('body').evaluate(body => ({
          inline: body.dataset.inline === 'true', attribute: body.dataset.attribute === 'true',
          external: body.dataset.external === 'true', eval: body.dataset.evaluated === 'true',
          bootstrap: body.dataset.bootstrap === 'true',
        }));
        for (const key of ['inline', 'attribute', 'external', 'eval']) {
          if (test[key] !== undefined) assert.equal(actual[key], test[key], `${test.name}: browser ${key}`);
        }
        const findings = analyze(test.policy);
        if (test.inline !== undefined) {
          assert.equal(findings.includes('csp-unsafe-inline'), actual.inline || actual.attribute, `${test.name}: inline verdict`);
        }
        if (test.eval !== undefined) {
          assert.ok(actual.bootstrap, `${test.name}: eval fixture must execute`);
          assert.equal(findings.includes('csp-unsafe-eval'), actual.eval, `${test.name}: eval verdict`);
        }
        if (test.gadget !== undefined) assert.equal(findings.includes('csp-bypassable-host'), test.gadget, `${test.name}: gadget verdict`);
        if (test.wildcard !== undefined) assert.equal(findings.includes('csp-wildcard-source'), test.wildcard, `${test.name}: wildcard verdict`);
      } catch (error) {
        failures.push(error.message);
      } finally {
        await context.close();
      }
    }
    assert.equal(failures.length, 0, failures.join('\n'));
    console.log(`PASS: ${cases.length} CSP browser/analyzer differential cases`);
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error.message); process.exitCode = 1; });
