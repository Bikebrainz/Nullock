// Real repeated HTTP fields and comma-combined policies must agree with the
// production analyzer. Only the loopback fixture and in-memory scripts run.
const assert = require('node:assert/strict');
const http = require('node:http');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const { chromium } = require('playwright');
const executable = path.resolve(process.argv[2] || 'build/Tests/header_audit/Release/header_audit_test.exe');
const gadget = 'https://ajax.googleapis.com';
const cases = [
  { name: 'strict second policy', csp: ["script-src 'unsafe-inline' https:", "script-src 'none'"], inline: false, attribute: false, external: false, wildcard: false, gadget: false },
  { name: 'complementary overrides', csp: ["script-src 'unsafe-inline'; script-src-elem 'none'", "script-src 'unsafe-inline'; script-src-attr 'none'"], inline: false, attribute: false },
  { name: 'handler context survives', csp: ["script-src 'unsafe-inline'; script-src-elem 'none'", "script-src 'unsafe-inline'"], inline: false, attribute: true },
  { name: 'unrelated directive', csp: ["img-src 'none'", "script-src 'unsafe-inline'"], inline: true, attribute: true },
  { name: 'nonce suppresses inline', csp: ["script-src 'unsafe-inline'", "script-src 'unsafe-inline' 'nonce-abc'"], inline: false, attribute: false },
  { name: 'eval requires every policy', csp: ["script-src 'self' 'unsafe-eval'", "script-src 'self'"], eval: false },
  { name: 'unrestricted eval fallback', csp: ["script-src 'self' 'unsafe-eval'", 'img-src *'], eval: true },
  { name: 'scheme narrowed to gadget', csp: ['script-src https:', `script-src ${gadget}`], external: true, gadget: true, wildcard: false },
  { name: 'disjoint gadget hosts', csp: [`script-src ${gadget}`, 'script-src https://unpkg.com'], external: false, gadget: false, wildcard: false },
  { name: 'scheme overlap', csp: ['script-src http:', 'script-src https:'], external: true, wildcard: true },
  { name: 'data excluded by star', csp: ['script-src *', 'script-src data:'], url: 'data:text/javascript,document.body.dataset.external%3D%22true%22', external: false, wildcard: false },
  { name: 'data overlap', csp: ['script-src data: https:', 'script-src data:'], url: 'data:text/javascript,document.body.dataset.external%3D%22true%22', external: true, wildcard: true },
  { name: 'wildcard excludes bare host', csp: ['script-src *.googleapis.com', 'script-src googleapis.com'], url: 'http://googleapis.com/fixture.js', external: false, gadget: false },
  { name: 'wildcard includes subdomain', csp: ['script-src *.googleapis.com', `script-src ${gadget}`], external: true, gadget: true },
  { name: 'port mismatch', csp: [`script-src ${gadget}:8443`, `script-src ${gadget}`], external: false, gadget: false },
  { name: 'port wildcard', csp: [`script-src ${gadget}:*`, `script-src ${gadget}:8443`], url: `${gadget}:8443/fixture.js`, external: true, gadget: true },
  { name: 'HTTP port upgrade', csp: ['script-src http://ajax.googleapis.com:80', `script-src ${gadget}`], external: true, gadget: true },
  { name: 'explicit HTTPS port 80', csp: [`script-src ${gadget}:80`, `script-src ${gadget}:*`], url: `${gadget}:80/fixture.js`, external: true, gadget: true },
  { name: 'disjoint paths', csp: [`script-src ${gadget}/a/`, `script-src ${gadget}/b/`], url: `${gadget}/a/fixture.js`, external: false, gadget: false },
  { name: 'exact path outside prefix', csp: [`script-src ${gadget}/a/`, `script-src ${gadget}/a`], url: `${gadget}/a`, external: false, gadget: false },
  { name: 'nested prefix', csp: [`script-src ${gadget}/a/`, `script-src ${gadget}/a/b/`], url: `${gadget}/a/b/fixture.js`, external: true, gadget: true },
  { name: 'decoded path segments', csp: [`script-src ${gadget}/%61/`, `script-src ${gadget}/a/fixture.js`], url: `${gadget}/a/fixture.js`, external: true, gadget: true },
  { name: 'Chromium decodes slash in CSP path', csp: [`script-src ${gadget}/a%2fb/`, `script-src ${gadget}/a/b/`], url: `${gadget}/a/b/fixture.js`, external: true, gadget: true },
  { name: 'Chromium encoded trailing slash', csp: [`script-src ${gadget}/a%2f`, `script-src ${gadget}/a/`], url: `${gadget}/a/fixture.js`, external: true, gadget: true },
  { name: 'strict dynamic blocks parser script', csp: [`script-src ${gadget}`, "script-src 'strict-dynamic' https:"], external: false, gadget: false, wildcard: false },
  { name: 'self narrows scheme', csp: ["script-src 'self'", 'script-src http:'], url: '/fixture.js', external: true, gadget: false, wildcard: false },
  { name: 'self excludes remote gadget', csp: ["script-src 'self'", `script-src ${gadget}`], external: false, gadget: false, wildcard: false },
  { name: 'sandbox blocks scripts', csp: ["script-src 'unsafe-inline' https:", 'sandbox'], inline: false, attribute: false, external: false, wildcard: false },
  { name: 'sandbox allows scripts', csp: ["script-src 'unsafe-inline'", 'sandbox allow-scripts'], inline: true, attribute: true },
  { name: 'report only cannot block', csp: ["script-src 'unsafe-inline'", 'img-src *'], reportOnly: ["script-src 'none'", 'sandbox'], inline: true, attribute: true },
];
const frameCases = [
  { name: 'XFO alone', csp: [], xfo: 'DENY', framed: false, missing: false },
  { name: 'permissive ancestors override XFO', csp: ['frame-ancestors *'], xfo: 'DENY', framed: true, missing: true },
  { name: 'empty ancestors', csp: ['frame-ancestors'], framed: false, missing: false },
  { name: 'later restrictive ancestors', csp: ['frame-ancestors *', "frame-ancestors 'none'"], framed: false, missing: false },
  { name: 'later empty ancestors', csp: ['frame-ancestors *', 'frame-ancestors'], framed: false, missing: false },
  { name: 'disjoint ancestor ports', csp: ['frame-ancestors http://*:8080', 'frame-ancestors https://*:8443'], framed: false, missing: false },
  { name: 'ancestor source with non-root path', csp: ['frame-ancestors http://*/a/', 'frame-ancestors *'], framed: false, missing: false },
  { name: 'report only ancestors do not block', csp: [], reportOnly: ["frame-ancestors 'none'"], framed: true, missing: true },
  { name: 'report only cannot override XFO', csp: [], reportOnly: ['frame-ancestors *'], xfo: 'DENY', framed: false, missing: false },
];

function analyze(test, origin, combined) {
  const input = { ...test, origin, csp: combined && test.csp.length ? [test.csp.join(', ')] : test.csp };
  const result = spawnSync(executable, ['--analyze-headers', JSON.stringify(input)], { encoding: 'utf8', timeout: 15000 });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

(async () => {
  let active, combined, origin;
  const server = http.createServer((req, res) => {
    if (req.url.endsWith('.js')) {
      res.setHeader('Content-Type', 'text/javascript');
      return res.end(req.url === '/eval.js'
        ? `document.body.dataset.bootstrap='true'; try { eval("document.body.dataset.evaluated='true'"); } catch {}`
        : "document.body.dataset.external='true';");
    }
    if (active.csp.length) res.setHeader('Content-Security-Policy', combined ? active.csp.join(', ') : active.csp);
    if (active.reportOnly) res.setHeader('Content-Security-Policy-Report-Only', active.reportOnly);
    if (active.xfo) res.setHeader('X-Frame-Options', active.xfo);
    res.setHeader('Content-Type', 'text/html');
    if (req.url === '/child') return res.end('<!doctype html><body data-child="true">framing fixture</body>');
    res.end(`<!doctype html><body>
      <button id="handler" onclick="document.body.dataset.attribute='true'">test</button>
      <script>document.body.dataset.inline='true';</script>
      <script src="${active.url || `${gadget}/fixture.js`}"></script>
      ${active.eval === undefined ? '' : '<script src="/eval.js"></script>'}
    </body>`);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
  const parentServer = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.end(`<!doctype html><iframe src="${origin}/child"></iframe>`);
  });
  await new Promise(resolve => parentServer.listen(0, '127.0.0.1', resolve));
  const parentOrigin = `http://127.0.0.1:${parentServer.address().port}`;
  let browser;
  const failures = [];
  let count = 0;
  try {
    browser = await chromium.launch({ headless: true });
    for (const test of [...cases, ...frameCases]) for (const reverse of [false, true]) for (combined of [false, true]) {
      active = { ...test, csp: reverse ? [...test.csp].reverse() : test.csp };
      const label = `${test.name}, reverse=${reverse}, combined=${combined}`;
      const context = await browser.newContext({ serviceWorkers: 'block' });
      try {
        await context.route('**/*', route => {
          const url = new URL(route.request().url());
          if (url.origin === origin || url.origin === parentOrigin) return route.continue();
          if (['ajax.googleapis.com', 'googleapis.com'].includes(url.hostname))
            return route.fulfill({ contentType: 'text/javascript', body: "document.body.dataset.external='true';" });
          return route.abort();
        });
        const page = await context.newPage();
        const errors = [];
        page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
        page.on('requestfailed', request => errors.push(`${request.url()}: ${request.failure()?.errorText}`));
        const findings = analyze(active, origin, combined);
        if (test.framed !== undefined) {
          await page.goto(parentOrigin, { waitUntil: 'load' });
          const frame = page.frames().find(frame => frame.url() === `${origin}/child`);
          const framed = Boolean(frame && await frame.locator('body[data-child="true"]').count());
          assert.equal(framed, test.framed, `${label}: browser framing (${page.frames().map(f => f.url()).join(', ')}; ${errors.join('; ')})`);
          assert.equal(findings.includes('clickjacking-missing'), test.missing, `${label}: framing verdict`);
        } else {
          await page.goto(origin, { waitUntil: 'load' });
          await page.locator('#handler').click();
          const actual = await page.locator('body').evaluate(body => ({
            inline: body.dataset.inline === 'true', attribute: body.dataset.attribute === 'true',
            external: body.dataset.external === 'true', eval: body.dataset.evaluated === 'true',
            bootstrap: body.dataset.bootstrap === 'true',
          }));
          for (const key of ['inline', 'attribute', 'external', 'eval'])
            if (test[key] !== undefined) assert.equal(actual[key], test[key], `${label}: browser ${key}`);
          if (test.inline !== undefined) assert.equal(findings.includes('csp-unsafe-inline'), actual.inline || actual.attribute, `${label}: inline verdict`);
          if (test.eval !== undefined) {
            assert.ok(actual.bootstrap, `${label}: eval fixture must execute`);
            assert.equal(findings.includes('csp-unsafe-eval'), actual.eval, `${label}: eval verdict`);
          }
          if (test.gadget !== undefined) assert.equal(findings.includes('csp-bypassable-host'), test.gadget, `${label}: gadget verdict`);
          if (test.wildcard !== undefined) assert.equal(findings.includes('csp-wildcard-source'), test.wildcard, `${label}: wildcard verdict`);
          assert.ok(!findings.includes('csp-analysis-incomplete'), `${label}: ordinary policies should resolve`);
        }
        ++count;
      } catch (error) { failures.push(error.message); }
      finally { await context.close(); }
    }
    assert.equal(failures.length, 0, failures.join('\n'));
    console.log(`PASS: ${count} multiple-policy CSP browser/analyzer comparisons`);
  } finally {
    if (browser) await browser.close();
    await new Promise(resolve => parentServer.close(resolve));
    await new Promise(resolve => server.close(resolve));
  }
})().catch(error => { console.error(error.message); process.exitCode = 1; });
