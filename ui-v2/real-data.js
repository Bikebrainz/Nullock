// Real data shim. Replaces mock-data.js.
//
// The React app expects window.NL to be populated synchronously before
// app.jsx runs. We block on a sync XHR to /api/snapshot the first time so
// the initial render has real data, then set up a polling loop that
// refreshes NL.* every 500 ms and dispatches a 'nl-update' event the app
// listens to.
//
// requestRawById / responseRawById also need to be synchronous from the React
// side. We cache them on demand (sync XHR on first call per row id, then
// memoize).

(function () {
  window.NL = window.NL || {};
  NL._cache = NL._cache || { req: {}, resp: {} };

  function syncFetch(url) {
    try {
      const xhr = new XMLHttpRequest();
      xhr.open("GET", url, false); // synchronous
      xhr.send();
      if (xhr.status >= 200 && xhr.status < 300) return xhr.responseText;
    } catch (e) {
      console.warn("NL fetch failed", url, e);
    }
    return null;
  }

  function applySnapshot(snap) {
    if (!snap) return;
    NL.bootInfo      = snap.bootInfo      || {};
    NL.themes        = snap.themes        || [];
    NL.scope         = snap.scope         || { in: [], out: [], notes: "" };
    NL.rules         = snap.rules         || [];
    NL.rulesHit      = snap.rulesHit      || 0;
    NL.findings      = snap.findings      || [];
    NL.findingsCount = snap.findingsCount || 0;
    NL.portScan      = snap.portScan      || { host: "", running: false, done: 0, total: 0, results: [], error: "" };
    NL.recon         = snap.recon         || { target: "", running: false, dns: [], subdomains: [], error: "" };
    NL.sessions      = snap.sessions      || [];
    NL.sessionRules  = snap.sessionRules  || { rules: [], variables: {} };
    NL.rows          = snap.rows          || [];
    NL.sitemap     = snap.sitemap     || [];
    NL.intercepted = snap.intercepted || [];
    NL.repeater    = snap.repeater    || { host: "", port: 443, tls: true,
                                            request: "", response: "",
                                            statusLine: "", autoContentLength: true };
    NL.intruder    = snap.intruder    || { host: "", port: 443, tls: true,
                                            template: "", payloads: [],
                                            results: [], running: false,
                                            concurrency: 10, throttleMs: 0,
                                            attackType: 0, positions: 0,
                                            payloadSets: [] };
    NL.currentTheme       = snap.currentTheme || "cyber";
    NL.interceptEnabled   = snap.interceptEnabled === true;
    NL.interceptResponsesEnabled = snap.interceptResponsesEnabled === true;
    NL.interceptAutoContentLength = snap.interceptAutoContentLength !== false;
    NL.interceptRules     = snap.interceptRules || [];
    NL.themeColors        = snap.themeColors || {};
    NL.themeIsBuiltin     = snap.themeIsBuiltin === true;
    NL.themesDir          = snap.themesDir || "";
    NL.update             = snap.update || { available: false, currentVersion: "", latestVersion: "", releaseUrl: "", releaseNotes: "", publishedAt: "" };

    // Push the backend theme's colors into the document as inline CSS
    // variables. The CSS file already supplies defaults via
    // [data-theme=…]; these inline values override per-key so the user can
    // tweak a single color without authoring a full theme. Keys are stored
    // without the "--" prefix.
    if (document && document.documentElement && NL._lastColors !== JSON.stringify(NL.themeColors)) {
      NL._lastColors = JSON.stringify(NL.themeColors);
      Object.entries(NL.themeColors).forEach(([k, v]) => {
        if (v) document.documentElement.style.setProperty("--" + k, v);
      });
    }
  }

  // Initial sync load so React renders with real data immediately. ALWAYS call
  // applySnapshot -- even if the fetch or parse fails -- so every NL.* field
  // gets its safe default (NL.rows = [], NL.bootInfo = {}, ...). Otherwise a
  // failed boot snapshot leaves them undefined and app.jsx's initialState
  // (NL.rows[2]?.id, ...) throws before the app can mount.
  const text = syncFetch("/api/snapshot");
  let snap = {};
  if (text) {
    try { snap = JSON.parse(text) || {}; }
    catch (e) { console.warn("NL parse failed", e); }
  }
  applySnapshot(snap);

  // Memoized per-row accessors used inside the React reducer.
  //
  // These take a ROW ID, not a position. They used to take an index into
  // NL.rows and every caller passed `id - 1`, which is only the same number
  // while nothing has been evicted: NL.rows carries the bounded in-memory
  // window, so once the server starts dropping the oldest rows, rows[0].id is
  // no longer 1 and `id - 1` addresses a DIFFERENT row. The detail pane then
  // fetched and cached some other request's bytes, and the comparer diffed the
  // wrong pair -- silently, since every id in the window resolves to something.
  //
  // Taking the id directly removes the conversion entirely rather than fixing
  // it, so the mistake cannot come back.
  NL.requestRawById = function (rowId) {
    if (rowId == null) return "";
    if (NL._cache.req[rowId] !== undefined) return NL._cache.req[rowId];
    const t = syncFetch("/api/history/" + rowId + "/request") || "";
    NL._cache.req[rowId] = t;
    return t;
  };
  NL.responseRawById = function (rowId) {
    if (rowId == null) return "";
    if (NL._cache.resp[rowId] !== undefined) return NL._cache.resp[rowId];
    const t = syncFetch("/api/history/" + rowId + "/response") || "";
    NL._cache.resp[rowId] = t;
    return t;
  };
  // POST helpers wired to the control server's action endpoints. Fire and
  // forget -- the snapshot poll picks up resulting state changes within
  // ~500 ms. Callers can chain .then() if they want to refresh sooner.
  function post(path, payload) {
    return fetch(path, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        // Custom header the backend CSRF guard accepts in lieu of a
        // same-origin Origin. Browsers refuse to set custom headers on
        // simple cross-origin POSTs without a CORS preflight, which we
        // never grant -- so a malicious site can't trick us into
        // mutating state on a user's behalf.
        "X-Nullock-UI": "1",
      },
      body: JSON.stringify(payload || {}),
    });
  }
  // Same CSRF contract as post(), but for endpoints that take a raw
  // non-JSON body (e.g. nmap XML) rather than a JSON payload.
  function postRaw(path, text, contentType) {
    return fetch(path, {
      method: "POST",
      headers: {
        "Content-Type": contentType || "text/plain",
        "X-Nullock-UI": "1",
      },
      body: text || "",
    });
  }
  NL.actions = {
    toggleProxy()           { return post("/api/proxy/toggle"); },
    toggleIntercept()          { return post("/api/intercept/toggle"); },
    toggleInterceptResponses() { return post("/api/intercept/responses/toggle"); },
    interceptForward(text)  { return post("/api/intercept/forward", { text }); },
    interceptDrop()         { return post("/api/intercept/drop"); },
    interceptForwardAll()   { return post("/api/intercept/forwardAll"); },
    interceptRulesSet(rules) { return post("/api/intercept/rules", { rules }); },
    interceptSetAutoContentLength(autoContentLength) { return post("/api/intercept/autocl", { autoContentLength }); },
    scopeAddIn(glob)        { return post("/api/scope/in/add",     { glob }); },
    scopeRemoveIn(glob)     { return post("/api/scope/in/remove",  { glob }); },
    scopeAddOut(glob)       { return post("/api/scope/out/add",    { glob }); },
    scopeRemoveOut(glob)    { return post("/api/scope/out/remove", { glob }); },
    scopeSetNotes(notes)    { return post("/api/scope/notes",      { notes }); },
    repeaterSet(payload)    { return post("/api/repeater/set",     payload); },
    repeaterSend()          { return post("/api/repeater/send"); },
    repeaterClear()         { return post("/api/repeater/clear"); },
    repeaterTabAdd(name)            { return post("/api/repeater/tab/add", { name }); },
    repeaterTabAddFromHistory(row)  { return post("/api/repeater/tab/addFromHistory", { row }); },
    repeaterTabClose(index)         { return post("/api/repeater/tab/close",    { index }); },
    repeaterTabActivate(index)      { return post("/api/repeater/tab/activate", { index }); },
    repeaterTabRename(index, name)  { return post("/api/repeater/tab/rename",   { index, name }); },
    repeaterTabDuplicate(index)     { return post("/api/repeater/tab/duplicate",{ index }); },
    repeaterTabNotes(index, notes)  { return post("/api/repeater/tab/notes",   { index, notes }); },
    // Load a prior send (index into the ACTIVE tab's history, newest last) back
    // into that tab's request/response for review or re-send (< > navigation).
    repeaterHistoryLoad(index)      { return post("/api/repeater/history/load", { index }); },
    // GET search; returns { hits: [{id, where, excerpts:[...]}], count }
    search(q, where = "both", limit = 200) {
      const url = "/api/search?q=" + encodeURIComponent(q || "")
                + "&where=" + encodeURIComponent(where)
                + "&limit=" + encodeURIComponent(limit);
      return fetch(url).then(r => r.json());
    },
    intruderSet(payload)    { return post("/api/intruder/set",     payload); },
    intruderStart()         { return post("/api/intruder/start"); },
    intruderStop()          { return post("/api/intruder/stop"); },
    intruderClear()         { return post("/api/intruder/clear"); },
    intruderResend(row)     { return post("/api/intruder/resend", { row }); },
    // Save the whole attack (config + result rows) as a JSON document, and
    // restore one. GET /export returns the saved-run doc; feed it straight
    // back to POST /load. The backend refuses /load while an attack runs.
    intruderExport()        { return fetch("/api/intruder/export").then(r => r.json()); },
    intruderLoad(doc)       { return post("/api/intruder/load", doc).then(r => r.json()); },
    // GET discovery: the payload-processing op names the rule engine
    // understands (prefix/suffix/hash/encode/...). Read-only, allowlisted.
    intruderRuleOps()       { return fetch("/api/intruder/rule-ops").then(r => r.json()); },
    // GET discovery: the generator types this build understands (numbers/
    // dates/brute). Read-only, allowlisted.
    intruderGeneratorTypes() { return fetch("/api/intruder/generator-types").then(r => r.json()); },
    // POST preview: expand a generator spec into a count + bounded sample
    // without touching the live payload set. spec is {type,...} bare (no
    // {generator:} wrapper needed -- the endpoint accepts either).
    intruderGenerate(spec)  { return post("/api/intruder/generate", spec).then(r => r.json()); },
    setTheme(name)          { return post("/api/theme", { name }); },
    saveTheme(name, colors) { return post("/api/theme/save-as", { name, colors }).then(r => r.json()); },
    reloadThemes()          { return post("/api/theme/reload"); },
    // opts may carry { redact: false } to include auth material the
    // backend redacts by default -- see the "include unredacted" checkbox
    // next to Settings' Export HAR button.
    exportHar(opts)          { return post("/api/har/export", opts || {}).then(r => r.json()); },
    importHarPath(path)     { return post("/api/har/import", { path }).then(r => r.json()); },
    importHar(harObject)    { return post("/api/har/import", { har: harObject }).then(r => r.json()); },
    clearHistory()          { return post("/api/clear-history"); },
    clearMitmBlocked()      { return post("/api/mitm/clear-blocked"); },
    reloadExtensions()      { return post("/api/extensions/reload"); },

    // --- extension marketplace ---
    // Fetches the published catalog already merged against what is on disk, so
    // one call answers "what exists / what do I have / what has an update".
    marketplaceCatalog()    { return post("/api/marketplace/catalog").then(r => r.json()); },
    // confirmMutating is the user's answer to "this extension can rewrite your
    // traffic". It is passed through explicitly and defaults to FALSE: the
    // server refuses a mutating install without it and returns needsConfirmation
    // so the caller can prompt. Never hardcode this true -- it is the only
    // consent gate between the catalog and code running inside the proxy.
    marketplaceInstall(id, confirmMutating) {
      return post("/api/marketplace/install",
                  { id, confirmMutating: !!confirmMutating }).then(r => r.json());
    },
    marketplaceUninstall(id) {
      return post("/api/marketplace/uninstall", { id }).then(r => r.json());
    },
    clearFindings()         { return post("/api/findings/clear"); },
    projectList()           { return fetch("/api/project/list").then(r => r.json()); },
    projectOpen(name)       { return post("/api/project/open",   { name }).then(r => r.json()); },
    projectCreate(name)     { return post("/api/project/create", { name }).then(r => r.json()); },
    replayRow(rowId) {
      // POST /api/history/<id>/replay -- re-fires the captured request
      // through the proxy's mutation pipeline. New round-trip lands as
      // a new history row.
      return fetch("/api/history/" + rowId + "/replay", { method: "POST" })
        .then(r => r.json());
    },
    probeRow(rowId) {
      // Light active scan: per-param canary injection + reflection check.
      return fetch("/api/history/" + rowId + "/probe", { method: "POST" })
        .then(r => r.json());
    },
    csrfPoc(rowId) {
      // Auto-submitting CSRF PoC HTML for a captured request (CWE-352).
      // Returns { ok, method, url, note, html }.
      return post("/api/csrf/poc", { id: rowId }).then(r => r.json());
    },
    authzTest(rowId, identities) {
      // Multi-identity replay (Burp Auth Analyzer equivalent, CWE-863).
      // identities: [{name, headers: {...}}]. Returns
      // { ok, divergent, results: [{identity,ok,status,bodySize,error}], row }.
      return post("/api/authz-test", { rowId, identities }).then(r => r.json());
    },
    portscanStart(payload) { return post("/api/portscan/start", payload).then(r => r.json()); },
    portscanStop()         { return post("/api/portscan/stop"); },
    portscanClear()        { return post("/api/portscan/clear"); },
    probeAll(throttleMs, limit) {
      // Fire the active probe against every history row that has query
      // params. Throttle defaults to 200ms server-side; pass 0 to go fast.
      return post("/api/probe/all", { throttleMs, limit }).then(r => r.json());
    },
    auditAll(throttleMs, limit, include) {
      // Full deep-audit battery (cmdi/xxe/ldap/xpath/smuggle/hostheader/
      // cache-poison/deser/nosql/mass-assign/cors, etc) against every
      // history row with a query string or body. `include` optionally
      // narrows the battery to specific check names (lowercase); omit
      // for the default sweep.
      return post("/api/audit/all", { fromHistory: true, throttleMs, limit, include }).then(r => r.json());
    },
    reconDns(domain)            { return post("/api/recon/dns",      { domain }); },
    reconReverse(ip)            { return post("/api/recon/reverse",  { ip }); },
    reconWhois(domain)          { return post("/api/recon/whois",    { domain }); },
    reconCrt(domain)            { return post("/api/recon/crt",      { domain }); },
    reconWordlist(domain, subdomains) { return post("/api/recon/wordlist", { domain, subdomains }); },
    reconStop()                 { return post("/api/recon/stop"); },
    reconClear()                { return post("/api/recon/clear"); },
    forgePayloads(technique)    { return fetch("/api/payloads?technique=" + encodeURIComponent(technique || "all")).then(r => r.json()); },
    transcode(op, input)        { return post("/api/transcode", { op, input }).then(r => r.json()); },
    compareBlobs(mode, a, b)    { return post("/api/compare", { mode, a, b }).then(r => r.json()); },
    processPayload(payload)     { return post("/api/process", { payload }).then(r => r.json()); },
    inspect(raw, kind)          { return post("/api/inspect", { raw, kind: kind || "" }).then(r => r.json()); },
    // JWT attack toolkit (offline analyze/forge + a live acceptance test).
    // See control_server.cpp /api/jwt/analyze|forge|test for the response shapes.
    jwtAnalyze(token, wordlist) {
      const b = { token };
      if (wordlist && wordlist.length) b.wordlist = wordlist;
      return post("/api/jwt/analyze", b).then(r => r.json());
    },
    jwtForge(token, attack, secret, claims) {
      const b = { token, attack: attack || "none" };
      if (secret) b.secret = secret;
      if (claims) b.claims = claims;
      return post("/api/jwt/forge", b).then(r => r.json());
    },
    jwtTest(url, token, opts) {
      const b = Object.assign({ url, token }, opts || {});
      return post("/api/jwt/test", b).then(r => r.json());
    },
    // Token randomness analyzer (Burp's Sequencer). tokens is a flat array
    // of strings; see sequencer.hpp for the returned JSON shape.
    sequencerAnalyze(tokens)    { return post("/api/sequencer/analyze", { tokens }).then(r => r.json()); },
    fingerprintUrl(url)         { return post("/api/fingerprint", { url }).then(r => r.json()); },
    auditHeaders(url)           { return post("/api/headers/audit", { url }).then(r => r.json()); },
    detectWaf(url)              { return post("/api/waf/detect", { url }).then(r => r.json()); },
    scanSecrets(url)            { return post("/api/secrets/scan", { url }).then(r => r.json()); },
    // GraphQL: introspection/schema analysis (synchronous) and an active
    // probe suite (introspection/field-suggestion/alias-amplification/
    // depth-bypass/batch-bypass -- async, findings stream into Issues).
    graphqlSchema(url, headers)  { return post("/api/graphql/schema", { url, headers: headers || undefined }).then(r => r.json()); },
    graphqlProbe(url, headers)   { return post("/api/graphql/probe", { url, headers: headers || undefined }).then(r => r.json()); },
    discoverContent(url, max, opts) {
      opts = opts || {};
      return post("/api/content/discover", {
        url, max: max || undefined,
        wordlist: opts.wordlist && opts.wordlist.length ? opts.wordlist : undefined,
        extensions: opts.extensions && opts.extensions.length ? opts.extensions : undefined,
        concurrency: opts.concurrency || undefined,
        throttleMs: opts.throttleMs || undefined,
      }).then(r => r.json());
    },
    scanRobots(url)             { return post("/api/robots/scan", { url }).then(r => r.json()); },
    crawlerStart(seed, maxPages, maxDepth, throttleMs) {
      return post("/api/crawler/start", { seed, maxPages: maxPages || undefined, maxDepth: maxDepth || undefined, throttleMs: throttleMs || undefined }).then(r => r.json());
    },
    crawlerStop()                { return post("/api/crawler/stop").then(r => r.json()); },
    // Active vulnerability tests: one uniform {url, param?, method?} contract
    // across /api/<type>/test. `type` is picked from a fixed known-safe list in
    // the TESTS tab (lowercase [a-z], no interpolation risk).
    runTest(type, url, param, method) {
      const b = { url };
      if (param)  b.param  = param;
      if (method) b.method = method;
      return post("/api/" + type + "/test", b).then(r => r.json());
    },
    sessionAutoInject(host, on) { return post("/api/sessions/autoInject", { host, on }); },
    sessionClearHost(host)      { return post("/api/sessions/clear",      { host }); },
    sessionClearAll()           { return post("/api/sessions/clear",      {}); },
    sessionCopyTo(from, to)     { return post("/api/sessions/copyTo",     { from, to }); },
    sessionRulesSet(rules)      { return post("/api/session-rules/set",        { rules }); },
    sessionRulesClearVars()     { return post("/api/session-rules/clear-vars", {}); },
    ruleAdd(rule)           { return post("/api/rules/add",    rule).then(r => r.json()); },
    ruleUpdate(index, rule) { return post("/api/rules/update", Object.assign({ index }, rule)); },
    ruleRemove(index)       { return post("/api/rules/remove", { index }); },
    ruleToggle(index)       { return post("/api/rules/toggle", { index }); },
    ruleMove(from, to)      { return post("/api/rules/move",   { from, to }); },

    // --- reporting / export ---
    // report/build and report/html are POST-only (engagement documents, not
    // idempotent GETs) so they return the raw fetch Response for the caller
    // to turn into a blob download, rather than parsing JSON.
    reportBuild()  { return post("/api/report/build"); },
    reportHtml()   { return post("/api/report/html"); },
    reportJson()   { return fetch("/api/report/json").then(r => r.json()); },
    openapiImport(spec, baseUrl) {
      return post("/api/openapi/import", { spec, baseUrl: baseUrl || undefined }).then(r => r.json());
    },
    workspacePush(url, key, engagement, author) {
      return post("/api/workspace/push", { url, key, engagement, author: author || undefined }).then(r => r.json());
    },
    workspacePull(url, key, engagement, since) {
      return post("/api/workspace/pull", { url, key, engagement, since: since || undefined }).then(r => r.json());
    },

    // --- OAST / Collaborator ---
    // Mint an out-of-band callback token. `opts` optionally registers it with
    // the correlator so a real callback auto-appears as a confirmed finding:
    // { register: true, rowId?, host?, param?, note? }.
    oastMint(opts)  { return post("/api/oast/mint", opts || {}).then(r => r.json()); },
    // Poll for HTTP callbacks landed since hit id `since` (0 = all). Also
    // carries live server status (running/port/baseHost) in every response.
    oastPoll(since) { return fetch("/api/oast/poll?since=" + encodeURIComponent(since || 0)).then(r => r.json()); },
    // Spray OOB payloads (SSRF param battery + optional XXE/RCE/log4shell)
    // at one target URL; each vector gets its own registered token.
    oastBlast(payload) { return post("/api/oast/blast", payload).then(r => r.json()); },

    // --- unified scan/audit runners ---
    // One-shot passive+active fingerprint/CVE/header/method/TLS assessment
    // of a single target URL. Also emits findings into the scanner.
    assess(url) { return post("/api/assess", { url }).then(r => r.json()); },
    // Synchronous (blocking) deep-audit battery against one URL. `opts` may
    // carry { method, body, headers, include } -- include narrows the
    // tester set (see runDeepAudit); omit for the default sweep.
    auditRun(url, opts) {
      return post("/api/audit/run", Object.assign({ url }, opts)).then(r => r.json());
    },
    // Hidden query-param/body-param discovery via response-diffing.
    // `opts` may carry { method, wordlist, headers, batchSize }.
    paramMine(url, opts) {
      return post("/api/paramminer", Object.assign({ url }, opts)).then(r => r.json());
    },
    // Multi-step raw-HTTP request chain with {{var}} extraction/substitution
    // between steps (login -> use token -> ...). `steps` is the raw array
    // the backend expects; see ChainRunner::run.
    chainRun(steps, continueOnError) {
      return post("/api/chain/run", { steps, continueOnError: !!continueOnError }).then(r => r.json());
    },
    // Capstone "point at a host" orchestrator: bridges port-scan results
    // into findings, then runs `assess` against every open web port found.
    // `opts` may carry { host, assessWeb, includeOpenPorts, correlateCves }.
    pipelineRun(opts) { return post("/api/pipeline/run", opts || {}).then(r => r.json()); },
    // Read-only posture/coverage rollups over the in-memory finding set --
    // no scanning, just aggregation, safe to poll on demand.
    getInventory()   { return fetch("/api/inventory").then(r => r.json()); },
    getPosture()     { return fetch("/api/posture").then(r => r.json()); },
    getCompliance()  { return fetch("/api/compliance").then(r => r.json()); },
    getGate(failOn)  { return fetch("/api/gate?fail-on=" + encodeURIComponent(failOn || "")).then(r => r.json()); },

    // --- issue grouping / baseline delta / AI triage ---
    // Findings bucketed by kind+host (count, max severity/CVSS, sample row ids)
    // -- the "group similar issues" view Burp does automatically.
    findingsGrouped()  { return fetch("/api/findings/grouped").then(r => r.json()); },
    // Save/compare a findings snapshot across engagements (scan-to-scan delta).
    // save/clear mutate a project-local baseline.json; status/diff are read-only.
    baselineSave()   { return post("/api/baseline/save").then(r => r.json()); },
    baselineStatus() { return fetch("/api/baseline/status").then(r => r.json()); },
    baselineDiff()   { return fetch("/api/baseline/diff").then(r => r.json()); },
    baselineClear()  { return post("/api/baseline/clear").then(r => r.json()); },
    // Ask a local Ollama model (falls back to a heuristic if unreachable) to
    // grade impact / suggest a fix / flag false-positive risk for one finding.
    triageFinding(payload) { return post("/api/triage/finding", payload).then(r => r.json()); },
    // Issue lifecycle (persisted in the project, keyed by finding identity so
    // it survives a re-scan): mark/unmark false positive, soft-delete/restore,
    // override severity (empty string clears the override back to the
    // scanner's own verdict), and mute/unmute every finding of one kind.
    // Every finding in NL.findings already carries falsePositive/deleted/
    // suppressed flags computed server-side from these same stores.
    findingMark(id, falsePositive)   { return post("/api/findings/mark", { id, falsePositive }).then(r => r.json()); },
    findingDelete(id, deleted)       { return post("/api/findings/delete", { id, deleted }).then(r => r.json()); },
    findingSetSeverity(id, severity) { return post("/api/findings/set-severity", { id, severity }).then(r => r.json()); },
    findingSuppressKind(kind, suppressed) { return post("/api/findings/suppress-kind", { kind, suppressed }).then(r => r.json()); },

    // --- recon: sensitive-path exposure / service-banner CVE / JS mining ---
    // Probes curated sensitive paths (.git/.env/actuator/...) against one
    // target URL, confirmed by content signature. Read-only.
    exposureScan(url, opts) {
      return post("/api/exposure/scan", Object.assign({ url }, opts)).then(r => r.json());
    },
    // Banner-grabs network services on a host and matches versions against a
    // curated CVE table. `opts` may carry { ports: [...], timeoutMs }.
    servicevulnsScan(host, opts) {
      return post("/api/servicevulns/scan", Object.assign({ host }, opts)).then(r => r.json());
    },
    // Mines a page's same-origin JS bundles for API endpoints, hardcoded
    // secrets, and exposed source maps. `opts` may carry { headers, maxScripts }.
    jsReconScan(url, opts) {
      return post("/api/jsrecon/scan", Object.assign({ url }, opts)).then(r => r.json());
    },
    // Opens a live TLS connection to host:port, reads the peer cert +
    // negotiated protocol/cipher, and flags weak config (expired/self-signed/
    // weak-key/hostname-mismatch/legacy-protocol). Findings also file into
    // Issues. `opts` may carry { port, timeoutMs, probeLegacy }.
    tlsInspect(host, opts) {
      return post("/api/tls/inspect", Object.assign({ host }, opts)).then(r => r.json());
    },
    // Checks whether a target advertises HTTP/3 support via the Alt-Svc
    // response header (h3/h3-* protocol IDs). An advertised-but-not-yet-used
    // protocol also files an info finding into Issues. `opts` may carry
    // { headers }. Response: { ok, error, advertisesHttp3, http3Versions,
    // altSvc, protocols: [{id, authority, maxAge, isHttp3}], baselineStatus }.
    http3Detect(url, opts) {
      return post("/api/http3/detect", Object.assign({ url }, opts)).then(r => r.json());
    },

    // --- Detection templates (nuclei-style matcher/extractor engine) ---
    // Lists the bundled template library (templates/detections/*.json).
    // Read-only. Response: { ok, count, templates: [{id, name, severity,
    // description}] }.
    templateList() { return fetch("/api/template/list").then(r => r.json()); },
    // Runs a detection template against one URL. `spec` is exactly one of
    // { templateId } (library template), { template: {...} } (inline JSON),
    // or { yaml } (nuclei-YAML, converted server-side). A template with a
    // "request" block crafts and fires its own request(s); otherwise a plain
    // GET is issued. A match also files a finding into Issues. Response:
    // { ok, matched, matchedCount, requests, capped, results: [{payloads,
    // status, matched, extracted, error?}], templateId, name, severity, url }.
    templateRun(url, spec) {
      return post("/api/template/run", Object.assign({ url }, spec)).then(r => r.json());
    },

    // --- port scan <-> findings / nmap XML bridge ---
    // Imports a raw nmap XML scan (<host>/<ports>/<port>/<state>/<service>)
    // into the port scanner's result set, so scans run outside Nullock
    // still populate one findings pipeline. Response: { ok, imported }.
    portscanImportNmap(xmlText) {
      return postRaw("/api/portscan/import-nmap", xmlText, "application/xml").then(r => r.json());
    },
    // Turns the port scanner's *current* results into first-class findings
    // (exposed database/remote-admin/management-API/cleartext/file-share,
    // plus banner->CVE correlation), idempotent on re-post. `opts` may carry
    // { includeOpenPorts, correlateCves }. Response: { ok, openPorts,
    // emitted, skippedDuplicates, bySeverity: {sev:count}, findings: [...] }.
    portscanToFindings(opts) {
      return post("/api/portscan/to-findings", opts || {}).then(r => r.json());
    },

    // --- built-in extensions install ---
    // Copies the extensions shipped with the repo (extensions/*.js) into the
    // user's extensions dir and reloads. Response: { ok, installed, destDir }.
    installBuiltinExtensions() {
      return post("/api/extensions/install-builtins").then(r => r.json());
    },

    // --- Cookie jar inventory (host-wide, beyond the Sessions tab's
    // inject-focused per-host list -- adds path/expiry + httpOnly/secure/
    // sameSite percentage rollups per host). Response: { hosts: [{host,
    // lastSeenMs, autoInject, count, httpOnlyPct, securePct, sameSitePct,
    // cookies: [{name, valueLen, path, expires, persistent, expiresEpoch,
    // httpOnly, secure, sameSite}] }] }.
    cookieJar() { return fetch("/api/cookies").then(r => r.json()); },

    // --- CVE overlay (extend Service CVE correlation at runtime) ---
    // GET current overlay size. Response: { ok, count }.
    cveOverlay() { return fetch("/api/cve/overlay").then(r => r.json()); },
    // Clears every pushed/synced overlay entry. Response: { ok, count: 0 }.
    cveOverlayClear() { return post("/api/cve/overlay/clear").then(r => r.json()); },
    // payload is either { entries: [...] } (direct/air-gapped push) or
    // { url: "https://..." } (fetch + parse a JSON feed, SSRF-guarded
    // server-side). Response: { ok, synced, received, dropped, source }.
    cveSync(payload) { return post("/api/cve/sync", payload).then(r => r.json()); },

    // --- Project templates (Burp: New project from template) ---
    // Response: { templates: [{id, name, description, inScope, outOfScope,
    // extensionsEnabled}] }.
    projectTemplates() { return fetch("/api/project/templates").then(r => r.json()); },
    // Applies a template's scope/notes onto a freshly-created project.
    // Response: { ok, project, applied } or { ok:false, error }.
    projectCreateFromTemplate(templateId, projectName) {
      return post("/api/project/create-from-template", { templateId, projectName }).then(r => r.json());
    },

    // --- WebSocket Repeater (Burp: WebSocket Repeater) ---
    // Lists every currently-open WS tunnel the MITM proxy is relaying, with
    // frame counters. Read-only, safe to poll. Response: { sessions: [{id,
    // host, port, openedAtMs, framesUp, framesDown}] }.
    wsSessions() { return fetch("/api/ws/sessions").then(r => r.json()); },
    // Queues a frame onto a live session's relay thread. direction is
    // "up" (client->server) or "down" (server->client); opcode 0x1=text,
    // 0x2=binary (payload sent as base64), 0x8=close, 0x9=ping, 0xA=pong.
    // Response: { ok, queued } -- queued=false means no session with that id
    // is open anymore (nothing about delivery to the wire is known here).
    wsSend(sessionId, direction, opcode, payload) {
      return post("/api/ws/send", { sessionId, direction, opcode, payload }).then(r => r.json());
    },

    // --- HTTP/2 frame-level visibility (#277: Burp has no frame log at all) ---
    // Lists every h2 stream captured on either MITM leg (client or upstream).
    // Read-only, safe to poll. Response: { streams: [{streamId, conn, method,
    // path, status, bytesIn, bytesOut, framesIn, framesOut, lastError,
    // openedAtMs, closed}] }.
    h2Streams() { return fetch("/api/h2/streams").then(r => r.json()); },
    // Raw h2 frame log since a cursor timestamp (ms), for a live tail. Pass
    // the previous call's latest `ts` back in as `sinceMs` to page forward.
    // Read-only. Response: { events: [{ts, conn, type, flags, streamId,
    // bytes, errorCode}] } -- type is a decoded frame-type name (DATA,
    // HEADERS, PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY,
    // WINDOW_UPDATE, CONTINUATION) or the raw numeric type if unrecognized.
    h2Events(sinceMs) {
      const q = sinceMs ? ("?since=" + encodeURIComponent(sinceMs)) : "";
      return fetch("/api/h2/events" + q).then(r => r.json());
    },

    // --- SQLite-backed history search (#268: the in-UI search is capped to
    // NL.rows' in-memory window, so a row evicted from that window could
    // never be found again -- this queries the on-disk index directly). ---
    // filters: { method?, host?, path?, status?, minSize?, maxSize?, sinceMs?,
    // limit? } -- every field optional, unreadable numeric filters are
    // dropped server-side rather than guessed at. Response: { rows: [{id, ts,
    // method, host, port, path, status, size, tls, mime}], count }.
    historyFind(filters) {
      return post("/api/history/find", filters || {}).then(r => r.json());
    },
  };

  NL.statusText = function (s) {
    return ({200:"OK",201:"Created",204:"No Content",301:"Moved Permanently",
             302:"Found",304:"Not Modified",401:"Unauthorized",403:"Forbidden",
             404:"Not Found",422:"Unprocessable",429:"Too Many Requests",
             500:"Server Error",502:"Bad Gateway",503:"Service Unavailable",
             101:"Switching Protocols"})[s] || "";
  };

  // Live updates: poll snapshot every 250 ms. The server bumps a `seq`
  // counter on every backend change; if seq hasn't moved it returns
  // 304 and we don't even parse JSON. Net cost when idle: ~1 KB/s.
  NL._seq = NL._seq || 0;
  setInterval(function () {
    try {
      const xhr = new XMLHttpRequest();
      xhr.open("GET", "/api/snapshot?since=" + NL._seq, true);
      xhr.onload = function () {
        if (xhr.status === 304) return;        // nothing changed, snooze
        if (xhr.status < 200 || xhr.status >= 300) return;
        try {
          const snap = JSON.parse(xhr.responseText);
          NL._seq = snap.seq || (NL._seq + 1);
          applySnapshot(snap);
          window.dispatchEvent(new CustomEvent("nl-update"));
        } catch (e) { /* malformed payload, ignore */ }
      };
      xhr.send();
    } catch (e) { /* network blip; retry next tick */ }
  }, 250);
})();
