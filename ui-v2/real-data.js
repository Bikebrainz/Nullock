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
    NL.rows          = snap.rows          || [];
    NL.sitemap     = snap.sitemap     || [];
    NL.intercepted = snap.intercepted || [];
    NL.repeater    = snap.repeater    || { host: "", port: 443, tls: true,
                                            request: "", response: "",
                                            statusLine: "" };
    NL.intruder    = snap.intruder    || { host: "", port: 443, tls: true,
                                            template: "", payloads: [],
                                            results: [], running: false,
                                            concurrency: 10, throttleMs: 0,
                                            attackType: 0, positions: 0,
                                            payloadSets: [] };
    NL.currentTheme       = snap.currentTheme || "cyber";
    NL.interceptEnabled   = snap.interceptEnabled === true;
    NL.interceptResponsesEnabled = snap.interceptResponsesEnabled === true;
    NL.themeColors        = snap.themeColors || {};
    NL.themeIsBuiltin     = snap.themeIsBuiltin === true;
    NL.themesDir          = snap.themesDir || "";

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
  NL.actions = {
    toggleProxy()           { return post("/api/proxy/toggle"); },
    toggleIntercept()          { return post("/api/intercept/toggle"); },
    toggleInterceptResponses() { return post("/api/intercept/responses/toggle"); },
    interceptForward(text)  { return post("/api/intercept/forward", { text }); },
    interceptDrop()         { return post("/api/intercept/drop"); },
    interceptForwardAll()   { return post("/api/intercept/forwardAll"); },
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
    setTheme(name)          { return post("/api/theme", { name }); },
    saveTheme(name, colors) { return post("/api/theme/save-as", { name, colors }).then(r => r.json()); },
    reloadThemes()          { return post("/api/theme/reload"); },
    exportHar()             { return post("/api/har/export").then(r => r.json()); },
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
    fingerprintUrl(url)         { return post("/api/fingerprint", { url }).then(r => r.json()); },
    auditHeaders(url)           { return post("/api/headers/audit", { url }).then(r => r.json()); },
    detectWaf(url)              { return post("/api/waf/detect", { url }).then(r => r.json()); },
    scanSecrets(url)            { return post("/api/secrets/scan", { url }).then(r => r.json()); },
    discoverContent(url, max)   { return post("/api/content/discover", { url, max: max || undefined }).then(r => r.json()); },
    scanRobots(url)             { return post("/api/robots/scan", { url }).then(r => r.json()); },
    crawlerStart(seed, maxPages, maxDepth) {
      return post("/api/crawler/start", { seed, maxPages: maxPages || undefined, maxDepth: maxDepth || undefined }).then(r => r.json());
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
