// Real data shim. Replaces mock-data.js.
//
// The React app expects window.NL to be populated synchronously before
// app.jsx runs. We block on a sync XHR to /api/snapshot the first time so
// the initial render has real data, then set up a polling loop that
// refreshes NL.* every 500 ms and dispatches a 'nl-update' event the app
// listens to.
//
// requestRawAt / responseRawAt also need to be synchronous from the React
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
    NL.rows          = snap.rows          || [];
    NL.sitemap     = snap.sitemap     || [];
    NL.intercepted = snap.intercepted || [];
    NL.repeater    = snap.repeater    || { host: "", port: 443, tls: true,
                                            request: "", response: "",
                                            statusLine: "" };
    NL.intruder    = snap.intruder    || { host: "", port: 443, tls: true,
                                            template: "", payloads: [],
                                            results: [], running: false };
    NL.currentTheme       = snap.currentTheme || "cyber";
    NL.interceptEnabled   = snap.interceptEnabled === true;
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

  // Initial sync load so React renders with real data immediately.
  const text = syncFetch("/api/snapshot");
  if (text) {
    try { applySnapshot(JSON.parse(text)); }
    catch (e) { console.warn("NL parse failed", e); }
  }

  // Memoized per-row accessors used inside the React reducer.
  NL.requestRawAt = function (rowIndex) {
    const r = NL.rows[rowIndex];
    if (!r) return "";
    if (NL._cache.req[r.id] !== undefined) return NL._cache.req[r.id];
    const t = syncFetch("/api/history/" + r.id + "/request") || "";
    NL._cache.req[r.id] = t;
    return t;
  };
  NL.responseRawAt = function (rowIndex) {
    const r = NL.rows[rowIndex];
    if (!r) return "";
    if (NL._cache.resp[r.id] !== undefined) return NL._cache.resp[r.id];
    const t = syncFetch("/api/history/" + r.id + "/response") || "";
    NL._cache.resp[r.id] = t;
    return t;
  };
  // POST helpers wired to the control server's action endpoints. Fire and
  // forget -- the snapshot poll picks up resulting state changes within
  // ~500 ms. Callers can chain .then() if they want to refresh sooner.
  function post(path, payload) {
    return fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload || {}),
    });
  }
  NL.actions = {
    toggleProxy()           { return post("/api/proxy/toggle"); },
    toggleIntercept()       { return post("/api/intercept/toggle"); },
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
    setTheme(name)          { return post("/api/theme", { name }); },
    saveTheme(name, colors) { return post("/api/theme/save-as", { name, colors }).then(r => r.json()); },
    reloadThemes()          { return post("/api/theme/reload"); },
    exportHar()             { return post("/api/har/export").then(r => r.json()); },
    importHarPath(path)     { return post("/api/har/import", { path }).then(r => r.json()); },
    importHar(harObject)    { return post("/api/har/import", { har: harObject }).then(r => r.json()); },
    clearHistory()          { return post("/api/clear-history"); },
    clearMitmBlocked()      { return post("/api/mitm/clear-blocked"); },
    reloadExtensions()      { return post("/api/extensions/reload"); },
    clearFindings()         { return post("/api/findings/clear"); },
    ruleAdd(rule)           { return post("/api/rules/add",    rule).then(r => r.json()); },
    ruleUpdate(index, rule) { return post("/api/rules/update", Object.assign({ index }, rule)); },
    ruleRemove(index)       { return post("/api/rules/remove", { index }); },
    ruleToggle(index)       { return post("/api/rules/toggle", { index }); },
    ruleMove(from, to)      { return post("/api/rules/move",   { from, to }); },
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
