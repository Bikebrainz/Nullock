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
    NL.bootInfo    = snap.bootInfo    || {};
    NL.themes      = snap.themes      || [];
    NL.scope       = snap.scope       || { in: [], out: [], notes: "" };
    NL.rows        = snap.rows        || [];
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
    intruderSet(payload)    { return post("/api/intruder/set",     payload); },
    intruderStart()         { return post("/api/intruder/start"); },
    intruderStop()          { return post("/api/intruder/stop"); },
    intruderClear()         { return post("/api/intruder/clear"); },
    setTheme(name)          { return post("/api/theme", { name }); },
    exportHar()             { return post("/api/har/export").then(r => r.json()); },
    clearHistory()          { return post("/api/clear-history"); },
    clearMitmBlocked()      { return post("/api/mitm/clear-blocked"); },
    reloadExtensions()      { return post("/api/extensions/reload"); },
  };

  NL.statusText = function (s) {
    return ({200:"OK",201:"Created",204:"No Content",301:"Moved Permanently",
             302:"Found",304:"Not Modified",401:"Unauthorized",403:"Forbidden",
             404:"Not Found",422:"Unprocessable",429:"Too Many Requests",
             500:"Server Error",502:"Bad Gateway",503:"Service Unavailable",
             101:"Switching Protocols"})[s] || "";
  };

  // Live updates: fetch snapshot every 500ms, dispatch event so the React
  // app can React.useSyncExternalStore against it. For now we just mutate
  // NL.* in place and the app re-reads on the next render cycle (caller
  // polls window.NL.rows via a state effect, see app.jsx).
  let lastBody = text || "";
  setInterval(function () {
    try {
      const xhr = new XMLHttpRequest();
      xhr.open("GET", "/api/snapshot", true);
      xhr.onload = function () {
        if (xhr.status >= 200 && xhr.status < 300 && xhr.responseText !== lastBody) {
          lastBody = xhr.responseText;
          try {
            applySnapshot(JSON.parse(xhr.responseText));
            window.dispatchEvent(new CustomEvent("nl-update"));
          } catch (e) { /* skip bad payload */ }
        }
      };
      xhr.send();
    } catch (e) { /* network blip, try again next tick */ }
  }, 500);
})();
