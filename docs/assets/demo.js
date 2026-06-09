/* nullock landing — live capture demo + copy buttons */
(function () {
  "use strict";

  /* ---------- copy-to-clipboard ---------- */
  document.addEventListener("click", function (e) {
    var btn = e.target.closest(".copy");
    if (!btn) return;
    var text = (btn.getAttribute("data-copy") || "").replace(/&#10;/g, "\n");
    navigator.clipboard && navigator.clipboard.writeText(text);
    var prev = btn.textContent;
    btn.textContent = "copied ✓";
    setTimeout(function () { btn.textContent = prev; }, 1400);
  });

  /* ---------- proxy capture demo ---------- */
  var body = document.getElementById("histBody");
  if (!body) return;

  var SAMPLES = [
    { m: "GET",  host: "api.stripe.com",   path: "/v1/charges?limit=20",          s: 200, len: "4.1 KB", t: 142,
      reqExtra: "Authorization: Bearer sk_live_4eC39H••••••••\nAccept: application/json",
      res: '{\n  "object": "list",\n  "data": [ { "id": "ch_3Pz...", "amount": 4200, "paid": true } ],\n  "has_more": false\n}' },
    { m: "POST", host: "app.local",        path: "/api/login",                    s: 201, len: "612 B", t: 88,
      reqExtra: "Content-Type: application/json\n\n{ \"email\": \"ada@local\", \"pw\": \"••••••••\" }",
      res: '{\n  "token": "ey_8f2c...d91a",\n  "expires_in": 3600,\n  "scope": "read:write"\n}' },
    { m: "GET",  host: "cdn.site.com",      path: "/static/app.4f2c.js",           s: 304, len: "0 B", t: 12,
      reqExtra: "If-None-Match: \"4f2c-d91a\"\nAccept: */*",
      res: "(not modified — served from cache)" },
    { m: "GET",  host: "api.github.com",    path: "/repos/nullock/cli/releases",   s: 200, len: "8.7 KB", t: 211,
      reqExtra: "Accept: application/vnd.github+json\nUser-Agent: nullock/3.2.0",
      res: '[\n  { "tag_name": "v3.2.0", "name": "Repeater diff" },\n  { "tag_name": "v3.1.4", "name": "SQLite vacuum" }\n]' },
    { m: "POST", host: "app.local",         path: "/api/graphql",                  s: 400, len: "188 B", t: 34,
      reqExtra: "Content-Type: application/json\n\n{ \"query\": \"{ me { id roles } }\" }",
      res: '{\n  "errors": [ { "message": "missing scope: roles:read" } ]\n}' },
    { m: "DELETE", host: "app.local",       path: "/api/session/9f2c",             s: 204, len: "0 B", t: 41,
      reqExtra: "Authorization: Bearer ey_8f2c...d91a",
      res: "(no content)" },
    { m: "GET",  host: "telemetry.vendor.io",path: "/collect?e=open",              s: 403, len: "97 B", t: 19,
      reqExtra: "X-Client: web\nOrigin: https://app.local",
      res: '{ "error": "blocked by match&replace rule #4" }' },
    { m: "GET",  host: "fonts.gstatic.com",  path: "/s/inter/v13/font.woff2",      s: 200, len: "32 KB", t: 64,
      reqExtra: "Accept: font/woff2\nReferer: https://app.local/",
      res: "(binary — 32 KB woff2)" },
    { m: "POST", host: "api.stripe.com",     path: "/v1/payment_intents",          s: 500, len: "240 B", t: 503,
      reqExtra: "Content-Type: application/x-www-form-urlencoded\n\namount=4200&currency=usd",
      res: '{\n  "error": { "type": "api_error", "message": "upstream timeout" }\n}' },
    { m: "GET",  host: "app.local",          path: "/api/users/me",                s: 200, len: "1.2 KB", t: 27,
      reqExtra: "Authorization: Bearer ey_8f2c...d91a",
      res: '{\n  "id": "u_77",\n  "email": "ada@local",\n  "roles": ["admin"]\n}' }
  ];

  var rows = [];
  var n = 0;
  var selectedId = null;

  function methodClass(m){ return m === "GET" ? "m-get" : m === "DELETE" ? "m-del" : "m-post"; }
  function statusClass(s){ return "s-" + String(s).charAt(0); }

  function rawRequest(r){
    return r.m + " " + r.path + " HTTP/2\nHost: " + r.host + "\n" + (r.reqExtra || "") ;
  }
  function rawResponse(r){
    var line = "HTTP/2 " + r.s + " " + statusText(r.s);
    return line + "\nContent-Length: " + r.len + "\nServer: nullock-proxy\n\n" + r.res;
  }
  function statusText(s){
    return ({200:"OK",201:"Created",204:"No Content",304:"Not Modified",400:"Bad Request",403:"Forbidden",500:"Internal Server Error"})[s] || "";
  }

  function select(id){
    selectedId = id;
    var r = rows.find(function(x){ return x.id === id; });
    if (!r) return;
    document.querySelectorAll(".hist-row").forEach(function(el){
      el.classList.toggle("sel", +el.dataset.id === id);
    });
    document.getElementById("reqBody").textContent = rawRequest(r);
    document.getElementById("resBody").textContent = rawResponse(r);
    document.getElementById("reqMeta").textContent = r.host;
    document.getElementById("resMeta").textContent = r.s + " · " + r.t + "ms";
  }

  function addRow(){
    var src = SAMPLES[n % SAMPLES.length];
    n++;
    var r = Object.assign({}, src, { id: n });
    rows.push(r);
    if (rows.length > 9) rows.shift();

    var el = document.createElement("div");
    el.className = "hist-row";
    el.dataset.id = r.id;
    el.innerHTML =
      '<span>' + r.id + '</span>' +
      '<span class="' + methodClass(r.m) + '">' + r.m + '</span>' +
      '<span>' + r.host + '</span>' +
      '<span>' + r.path + '</span>' +
      '<span class="' + statusClass(r.s) + '">' + r.s + '</span>' +
      '<span>' + r.len + '</span>' +
      '<span>' + r.t + 'ms</span>';
    el.addEventListener("click", function(){ select(r.id); });
    body.appendChild(el);

    // prune DOM to match
    while (body.children.length > 9) body.removeChild(body.firstChild);

    document.getElementById("rowcount").textContent = n + " captured";

    // auto-select newest if user hasn't picked, or selected got pruned
    var stillThere = rows.some(function(x){ return x.id === selectedId; });
    if (!stillThere) select(r.id);

    body.scrollTop = body.scrollHeight;
  }

  // seed a few, then stream
  for (var i = 0; i < 5; i++) addRow();
  select(rows[2].id);

  var paused = false;
  document.getElementById("proxy").addEventListener("mouseenter", function(){ paused = true; });
  document.getElementById("proxy").addEventListener("mouseleave", function(){ paused = false; });

  function tick(){
    if (!paused) addRow();
    setTimeout(tick, 1600 + Math.random() * 900);
  }
  setTimeout(tick, 1600);

  // tab clicks (visual only)
  document.querySelectorAll(".ptab").forEach(function(tab){
    tab.addEventListener("click", function(){
      document.querySelectorAll(".ptab").forEach(function(t){ t.classList.remove("active"); });
      tab.classList.add("active");
    });
  });
})();
