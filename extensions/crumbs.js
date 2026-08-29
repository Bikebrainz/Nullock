// crumbs.js -- endpoint & route crumbs picked out of served JavaScript.
//
// nullock:version 0.1.0
//
// The recon staple: modern apps ship their whole API surface in the JS
// bundle. Pull the paths, fetch()/axios() targets and route strings out of
// every script that flows past, and you get a map of endpoints to go poke --
// including the /admin, /internal and /debug ones nothing links to. This is
// the job LinkFinder / GAP do; Nullock's native JS pass hunts secrets, not
// routes, so this is a clean addition rather than a duplicate.
//
// Observe-only: onResponse over JS (and inline <script>), no permission.
//
// It reports two ways so it stays high-signal:
//   - One `js-endpoints-discovered` info finding per script summarising the
//     count with a sample (the full list goes to the extension log).
//   - A `js-endpoint-sensitive` low finding for any path that smells juicy
//     (admin / internal / debug / token / upload / actuator / graphql /
//     swagger / api-key / a versioned /v1 API ...), so those surface on their
//     own instead of drowning in the summary.
//
// Limits: static string-scraping. It won't see endpoints built by
// concatenation at runtime, and it will occasionally grab a non-endpoint
// string that happens to look like a path. Treat it as leads to explore.

(function() {
'use strict';

function headerVal(headers, name) {
    if (!headers) return "";
    var low = name.toLowerCase();
    for (var i = 0; i < headers.length; i++)
        if (headers[i][0] && headers[i][0].toLowerCase() === low) return headers[i][1] || "";
    return "";
}
function clip(s, n) { s = String(s || ""); return s.length > n ? s.substring(0, n) + "..." : s; }

var seen = {};
function report(sev, kind, summary, evidence, url, key) {
    if (seen[key]) return; seen[key] = 1;
    try { nullock.reportFinding(sev, kind, summary, evidence, url); }
    catch (e) { nullock.log("crumbs report failed: " + e); }
}

// A path/URL string is "boring" if it's really a static asset or a fragment.
var BORING = /\.(?:png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|eot|map|mp4|webm|json)(?:$|\?|#)/i;
var SENSITIVE = /(?:admin|internal|private|secret|token|passwd|password|debug|actuator|swagger|openapi|graphql|graphiql|upload|export|backup|console|\.git|\/v\d+\/|api[_-]?key|oauth|sso|saml|impersonate|sudo|superuser)/i;

// Endpoint extraction patterns over a chunk of JS/HTML.
function extract(code) {
    var found = {};
    function add(p) {
        if (!p) return;
        p = p.trim();
        if (p.length < 2 || p.length > 180) return;
        if (BORING.test(p)) return;
        if (/^https?:\/\//i.test(p) || /^\//.test(p)) found[p] = 1;
    }
    var m, re;
    // Quoted absolute-path or URL literals: "/api/v2/users", 'https://x/y'
    re = /["'`](https?:\/\/[^"'`\s]{4,180}|\/[A-Za-z0-9_~%\-./]{2,180})["'`]/g;
    while ((m = re.exec(code)) !== null) add(m[1]);
    // fetch("...") / axios.get("...") targets, and window.open("...") whose URL
    // is the FIRST argument. (`.open` stays here so single-arg window.open is
    // still caught; for XHR its first arg is the method, harmlessly rejected by
    // add().)
    re = /(?:fetch|axios(?:\.\w+)?|\.open|url\s*[:=]|href\s*[:=]|api\s*[:=])\s*\(?\s*["'`]([^"'`]{2,180})["'`]/g;
    while ((m = re.exec(code)) !== null) add(m[1]);
    // XMLHttpRequest.open(method, url): the URL is the SECOND argument. The
    // pattern above captures the FIRST quoted token (the HTTP method) and add()
    // drops it; pattern-1 can't rescue a query-bearing URL because its path
    // charset excludes ?=&#. So capture the 2nd arg explicitly, or a query-
    // string endpoint referenced only via xhr.open is silently missed.
    re = /\.open\s*\(\s*["'`][^"'`]*["'`]\s*,\s*["'`]([^"'`]{2,180})["'`]/g;
    while ((m = re.exec(code)) !== null) add(m[1]);
    var out = Object.keys(found);
    // Drop obvious non-endpoints: pure "//", protocol-relative junk, regexes.
    out = out.filter(function(p){ return !/^\/\//.test(p) && !/[<>{}]/.test(p); });
    return out;
}

function scriptChunks(body, ct, url) {
    var isJs = ct.indexOf("javascript") >= 0 || ct.indexOf("ecmascript") >= 0 || /\.m?js(\?|$)/i.test(url);
    if (isJs) return [body];
    if (ct.indexOf("html") >= 0 || /<html|<!doctype/i.test(body)) {
        var chunks = [], re = /<script\b[^>]*>([\s\S]*?)<\/script>/gi, m;
        while ((m = re.exec(body)) !== null) if (m[1] && m[1].trim()) chunks.push(m[1]);
        return chunks;
    }
    return [];
}

nullock.onResponse(function(entry) {
    try {
        var url = entry.url || "";
        var ct = headerVal(entry.headers, "Content-Type").toLowerCase();
        var body = entry.bodyText || entry.bodyPreview || "";
        if (!body) return entry;

        var chunks = scriptChunks(body, ct, url), all = {};
        for (var i = 0; i < chunks.length; i++) {
            var eps = extract(chunks[i]);
            for (var j = 0; j < eps.length; j++) all[eps[j]] = 1;
        }
        var list = Object.keys(all);
        if (!list.length) return entry;

        // Sensitive ones get their own low finding.
        var juicy = list.filter(function(p){ return SENSITIVE.test(p); });
        for (var k = 0; k < juicy.length && k < 25; k++) {
            report("low", "js-endpoint-sensitive",
                "Sensitive-looking endpoint referenced in JS: " + clip(juicy[k], 100),
                "source: " + clip(url, 90), url, "juicy|" + url + "|" + juicy[k]);
        }
        // One rolled-up info finding for the rest.
        var sample = list.slice(0, 12).map(function(p){ return clip(p, 80); }).join("  ");
        report("info", "js-endpoints-discovered",
            list.length + " endpoint(s) extracted from JavaScript"
            + (juicy.length ? " (" + juicy.length + " sensitive-looking)" : ""),
            "sample: " + sample + (list.length > 12 ? "  (+" + (list.length - 12) + " more in ext log)" : ""),
            url, "sum|" + url + "|" + list.length);
        if (list.length > 12) nullock.log("crumbs: " + url + " -> " + list.join("  "));
    } catch (e) {
        nullock.log("crumbs: " + (e && e.message ? e.message : String(e)));
    }
    return entry;
});

nullock.log("crumbs: loaded (endpoint extraction from served JS)");

})();
