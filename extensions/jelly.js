// jelly.js -- wobbly JSON: JSONP endpoints & cross-site JSON hijacking.
//
// nullock:version 0.1.0
//
// A JSONP endpoint wraps its data in an attacker-named callback, so any site
// can <script src> it and read the response cross-origin -- and if the
// callback name is reflected raw, that's reflected XSS on top. Top-level JSON
// arrays are the classic array-hijack shape. Nullock covers CORS natively but
// nothing looks at the JSONP/callback angle, so this fills it.
//
// Observe-only: onResponse, reads the request URL's query + the response body
// and content-type. No permission.
//
// What it reports:
//   - jsonp-callback-xss (high): the callback value is reflected verbatim AND
//     carries HTML/JS metacharacters -> reflected XSS via the callback param.
//   - jsonp-endpoint (medium): the response is a reflected callback wrapper
//     around data -> cross-site readable; confirm it returns anything sensitive.
//   - json-array-hijack (low): a top-level JSON array served 200 -> legacy
//     array-constructor hijack shape; low on modern browsers, still worth noting.
//
// Limits: passive and single-message -- it flags the shape, it can't prove the
// body is sensitive or that a victim is authenticated. Leads, not proof.

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

function queryParam(url, names) {
    var qm = url.indexOf("?"); if (qm < 0) return null;
    var qs = url.substring(qm + 1); var h = qs.indexOf("#"); if (h >= 0) qs = qs.substring(0, h);
    var parts = qs.split("&");
    for (var i = 0; i < parts.length; i++) {
        var eq = parts[i].indexOf("=");
        var k = (eq >= 0 ? parts[i].substring(0, eq) : parts[i]).toLowerCase();
        if (names.indexOf(k) >= 0) {
            var v = eq >= 0 ? parts[i].substring(eq + 1) : "";
            try { v = decodeURIComponent(v.replace(/\+/g, " ")); } catch (e) {}
            return v;
        }
    }
    return null;
}

var seen = {};
function report(sev, kind, summary, evidence, url, key) {
    if (seen[key]) return; seen[key] = 1;
    try { nullock.reportFinding(sev, kind, summary, evidence, url); }
    catch (e) { nullock.log("jelly report failed: " + e); }
}

var CALLBACK_PARAMS = ["callback", "jsonp", "jsonpcallback", "cb", "json.callback", "callbackname", "jsoncallback"];

nullock.onResponse(function(entry) {
    try {
        if (entry.status && (entry.status < 200 || entry.status >= 300)) return entry;
        var url = entry.url || "";
        var ct = headerVal(entry.headers, "Content-Type").toLowerCase();
        var body = entry.bodyText || entry.bodyPreview || "";
        if (!body) return entry;

        var head = body.replace(/^﻿/, "").replace(/^\s*\/\*[\s\S]*?\*\/\s*/, "").replace(/^[\s;]+/, "");
        var isJsCt = /javascript|ecmascript/.test(ct);

        // JSONP: leading `name(` wrapper.
        var wrap = head.match(/^([A-Za-z_$][\w$.\[\]'"]{0,120})\s*\(/);
        var cbVal = queryParam(url, CALLBACK_PARAMS);
        if (wrap && (isJsCt || cbVal)) {
            var fn = wrap[1];
            var reflected = cbVal && head.indexOf(cbVal) === 0;   // callback value drives the wrapper name
            if (reflected && /[<>"'();=\s]/.test(cbVal)) {
                report("high", "jsonp-callback-xss",
                    "JSONP callback reflected verbatim with JS/HTML metacharacters -- reflected XSS via the callback parameter",
                    "callback=" + clip(cbVal, 80) + "  ->  body starts: " + clip(head, 80), url,
                    "cbxss|" + url.split("?")[0]);
            } else if (reflected || (isJsCt && /^[\w$.]+\($/.test(fn + "("))) {
                report("medium", "jsonp-endpoint",
                    "JSONP endpoint (callback-wrapped response) -- cross-site readable via <script src>",
                    "wrapper: " + clip(fn, 60) + "(...)" + (cbVal ? ", callback param reflected" : ""), url,
                    "jsonp|" + url.split("?")[0]);
            }
            return entry;
        }

        // Top-level JSON array (array-hijack shape) -- only when it's really JSON.
        if (/json/.test(ct) && /^\s*\[/.test(body) && /[\{"]/.test(body)) {
            report("low", "json-array-hijack",
                "Top-level JSON array response -- legacy cross-site array-hijack shape; prefer an object or an anti-hijack prefix",
                "body starts: " + clip(body.replace(/\s+/g, " "), 60), url,
                "arr|" + url.split("?")[0]);
        }
    } catch (e) {
        nullock.log("jelly: " + (e && e.message ? e.message : String(e)));
    }
    return entry;
});

nullock.log("jelly: loaded (JSONP / JSON-hijacking detector)");

})();
