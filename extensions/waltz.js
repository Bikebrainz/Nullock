// waltz.js -- passive OAuth 2.0 / OpenID Connect misconfig auditor.
//
// nullock:version 0.1.0
//
// The proxy-side answer to EsPReSSO / OAuthScan: watch the OAuth dance go
// by and flag the classic mistakes without sending a single extra request.
// Nullock's native scanner already dissects JWTs; this covers the *flow*
// around them -- how the authorization request is built and how tokens come
// back -- which nothing native looks at.
//
// Observe-only: it registers onResponse and reads the request URL (query
// included), the response status + Location header, and the body preview.
// It never mutates and needs no permission.
//
// What it catches:
//   - Implicit flow: response_type=token / id_token (tokens delivered in the
//     URL, cacheable, logged, in Referer -- deprecated by OAuth 2.1).
//   - Missing `state`: no CSRF defence on the authorization request.
//   - Missing PKCE: an authorization-code request with no code_challenge
//     (mandatory for public clients under OAuth 2.1).
//   - Tokens in the URL: access_token / id_token / code landing in a query
//     string or a redirect Location (leaks via history, Referer, logs).
//   - Cleartext redirect_uri: an http:// callback for a bearer-token flow.
//
// Limits: purely passive and single-message -- it can't confirm redirect_uri
// allow-listing or replay `code`. Treat findings as leads, per the BApp it
// mirrors. `client_id` is truncated in evidence; no secrets are logged.

(function() {
'use strict';

var AUTHZ_PATH = /\/(?:oauth2?|connect|auth|authorize|authorization|signin-oidc|as)\b|\/authorize|\/authorization/i;

function parseQuery(qs) {
    var out = {};
    if (!qs) return out;
    var parts = qs.split("&");
    for (var i = 0; i < parts.length; i++) {
        var eq = parts[i].indexOf("=");
        var k = eq >= 0 ? parts[i].substring(0, eq) : parts[i];
        var v = eq >= 0 ? parts[i].substring(eq + 1) : "";
        try { k = decodeURIComponent(k); } catch (e) {}
        try { v = decodeURIComponent(v.replace(/\+/g, " ")); } catch (e2) {}
        if (k) out[k.toLowerCase()] = v;
    }
    return out;
}

function splitUrl(url) {
    var q = "", frag = "", u = url || "";
    var h = u.indexOf("#");
    if (h >= 0) { frag = u.substring(h + 1); u = u.substring(0, h); }
    var qm = u.indexOf("?");
    if (qm >= 0) { q = u.substring(qm + 1); u = u.substring(0, qm); }
    return { base: u, query: q, fragment: frag };
}

function headerVal(headers, name) {
    if (!headers) return "";
    var low = name.toLowerCase();
    for (var i = 0; i < headers.length; i++)
        if (headers[i][0] && headers[i][0].toLowerCase() === low) return headers[i][1] || "";
    return "";
}

function clip(s, n) { s = String(s || ""); return s.length > n ? s.substring(0, n) + "..." : s; }

var seen = {};
function once(key) { if (seen[key]) return false; seen[key] = 1; return true; }
function report(sev, kind, summary, evidence, url, dedupeKey) {
    if (!once(dedupeKey)) return;
    try { nullock.reportFinding(sev, kind, summary, evidence, url); }
    catch (e) { nullock.log("waltz report failed: " + e); }
}

// Does this URL/fragment carry a token or auth code?
function tokenLeak(part) {
    if (!part) return "";
    if (/(?:^|[&?#])access_token=/.test(part))  return "access_token";
    if (/(?:^|[&?#])id_token=/.test(part))      return "id_token";
    if (/(?:^|[&?#])code=[^&]{8,}/.test(part))  return "authorization code";
    return "";
}

function auditAuthorize(url, q) {
    // Only treat it as an OAuth authorize request if it smells like one.
    var looksOAuth = ("client_id" in q) && (("redirect_uri" in q) || ("response_type" in q) || ("scope" in q));
    if (!looksOAuth) return;

    var rt = (q["response_type"] || "").toLowerCase();
    var cid = clip(q["client_id"], 24);
    var ruri = q["redirect_uri"] || "";

    if (/\btoken\b/.test(rt) || rt.indexOf("id_token") >= 0) {
        report("medium", "oauth-implicit-flow",
            "OAuth implicit flow in use (response_type=" + rt + "): tokens are returned in the URL",
            "authorize request, client_id=" + cid + ", response_type=" + rt, url,
            "impl|" + splitUrl(url).base + "|" + rt);
    }
    if (!("state" in q)) {
        report("medium", "oauth-missing-state",
            "OAuth authorization request has no `state` parameter (no CSRF binding)",
            "authorize request, client_id=" + cid, url,
            "state|" + splitUrl(url).base);
    }
    if (rt.indexOf("code") >= 0 && !("code_challenge" in q)) {
        report("medium", "oauth-missing-pkce",
            "Authorization-code request without PKCE (no code_challenge)",
            "authorize request, client_id=" + cid + ", response_type=" + rt, url,
            "pkce|" + splitUrl(url).base + "|" + cid);
    }
    // Include the OIDC implicit `id_token` flow, matching the implicit-flow check
    // above: /\btoken\b/ can't match "id_token" (the '_' is a word char, so there's
    // no word boundary before "token"), so an id_token implicit flow over a
    // cleartext http:// redirect_uri -- which leaks the token on the callback --
    // was silently missed.
    if (/^http:\/\//i.test(ruri) && (/\btoken\b/.test(rt) || rt.indexOf("id_token") >= 0 || rt.indexOf("code") >= 0)) {
        report("medium", "oauth-cleartext-redirect-uri",
            "OAuth redirect_uri is cleartext http:// -- credentials/code exposed on the callback",
            "redirect_uri=" + clip(ruri, 80), url,
            "ruri|" + splitUrl(url).base + "|" + clip(ruri, 40));
    }
}

nullock.onResponse(function(entry) {
    try {
        var url = entry.url || "";
        var parts = splitUrl(url);
        var q = parseQuery(parts.query);

        // 1. Audit an authorization request as it goes out.
        if (AUTHZ_PATH.test(parts.base) || ("response_type" in q) || ("client_id" in q))
            auditAuthorize(url, q);

        // 2. Token/code leaking into THIS request's own URL (query or fragment
        //    server-side can't see the fragment, but if we can it's exposure).
        var inUrl = tokenLeak(parts.query) || tokenLeak(parts.fragment);
        if (inUrl) {
            report("high", "oauth-token-in-url",
                "OAuth " + inUrl + " present in a request URL (leaks via history, Referer and logs)",
                "location: request URL", url, "urltok|" + parts.base + "|" + inUrl);
        }

        // 3. Token/code leaking through a redirect Location.
        if (entry.status >= 300 && entry.status < 400) {
            var loc = headerVal(entry.headers, "Location");
            var inLoc = tokenLeak(loc);
            if (inLoc) {
                report("high", "oauth-token-in-redirect",
                    "OAuth " + inLoc + " returned in a 3xx Location header (URL-borne token leakage)",
                    "Location: " + clip(loc, 100), url,
                    "loctok|" + parts.base + "|" + inLoc);
            }
        }
    } catch (e) {
        nullock.log("waltz: " + (e && e.message ? e.message : String(e)));
    }
    return entry;
});

nullock.log("waltz: loaded (passive OAuth 2.0 / OIDC flow auditor)");

})();
