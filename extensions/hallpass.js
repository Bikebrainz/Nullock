// hallpass.js -- passive anti-CSRF token auditor for HTML forms.
//
// nullock:version 0.1.0
//
// A proxy-side CSRF Scanner: for every state-changing form the app serves,
// check whether it carries an anti-CSRF token. Nullock's native scanner
// grades cookie SameSite attributes, but SameSite is a backstop, not the
// control -- a POST form with no synchronizer token (and no other defence)
// is the textbook CSRF setup, and nothing native looks at form bodies for it.
//
// Observe-only: onResponse over response HTML, no mutation, no permission.
//
// Heuristic (and it IS a heuristic -- treat findings as leads):
//   - Scan each <form method="post"> in the response.
//   - Look for a hidden input whose NAME matches the well-known token names
//     (csrf/xsrf/authenticity_token/__RequestVerificationToken/_token/nonce...)
//     OR a hidden input carrying a token-SHAPED value (long, random-ish).
//   - A POST form to a same-origin/relative action with neither is reported.
//
// Known false positives (documented, not hidden): APIs protected purely by a
// custom request header or a strict SameSite=Strict cookie; SPA forms whose
// token is attached by JS at submit time; forms posting cross-origin on
// purpose. The finding says to confirm the request actually rides a cookie
// and lacks a custom-header/double-submit defence. GET forms are ignored
// (CSRF on a safe method isn't state-changing).

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

var TOKEN_NAME = /(csrf|xsrf|authenticity_token|request.?verification|anti.?forgery|_token|nonce|__csrf)/i;

var seen = {};
function report(sev, kind, summary, evidence, url, key) {
    if (seen[key]) return; seen[key] = 1;
    try { nullock.reportFinding(sev, kind, summary, evidence, url); }
    catch (e) { nullock.log("hallpass report failed: " + e); }
}

// A hidden input whose value looks like a random token (not a flag/id).
function hasTokenShapedInput(formHtml) {
    var re = /<input\b[^>]*>/gi, m;
    while ((m = re.exec(formHtml)) !== null) {
        var tag = m[0];
        if (!/type\s*=\s*["']?hidden/i.test(tag)) continue;
        var nameM = tag.match(/name\s*=\s*["']([^"']*)["']/i);
        if (nameM && TOKEN_NAME.test(nameM[1])) return true;
        var valM = tag.match(/value\s*=\s*["']([^"']*)["']/i);
        if (valM) {
            var v = valM[1];
            // token-shaped: long, mixed, not all digits (an id) or all letters.
            if (v.length >= 24 && /[A-Za-z]/.test(v) && /[0-9\-_+/=]/.test(v) && !/^\d+$/.test(v))
                return true;
        }
    }
    return false;
}

function formAction(formTag) {
    var m = formTag.match(/action\s*=\s*["']([^"']*)["']/i);
    return m ? m[1] : "";
}

nullock.onResponse(function(entry) {
    try {
        var ct = headerVal(entry.headers, "Content-Type").toLowerCase();
        if (ct && ct.indexOf("html") < 0) return entry;
        var body = entry.bodyText || entry.bodyPreview || "";
        // Case-INSENSITIVE prefilter to match the /gi extraction regex below: a
        // literal lowercase indexOf("<form") dropped valid uppercase/mixed-case
        // forms (<FORM METHOD="POST">, classic ASP/ColdFusion/older JSP output),
        // so a genuinely CSRF-vulnerable uppercase POST form was silently skipped.
        if (!body || !/<form\b/i.test(body)) return entry;

        var url = entry.url || "";
        var host = "";
        var hm = url.match(/^https?:\/\/([^\/]+)/i); if (hm) host = hm[1].toLowerCase();

        var re = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi, m, idx = 0;
        while ((m = re.exec(body)) !== null) {
            idx++;
            var attrs = m[1], inner = m[2];
            if (!/method\s*=\s*["']?post/i.test(attrs)) continue;    // only state-changing

            var action = formAction(attrs);
            // Skip clearly cross-origin actions (different host) -- not this app's CSRF posture.
            var actHost = action.match(/^https?:\/\/([^\/]+)/i);
            if (actHost && host && actHost[1].toLowerCase() !== host) continue;

            if (hasTokenShapedInput(inner)) continue;               // looks protected

            report("medium", "csrf-token-missing",
                "POST form appears to lack an anti-CSRF token" + (action ? " (action=" + clip(action, 50) + ")" : ""),
                "form #" + idx + " on page, method=POST, no recognizable CSRF token field"
                + " -- confirm it rides a cookie and has no custom-header/SameSite=Strict defence",
                url, "csrf|" + url + "|" + (action || idx));
        }
    } catch (e) {
        nullock.log("hallpass: " + (e && e.message ? e.message : String(e)));
    }
    return entry;
});

nullock.log("hallpass: loaded (passive anti-CSRF token auditor)");

})();
