// sniffy.js -- a nose for interesting data in responses (HaE-style).
//
// Highlighter-and-Extractor's whole idea is a user-editable rule list that
// tags interesting strings as they fly past -- PII, custom markers, whatever
// this engagement cares about. Nullock's native scanner hunts *credentials*;
// this is the complementary "flag the sensitive DATA" pass, and it's yours to
// extend: add a rule to CONFIG.rules and it starts matching immediately.
//
// Observe-only: onResponse over text bodies, no permission.
//
// Each rule is { name, kind, severity, re, luhn? }. `re` is a RegExp; add the
// `g` flag for multi-match. Set `luhn:true` to keep only Luhn-valid matches
// (kills the credit-card false-positive flood). Matches are value-deduped and
// capped per rule per response so a contacts page doesn't emit 400 findings.
//
// Ships with sensible PII defaults; the credential/secret rules are
// intentionally NOT here (Nullock does those natively -- no double-reporting).

(function() {
'use strict';

var CONFIG = {
    perRuleCap: 5,     // max distinct matches reported per rule per response
    rules: [
        { name: "Email address",        kind: "pii-email",       severity: "info",   re: /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g },
        { name: "US SSN",               kind: "pii-ssn",         severity: "high",   re: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g },
        { name: "Credit-card PAN",      kind: "pci-pan",         severity: "high",   re: /\b(?:\d[ -]?){13,19}\b/g, luhn: true },
        { name: "US phone",             kind: "pii-phone",       severity: "info",   re: /\b(?:\+?1[ .\-]?)?\(?\d{3}\)?[ .\-]\d{3}[ .\-]\d{4}\b/g },
        { name: "Private IPv4",         kind: "internal-ipv4",   severity: "low",    re: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g },
        { name: "MAC address",          kind: "internal-mac",    severity: "low",    re: /\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b/g },
        { name: "AWS ARN",              kind: "cloud-arn",       severity: "low",    re: /\barn:aws:[a-z0-9\-]*:[a-z0-9\-]*:\d{12}:[^\s"']+/g },
        { name: "IBAN",                 kind: "pii-iban",        severity: "medium", re: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g },
    ],
};

// Luhn check (strip separators first).
function luhnOk(s) {
    var d = s.replace(/[ -]/g, "");
    if (d.length < 13 || d.length > 19 || /\D/.test(d)) return false;
    var sum = 0, alt = false;
    for (var i = d.length - 1; i >= 0; i--) {
        var n = d.charCodeAt(i) - 48;
        if (alt) { n *= 2; if (n > 9) n -= 9; }
        sum += n; alt = !alt;
    }
    return sum % 10 === 0;
}

function headerVal(headers, name) {
    if (!headers) return "";
    var low = name.toLowerCase();
    for (var i = 0; i < headers.length; i++)
        if (headers[i][0] && headers[i][0].toLowerCase() === low) return headers[i][1] || "";
    return "";
}
// Redact all but the last 4 chars so we never write the full PII into a finding.
function redact(s) {
    s = String(s);
    if (s.length <= 4) return "****";
    return s.replace(/[0-9A-Za-z]/g, "*").slice(0, -4) + s.slice(-4);
}

var seen = {};
function report(sev, kind, summary, evidence, url, key) {
    if (seen[key]) return; seen[key] = 1;
    try { nullock.reportFinding(sev, kind, summary, evidence, url); }
    catch (e) { nullock.log("sniffy report failed: " + e); }
}

nullock.onResponse(function(entry) {
    try {
        var ct = headerVal(entry.headers, "Content-Type").toLowerCase();
        if (ct && !/text|html|json|xml|plain|csv/.test(ct)) return entry;
        var body = entry.bodyText || entry.bodyPreview || "";
        if (!body) return entry;
        var url = entry.url || "";

        for (var r = 0; r < CONFIG.rules.length; r++) {
            var rule = CONFIG.rules[r];
            var re = rule.re; re.lastIndex = 0;
            var hits = {}, count = 0, m;
            while ((m = re.exec(body)) !== null) {
                var val = m[0];
                if (rule.luhn && !luhnOk(val)) { if (re.lastIndex === m.index) re.lastIndex++; continue; }
                if (!hits[val]) { hits[val] = 1; count++; }
                if (count >= 5000) break;                    // pathological guard
                if (!re.global) break;
                if (re.lastIndex === m.index) re.lastIndex++;
            }
            var vals = Object.keys(hits);
            for (var i = 0; i < vals.length && i < CONFIG.perRuleCap; i++) {
                report(rule.severity, rule.kind,
                    rule.name + " found in response body",
                    rule.name + ": " + redact(vals[i]), url,
                    "sniff|" + rule.kind + "|" + url + "|" + vals[i]);
            }
            if (vals.length > CONFIG.perRuleCap)
                nullock.log("sniffy: " + rule.name + " x" + vals.length + " on " + url
                            + " (reported first " + CONFIG.perRuleCap + ")");
        }
    } catch (e) {
        nullock.log("sniffy: " + (e && e.message ? e.message : String(e)));
    }
    return entry;
});

nullock.log("sniffy: loaded (" + CONFIG.rules.length + " data-pattern rules; edit CONFIG.rules to add your own)");

})();
