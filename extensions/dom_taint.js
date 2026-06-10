// dom_taint.js -- static DOM-XSS taint analysis on served HTML/JS.
//
// Burp Pro's DOM Invader runs *inside* the browser and instruments the
// live DOM at runtime. Nullock is a proxy, so we can't hook the page --
// but every script the app serves passes through us, and we can analyse
// it statically. This extension does source -> sink taint matching on
// each HTML/JS response and emits findings when attacker-controllable
// input can reach a dangerous sink.
//
// Beyond naive co-occurrence, we do ONE-HOP dataflow: if a source is
// assigned into a variable (`var h = location.hash`) and that variable
// then reaches a sink (`el.innerHTML = h`), we connect them and report
// the *original* source -- not whatever token happened to sit nearest
// the sink. Two propagation passes catch `y = x` chains as well.
//
// What this catches:
//   - innerHTML / outerHTML / document.write / insertAdjacentHTML fed
//     (directly or via a 1-2 hop variable) from location.* /
//     document.referrer / window.name / postMessage / web-storage
//   - eval / Function / setTimeout(string) fed from the same
//   - location assignment / element.src (DOM open-redirect) from a source
//
// Honest limits of static analysis:
//   - Taint through 3+ variable hops, function params, or object props
//     is not followed (we do shallow, single-statement dataflow)
//   - Sinks reached only via dynamically built code aren't seen
//   - Anything past the 64 KiB body preview the proxy hands us
// Treat findings as leads to confirm in a browser, like Burp's DOM hints.

(function() {
'use strict';

// ---- source / sink vocabularies ---------------------------------------
// Sources: values an attacker can influence without touching the server.
// `re` is used global (offset scan) and reset before each .test().
var SOURCES = [
    { re: /location\s*\.\s*(?:href|search|hash|pathname|host|hostname)/g, name: "location.*" },
    { re: /document\s*\.\s*(?:URL|documentURI|baseURI)/g,                name: "document.URL" },
    { re: /document\s*\.\s*referrer/g,                                   name: "document.referrer" },
    { re: /\bwindow\s*\.\s*name\b/g,                                     name: "window.name" },
    { re: /document\s*\.\s*cookie/g,                                     name: "document.cookie" },
    { re: /\.(?:getItem)\s*\(/g,                                         name: "web-storage" },
    { re: /\baddEventListener\s*\(\s*['"]message['"]/g,                  name: "postMessage" },
    { re: /\bonmessage\b/g,                                              name: "postMessage" },
    // Bare `location` last so the qualified forms above win attribution.
    { re: /\blocation\b(?!\s*\.\s*(?:protocol|origin)\b)/g,              name: "location" },
];

// Sinks: APIs that execute code or inject markup. The capture after the
// sink token (RHS of `=`, or call arguments) is the tainted region.
var SINKS = [
    { re: /\.\s*innerHTML\s*=/g,                 name: "innerHTML",          cls: "html" },
    { re: /\.\s*outerHTML\s*=/g,                 name: "outerHTML",          cls: "html" },
    { re: /\.\s*insertAdjacentHTML\s*\(/g,       name: "insertAdjacentHTML", cls: "html" },
    { re: /document\s*\.\s*write(?:ln)?\s*\(/g,  name: "document.write",     cls: "html" },
    { re: /\.\s*html\s*\(/g,                      name: "jQuery.html",        cls: "html" },
    { re: /\bcreateContextualFragment\s*\(/g,    name: "createContextualFragment", cls: "html" },
    { re: /\beval\s*\(/g,                         name: "eval",               cls: "code" },
    { re: /\bnew\s+Function\s*\(/g,              name: "Function",           cls: "code" },
    { re: /\bsetTimeout\s*\(/g,                   name: "setTimeout",         cls: "code" },
    { re: /\bsetInterval\s*\(/g,                  name: "setInterval",        cls: "code" },
    { re: /location\s*\.\s*(?:href|assign|replace)\s*[=(]/g, name: "location-nav", cls: "nav" },
    { re: /\.\s*src\s*=/g,                         name: "element.src",        cls: "nav" },
];

var CLASS_META = {
    html: { sev: "high",   label: "DOM-based XSS (markup sink)" },
    code: { sev: "high",   label: "DOM-based code injection" },
    nav:  { sev: "medium", label: "DOM-based open redirect / src injection" },
};

// Bounded de-dup so a reloaded page doesn't re-report the same flow.
var seen = {};
var SEEN_CAP = 5000;
function alreadyReported(key) {
    if (seen[key]) return true;
    seen[key] = 1;
    var n = 0; for (var k in seen) { if (++n > SEEN_CAP) { seen = {}; break; } }
    return false;
}

// ---- helpers -----------------------------------------------------------
function headerVal(headers, name) {
    if (!headers) return "";
    var low = name.toLowerCase();
    for (var i = 0; i < headers.length; i++) {
        if (headers[i][0] && headers[i][0].toLowerCase() === low)
            return headers[i][1] || "";
    }
    return "";
}

// Returns the source name if `text` contains any source token, else "".
function sourceIn(text) {
    for (var s = 0; s < SOURCES.length; s++) {
        SOURCES[s].re.lastIndex = 0;
        if (SOURCES[s].re.test(text)) return SOURCES[s].name;
    }
    return "";
}

// Returns the origin-source name if `text` references any tainted var.
function taintedVarIn(text, taint) {
    for (var v in taint) {
        // word-boundary match so `h` doesn't match `height`
        var re = new RegExp("(?:^|[^\\w$])" + v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "(?:[^\\w$]|$)");
        if (re.test(text)) return taint[v];
    }
    return "";
}

// The tainted region for a sink at `idx`: everything from the sink token
// to the end of its statement (next ; or newline or block close), capped.
function sinkRegion(code, afterIdx) {
    var end = code.length;
    for (var i = afterIdx; i < code.length && i < afterIdx + 300; i++) {
        var ch = code[i];
        if (ch === ';' || ch === '\n' || ch === '}') { end = i; break; }
    }
    return code.substring(afterIdx, Math.min(end, afterIdx + 300));
}

// Collect variables assigned (directly or transitively) from a source.
// taint[varName] = originSourceName. Two passes to catch `y = x` chains.
function collectTaint(code) {
    var taint = {};
    var assignRe = /(?:\bvar\b|\blet\b|\bconst\b)?\s*([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{0,240})/g;
    for (var pass = 0; pass < 2; pass++) {
        assignRe.lastIndex = 0;
        var m;
        while ((m = assignRe.exec(code)) !== null) {
            var lhs = m[1], rhs = m[2];
            if (taint[lhs]) continue;
            var src = sourceIn(rhs);
            if (src) { taint[lhs] = src; continue; }
            if (pass > 0) {
                var via = taintedVarIn(rhs, taint);
                if (via) taint[lhs] = via;
            }
        }
    }
    return taint;
}

function offsets(re, code) {
    re.lastIndex = 0;
    var out = [], m;
    while ((m = re.exec(code)) !== null) {
        out.push(re.lastIndex);   // position AFTER the sink token
        if (re.lastIndex === m.index) re.lastIndex++;
    }
    return out;
}

function snippet(code, idx) {
    var a = Math.max(0, idx - 50), b = Math.min(code.length, idx + 90);
    return code.substring(a, b).replace(/\s+/g, " ").substring(0, 200);
}

// ---- script context extraction ----------------------------------------
function scriptContexts(body, contentType, url) {
    var ct = (contentType || "").toLowerCase();
    var isJs = ct.indexOf("javascript") >= 0 || ct.indexOf("ecmascript") >= 0
            || /\.m?js(\?|$)/i.test(url);
    if (isJs) return [{ code: body, where: "script body" }];

    var isHtml = ct.indexOf("html") >= 0 || /<html|<!doctype/i.test(body);
    if (!isHtml) return [];

    var ctxs = [];
    var re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi, m;
    while ((m = re.exec(body)) !== null) {
        if (/\bsrc\s*=/i.test(m[1])) continue;   // external; analysed when fetched
        if (m[2] && m[2].trim().length) ctxs.push({ code: m[2], where: "inline <script>" });
    }
    var reAttr = /\bon[a-z]+\s*=\s*("(?:[^"]*)"|'(?:[^']*)')/gi;
    while ((m = reAttr.exec(body)) !== null) {
        ctxs.push({ code: m[1], where: "inline event-handler" });
    }
    return ctxs;
}

// ---- main pass ---------------------------------------------------------
function analyse(entry) {
    var body = entry.bodyText || entry.bodyPreview || "";
    if (!body) return;
    var url = entry.url || "";
    var ct = headerVal(entry.headers, "Content-Type");

    var contexts = scriptContexts(body, ct, url);
    for (var c = 0; c < contexts.length; c++) {
        var code = contexts[c].code, where = contexts[c].where;
        var taint = collectTaint(code);

        for (var k = 0; k < SINKS.length; k++) {
            var sink = SINKS[k];
            var ends = offsets(sink.re, code);
            for (var j = 0; j < ends.length; j++) {
                var region = sinkRegion(code, ends[j]);

                // Direct source in the sink's own expression -> high
                // confidence. Else a tainted variable reaching it -> still
                // a real flow, attribute to the variable's origin source.
                var src = sourceIn(region);
                var direct = !!src;
                if (!src) src = taintedVarIn(region, taint);
                if (!src) continue;   // no taint reaches this sink; skip

                var meta = CLASS_META[sink.cls];
                var sev = (sink.cls === "nav" && !direct) ? "medium"
                        : (sink.cls === "nav") ? "medium" : "high";

                var key = url + "|" + sink.name + "|" + src + "|" + where;
                if (alreadyReported(key)) continue;

                var summary = meta.label + ": " + src + " -> " + sink.name
                            + (direct ? "" : " (via variable)");
                var evidence = "[" + where + "] " + snippet(code, ends[j]);
                try {
                    nullock.reportFinding(sev, "dom-taint-" + sink.cls,
                                          summary, evidence, url);
                } catch (e) {
                    nullock.log("dom_taint report failed: " + e);
                }
            }
        }
    }
}

nullock.onResponse(function(entry) {
    try { analyse(entry); }
    catch (e) {
        nullock.log("dom_taint: " + (e && e.message ? e.message : String(e)));
    }
    return entry;   // read-only; we never mutate
});

nullock.log("dom_taint: loaded (" + SOURCES.length + " sources, "
            + SINKS.length + " sinks, one-hop dataflow)");

})();
