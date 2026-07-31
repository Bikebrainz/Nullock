// ouchie.js -- catches the app saying "ouch" out loud.
//
// Verbose errors are a gift to an attacker: framework stack traces leak
// internal file paths, library versions, SQL, and sometimes source; an
// interactive debugger page (Werkzeug console, Symfony/Whoops) can be an
// outright RCE. Nullock natively flags SQL-error and TRACE/debug-method
// cases, but not the broad "the server dumped a stack trace / debug page"
// class -- so that's what this adds.
//
// Observe-only: onResponse over text/HTML bodies, no permission.
//
// Tiers:
//   - high   : an INTERACTIVE debugger is exposed (Werkzeug debugger pin
//              console, Symfony/Whoops, Rails web-console) -- often RCE.
//   - medium : a framework stack trace / debug error page leaked internals
//              (Java, .NET yellow-screen, Django DEBUG, PHP fatal + path,
//              Ruby trace, Node trace, Spring Whitelabel with trace).
//
// Limits: signature-based over the 64 KiB preview. A page that merely says
// "error" without a trace won't (and shouldn't) fire. Framework detection is
// best-effort; the evidence snippet names what tripped it.

(function() {
'use strict';

function headerVal(headers, name) {
    if (!headers) return "";
    var low = name.toLowerCase();
    for (var i = 0; i < headers.length; i++)
        if (headers[i][0] && headers[i][0].toLowerCase() === low) return headers[i][1] || "";
    return "";
}

var seen = {};
function report(sev, kind, summary, evidence, url, key) {
    if (seen[key]) return; seen[key] = 1;
    try { nullock.reportFinding(sev, kind, summary, evidence, url); }
    catch (e) { nullock.log("ouchie report failed: " + e); }
}

// Interactive debuggers -- highest value, treat as high.
var DEBUGGERS = [
    { re: /Werkzeug Debugger|The debugger caught an exception|__debugger__|\?__debugger__=yes/, name: "Werkzeug interactive debugger" },
    { re: /Whoops, looks like something went wrong|Whoops\\Run|class="Whoops|frames-container/, name: "Whoops / Symfony debug page" },
    { re: /web-console|Rails\.application\.config\.web_console|console-plugin/, name: "Rails web-console" },
];

// Framework stack traces / debug pages -- medium.
var TRACES = [
    { re: /Traceback \(most recent call last\)/, name: "Python traceback" },
    { re: /You(?:'|&#39;)re seeing this error because you have\s+DEBUG\s*=\s*True|django\.core\.exceptions|at django\./i, name: "Django DEBUG error page" },
    { re: /\bat (?:java|javax|com|org)\.[\w.$]+\([\w$]+\.java:\d+\)/, name: "Java stack trace" },
    { re: /Exception in thread \"|caused by:.*Exception/i, name: "Java exception dump" },
    { re: /org\.springframework[\w.]*Exception|Whitelabel Error Page/, name: "Spring error" },
    { re: /Server Error in '\/?' Application|\[[A-Za-z]*Exception:|Microsoft\.[\w.]+Exception|System\.[\w.]+Exception:/, name: ".NET / ASP.NET error" },
    { re: /at [\w.<>$]+ in [A-Za-z]:\\[^\n]+:line \d+/, name: ".NET stack trace" },
    { re: /(?:Fatal error|Parse error|Warning|Notice)\s*:\s*.+ in \/?[\w./-]+\.php on line \d+/i, name: "PHP error with path" },
    { re: /#\d+ \/[\w./-]+\(\d+\):|Stack trace:\s*#0/, name: "PHP stack trace" },
    { re: /(?:app\/controllers\/|\/gems\/|activerecord|actionpack)[\w./-]*\.rb:\d+/, name: "Ruby / Rails trace" },
    { re: /\bat (?:Object\.|Module\.|Function\.)?[\w.<>$]*\s*\(?[\w./-]*node_modules[\w./-]+:\d+:\d+\)?/, name: "Node.js stack trace" },
    { re: /goroutine \d+ \[[^\]]+\]:|panic: .+\n\s+\/[\w./-]+\.go:\d+/, name: "Go panic trace" },
];

nullock.onResponse(function(entry) {
    try {
        var ct = headerVal(entry.headers, "Content-Type").toLowerCase();
        // Only meaningful for text-ish bodies.
        if (ct && !/text|html|json|xml|plain/.test(ct)) return entry;
        var body = entry.bodyText || entry.bodyPreview || "";
        if (!body || body.length < 24) return entry;
        var url = entry.url || "";
        var i;

        for (i = 0; i < DEBUGGERS.length; i++) {
            if (DEBUGGERS[i].re.test(body)) {
                report("high", "debug-console-exposed",
                    "Interactive debugger exposed (" + DEBUGGERS[i].name + ") -- typically leads to RCE",
                    DEBUGGERS[i].name + " markers in response body", url, "dbg|" + url + "|" + i);
                return entry; // one is plenty
            }
        }
        for (i = 0; i < TRACES.length; i++) {
            if (TRACES[i].re.test(body)) {
                report("medium", "verbose-error-disclosure",
                    "Verbose error / stack trace disclosed (" + TRACES[i].name + ") -- leaks paths, versions, internals",
                    TRACES[i].name + " matched in response body", url, "trace|" + url + "|" + i);
                return entry;
            }
        }
    } catch (e) {
        nullock.log("ouchie: " + (e && e.message ? e.message : String(e)));
    }
    return entry;
});

nullock.log("ouchie: loaded (" + (DEBUGGERS.length + TRACES.length) + " error/debug signatures)");

})();
