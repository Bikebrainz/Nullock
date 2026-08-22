// peep.js -- decorate outbound traffic with OAST canaries.
//
// nullock:permissions modify-requests
// nullock:version 0.1.0
//
// A port of James Kettle's "Collaborator Everywhere" (PortSwigger's own
// flagship BApp). The idea: a lot of blind server-side vulnerabilities --
// SSRF, blind XXE, misrouted proxies, analytics that re-fetch a Referer,
// password-reset links built from a Host header -- only reveal themselves
// when the server reaches back out to a URL you planted. So plant one in
// every request, in the headers servers are most likely to trust and act
// on, and watch your OAST sink for the callbacks.
//
// Nullock ships its own OAST server + correlator (the half of Collaborator
// that's actually worth money -- see Src/Core/APIs/Oast). This extension is
// the *injection* half: it appends `<token>.<yourOastDomain>` into a curated
// set of "the server tends to trust this" headers on matching requests, and
// logs each injection so you can line callbacks up against the host you hit.
//
// SETUP -- required, and it is a DEFAULT-OFF no-op until you do it:
//   1. Stand up the OAST sink (see DEPLOY_OAST.md) and note its domain.
//   2. Put that domain in CONFIG.oastDomain below.
//   3. Optionally scope CONFIG.onlyHosts so you don't decorate every host
//      you browse -- injecting canaries into third-party traffic is noisy
//      and, on targets you're not authorised to test, out of scope.
//   4. Browse / scan as normal; poll the OAST sink (/api/oast/poll) for hits.
//
// Correlation note: because the sandbox can't call the C++ correlator's
// registerToken() directly, a callback shows up as a raw OAST hit rather
// than an auto-linked "confirmed" finding. The per-injection log line
// (host + token + header) is what you match it against. Exposing an
// `nullock.oastMint(context)` bridge call would make these first-class --
// a good candidate for the JS-bridge work.
//
// Safety: injection only rewrites request headers (never the body or
// method), only fires when oastDomain is set, respects onlyHosts, and skips
// hosts that ARE your OAST domain so canaries never chase their own tail.

(function() {
'use strict';

var CONFIG = {
    // Your OAST sink's domain, e.g. "oast.mytunnel.example". BLANK => disabled.
    oastDomain: "",

    // Only decorate requests to these hosts (exact or *.suffix). Empty =>
    // every host except the OAST domain itself. Keep this tight in the wild.
    onlyHosts: [],

    // Headers to plant a canary in. These are the classic "server re-uses
    // this to make a decision or a request" set. Value-carrying headers
    // (Referer / X-Forwarded-Host) embed a full https:// URL; IP-shaped
    // headers get the bare hostname so they still parse as a host.
    urlHeaders: ["Referer", "X-Forwarded-Host", "X-Host", "X-Forwarded-Server",
                 "X-Original-URL", "X-Rewrite-URL", "Origin"],
    hostHeaders: ["X-Forwarded-For", "True-Client-IP", "X-Client-IP",
                  "X-Real-IP", "Forwarded", "CF-Connecting-IP"],

    // Cap injections/host so a long crawl doesn't spray thousands of tokens.
    maxPerHost: 40,
};

var perHostCount = {};

function hostMatches(host) {
    if (!CONFIG.onlyHosts.length) return true;
    for (var i = 0; i < CONFIG.onlyHosts.length; i++) {
        var rule = CONFIG.onlyHosts[i].toLowerCase();
        if (rule.charAt(0) === "*" && rule.charAt(1) === ".") {
            var suf = rule.substring(1); // ".example.com"
            if (host === rule.substring(2) || host.slice(-suf.length) === suf) return true;
        } else if (host === rule) {
            return true;
        }
    }
    return false;
}

// A short, unique-ish, DNS-label-safe token. Not crypto-strong -- it only
// needs to be collision-resistant enough to tell two callbacks apart.
function mintToken(host) {
    var t = "";
    while (t.length < 12) t += Math.floor(Math.random() * 36).toString(36);
    t = t.substring(0, 12);
    // Fold a hint of the host in so a raw OAST hit is easier to eyeball.
    var tag = host.replace(/[^a-z0-9]/gi, "").toLowerCase().substring(0, 8);
    return (tag ? tag + "-" : "") + t;
}

function setHeader(headers, name, val) {
    var low = name.toLowerCase();
    for (var i = 0; i < headers.length; i++)
        if (headers[i][0].toLowerCase() === low) { headers[i][1] = val; return; }
    headers.push([name, val]);
}

nullock.onRequest(function(req) {
    try {
        if (!CONFIG.oastDomain) return req;                 // disabled
        var host = (req.host || "").toLowerCase();
        if (!host || host === CONFIG.oastDomain.toLowerCase()) return req;
        if (host.slice(-CONFIG.oastDomain.length) === CONFIG.oastDomain.toLowerCase()) return req;
        if (!hostMatches(host)) return req;
        if ((perHostCount[host] || 0) >= CONFIG.maxPerHost) return req;

        var token = mintToken(host);
        var fqdn = token + "." + CONFIG.oastDomain;

        var i;
        for (i = 0; i < CONFIG.urlHeaders.length; i++)
            setHeader(req.headers, CONFIG.urlHeaders[i], "https://" + fqdn + "/");
        for (i = 0; i < CONFIG.hostHeaders.length; i++)
            setHeader(req.headers, CONFIG.hostHeaders[i], fqdn);

        perHostCount[host] = (perHostCount[host] || 0) + 1;
        nullock.log("peep: " + host + " <= " + fqdn
                    + " (" + (req.method || "?") + " " + (req.path || "/") + ")");
        return req;
    } catch (e) {
        nullock.log("peep: " + (e && e.message ? e.message : String(e)));
        return req;
    }
});

// Console helper: forget the per-host budget and re-arm injection.
nullock.resetPeep = function() {
    perHostCount = {};
    nullock.log("peep: per-host injection budget reset");
};

nullock.log(CONFIG.oastDomain
    ? "peep: loaded (planting canaries under ." + CONFIG.oastDomain + ")"
    : "peep: loaded but DISABLED (set CONFIG.oastDomain to arm)");

})();
