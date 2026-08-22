// identity_rotate.js -- per-request identity rotation.
//
// nullock:permissions modify-requests
// nullock:version 0.1.0
//
// Rotates User-Agent, Accept-Language, Sec-CH-UA, and a handful of
// other browser-fingerprint headers across a pool of realistic
// browsers. Useful for testing apps that key on user identity for
// rate-limiting, A/B-bucket assignment, or bot detection.
//
// Caveat: this is HTTP-level rotation only. JA3 / JA4 (TLS handshake
// fingerprint) is unchanged; Qt's QSslSocket doesn't expose enough
// to reorder TLS extensions and SChannel ignores the order anyway.
// A WAF that fingerprints TLS will still see a "Qt-shaped" handshake.
// That's a fundamental architectural limit -- a real fix would
// require swapping the outbound TLS stack to something like utls.

(function() {
'use strict';

// Curated pool. Picks were grabbed from recent Chrome/Firefox/Safari
// releases. Don't add anything older than 6 months: WAFs flag stale UAs.
var PROFILES = [
    {
        ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        secChUa: '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
        secChUaMobile: "?0",
        secChUaPlatform: '"Windows"',
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        acceptLang: "en-US,en;q=0.9",
    },
    {
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        secChUa: '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
        secChUaMobile: "?0",
        secChUaPlatform: '"macOS"',
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        acceptLang: "en-US,en;q=0.9",
    },
    {
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:131.0) Gecko/20100101 Firefox/131.0",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        acceptLang: "en-US,en;q=0.5",
    },
    {
        ua: "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        acceptLang: "en-US,en;q=0.5",
    },
    {
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        acceptLang: "en-US,en;q=0.9",
    },
    {
        ua: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        acceptLang: "en-US,en;q=0.9",
    },
];

// Sticky per-host: requests to the same host get the same identity until
// the user explicitly rotates. Otherwise a single browsing session looks
// schizophrenic to the target.
var STICKY = {};

function pickFor(host) {
    if (STICKY[host]) return STICKY[host];
    var p = PROFILES[Math.floor(Math.random() * PROFILES.length)];
    STICKY[host] = p;
    return p;
}

function setHeader(headers, name, val) {
    var nameLow = name.toLowerCase();
    for (var i = 0; i < headers.length; i++) {
        if (headers[i][0].toLowerCase() === nameLow) {
            headers[i][1] = val;
            return;
        }
    }
    headers.push([name, val]);
}

function dropHeader(headers, name) {
    var nameLow = name.toLowerCase();
    for (var i = headers.length - 1; i >= 0; i--) {
        if (headers[i][0].toLowerCase() === nameLow) headers.splice(i, 1);
    }
}

nullock.onRequest(function(req) {
    try {
        var prof = pickFor(req.host);
        setHeader(req.headers, "User-Agent", prof.ua);
        setHeader(req.headers, "Accept", prof.accept);
        setHeader(req.headers, "Accept-Language", prof.acceptLang);
        // Chromium-only client hints. For Firefox/Safari we drop them
        // entirely so the request looks consistent.
        if (prof.secChUa) {
            setHeader(req.headers, "Sec-CH-UA", prof.secChUa);
            setHeader(req.headers, "Sec-CH-UA-Mobile", prof.secChUaMobile);
            setHeader(req.headers, "Sec-CH-UA-Platform", prof.secChUaPlatform);
        } else {
            dropHeader(req.headers, "Sec-CH-UA");
            dropHeader(req.headers, "Sec-CH-UA-Mobile");
            dropHeader(req.headers, "Sec-CH-UA-Platform");
        }
        return req;
    } catch (e) {
        nullock.log("identity_rotate: " + (e && e.message ? e.message : String(e)));
        return req;
    }
});

// Optional hook: user can call from the console to drop the sticky
// bag and re-roll identities on the next request.
nullock.resetIdentityPool = function() {
    STICKY = {};
    nullock.log("identity_rotate: sticky pool reset");
};

nullock.log("identity_rotate: loaded (" + PROFILES.length + " profiles, sticky per host)");

})();
