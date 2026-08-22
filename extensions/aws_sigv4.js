// aws_sigv4.js -- AWS SigV4 request signer.
//
// nullock:permissions modify-requests
// nullock:version 0.1.0
//
// Hooks the request-mutation pipeline. Any request whose host ends with
// ".amazonaws.com" (configurable) gets signed with AWS Signature v4
// using credentials read from a project config object.
//
// SETUP: tell Nullock your AWS credentials by setting these via the
// session-rules variable bag (one-time per engagement):
//
//     nullock session-rules ... extract... variable=aws_access_key value=AKIA...
//     nullock session-rules ... extract... variable=aws_secret_key value=...
//     nullock session-rules ... extract... variable=aws_region     value=us-east-1
//     (optional) variable=aws_session_token  value=... for STS / SSO creds
//
// Or hard-code below for quick local testing. NEVER commit real creds.
//
// This implementation has no external dependencies -- SHA256 and HMAC
// are inlined because QJSEngine doesn't ship Web Crypto.
//
// References:
//   https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
//   https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

(function() {
'use strict';

// ---- credentials (override at runtime, or leave blank to skip) -------
var CONFIG = {
    accessKey:    "",
    secretKey:    "",
    sessionToken: "",
    region:       "us-east-1",
    service:      "",   // auto-detect from host if empty (e.g. s3, ec2, lambda)
    hostSuffix:   ".amazonaws.com",
};

// ---- SHA256 (FIPS 180-4) ----------------------------------------------
var K256 = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
];
function ror(x,n){ return ((x>>>n) | (x<<(32-n))) >>> 0; }
function sha256bytes(bytes) {
    // bytes: Uint8Array-like
    var L = bytes.length;
    var withOne = new Array(L + 1);
    for (var i = 0; i < L; i++) withOne[i] = bytes[i];
    withOne[L] = 0x80;
    while (withOne.length % 64 !== 56) withOne.push(0);
    var bitLen = L * 8;
    for (var i = 0; i < 4; i++) withOne.push(0);
    withOne.push((bitLen >>> 24) & 0xff);
    withOne.push((bitLen >>> 16) & 0xff);
    withOne.push((bitLen >>> 8) & 0xff);
    withOne.push(bitLen & 0xff);
    var H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
             0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    for (var blk = 0; blk < withOne.length; blk += 64) {
        var w = new Array(64);
        for (var t = 0; t < 16; t++) {
            w[t] = (withOne[blk+t*4]<<24)|(withOne[blk+t*4+1]<<16)
                 | (withOne[blk+t*4+2]<<8)|withOne[blk+t*4+3];
            w[t] >>>= 0;
        }
        for (var t = 16; t < 64; t++) {
            var s0 = ror(w[t-15],7)^ror(w[t-15],18)^(w[t-15]>>>3);
            var s1 = ror(w[t-2],17)^ror(w[t-2],19)^(w[t-2]>>>10);
            w[t] = (w[t-16] + s0 + w[t-7] + s1) >>> 0;
        }
        var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
        for (var t = 0; t < 64; t++) {
            var S1 = ror(e,6)^ror(e,11)^ror(e,25);
            var ch = (e & f) ^ ((~e) & g);
            var t1 = (h + S1 + ch + K256[t] + w[t]) >>> 0;
            var S0 = ror(a,2)^ror(a,13)^ror(a,22);
            var mj = (a & b) ^ (a & c) ^ (b & c);
            var t2 = (S0 + mj) >>> 0;
            h = g; g = f; f = e; e = (d + t1) >>> 0;
            d = c; c = b; b = a; a = (t1 + t2) >>> 0;
        }
        H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
        H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
    }
    var out = [];
    for (var i = 0; i < 8; i++) {
        out.push((H[i]>>>24)&0xff); out.push((H[i]>>>16)&0xff);
        out.push((H[i]>>>8)&0xff);  out.push(H[i]&0xff);
    }
    return out;
}
function strToBytes(s) {
    // UTF-8 encode.
    var out = [];
    for (var i = 0; i < s.length; i++) {
        var c = s.charCodeAt(i);
        if (c < 0x80) out.push(c);
        else if (c < 0x800) { out.push(0xc0|(c>>6)); out.push(0x80|(c&0x3f)); }
        else if ((c & 0xfc00) === 0xd800) {
            var c2 = s.charCodeAt(++i);
            var cp = 0x10000 + (((c & 0x3ff) << 10) | (c2 & 0x3ff));
            out.push(0xf0|(cp>>18)); out.push(0x80|((cp>>12)&0x3f));
            out.push(0x80|((cp>>6)&0x3f)); out.push(0x80|(cp&0x3f));
        } else {
            out.push(0xe0|(c>>12)); out.push(0x80|((c>>6)&0x3f));
            out.push(0x80|(c&0x3f));
        }
    }
    return out;
}
function bytesToHex(b) {
    var h = "";
    for (var i = 0; i < b.length; i++) {
        var x = b[i].toString(16); if (x.length < 2) x = "0" + x;
        h += x;
    }
    return h;
}
function sha256hex(s) { return bytesToHex(sha256bytes(strToBytes(s))); }
function hmacSha256(key, msg) {
    // key: byte array, msg: byte array.
    if (key.length > 64) key = sha256bytes(key);
    while (key.length < 64) key.push(0);
    var oKeyPad = new Array(64), iKeyPad = new Array(64);
    for (var i = 0; i < 64; i++) { oKeyPad[i] = key[i] ^ 0x5c; iKeyPad[i] = key[i] ^ 0x36; }
    var inner = sha256bytes(iKeyPad.concat(msg));
    return sha256bytes(oKeyPad.concat(inner));
}

// ---- SigV4 -----------------------------------------------------------
function detectService(host) {
    // s3.amazonaws.com, s3-us-east-1.amazonaws.com -> s3
    // bucket.s3.amazonaws.com -> s3
    // dynamodb.us-east-1.amazonaws.com -> dynamodb
    // lambda.us-east-1.amazonaws.com -> lambda
    var stripped = host.toLowerCase();
    var parts = stripped.split(".");
    for (var i = 0; i < parts.length; i++) {
        if (parts[i].indexOf("amazonaws") >= 0) {
            // Walk back: typical shape "<service>.<region>.amazonaws.com"
            // or "<service>-<region>.amazonaws.com" or just "<service>.amazonaws.com"
            if (i >= 2) return parts[i-2].split("-")[0];
            if (i >= 1) return parts[i-1].split("-")[0];
        }
    }
    return "execute-api";  // safe fallback (api-gateway)
}

function isoDate(d) {
    // 20240115T142500Z
    function pad(n){ return (n<10?"0":"")+n; }
    return d.getUTCFullYear()
         + pad(d.getUTCMonth()+1)
         + pad(d.getUTCDate()) + "T"
         + pad(d.getUTCHours())
         + pad(d.getUTCMinutes())
         + pad(d.getUTCSeconds()) + "Z";
}

function uriEncode(s, encodeSlash) {
    var out = "";
    for (var i = 0; i < s.length; i++) {
        var c = s[i];
        var code = s.charCodeAt(i);
        if ((c >= "A" && c <= "Z") || (c >= "a" && c <= "z") ||
            (c >= "0" && c <= "9") ||
            c === "-" || c === "_" || c === "." || c === "~") {
            out += c;
        } else if (c === "/" && !encodeSlash) {
            out += "/";
        } else {
            // percent-encode UTF-8 bytes
            var bs = strToBytes(c);
            for (var j = 0; j < bs.length; j++) {
                var h = bs[j].toString(16).toUpperCase();
                if (h.length < 2) h = "0" + h;
                out += "%" + h;
            }
        }
    }
    return out;
}

function signRequest(req, now) {
    if (!CONFIG.accessKey || !CONFIG.secretKey) return req;
    var host = req.host || "";
    if (host.indexOf(CONFIG.hostSuffix) < 0) return req;

    var service = CONFIG.service || detectService(host);
    var amzDate = isoDate(now);
    var dateStamp = amzDate.substring(0, 8);

    // Canonical request.
    var method = req.method.toUpperCase();
    var pathOnly = req.path;
    var queryStr = "";
    var qIdx = pathOnly.indexOf("?");
    if (qIdx >= 0) {
        queryStr = pathOnly.substring(qIdx + 1);
        pathOnly = pathOnly.substring(0, qIdx);
    }
    var canonicalUri = uriEncode(pathOnly || "/", false);

    // Canonical query: sort by key, encode both.
    var qpairs = [];
    if (queryStr.length) {
        var raw = queryStr.split("&");
        for (var i = 0; i < raw.length; i++) {
            var eq = raw[i].indexOf("=");
            var k = eq >= 0 ? raw[i].substring(0, eq) : raw[i];
            var v = eq >= 0 ? raw[i].substring(eq + 1) : "";
            qpairs.push([decodeURIComponent(k), decodeURIComponent(v)]);
        }
        qpairs.sort(function(a, b){ return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0; });
    }
    var canonicalQuery = qpairs.map(function(p){
        return uriEncode(p[0], true) + "=" + uriEncode(p[1], true);
    }).join("&");

    // Canonical headers.
    // Force-set Host + X-Amz-Date + (optional) X-Amz-Security-Token.
    var headerMap = {};
    for (var i = 0; i < req.headers.length; i++) {
        var h = req.headers[i];
        headerMap[h[0].toLowerCase()] = (h[1] || "").trim();
    }
    headerMap["host"]         = host;
    headerMap["x-amz-date"]   = amzDate;
    if (CONFIG.sessionToken)
        headerMap["x-amz-security-token"] = CONFIG.sessionToken;

    // Payload hash (body).
    var body = req.body || "";
    // body may be a QByteArray-like; Convert to string.
    if (typeof body !== "string") {
        try { body = String(body); } catch (_e) { body = ""; }
    }
    var payloadHash = sha256hex(body);
    headerMap["x-amz-content-sha256"] = payloadHash;

    var headerNames = Object.keys(headerMap).sort();
    var canonicalHeaders = "";
    for (var i = 0; i < headerNames.length; i++) {
        canonicalHeaders += headerNames[i] + ":" + headerMap[headerNames[i]] + "\n";
    }
    var signedHeaders = headerNames.join(";");

    var canonicalRequest = [
        method,
        canonicalUri,
        canonicalQuery,
        canonicalHeaders,
        signedHeaders,
        payloadHash,
    ].join("\n");

    var credScope = dateStamp + "/" + CONFIG.region + "/" + service + "/aws4_request";
    var stringToSign = [
        "AWS4-HMAC-SHA256",
        amzDate,
        credScope,
        sha256hex(canonicalRequest),
    ].join("\n");

    var kDate    = hmacSha256(strToBytes("AWS4" + CONFIG.secretKey), strToBytes(dateStamp));
    var kRegion  = hmacSha256(kDate,    strToBytes(CONFIG.region));
    var kService = hmacSha256(kRegion,  strToBytes(service));
    var kSigning = hmacSha256(kService, strToBytes("aws4_request"));
    var signature = bytesToHex(hmacSha256(kSigning, strToBytes(stringToSign)));

    var auth = "AWS4-HMAC-SHA256 Credential=" + CONFIG.accessKey + "/" + credScope
             + ", SignedHeaders=" + signedHeaders
             + ", Signature=" + signature;

    // Mutate req.headers: drop any existing Authorization / X-Amz-Date,
    // then re-append the signed set.
    var out = [];
    var dropNames = ["authorization", "x-amz-date", "x-amz-security-token",
                     "x-amz-content-sha256"];
    for (var i = 0; i < req.headers.length; i++) {
        if (dropNames.indexOf(req.headers[i][0].toLowerCase()) < 0)
            out.push(req.headers[i]);
    }
    out.push(["Host", host]);
    out.push(["X-Amz-Date", amzDate]);
    out.push(["X-Amz-Content-Sha256", payloadHash]);
    if (CONFIG.sessionToken)
        out.push(["X-Amz-Security-Token", CONFIG.sessionToken]);
    out.push(["Authorization", auth]);

    req.headers = out;
    return req;
}

// Nullock extension hook: called for every captured request before it
// goes to the wire. Returning a mutated request swaps it in; returning
// false / nothing leaves the original alone.
nullock.onRequest(function(req) {
    try {
        return signRequest(req, new Date());
    } catch (e) {
        nullock.log("aws_sigv4: " + (e && e.message ? e.message : String(e)));
        return req;
    }
});

nullock.log("aws_sigv4: loaded (signing hosts ending in " + CONFIG.hostSuffix + ")");

})();
