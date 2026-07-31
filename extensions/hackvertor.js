// hackvertor.js -- inline tag-based transforms on outgoing requests.
//
// nullock:permissions modify-requests
//
// A proxy-side port of Gareth Heyes' Hackvertor (one of the most-installed
// BApps). Hackvertor lets you drop <@tag>...<@/tag> markup into a request
// and have Burp substitute the encoded/hashed/generated value on the way
// out -- so you can keep a payload readable in Repeater and let the tool do
// the base64 / URL-encoding / hashing / timestamping for you.
//
// Nullock has no per-request editor tab, so we do the same thing at the
// proxy: every outgoing request's path, header VALUES and body are scanned
// for <@...@> tags and rewritten before they hit the wire. Type a tag
// anywhere you can type a request (Repeater, a crafted client, a fuzzer
// template) and it resolves.
//
// Supported tags (a faithful subset of Hackvertor's set):
//
//   Encoders (paired):   <@base64>x<@/base64>  <@b64d>x<@/b64d>
//                        <@urlenc>x<@/urlenc>  <@urldec>x<@/urldec>
//                        <@hex>x<@/hex>        <@unhex>x<@/unhex>
//                        <@htmlent>x<@/htmlent>
//   Case / order:        <@upper> <@lower> <@reverse>
//   Hashes (paired):     <@sha256>x<@/sha256>  <@sha1>x<@/sha1>
//   Generators (self-closing):
//                        <@timestamp/>    unix seconds, now
//                        <@timestamp_ms/> unix millis, now
//                        <@random(N)/>    N hex chars (default 8)
//                        <@uuid/>         random v4 UUID
//   Repeat (paired):     <@repeat(3)>ab<@/repeat>  -> ababab
//
// Tags nest: <@base64><@sha256>hunter2<@/sha256><@/base64> hashes then
// base64s the digest. Innermost tags resolve first.
//
// Honest limits: QJSEngine ships no crypto, so SHA-1/256 are inlined here
// (correct, but not constant-time -- fine for test payloads, don't build a
// production signer on it). Only the tags above are implemented; unknown
// tags are left untouched so they're visible rather than silently dropped.

(function() {
'use strict';

// ---- UTF-8 <-> byte helpers -------------------------------------------
function strToBytes(s) {
    var out = [];
    for (var i = 0; i < s.length; i++) {
        var c = s.charCodeAt(i);
        if (c < 0x80) out.push(c);
        else if (c < 0x800) { out.push(0xc0 | (c >> 6)); out.push(0x80 | (c & 0x3f)); }
        else if ((c & 0xfc00) === 0xd800) {
            var c2 = s.charCodeAt(++i);
            var cp = 0x10000 + (((c & 0x3ff) << 10) | (c2 & 0x3ff));
            out.push(0xf0 | (cp >> 18)); out.push(0x80 | ((cp >> 12) & 0x3f));
            out.push(0x80 | ((cp >> 6) & 0x3f)); out.push(0x80 | (cp & 0x3f));
        } else {
            out.push(0xe0 | (c >> 12)); out.push(0x80 | ((c >> 6) & 0x3f));
            out.push(0x80 | (c & 0x3f));
        }
    }
    return out;
}
function bytesToStr(b) {
    var s = "", i = 0;
    while (i < b.length) {
        var c = b[i++];
        if (c < 0x80) s += String.fromCharCode(c);
        else if (c >= 0xc0 && c < 0xe0) s += String.fromCharCode(((c & 0x1f) << 6) | (b[i++] & 0x3f));
        else if (c >= 0xe0 && c < 0xf0)
            s += String.fromCharCode(((c & 0x0f) << 12) | ((b[i++] & 0x3f) << 6) | (b[i++] & 0x3f));
        else {
            var cp = ((c & 0x07) << 18) | ((b[i++] & 0x3f) << 12)
                   | ((b[i++] & 0x3f) << 6) | (b[i++] & 0x3f);
            cp -= 0x10000;
            s += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff));
        }
    }
    return s;
}

// ---- base64 (no atob/btoa in QJSEngine) -------------------------------
var B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function b64encodeBytes(bytes) {
    var out = "";
    for (var i = 0; i < bytes.length; i += 3) {
        var b0 = bytes[i], b1 = i + 1 < bytes.length ? bytes[i + 1] : 0,
            b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
        out += B64[b0 >> 2];
        out += B64[((b0 & 3) << 4) | (b1 >> 4)];
        out += i + 1 < bytes.length ? B64[((b1 & 15) << 2) | (b2 >> 6)] : "=";
        out += i + 2 < bytes.length ? B64[b2 & 63] : "=";
    }
    return out;
}
function b64decodeToBytes(str) {
    // The `=` padding is stripped by the filter above, so a final group can
    // legitimately hold 2 or 3 chars; absent positions decode as 0 and are
    // NOT emitted (indexing past the string would give indexOf() -1 and
    // corrupt the last byte).
    var clean = String(str).replace(/[^A-Za-z0-9+/]/g, ""), out = [];
    for (var i = 0; i < clean.length; i += 4) {
        var e0 = B64.indexOf(clean[i]), e1 = B64.indexOf(clean[i + 1]);
        var has2 = i + 2 < clean.length, has3 = i + 3 < clean.length;
        var e2 = has2 ? B64.indexOf(clean[i + 2]) : 0;
        var e3 = has3 ? B64.indexOf(clean[i + 3]) : 0;
        var n = (e0 << 18) | (e1 << 12) | ((e2 < 0 ? 0 : e2) << 6) | (e3 < 0 ? 0 : e3);
        out.push((n >> 16) & 0xff);
        if (has2) out.push((n >> 8) & 0xff);
        if (has3) out.push(n & 0xff);
    }
    return out;
}

// ---- hex --------------------------------------------------------------
function bytesToHex(b) {
    var h = "";
    for (var i = 0; i < b.length; i++) {
        var x = b[i].toString(16); if (x.length < 2) x = "0" + x; h += x;
    }
    return h;
}
function hexToBytes(s) {
    var clean = s.replace(/[^0-9a-fA-F]/g, ""), out = [];
    for (var i = 0; i + 1 < clean.length; i += 2) out.push(parseInt(clean.substr(i, 2), 16));
    return out;
}

// ---- SHA-256 (FIPS 180-4) ---------------------------------------------
var K256 = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
function ror(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }
function sha256bytes(bytes) {
    var L = bytes.length, m = bytes.slice(0);
    m.push(0x80);
    while (m.length % 64 !== 56) m.push(0);
    var bitLen = L * 8;
    m.push(0, 0, 0, 0, (bitLen >>> 24) & 0xff, (bitLen >>> 16) & 0xff, (bitLen >>> 8) & 0xff, bitLen & 0xff);
    var H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    for (var blk = 0; blk < m.length; blk += 64) {
        var w = new Array(64);
        for (var t = 0; t < 16; t++)
            w[t] = ((m[blk+t*4]<<24)|(m[blk+t*4+1]<<16)|(m[blk+t*4+2]<<8)|m[blk+t*4+3]) >>> 0;
        for (t = 16; t < 64; t++) {
            var s0 = ror(w[t-15],7) ^ ror(w[t-15],18) ^ (w[t-15]>>>3);
            var s1 = ror(w[t-2],17) ^ ror(w[t-2],19) ^ (w[t-2]>>>10);
            w[t] = (w[t-16] + s0 + w[t-7] + s1) >>> 0;
        }
        var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
        for (t = 0; t < 64; t++) {
            var S1 = ror(e,6) ^ ror(e,11) ^ ror(e,25);
            var t1 = (h + S1 + ((e & f) ^ ((~e) & g)) + K256[t] + w[t]) >>> 0;
            var S0 = ror(a,2) ^ ror(a,13) ^ ror(a,22);
            var t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
            h=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
        }
        H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
        H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
    }
    var out = [];
    for (var i = 0; i < 8; i++)
        out.push((H[i]>>>24)&0xff,(H[i]>>>16)&0xff,(H[i]>>>8)&0xff,H[i]&0xff);
    return out;
}

// ---- SHA-1 (FIPS 180-4) -----------------------------------------------
function sha1bytes(bytes) {
    var L = bytes.length, m = bytes.slice(0);
    m.push(0x80);
    while (m.length % 64 !== 56) m.push(0);
    var bitLen = L * 8;
    m.push(0, 0, 0, 0, (bitLen >>> 24) & 0xff, (bitLen >>> 16) & 0xff, (bitLen >>> 8) & 0xff, bitLen & 0xff);
    var h0=0x67452301,h1=0xEFCDAB89,h2=0x98BADCFE,h3=0x10325476,h4=0xC3D2E1F0;
    function rol(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }
    for (var blk = 0; blk < m.length; blk += 64) {
        var w = new Array(80);
        for (var t = 0; t < 16; t++)
            w[t] = ((m[blk+t*4]<<24)|(m[blk+t*4+1]<<16)|(m[blk+t*4+2]<<8)|m[blk+t*4+3]) >>> 0;
        for (t = 16; t < 80; t++) w[t] = rol(w[t-3]^w[t-8]^w[t-14]^w[t-16], 1);
        var a=h0,b=h1,c=h2,d=h3,e=h4;
        for (t = 0; t < 80; t++) {
            var fk;
            if (t < 20)      fk = [((b & c) | ((~b) & d)) >>> 0, 0x5A827999];
            else if (t < 40) fk = [(b ^ c ^ d) >>> 0, 0x6ED9EBA1];
            else if (t < 60) fk = [((b & c) | (b & d) | (c & d)) >>> 0, 0x8F1BBCDC];
            else             fk = [(b ^ c ^ d) >>> 0, 0xCA62C1D6];
            var tmp = (rol(a,5) + fk[0] + e + fk[1] + w[t]) >>> 0;
            e=d; d=c; c=rol(b,30); b=a; a=tmp;
        }
        h0=(h0+a)>>>0; h1=(h1+b)>>>0; h2=(h2+c)>>>0; h3=(h3+d)>>>0; h4=(h4+e)>>>0;
    }
    var out = [];
    [h0,h1,h2,h3,h4].forEach(function(x){ out.push((x>>>24)&0xff,(x>>>16)&0xff,(x>>>8)&0xff,x&0xff); });
    return out;
}

// ---- html entities (encode only; decode is rarely wanted outbound) ----
function htmlEncode(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

// ---- tag transforms ---------------------------------------------------
// Each returns a string. Paired tags receive their inner content; self-
// closing tags ignore it. `arg` is the numeric/string argument if any.
var TAGS = {
    base64:  function(x){ return b64encodeBytes(strToBytes(x)); },
    b64d:    function(x){ return bytesToStr(b64decodeToBytes(x)); },
    urlenc:  function(x){ return encodeURIComponent(x); },
    urldec:  function(x){ try { return decodeURIComponent(x); } catch (e) { return x; } },
    hex:     function(x){ return bytesToHex(strToBytes(x)); },
    unhex:   function(x){ return bytesToStr(hexToBytes(x)); },
    htmlent: function(x){ return htmlEncode(x); },
    upper:   function(x){ return x.toUpperCase(); },
    lower:   function(x){ return x.toLowerCase(); },
    reverse: function(x){ return x.split("").reverse().join(""); },
    sha256:  function(x){ return bytesToHex(sha256bytes(strToBytes(x))); },
    sha1:    function(x){ return bytesToHex(sha1bytes(strToBytes(x))); },
    repeat:  function(x, arg){ var n = Math.max(0, parseInt(arg||"1",10)||0); var o=""; while(n-->0) o+=x; return o; },
    len:     function(x){ return String(strToBytes(x).length); },
    // self-closing generators
    timestamp:    function(){ return String(Math.floor(Date.now()/1000)); },
    timestamp_ms: function(){ return String(Date.now()); },
    random:  function(_x, arg){ var n = Math.max(1, parseInt(arg||"8",10)||8), s=""; while(s.length<n) s += Math.floor(Math.random()*16).toString(16); return s.substring(0,n); },
    uuid:    function(){ return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function(ch){ var r = Math.floor(Math.random()*16); var v = ch === "x" ? r : (r & 0x3 | 0x8); return v.toString(16); }); },
};

// Resolve the innermost tag on each pass so nesting works; bounded so a
// pathological input can't spin forever.
var PAIRED = /<@([a-z0-9_]+)(?:\(([^)]*)\))?>((?:(?!<@)[\s\S])*?)<@\/\1>/i;
var SELF   = /<@([a-z0-9_]+)(?:\(([^)]*)\))?\/>/i;

function applyTags(text) {
    if (!text || text.indexOf("<@") < 0) return text;
    var out = text, passes = 0;
    while (passes++ < 200) {
        var changed = false, m;
        if ((m = PAIRED.exec(out)) !== null) {
            var fn = TAGS[m[1].toLowerCase()];
            var rep = fn ? fn(m[3], m[2]) : m[0];
            out = out.substring(0, m.index) + rep + out.substring(m.index + m[0].length);
            changed = true;
        } else if ((m = SELF.exec(out)) !== null) {
            var sfn = TAGS[m[1].toLowerCase()];
            var srep = sfn ? sfn("", m[2]) : m[0];
            out = out.substring(0, m.index) + srep + out.substring(m.index + m[0].length);
            changed = true;
        }
        if (!changed) break;
    }
    return out;
}

nullock.onRequest(function(req) {
    try {
        // Path (incl. query string), every header value, and the body.
        if (req.path && req.path.indexOf("<@") >= 0) req.path = applyTags(req.path);
        for (var i = 0; i < req.headers.length; i++) {
            if (req.headers[i][1] && req.headers[i][1].indexOf("<@") >= 0)
                req.headers[i][1] = applyTags(req.headers[i][1]);
        }
        if (req.bodyText && req.bodyText.indexOf("<@") >= 0)
            req.bodyText = applyTags(req.bodyText);
        return req;
    } catch (e) {
        nullock.log("hackvertor: " + (e && e.message ? e.message : String(e)));
        return req;
    }
});

nullock.log("hackvertor: loaded (" + Object.keys(TAGS).length + " tags; <@tag>..<@/tag> resolves outbound)");

})();
