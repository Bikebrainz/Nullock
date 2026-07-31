// peekaboo.js -- passive ASP.NET __VIEWSTATE auditor.
//
// ASP.NET Web Forms round-trips page state through a base64 __VIEWSTATE
// field. When it isn't encrypted (ViewStateEncryptionMode) it's readable --
// leaking control tree, data-bound values and internal structure -- and when
// it also isn't MAC-protected (EnableViewStateMac) it's *deserialized*
// server-side, which is the ObjectStateFormatter / ysoserial.net RCE path.
// This is the passive detection half of the "ViewState" BApp family, and
// nothing in Nullock's native scanner looks at ViewState today.
//
// Observe-only: onResponse over response HTML, no mutation, no permission.
//
// What it does: find __VIEWSTATE in a served form, base64-decode it, and
// classify:
//   - Starts with the ObjectStateFormatter marker (0xFF 0x01) and decodes to
//     readable content => UNENCRYPTED ViewState: contents exposed, and a
//     tamper/deserialization surface if MAC is off. Reported.
//   - High-entropy / no marker => encrypted; not reported (nothing to see).
// Also notes when __VIEWSTATEGENERATOR is present (needed to weaponise an
// unprotected ViewState with ysoserial.net --generator).
//
// Limits: MAC presence can't be proven from the blob alone (the HMAC is a
// trailing opaque tail); "unencrypted + readable" is the reliable passive
// signal, so the finding says to CONFIRM EnableViewStateMac before assuming
// RCE. Only the first 64 KiB of the body is visible.

(function() {
'use strict';

var B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function b64ToBytes(str) {
    var clean = String(str).replace(/[^A-Za-z0-9+/]/g, ""), out = [];
    for (var i = 0; i < clean.length; i += 4) {
        var has2 = i + 2 < clean.length, has3 = i + 3 < clean.length;
        var e0 = B64.indexOf(clean[i]), e1 = B64.indexOf(clean[i + 1]);
        var e2 = has2 ? B64.indexOf(clean[i + 2]) : 0, e3 = has3 ? B64.indexOf(clean[i + 3]) : 0;
        var n = (e0 << 18) | (e1 << 12) | ((e2 < 0 ? 0 : e2) << 6) | (e3 < 0 ? 0 : e3);
        out.push((n >> 16) & 0xff);
        if (has2) out.push((n >> 8) & 0xff);
        if (has3) out.push(n & 0xff);
    }
    return out;
}

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
    catch (e) { nullock.log("peekaboo report failed: " + e); }
}

function extractField(body, field) {
    var re = new RegExp("name\\s*=\\s*[\"']?" + field + "[\"']?[^>]*?value\\s*=\\s*[\"']([^\"']*)[\"']", "i");
    var m = body.match(re);
    if (m) return m[1];
    re = new RegExp("value\\s*=\\s*[\"']([^\"']*)[\"'][^>]*?name\\s*=\\s*[\"']?" + field, "i");
    m = body.match(re);
    return m ? m[1] : "";
}

// Fraction of bytes that are printable ASCII (rough "is this readable?").
function printableRatio(bytes, cap) {
    var n = Math.min(bytes.length, cap || 512), p = 0;
    if (!n) return 0;
    for (var i = 0; i < n; i++) { var b = bytes[i]; if ((b >= 0x20 && b <= 0x7e) || b === 0x09) p++; }
    return p / n;
}

nullock.onResponse(function(entry) {
    try {
        var ct = headerVal(entry.headers, "Content-Type").toLowerCase();
        if (ct && ct.indexOf("html") < 0) return entry;
        var body = entry.bodyText || entry.bodyPreview || "";
        if (!body || body.indexOf("__VIEWSTATE") < 0) return entry;

        var vs = extractField(body, "__VIEWSTATE");
        if (!vs || vs.length < 20) return entry;
        var hasGen = body.indexOf("__VIEWSTATEGENERATOR") >= 0;

        var bytes = b64ToBytes(vs);
        if (bytes.length < 4) return entry;

        var osfMarker = bytes[0] === 0xff && bytes[1] === 0x01;   // ObjectStateFormatter
        var readable = printableRatio(bytes) > 0.30;
        var url = entry.url || "";
        var key = "vs|" + url;

        if (osfMarker && readable) {
            report("medium", "viewstate-unencrypted",
                "ASP.NET __VIEWSTATE is unencrypted (ObjectStateFormatter marker + readable content)"
                + (hasGen ? "; __VIEWSTATEGENERATOR is present" : "")
                + " -- state is exposed and, if EnableViewStateMac is off, a deserialization/RCE surface (ysoserial.net)",
                "decoded " + bytes.length + "B, starts 0xFF01, printable~"
                + Math.round(printableRatio(bytes) * 100) + "%"
                + (hasGen ? ", generator present" : ""),
                url, key);
        } else if (osfMarker && !readable) {
            // Marker but low printable -> unusual; worth a low note.
            report("low", "viewstate-partial-plaintext",
                "ASP.NET __VIEWSTATE shows an unencrypted ObjectStateFormatter marker -- verify ViewStateEncryptionMode",
                "decoded " + bytes.length + "B, starts 0xFF01", url, key);
        }
        // No marker + high entropy => encrypted ViewState; nothing to report.
    } catch (e) {
        nullock.log("peekaboo: " + (e && e.message ? e.message : String(e)));
    }
    return entry;
});

nullock.log("peekaboo: loaded (passive ASP.NET ViewState auditor)");

})();
