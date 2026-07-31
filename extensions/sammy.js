// sammy.js -- passive SAML response/assertion auditor.
//
// A proxy-side take on SAML Raider (the SAML BApp everyone reaches for).
// SAML Raider is an active editor for forging/replaying assertions; Nullock
// can't hook the browser to intercept the POST, but it doesn't need to: the
// IdP hands the browser an auto-submitting HTML form carrying the base64
// SAMLResponse, and that form flows through us in a *response* body. So we
// grab it there, base64-decode it (POST binding is plain base64 -- no
// DEFLATE, unlike the redirect binding), and audit the XML.
//
// Observe-only: onResponse, no mutation, no permission.
//
// What it catches (the high-value SAML mistakes):
//   - Unsigned assertion / response: no <Signature> => the SP is trusting an
//     attacker-forgeable document. The #1 SAML finding.
//   - XML comment-injection surface: a comment inside NameID/attributes is
//     the CVE-2017-11427 / "SAML is insecure by design" truncation class.
//   - Over-long validity window: NotOnOrAfter far out, or NotBefore absent,
//     widening the replay window.
//   - Missing Destination / InResponseTo: no audience/flow binding, easing
//     token reuse and cross-SP replay.
//   - Cleartext ACS / Destination (http://): assertion delivered in the clear.
//
// Limits: POST-binding only (redirect-binding SAML is DEFLATE-compressed and
// QJSEngine has no inflate). Signature PRESENCE is checked, not signature
// VALIDITY or what it covers -- a present-but-scoped-wrong signature still
// warrants manual review. Only the first ~64 KiB of the body is visible.

(function() {
'use strict';

// ---- base64 decode (no atob in QJSEngine) -> UTF-8 string -------------
var B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function b64ToStr(str) {
    var clean = String(str).replace(/[^A-Za-z0-9+/]/g, ""), bytes = [];
    for (var i = 0; i < clean.length; i += 4) {
        var has2 = i + 2 < clean.length, has3 = i + 3 < clean.length;
        var e0 = B64.indexOf(clean[i]), e1 = B64.indexOf(clean[i + 1]);
        var e2 = has2 ? B64.indexOf(clean[i + 2]) : 0, e3 = has3 ? B64.indexOf(clean[i + 3]) : 0;
        var n = (e0 << 18) | (e1 << 12) | ((e2 < 0 ? 0 : e2) << 6) | (e3 < 0 ? 0 : e3);
        bytes.push((n >> 16) & 0xff);
        if (has2) bytes.push((n >> 8) & 0xff);
        if (has3) bytes.push(n & 0xff);
    }
    // UTF-8 decode
    var s = "", j = 0;
    while (j < bytes.length) {
        var c = bytes[j++];
        if (c < 0x80) s += String.fromCharCode(c);
        else if (c >= 0xc0 && c < 0xe0) s += String.fromCharCode(((c & 0x1f) << 6) | (bytes[j++] & 0x3f));
        else if (c >= 0xe0 && c < 0xf0)
            s += String.fromCharCode(((c & 0x0f) << 12) | ((bytes[j++] & 0x3f) << 6) | (bytes[j++] & 0x3f));
        else j += 3; // skip astral; SAML XML is ~ASCII
    }
    return s;
}

function clip(s, n) { s = String(s || ""); return s.length > n ? s.substring(0, n) + "..." : s; }

var seen = {};
function report(sev, kind, summary, evidence, url, key) {
    if (seen[key]) return; seen[key] = 1;
    try { nullock.reportFinding(sev, kind, summary, evidence, url); }
    catch (e) { nullock.log("sammy report failed: " + e); }
}

// Pull the base64 SAML blob out of an HTML auto-post form or a urlencoded body.
function extractSaml(body) {
    var out = [];
    // <input ... name="SAMLResponse" ... value="BASE64" ...> (attr order varies)
    var re = /name\s*=\s*["']?(SAMLResponse|SAMLRequest)["']?[^>]*?value\s*=\s*["']([^"']+)["']/gi, m;
    while ((m = re.exec(body)) !== null) out.push({ kind: m[1], b64: m[2] });
    // value-before-name ordering
    var re2 = /value\s*=\s*["']([A-Za-z0-9+/=\s]{40,})["'][^>]*?name\s*=\s*["']?(SAMLResponse|SAMLRequest)/gi;
    while ((m = re2.exec(body)) !== null) out.push({ kind: m[2], b64: m[1] });
    // form-urlencoded (rare in a response, but cheap to check)
    var re3 = /(?:^|[&?])(SAMLResponse|SAMLRequest)=([A-Za-z0-9%+/=]{40,})/gi;
    while ((m = re3.exec(body)) !== null) {
        var v = m[2]; try { v = decodeURIComponent(v.replace(/\+/g, " ")); } catch (e) {}
        out.push({ kind: m[1], b64: v });
    }
    return out;
}

function auditXml(xml, kind, url, tokenTag) {
    var isResponse = kind === "SAMLResponse";

    // 1. Signature presence. An unsigned Response/Assertion is the big one.
    if (!/<(?:\w+:)?Signature\b/.test(xml)) {
        report(isResponse ? "high" : "medium", "saml-unsigned",
            "SAML " + kind + " has no <Signature> -- assertion is forgeable/tamperable",
            "decoded " + kind + " (" + xml.length + " bytes), no Signature element", url,
            "sig|" + tokenTag);
    }

    // 2. XML comment inside identity-bearing nodes => comment-truncation surface.
    if (/<!--/.test(xml)) {
        var nearId = /<(?:\w+:)?(?:NameID|Attribute|AttributeValue|Subject)\b[^>]*>[^<]*<!--/.test(xml)
                  || /<!--[\s\S]{0,80}(?:NameID|AttributeValue)/.test(xml);
        report(nearId ? "high" : "medium", "saml-comment-injection-surface",
            "XML comment present in the SAML document (CVE-2017-11427-class comment-truncation surface)"
            + (nearId ? " near an identity node" : ""),
            "comment found in decoded " + kind, url, "cmt|" + tokenTag);
    }

    // 3. Validity window.
    var naMatch = xml.match(/NotOnOrAfter\s*=\s*["']([^"']+)["']/);
    var nbPresent = /NotBefore\s*=/.test(xml);
    if (naMatch) {
        var na = Date.parse(naMatch[1]);
        if (!isNaN(na)) {
            var hours = (na - Date.now()) / 3600000;
            if (hours > 24)
                report("low", "saml-long-validity",
                    "SAML assertion valid for ~" + Math.round(hours) + "h (wide replay window)",
                    "NotOnOrAfter=" + naMatch[1], url, "val|" + tokenTag);
        }
    }
    if (isResponse && !nbPresent)
        report("low", "saml-no-notbefore",
            "SAML assertion has no NotBefore constraint",
            "no NotBefore attribute in decoded assertion", url, "nb|" + tokenTag);

    // 4. Flow binding.
    if (isResponse && !/InResponseTo\s*=/.test(xml))
        report("low", "saml-no-inresponseto",
            "SAML Response has no InResponseTo (unsolicited-response / replay surface)",
            "no InResponseTo attribute", url, "irt|" + tokenTag);
    if (!/Destination\s*=/.test(xml) && isResponse)
        report("low", "saml-no-destination",
            "SAML Response has no Destination attribute (audience not bound to the ACS URL)",
            "no Destination attribute", url, "dst|" + tokenTag);

    // 5. Cleartext ACS / Destination / Recipient.
    var cleartext = xml.match(/(?:Destination|Recipient|AssertionConsumerServiceURL)\s*=\s*["'](http:\/\/[^"']+)["']/);
    if (cleartext)
        report("medium", "saml-cleartext-endpoint",
            "SAML endpoint is cleartext http:// -- assertion delivered without TLS",
            clip(cleartext[0], 120), url, "clr|" + tokenTag);
}

nullock.onResponse(function(entry) {
    try {
        var body = entry.bodyText || entry.bodyPreview || "";
        if (!body || body.indexOf("SAML") < 0) return entry;
        var blobs = extractSaml(body);
        for (var i = 0; i < blobs.length; i++) {
            var xml;
            try { xml = b64ToStr(blobs[i].b64); } catch (e) { continue; }
            if (xml.indexOf("<") < 0) continue;             // not XML; skip
            var tag = (entry.url || "") + "|" + blobs[i].kind + "|" + blobs[i].b64.length;
            auditXml(xml, blobs[i].kind, entry.url || "", tag);
        }
    } catch (e) {
        nullock.log("sammy: " + (e && e.message ? e.message : String(e)));
    }
    return entry;
});

nullock.log("sammy: loaded (passive SAML POST-binding auditor)");

})();
