// mappy.js -- flag exposed JavaScript/CSS source maps.
//
// nullock:version 0.1.0
//
// Source maps are a build-time convenience that routinely ship to prod by
// accident. A reachable .map file hands an attacker your ORIGINAL source --
// pre-minification names, code comments, dead/feature-flagged branches,
// internal file paths, sometimes hard-coded endpoints or secrets. Tools
// that "unpack webpack" (and half of every recon methodology) start here.
// Nullock's native scanner reads served JS for secrets and links but says
// nothing about source-map exposure, so this fills that gap.
//
// Observe-only: onResponse, no mutation, no permission.
//
// What it reports:
//   - A served asset referencing an external .map via
//     `//# sourceMappingURL=...` (original source likely one fetch away).
//   - An inline `data:` source map embedded in the asset (source is right
//     there in the response -- no second request needed).
//   - A .map served directly with `sourcesContent` (CONFIRMED source leak:
//     the original files are inlined in the map).
//
// Limits: for the external-reference case it flags the *reference*; it can't
// fetch the .map to confirm it 200s (passive, single-message). The direct-
// .map and inline-data cases are confirmed from the body we already have.

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

var seen = {};
function report(sev, kind, summary, evidence, url, key) {
    if (seen[key]) return; seen[key] = 1;
    try { nullock.reportFinding(sev, kind, summary, evidence, url); }
    catch (e) { nullock.log("mappy report failed: " + e); }
}

nullock.onResponse(function(entry) {
    try {
        var url = entry.url || "";
        var ct = headerVal(entry.headers, "Content-Type").toLowerCase();
        var body = entry.bodyText || entry.bodyPreview || "";
        if (!body) return entry;

        var isJs  = ct.indexOf("javascript") >= 0 || ct.indexOf("ecmascript") >= 0 || /\.m?js(\?|$)/i.test(url);
        var isCss = ct.indexOf("css") >= 0 || /\.css(\?|$)/i.test(url);
        var isMap = ct.indexOf("json") >= 0 || /\.map(\?|$)/i.test(url) || /^\s*\{\s*"version"\s*:\s*3/.test(body);

        // 1. A .map served directly and carrying inlined original sources.
        if (isMap && /"sourcesContent"\s*:/.test(body) && /"version"\s*:\s*3/.test(body)) {
            var srcCount = (body.match(/"sources"\s*:\s*\[([^\]]*)\]/) || [,""])[1].split(",").length;
            report("medium", "sourcemap-exposed",
                "Source map served with inlined original sources (sourcesContent) -- original code is exposed",
                "~" + srcCount + " source file(s) inlined in the served .map", url, "map|" + url);
            return entry;
        }

        if (!isJs && !isCss) return entry;

        // 2. sourceMappingURL directive in a served asset.
        var m = body.match(/[#@]\s*sourceMappingURL\s*=\s*([^\s'"]+)/);
        if (m) {
            var ref = m[1];
            if (/^data:/i.test(ref)) {
                report("medium", "sourcemap-inline-data",
                    "Asset embeds an inline data: source map -- original source is inside the response",
                    "sourceMappingURL=data:... (" + ref.length + " bytes)", url, "inline|" + url);
            } else {
                report("low", "sourcemap-reference-exposed",
                    "Asset references an external source map (" + clip(ref, 60) + ") -- fetch it to confirm source exposure",
                    "sourceMappingURL=" + clip(ref, 100), url, "ref|" + url + "|" + ref);
            }
        }
    } catch (e) {
        nullock.log("mappy: " + (e && e.message ? e.message : String(e)));
    }
    return entry;
});

nullock.log("mappy: loaded (flags exposed JS/CSS source maps)");

})();
