// Pure, I/O-free helpers for the NoSQL injection probe: the length-difference
// classifier, the 2x2 differential confirmation, and the CR/LF-guarded request
// builder. Kept in their OWN translation unit (separate from
// nosql_injection.cpp's test(), which pulls HttpClient and the networking/GUI
// chain) so the unit test can link this logic against Qt6::Core alone.

#include "nosql_injection.hpp"

namespace Nullock::Core::NoSqlInjection {

bool lenDiffers(int a, int b) {
    const int mx = qMax(a, b), d = qAbs(a - b);
    return mx > 0 && d > 40 && double(d) / mx > 0.25;
}
// Strict complement -- every pair is classified exactly once.
bool lenSimilar(int a, int b) { return !lenDiffers(a, b); }

// 2x2 differential. The OLD test ("$ne diverges from the literal while $eq
// tracks it") false-positived whenever something keyed on the operator NAME --
// a validator/WAF denylisting "$ne", a router, or a redirect -- made $ne differ
// without any datastore interpreting it. This requires a SECOND always-true
// operator ($gt) and confirms only when:
//   - the two ALWAYS-TRUE operators ($ne, $gt) behave the SAME (both over-match)
//     -- a quirk keyed on one operator name breaks this agreement;
//   - the ALWAYS-FALSE operator ($eq) tracks the bogus literal (both match
//     nothing) -- if the app merely treats objects specially, $eq diverges too;
//   - and the two groups actually differ (the operators were interpreted).
// An always-true operator that ERRORS over an OK literal is type confusion (an
// object where a string was wanted), not an over-match, so it is rejected.
bool confirmsInjection(int litLen, int litStatus,
                       int eqLen, int eqStatus,
                       int neLen, int neStatus,
                       int gtLen, int gtStatus) {
    if (litStatus < 400 && (neStatus >= 400 || gtStatus >= 400)) return false;  // type confusion
    const bool trueGroupAgrees     = lenSimilar(neLen, gtLen) && neStatus == gtStatus;
    const bool falseGroupTracksLit = lenSimilar(eqLen, litLen) && eqStatus == litStatus;
    const bool groupsDiffer        = lenDiffers(neLen, litLen) || neStatus != litStatus;
    return trueGroupAgrees && falseGroupTracksLit && groupsDiffer;
}

// Build the raw request, CR/LF-guarding method/host/path (returns {} if any is
// tainted) and dropping any CR/LF-bearing carried header, matching the jwt_probe
// hardening pattern. The query arrives percent-encoded from the caller.
QByteArray buildRequest(const Request &req, const QString &query) {
    if (req.method.contains('\r')   || req.method.contains('\n'))   return {};
    if (req.host.contains('\r')     || req.host.contains('\n'))     return {};
    if (req.basePath.contains('\r') || req.basePath.contains('\n')) return {};
    const QString target = query.isEmpty() ? req.basePath : req.basePath + "?" + query;
    QByteArray out;
    out  = req.method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/nosqli\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

} // namespace Nullock::Core::NoSqlInjection
