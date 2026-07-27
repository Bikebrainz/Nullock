// Pure, I/O-free helpers for the SSTI tester: digit-grouping normalization, the
// sentinel-region extractor, the two-expression evaluation predicate, and the
// CR/LF-guarded request builder. Kept in their OWN translation unit (separate
// from ssti_tester.cpp's test(), which pulls HttpClient and the networking/GUI
// chain) so the unit test can link this logic against Qt6::Core alone.

#include "ssti_tester.hpp"

namespace Nullock::Core::Ssti {

// Strip every locale digit-grouping separator (US comma, EU dot, Swiss
// apostrophe, ASCII space, NBSP, narrow NBSP) so a product rendered as
// "24 534 638" / "24.534.638" / "24'534'638" still matches its plain digits.
// The original only stripped ',' and ' ', silently missing FreeMarker's
// default locale-grouped output -- a confirmed-SSTI false negative.
QString stripGroupingDigits(const QString &s) {
    QString t = s;
    t.remove(',').remove('.').remove('\'').remove(' ');
    t.remove(QChar(0x00A0));   // NBSP
    t.remove(QChar(0x202F));   // narrow NBSP
    return t;
}

// Every sentinel-bracketed region (pre...suf, <= 64 chars) in the body -- ALL of
// them, not just the first. A target that reflects the param twice (e.g. once
// raw in an <input value=...> and once rendered) puts the literal echo first;
// returning only that region would miss the evaluated one below it.
QStringList renderedRegions(const QString &body, const QString &pre, const QString &suf) {
    QStringList out;
    int p = body.indexOf(pre);
    while (p >= 0) {
        const int from = p + pre.size();
        const int s = body.indexOf(suf, from);
        if (s < 0) break;
        if (s - from <= 64) out << body.mid(from, s - from);
        p = body.indexOf(pre, from);
    }
    return out;
}

// SSTI is confirmed only when some region carries TWO independently-evaluated
// products bracketing a literal separator -- "<productA><sep><productB>" -- and
// does NOT echo either literal expression. Arithmetic alone is not enough: any
// calculator / inline-math / expression API computes a single a*b, so the
// old "product present, expression absent" test false-positived on them at the
// tool's CRITICAL severity. Only a template engine evaluates two DELIMITED
// sub-expressions while preserving the literal text between them, which is what
// this requires.
bool confirmsArithmetic(const QStringList &regions,
                        const QString &productA, const QString &sep,
                        const QString &productB,
                        const QString &exprA, const QString &exprB) {
    const QString needle = productA + sep + productB;
    for (const QString &region : regions) {
        if (region.contains(exprA) || region.contains(exprB)) continue;  // pure reflection
        if (stripGroupingDigits(region).contains(needle)) return true;
    }
    return false;
}

// Secondary "engine likely" signal: a template-syntax break that 5xx'd a
// previously-OK endpoint, corroborated by a minimal-pair CONTROL (same length /
// char multiset, only the delimiter bigrams broken up) that did NOT also 5xx. A
// control that FAILED to complete is no evidence, so it stays fail-closed (no
// engineLikely) -- mirrors the ldap/sql failed-control ethos.
bool engineLikelyFrom(int baselineStatus, bool delimOk, int delimStatus,
                      bool ctrlOk, int ctrlStatus) {
    if (baselineStatus >= 500) return false;              // endpoint already 5xx-noisy
    if (!(delimOk && delimStatus >= 500)) return false;   // the syntax break must 5xx
    if (!ctrlOk) return false;                            // control must complete (fail-closed)
    return ctrlStatus < 500;                              // ...and NOT also 5xx (else it cancels)
}

// Build the raw request, CR/LF-guarding the method/host/path and the
// Content-Type (a tainted one aborts the request -> {}) and dropping any
// CR/LF-bearing header, matching the jwt_probe hardening pattern. The query
// arrives percent-encoded from the caller, so it is safe by construction.
QByteArray buildRequest(const Request &req, const QString &path,
                        const QString &query, const QByteArray &body) {
    if (req.method.contains('\r') || req.method.contains('\n')) return {};
    if (req.host.contains('\r')   || req.host.contains('\n'))   return {};
    if (path.contains('\r')       || path.contains('\n'))       return {};
    const QString target = query.isEmpty() ? path : path + "?" + query;
    const bool bodyMethod = req.method.compare("POST",  Qt::CaseInsensitive) == 0
                         || req.method.compare("PUT",   Qt::CaseInsensitive) == 0
                         || req.method.compare("PATCH", Qt::CaseInsensitive) == 0;
    QByteArray out;
    out  = req.method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/ssti\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Type", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    if (!body.isEmpty() || bodyMethod) {
        const QString ct = req.contentType.isEmpty()
            ? (req.paramIn == "json" ? QStringLiteral("application/json")
                                     : QStringLiteral("application/x-www-form-urlencoded"))
            : req.contentType;
        if (ct.contains('\r') || ct.contains('\n')) return {};
        out += "Content-Type: " + ct.toUtf8() + "\r\n";
        out += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    out += body;
    return out;
}

} // namespace Nullock::Core::Ssti
