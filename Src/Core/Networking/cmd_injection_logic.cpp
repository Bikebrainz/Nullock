// Pure, I/O-free helpers for the command-injection probe: the command-execution
// proof token, the sentinel-region extractor, and the CR/LF-guarded request
// builder. Kept in their OWN translation unit (separate from cmd_injection.cpp's
// test(), which pulls HttpClient and the networking/GUI chain) so the unit test
// can link this logic against Qt6::Core alone.

#include "cmd_injection.hpp"

#include <QStringList>

namespace Nullock::Core::CmdInjection {

// The proof token placed in the echoed command body. The arithmetic is wrapped
// in a COMMAND SUBSTITUTION, so the bare product appears between the sentinels
// ONLY if a command actually executed (the $() ran `echo`) -- NOT merely if
// $(()) arithmetic was expanded. A restricted/sandboxed evaluator that performs
// arithmetic expansion but blocks command substitution leaves "$(echo <n>)"
// literal, so it can no longer be mistaken for RCE (the audit's high-severity
// false positive: arithmetic-only reflectors flagged as CWE-78 / CVSS 9.8).
QString commandProof(const QString &pre, const QString &suf, quint64 a, quint64 b) {
    return pre + QStringLiteral("$(echo $((%1*%2)))").arg(a).arg(b) + suf;
}

// EVERY sentinel-bracketed region (pre...suf, <= 64 chars) in the body -- ALL of
// them, not just the first. A target that reflects the param twice (once raw,
// once as executed output) puts the literal "$(echo $((a*b)))" echo first;
// returning only that region would miss the executed product below it.
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

// Build the raw request, CR/LF-guarding the method/host/path (a tainted one
// aborts the request -> {}) and dropping any CR/LF-bearing header, matching the
// jwt_probe hardening pattern. The query arrives percent-encoded from the
// caller, so it is safe by construction.
QByteArray buildRequest(const Request &req, const QString &query) {
    if (req.method.contains('\r')   || req.method.contains('\n'))   return {};
    if (req.host.contains('\r')     || req.host.contains('\n'))     return {};
    if (req.basePath.contains('\r') || req.basePath.contains('\n')) return {};
    const QString target = query.isEmpty() ? req.basePath : req.basePath + "?" + query;
    if (target.contains('\r') || target.contains('\n')) return {};   // guard the spliced query
    QByteArray out;
    out  = req.method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/cmdi\r\n";
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

} // namespace Nullock::Core::CmdInjection
