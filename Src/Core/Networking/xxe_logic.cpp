// Pure, I/O-free helpers for the XXE probe: the CR/LF-guarded request builder,
// the file-content signature matcher, and the inert-DOCTYPE-controlled
// confirmation. Kept in their OWN translation unit (separate from
// xxe_injection.cpp's test(), which pulls HttpClient and the networking/GUI
// chain) so the unit test can link this logic against Qt6::Core alone.

#include "xxe_injection.hpp"

#include <QRegularExpression>

namespace Nullock::Core::XxeInjection {

constexpr int kMaxBody = 512 * 1024;

QString matchSig(const QRegularExpression &re, const QByteArray &body) {
    const auto m = re.match(QString::fromUtf8(body.left(kMaxBody)));
    return m.hasMatch() ? m.captured(0) : QString();
}

// Confirm a real external-entity file read, immune to a hardened (disallow-
// doctype) server whose ERROR page happens to carry a file-shaped string:
//   - the signature must appear in the SYSTEM-entity response,
//   - the response must not be a server error (>= 500: a stack trace / WAF 5xx),
//   - and the signature must be ABSENT from both the benign baseline AND the
//     inert-DOCTYPE control (same DOCTYPE shell, internal entity, no SYSTEM).
// A disallow-doctype server returns the same error page for the inert and SYSTEM
// DOCTYPEs, so any file-shaped string in it cancels out; only an actually
// resolved external entity appears in the SYSTEM response alone.
QString confirmReadSig(const QRegularExpression &sig,
                       const QByteArray &systemBody, int systemStatus,
                       const QByteArray &baselineBody,
                       bool inertOk, const QByteArray &inertBody) {
    if (systemStatus >= 500) return QString();                 // error body, not a read
    const QString hit = matchSig(sig, systemBody);
    if (hit.isEmpty()) return QString();
    if (!matchSig(sig, baselineBody).isEmpty()) return QString();   // present without any DOCTYPE
    // FAIL CLOSED on the inert control. It is the ONLY signal that separates a
    // real external-entity read from a hardened (disallow-doctype) server whose
    // error page merely carries a file-shaped string. If that control request did
    // not succeed we cannot subtract its error page, so the read is unproven --
    // refuse to confirm rather than emit a possible false positive.
    if (!inertOk) return QString();
    if (!matchSig(sig, inertBody).isEmpty())    return QString();   // present from DOCTYPE rejection, not a read
    return hit;
}

// Build the XML POST, CR/LF-guarding method/host/path AND Content-Type (returns
// {} if any is tainted) and dropping any CR/LF-bearing carried header, matching
// the jwt_probe / ssti_logic hardening pattern.
QByteArray buildRequest(const Request &req, const QByteArray &body) {
    if (req.method.contains('\r')   || req.method.contains('\n'))   return {};
    if (req.host.contains('\r')     || req.host.contains('\n'))     return {};
    if (req.basePath.contains('\r') || req.basePath.contains('\n')) return {};
    const QString path = req.basePath.isEmpty() ? QStringLiteral("/") : req.basePath;
    const QString ct = req.contentType.isEmpty() ? QStringLiteral("application/xml")
                                                 : req.contentType;
    if (ct.contains('\r') || ct.contains('\n')) return {};
    QByteArray out;
    out  = req.method.toUtf8() + " " + path.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/xxe\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    out += "Content-Type: " + ct.toUtf8() + "\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Type", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
    out += "Connection: close\r\n\r\n";
    out += body;
    return out;
}

} // namespace Nullock::Core::XxeInjection
