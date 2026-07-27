// Pure (no-network) logic for the parameter-mining probe: canary generation,
// the request builder's CR/LF guards + duplicate-header avoidance, the
// reflection check (body + response headers), and the status-flip confirmation
// decision. Split out of param_miner.cpp so Tests/param_miner links Qt6::Core.

#include "param_miner.hpp"

#include <QRandomGenerator>
#include <QUrl>

namespace Nullock::Core::ParamMiner {

QString canaryFor(int idx) {
    // Unique, regex-inert: index disambiguates, random bits avoid collision.
    const quint32 r = QRandomGenerator::global()->generate();
    return QString("qm%1z%2").arg(idx).arg(r, 6, 16, QChar('0'));
}

QString enc(const QString &s) {
    return QString::fromUtf8(QUrl::toPercentEncoding(s));
}

QByteArray buildRequest(const Request &req,
                        const QList<QPair<QString, QString>> &params) {
    auto crlf = [](const QString &s) { return s.contains('\r') || s.contains('\n'); };
    QString path = req.basePath.isEmpty() ? QStringLiteral("/") : req.basePath;
    // method/host/path flow raw from the deep-audit / fromHistory path; a CR/LF
    // in any would smuggle a second request line or header -- refuse to build.
    if (crlf(req.method) || crlf(req.host) || crlf(path)) return {};

    const bool post = req.method.compare("POST", Qt::CaseInsensitive) == 0;
    QString extra;
    for (const auto &p : params) {
        if (!extra.isEmpty()) extra += "&";
        extra += enc(p.first) + "=" + enc(p.second);
    }

    QByteArray body;
    if (post) {
        body = extra.toUtf8();
    } else if (!extra.isEmpty()) {
        path += (path.contains('?') ? "&" : "?") + extra;
    }

    QByteArray out;
    out  = req.method.toUtf8() + " " + path.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/param-miner\r\n";
    out += "Accept: */*\r\n";
    // Identity encoding: we scan the body for our canary and the HTTP client
    // doesn't inflate gzip/deflate, so a compressed response would hide
    // reflections (false clean).
    out += "Accept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        // We set Content-Type/Content-Length ourselves for POST below; skip
        // any carried copies so the request can't carry duplicate framing.
        if (h.first.compare("Content-Type", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        // Drop a carried Accept-Encoding too: we set our own "identity" above so a
        // gzip response can't hide the canary. A surviving "gzip, deflate, br"
        // combines (RFC 7230 3.2.2) to let the server compress, and the client does
        // NOT inflate -> canaryReflected scans compressed bytes and misses a real
        // reflection (a false clean). Same duplicate-framing class as CT/CL above.
        if (h.first.compare("Accept-Encoding", Qt::CaseInsensitive) == 0) continue;
        if (crlf(h.first) || crlf(h.second)) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    if (post) {
        out += "Content-Type: application/x-www-form-urlencoded\r\n";
        out += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    out += body;
    return out;
}

bool canaryReflected(const QByteArray &body,
                     const QList<QPair<QString, QString>> &headers,
                     const QString &canary) {
    if (QString::fromUtf8(body).contains(canary)) return true;
    // A param value echoed into a response header (Set-Cookie, Location, a
    // custom X-... header) is just as much a "handled param" signal as a body
    // reflection -- the body-only scan missed it.
    for (const auto &h : headers)
        if (h.second.contains(canary)) return true;
    return false;
}

bool statusFlipConfirmed(int firstStatus, int reBaselineStatus,
                         int reSendStatus, int baseStatus) {
    // A real param-driven status flip must (a) flip on the first observation,
    // (b) reproduce on a re-send, AND (c) the freshly re-fetched baseline must
    // still equal the original baseline (else the baseline DRIFTED -- the
    // "flip" was load/deploy noise, not the param). Defeats a transient flap
    // mis-attributed to whatever name bisection happened to land on.
    // (b) requires the re-send to reproduce the SAME status as the first
    // observation -- a re-send that lands on a DIFFERENT non-baseline status is a
    // transient flap, not a deterministic param-driven flip. (reSendStatus ==
    // firstStatus implies reSendStatus != baseStatus, since firstStatus != base.)
    return firstStatus != baseStatus
        && reSendStatus == firstStatus
        && reBaselineStatus == baseStatus;
}

} // namespace Nullock::Core::ParamMiner
