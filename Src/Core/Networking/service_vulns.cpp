#include "service_vulns.hpp"

#include <QTcpSocket>

namespace Nullock::Core::ServiceVulns {

// The pure version-matching logic (table, the version parser/comparator,
// parseBanner/productOnly, matchVersion, the runtime overlay, serviceProbePorts)
// lives in service_vulns_logic.cpp so it can be unit-tested against Qt6::Core
// alone.
// This TU keeps grabBanner()/scan(), which use QTcpSocket (the Qt6::Network
// chain) and are therefore I/O.

namespace {

bool isHttpPort(int port) {
    return port == 80 || port == 8080 || port == 8000 || port == 8443
        || port == 443 || port == 8888 || port == 9200;
}

QString grabBanner(const QString &host, int port, int timeoutMs) {
    QTcpSocket s;
    s.connectToHost(host, static_cast<quint16>(port));
    if (!s.waitForConnected(timeoutMs)) return QString();
    QString banner;
    // SSH/FTP/SMTP push a banner unprompted.
    if (s.waitForReadyRead(timeoutMs))
        banner = QString::fromLatin1(s.readAll().left(1024));
    // HTTP-ish ports answer a HEAD with a Server: header.
    if (banner.isEmpty() && isHttpPort(port)) {
        s.write("HEAD / HTTP/1.0\r\nHost: " + host.toUtf8() + "\r\n\r\n");
        s.flush();
        if (s.waitForReadyRead(timeoutMs)) {
            const QString resp = QString::fromLatin1(s.readAll().left(2048));
            for (const QString &line : resp.split("\r\n"))
                if (line.startsWith("Server:", Qt::CaseInsensitive)) { banner = line.mid(7).trimmed(); break; }
        }
    }
    s.disconnectFromHost();
    return banner.trimmed();
}

} // namespace

Result scan(const Request &req) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }
    result.host = req.host;
    const QList<int> ports = req.ports.isEmpty() ? serviceProbePorts() : req.ports;

    for (int port : ports) {
        ++result.portsProbed;
        const QString banner = grabBanner(req.host, port, req.timeoutMs);
        if (banner.isEmpty()) continue;
        ++result.banners;
        QString product, version;
        parseBanner(banner, port, product, version);
        if (!product.isEmpty()) {
            for (CveHit h : matchVersion(product, version)) {
                h.port = port;
                h.banner = banner.left(200);
                result.hits.append(h);
            }
        } else if (const QString p = productOnly(banner, port); !p.isEmpty()) {
            // Product recognized, but the banner withheld its version -- emit an
            // INFO coverage-gap finding instead of silently dropping the host
            // (which would be indistinguishable from "fully patched").
            CveHit info;
            info.port = port;
            info.product = p;
            info.informational = true;
            info.summary = QStringLiteral("product identified, version not disclosed "
                                          "-- manual review / coverage incomplete");
            info.banner = banner.left(200);
            result.hits.append(info);
        }
    }
    return result;
}

} // namespace Nullock::Core::ServiceVulns
