#include "update_check.hpp"

#include "networking.hpp"

#include <QJsonDocument>
#include <QJsonObject>
#include <QMutexLocker>
#include <QtConcurrent/QtConcurrentRun>

namespace Nullock::Core {

namespace {

// Cheap semver compare. "1.0.0" < "1.0.1" < "1.1.0" < "2.0.0".
// Pre-release suffixes (-rc1) ignored: treated as equal to base.
int cmpSemver(const QString &a, const QString &b) {
    auto split = [](QString s) {
        // Strip leading "v" and pre-release suffix.
        if (s.startsWith('v') || s.startsWith('V')) s = s.mid(1);
        const int dash = s.indexOf('-');
        if (dash >= 0) s = s.left(dash);
        QList<int> parts;
        for (const QString &p : s.split('.', Qt::SkipEmptyParts)) {
            bool ok = false;
            parts.append(p.toInt(&ok));
            if (!ok) { parts.append(0); }
        }
        while (parts.size() < 3) parts.append(0);
        return parts;
    };
    const auto pa = split(a);
    const auto pb = split(b);
    for (int i = 0; i < 3 && i < pa.size() && i < pb.size(); ++i) {
        if (pa[i] < pb[i]) return -1;
        if (pa[i] > pb[i]) return 1;
    }
    return 0;
}

}

UpdateInfo UpdateChecker::doCheck(const QString &currentVersion) {
    UpdateInfo r;
    r.currentVersion = currentVersion;

    QByteArray req;
    req += "GET /repos/Bikebrainz/Nullock/releases/latest HTTP/1.1\r\n";
    req += "Host: api.github.com\r\n";
    req += "User-Agent: nullock-update-check/1.0\r\n";
    req += "Accept: application/vnd.github+json\r\n";
    req += "Connection: close\r\n\r\n";

    HttpClient client;
    auto res = client.send(QStringLiteral("api.github.com"), 443, true, req);
    if (!res.ok) {
        r.error = "fetch failed: " + res.errorMessage;
        return r;
    }
    if (res.parsed.statusCode != 200) {
        r.error = QString("HTTP %1 from github").arg(res.parsed.statusCode);
        return r;
    }
    const QJsonDocument doc = QJsonDocument::fromJson(res.parsed.body);
    if (!doc.isObject()) {
        r.error = "github response not JSON";
        return r;
    }
    const QJsonObject o = doc.object();
    r.latestVersion = o.value("tag_name").toString();
    r.releaseUrl    = o.value("html_url").toString();
    r.releaseNotes  = o.value("body").toString().left(8 * 1024);
    r.publishedAt   = o.value("published_at").toString();
    if (r.latestVersion.isEmpty()) {
        r.error = "no tag_name in release";
        return r;
    }
    r.available = cmpSemver(currentVersion, r.latestVersion) < 0;
    return r;
}

void UpdateChecker::checkAsync(const QString &currentVersion) {
    (void)QtConcurrent::run([this, currentVersion]() {
        const UpdateInfo r = doCheck(currentVersion);
        {
            QMutexLocker lk(&m_mu);
            m_last = r;
        }
        emit updated(r);
    });
}

UpdateInfo UpdateChecker::lastResult() const {
    QMutexLocker lk(&m_mu);
    return m_last;
}

} // namespace Nullock::Core
