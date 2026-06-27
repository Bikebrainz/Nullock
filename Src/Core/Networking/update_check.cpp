#include "update_check.hpp"

#include "networking.hpp"

#include <QJsonDocument>
#include <QJsonObject>
#include <QMutexLocker>
#include <QtConcurrent/QtConcurrentRun>

namespace Nullock::Core {

// compareSemver()/isTrustedReleaseUrl() are pure and live in update_check_logic.cpp
// so they can be unit-tested against Qt6::Core alone. This TU keeps doCheck()'s
// HttpClient I/O.

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
    // Only surface a release URL that is a real HTTPS github.com page -- never hand
    // the chrome a javascript:/file:/http: link from an unexpected field.
    const QString url = o.value("html_url").toString();
    r.releaseUrl    = UpdateLogic::isTrustedReleaseUrl(url) ? url : QString();
    r.releaseNotes  = o.value("body").toString().left(8 * 1024);
    r.publishedAt   = o.value("published_at").toString();
    if (r.latestVersion.isEmpty()) {
        r.error = "no tag_name in release";
        return r;
    }
    r.available = UpdateLogic::compareSemver(currentVersion, r.latestVersion) < 0;
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
