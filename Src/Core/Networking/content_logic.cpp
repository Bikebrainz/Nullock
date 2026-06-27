// Pure content-discovery classification, split out of content_discovery.cpp so a
// unit test can link it against Qt6::Core alone -- discover()'s HttpClient I/O
// stays in content_discovery.cpp. classify() is the soundness core: it turns a
// probed response + the calibrated soft-404 profile into a "is this a real,
// distinct resource?" verdict, discriminating a genuine dir-redirect / forbidden
// resource from a blanket soft-404 by Location and body size, not status alone.

#include "content_discovery.hpp"

#include <cstdlib>

namespace Nullock::Core::ContentDiscovery {

// Normalise a redirect target for comparison: trim, drop a trailing slash (so a
// soft-404 -> /login and a candidate -> /login/ aren't treated as different).
static QString locNorm(QString s) {
    s = s.trimmed();
    while (s.endsWith('/')) s.chop(1);
    return s;
}

QString normBase(const QString &p) {
    QString b = p;
    if (b == QLatin1String("/")) return QString();
    while (b.endsWith('/')) b.chop(1);
    if (!b.isEmpty() && !b.startsWith('/')) b.prepend('/');
    return b;
}

QString classify(int status, int bodyLen, const QString &location, const CalibProfile &cal) {
    const int st = status;

    // Redirects. A real directory commonly redirects (/admin -> /admin/), so a
    // soft-404 that ALSO redirects (e.g. everything -> /login) must not mask it:
    // suppress only when the status is a soft status AND the target matches the
    // calibrated soft-404 redirect target.
    if (st == 301 || st == 302 || st == 307 || st == 308) {
        if (cal.softStatuses.contains(st) && locNorm(location) == locNorm(cal.softLocation))
            return QString();
        return QStringLiteral("redirect");
    }

    // Auth-gated. A blanket-403 server (every absent path 403s) must not hide a
    // genuinely protected resource that 403s with a DISTINCT body: suppress only
    // when the status is soft AND the body size matches the soft page.
    if (st == 401 || st == 403) {
        if (cal.softStatuses.contains(st) && std::abs(bodyLen - cal.softLen) <= cal.jitter)
            return QString();
        return QStringLiteral("auth-gated");
    }

    if (st == 200) {
        // Baseline isn't a 200-soft-404 -> any 200 is a real resource.
        if (!cal.softStatuses.contains(200)) return QStringLiteral("ok");
        // 200-soft-404 server -> only a materially different body counts.
        return std::abs(bodyLen - cal.softLen) > cal.jitter ? QStringLiteral("ok-distinct") : QString();
    }

    // Other 2xx (204/206/...): interesting unless it's the soft status.
    if (st >= 200 && st < 300) {
        if (cal.softStatuses.contains(st)) return QString();
        return QStringLiteral("ok");
    }
    return QString();
}

bool forbiddenSaturated(int forbiddenHits, int wordsProbed) {
    // A WAF that pattern-blocks attack-shaped paths (.git/.env/phpmyadmin/...) but
    // passes the benign "nl404" calibration tokens returns 401/403 for a large
    // fraction of the wordlist. Treat that as WAF saturation -- one signal -- not
    // dozens of genuine "auth-gated" resources. Needs a meaningful absolute count
    // AND a high fraction so a handful of real protected paths still surface.
    if (wordsProbed <= 0 || forbiddenHits < 10) return false;
    return forbiddenHits * 100 >= wordsProbed * 40;   // >= 40% forbidden
}

} // namespace Nullock::Core::ContentDiscovery
