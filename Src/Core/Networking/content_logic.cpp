// Pure content-discovery classification, split out of content_discovery.cpp so a
// unit test can link it against Qt6::Core alone -- discover()'s HttpClient I/O
// stays in content_discovery.cpp. classify() is the soundness core: it turns a
// probed response + the calibrated soft-404 profile into a "is this a real,
// distinct resource?" verdict, discriminating a genuine dir-redirect / forbidden
// resource from a blanket soft-404 by Location and body size, not status alone.

#include "content_discovery.hpp"

#include <QRegularExpression>

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

// Canonicalise a response body so a REFLECTIVE / templated soft-404 -- one that
// echoes the requested path ("The page /nl404abc was not found") and/or carries
// per-request noise (timestamps, hit counters, request ids) -- collapses to a
// single stable form. We mask the exact path we requested (and its last segment,
// since 404 pages often echo just the leaf) with a sentinel, then collapse every
// run of digits to one '0'. Two soft-404s for DIFFERENT paths then canonicalise
// identically, while a genuinely different resource does not. Pure.
QString canonicalizeBody(const QString &body, const QString &probePath) {
    QString s = body;
    if (!probePath.isEmpty()) {
        s.replace(probePath, QStringLiteral("\x01P\x01"));   // full path: distinctive, plain substring
        const QString seg = probePath.section('/', -1);     // the leaf segment
        if (!seg.isEmpty() && seg != probePath) {
            // Mask the leaf only at a WORD BOUNDARY, NOT as a bare substring: a short /
            // common leaf ("dev" from "/dev") otherwise mangles a boilerplate word
            // ("developer") on the probe side but not on the random-token calibration
            // side, so the two canonical bodies diverge and a STABLE soft-404 is
            // misclassified as a real resource (a false-positive flood on common paths).
            const QRegularExpression re(QStringLiteral("\\b") + QRegularExpression::escape(seg)
                                        + QStringLiteral("\\b"));
            if (re.isValid()) s.replace(re, QStringLiteral("\x01P\x01"));
        }
    }
    QString out;
    out.reserve(s.size());
    bool inDigits = false;
    for (const QChar ch : s) {
        if (ch.isDigit()) { if (!inDigits) { out += QLatin1Char('0'); inDigits = true; } }
        else { out += ch; inDigits = false; }
    }
    return out;
}

// A stable 64-bit fingerprint of a (canonicalised) body. FNV-1a over the UTF-8
// bytes -- deliberately NOT qHash(QString), which in Qt6 is randomly seeded per
// process and so would never match across the calibration and probe responses.
quint64 bodyFingerprint(const QString &canonicalBody) {
    const QByteArray b = canonicalBody.toUtf8();
    quint64 h = 1469598103934665603ULL;                      // FNV-1a offset basis
    for (unsigned char c : b) { h ^= c; h *= 1099511628211ULL; }   // FNV-1a prime
    return h;
}

QString classify(int status, int bodyLen, const QString &location, const CalibProfile &cal,
                 quint64 candBodyHash, bool candHasHash) {
    const int st = status;

    // Redirects. A real directory commonly redirects (/admin -> /admin/), so a
    // soft-404 that ALSO redirects (e.g. everything -> /login) must not mask it:
    // suppress only when the status is a soft status AND the target matches the
    // calibrated soft-404 redirect target.
    if (st == 301 || st == 302 || st == 303 || st == 307 || st == 308) {
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
        // 200-soft-404 server. When a RELIABLE path-masked body fingerprint exists
        // (both calibration probes canonicalised to the same body), it is
        // authoritative and the length band is bypassed: a candidate whose masked
        // body matches the soft page IS the soft-404 -- whatever its length (this
        // kills the reflective-404 false-positive flood where the echoed path makes
        // every candidate's length differ); a candidate whose masked body DIFFERS
        // is a real resource -- even at the soft-404's exact length (this catches
        // the same-length real resource the length band silently dropped).
        if (cal.haveBodyHash && candHasHash)
            return candBodyHash == cal.softBodyHash ? QString() : QStringLiteral("ok-distinct");
        // No reliable fingerprint (e.g. un-maskable per-request variance) -> fall
        // back to the body-size band.
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
