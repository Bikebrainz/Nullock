// Pure update-check logic, split out of update_check.cpp so a unit test can link
// it against Qt6::Core alone -- doCheck()'s HttpClient I/O stays in update_check.cpp.
// compareSemver() decides whether a newer release exists; isTrustedReleaseUrl()
// gates the link the UI surfaces. Both are deterministic functions of strings.

#include "update_check.hpp"

#include <QStringList>
#include <QUrl>

namespace Nullock::Core::UpdateLogic {

namespace {

struct SemverParts {
    QList<int> nums;   // major/minor/patch (padded to 3)
    QString    pre;    // pre-release identifiers after '-' ("" when a normal release)
};

SemverParts parseSemver(QString s) {
    SemverParts r;
    s = s.trimmed();
    if (s.startsWith('v') || s.startsWith('V')) s = s.mid(1);
    // Build metadata (+...) does NOT affect precedence (semver §10) -- strip first.
    const int plus = s.indexOf('+');
    if (plus >= 0) s = s.left(plus);
    QString core = s;
    const int dash = s.indexOf('-');
    if (dash >= 0) { core = s.left(dash); r.pre = s.mid(dash + 1); }
    for (const QString &p : core.split('.', Qt::SkipEmptyParts)) {
        bool ok = false;
        const int v = p.toInt(&ok);
        r.nums.append(ok ? v : 0);          // a non-numeric / overflowing field -> 0
    }
    while (r.nums.size() < 3) r.nums.append(0);
    return r;
}

// Compare two pre-release strings per semver §11. An EMPTY pre-release outranks a
// non-empty one (a normal release > its own pre-release, e.g. 1.3.0 > 1.3.0-rc1).
int comparePre(const QString &a, const QString &b) {
    if (a.isEmpty() && b.isEmpty()) return 0;
    if (a.isEmpty()) return 1;              // a is a release, b a pre-release -> a > b
    if (b.isEmpty()) return -1;
    // A semver numeric identifier is "only digits" and compares NUMERICALLY. Detect
    // it structurally (all-digits) and compare as an arbitrary-precision decimal --
    // NOT via toInt(), which overflows to 0 / fails on a >INT_MAX identifier and then
    // falls through to a lexical compare that inverts the order (9999999999 vs
    // 10000000000 -> '9' > '1'). No overflow, spec-correct.
    auto allDigits = [](const QString &s) {
        if (s.isEmpty()) return false;
        for (const QChar c : s) if (c < QLatin1Char('0') || c > QLatin1Char('9')) return false;
        return true;
    };
    auto cmpNumeric = [](const QString &x, const QString &y) -> int {   // both all-digits
        int xi = 0; while (xi + 1 < x.size() && x[xi] == QLatin1Char('0')) ++xi;   // strip leading zeros
        int yi = 0; while (yi + 1 < y.size() && y[yi] == QLatin1Char('0')) ++yi;
        const QStringView xs = QStringView(x).mid(xi), ys = QStringView(y).mid(yi);
        if (xs.size() != ys.size()) return xs.size() < ys.size() ? -1 : 1;         // longer -> larger
        const int c = xs.compare(ys);
        return c < 0 ? -1 : (c > 0 ? 1 : 0);
    };
    const QStringList ai = a.split('.', Qt::SkipEmptyParts);
    const QStringList bi = b.split('.', Qt::SkipEmptyParts);
    const int n = qMin(ai.size(), bi.size());
    for (int i = 0; i < n; ++i) {
        const bool xn = allDigits(ai[i]);
        const bool yn = allDigits(bi[i]);
        if (xn && yn) { const int c = cmpNumeric(ai[i], bi[i]); if (c != 0) return c; }  // both numeric
        else if (xn != yn) return xn ? -1 : 1;                        // numeric identifiers rank below alphanumeric
        else { const int c = ai[i].compare(bi[i]); if (c != 0) return c < 0 ? -1 : 1; }  // ASCII order
    }
    if (ai.size() != bi.size()) return ai.size() < bi.size() ? -1 : 1;  // more identifiers -> greater
    return 0;
}

} // namespace

int compareSemver(const QString &a, const QString &b) {
    const SemverParts pa = parseSemver(a);
    const SemverParts pb = parseSemver(b);
    for (int i = 0; i < 3; ++i)
        if (pa.nums[i] != pb.nums[i]) return pa.nums[i] < pb.nums[i] ? -1 : 1;
    return comparePre(pa.pre, pb.pre);
}

bool isTrustedReleaseUrl(const QString &url) {
    // Defense-in-depth: only surface an HTTPS github.com release page. The response
    // comes from api.github.com over verified TLS, but validating the field before
    // the chrome opens it means a tampered/unexpected value can't hand the UI a
    // javascript:/file:/http: link.
    const QUrl u(url.trimmed());
    if (!u.isValid()) return false;
    if (u.scheme().compare(QLatin1String("https"), Qt::CaseInsensitive) != 0) return false;
    const QString host = u.host().toLower();
    return host == QLatin1String("github.com") || host.endsWith(QLatin1String(".github.com"));
}

bool noUpdateRequested(const QString &envValue) {
    const QString v = envValue.trimmed().toLower();
    if (v.isEmpty()) return false;
    // Explicitly-false spellings. Treating "set at all" as true (what this used
    // to do) meant NULLOCK_NO_UPDATE=0 disabled the check -- a documented
    // contract the code contradicted, and the failure was silent: the user got
    // no update notice and no reason why.
    return !(v == QLatin1String("0")
          || v == QLatin1String("false")
          || v == QLatin1String("no")
          || v == QLatin1String("off"));
}

} // namespace Nullock::Core::UpdateLogic
