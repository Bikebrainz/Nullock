// Pure crawler logic (see crawler_logic.hpp). No I/O; Qt6::Core only -- the
// Crawler QObject in crawler.cpp orchestrates the BFS and HTTP and calls these.

#include "crawler_logic.hpp"

#include <QRegularExpression>
#include <QSet>

namespace Nullock::Core::CrawlerLogic {

QByteArray truncateBodyAtTag(const QByteArray &body, int maxBytes) {
    if (maxBytes < 0 || body.size() <= maxBytes) return body;
    QByteArray head = body.left(maxBytes);
    const int lastGt = head.lastIndexOf('>');
    if (lastGt < 0) return QByteArray();          // no complete tag in range -> nothing safe to scan
    head.truncate(lastGt + 1);                    // keep through the last COMPLETE tag
    return head;
}

// Pick the matched alternative from a (double | single | unquoted) attribute
// capture: exactly one of groups 1/2/3 is non-null.
static QString attrValue(const QRegularExpressionMatch &m) {
    if (!m.captured(1).isNull()) return m.captured(1);
    if (!m.captured(2).isNull()) return m.captured(2);
    return m.captured(3);
}

QUrl resolveBase(const QString &html, const QUrl &pageUrl) {
    static const QRegularExpression rx(
        R"#(<base\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^"'\s>]+)))#",
        QRegularExpression::CaseInsensitiveOption);
    const auto m = rx.match(html);
    if (m.hasMatch()) {
        const QString href = attrValue(m).trimmed();
        if (!href.isEmpty()) {
            const QUrl b = pageUrl.resolved(QUrl(href));
            if (b.isValid() && !b.host().isEmpty()) return b;
        }
    }
    return pageUrl;
}

QStringList extractRawLinks(const QString &html) {
    // Quoted OR unquoted attribute values. The unquoted alternative stops at
    // whitespace or '>'. (data-href/xlink:href still match and yield the correct
    // URL value, which is harmless -- they are navigable.)
    static const QRegularExpression rx(
        R"#((?:href|src|action)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^"'\s>]+)))#",
        QRegularExpression::CaseInsensitiveOption);
    QStringList out;
    auto it = rx.globalMatch(html);
    while (it.hasNext()) {
        const QString v = attrValue(it.next()).trimmed();
        if (!v.isEmpty()) out << v;
    }
    return out;
}

QStringList extractSrcset(const QString &html) {
    static const QRegularExpression rx(
        R"#(\bsrcset\s*=\s*(?:"([^"]*)"|'([^']*)'|([^"'\s>]+)))#",
        QRegularExpression::CaseInsensitiveOption);
    QStringList out;
    auto it = rx.globalMatch(html);
    while (it.hasNext()) {
        const QString val = attrValue(it.next());
        for (const QString &cand : val.split(',', Qt::SkipEmptyParts)) {
            // each candidate is "URL [descriptor]" -- take the URL.
            const QString url = cand.trimmed().section(QLatin1Char(' '), 0, 0).trimmed();
            if (!url.isEmpty()) out << url;
        }
    }
    return out;
}

QStringList extractMetaRefresh(const QString &html) {
    static const QRegularExpression metaRx(R"#(<meta\b[^>]*>)#", QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression urlRx(R"#(\burl\s*=\s*['"]?([^'"\s;>]+))#", QRegularExpression::CaseInsensitiveOption);
    QStringList out;
    auto it = metaRx.globalMatch(html);
    while (it.hasNext()) {
        const QString tag = it.next().captured(0);
        if (!tag.contains(QLatin1String("refresh"), Qt::CaseInsensitive)) continue;
        const auto um = urlRx.match(tag);
        if (um.hasMatch()) out << um.captured(1).trimmed();
    }
    return out;
}

QStringList extractFormGets(const QString &html) {
    static const QRegularExpression formRx(R"#(<form\b([^>]*)>([\s\S]*?)</form>)#", QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression methodGet(R"#(\bmethod\s*=\s*["']?\s*get\b)#", QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression actionRx(R"#(\baction\s*=\s*(?:"([^"]*)"|'([^']*)'|([^"'\s>]+)))#", QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression nameRx(
        R"#(<(?:input|select|textarea)\b[^>]*\bname\s*=\s*(?:"([^"]*)"|'([^']*)'|([^"'\s>]+)))#",
        QRegularExpression::CaseInsensitiveOption);
    QStringList out;
    auto it = formRx.globalMatch(html);
    while (it.hasNext()) {
        const auto m = it.next();
        const QString attrs = m.captured(1);
        const QString body  = m.captured(2);
        if (!methodGet.match(attrs).hasMatch()) continue;   // GET forms only (a POST form isn't a URL surface)
        const auto am = actionRx.match(attrs);
        const QString action = am.hasMatch() ? attrValue(am).trimmed() : QString();
        QStringList names;
        auto nit = nameRx.globalMatch(body);
        while (nit.hasNext()) { const QString n = attrValue(nit.next()).trimmed(); if (!n.isEmpty()) names << n; }
        if (names.isEmpty()) continue;
        QString q;
        for (const QString &n : names) q += (q.isEmpty() ? "?" : "&") + n + "=";
        // action empty -> "?n1=&n2=" resolves against the page; else "action?...".
        out << action + q;
    }
    return out;
}

QString canonicalLink(const QString &href, const QUrl &base, QString &outHost) {
    outHost.clear();
    QUrl abs = base.resolved(QUrl(href));
    if (!abs.isValid() || abs.host().isEmpty()) return QString();
    const QString scheme = abs.scheme().toLower();
    if (scheme != QLatin1String("http") && scheme != QLatin1String("https"))
        return QString();                          // http(s)-only crawl
    abs.setFragment(QString());                    // fragments don't change the server view
    if (abs.path().isEmpty()) abs.setPath(QStringLiteral("/"));  // apex with/without slash -> one key
    outHost = abs.host();                          // Qt already lower-cases the host
    return abs.toString();
}

static QString apexOf(const QString &host) {
    QString h = host.toLower();
    if (h.startsWith(QLatin1String("www."))) h = h.mid(4);
    return h;
}

// An apex that is itself a PUBLIC SUFFIX (a bare TLD like "com", or a two-level
// suffix like "co.uk") must NOT be broadened with the endsWith("."+apex) test --
// that would scope the ENTIRE TLD (a fail-open the scope contract forbids). This
// arises when the seed is a "www.<public-suffix>" host (apexOf strips the "www."
// and exposes the suffix) or a bare-TLD seed. We ship no full PSL: the single-
// label check covers every TLD, and a curated set covers the common multi-level
// suffixes -- enough to keep the default scope fail-closed on realistic seeds.
static bool isPublicSuffix(const QString &apex) {
    if (!apex.contains(QLatin1Char('.'))) return true;   // a bare TLD label
    static const QSet<QString> twoLevel = {
        QStringLiteral("co.uk"),  QStringLiteral("org.uk"), QStringLiteral("gov.uk"),
        QStringLiteral("ac.uk"),  QStringLiteral("me.uk"),  QStringLiteral("net.uk"),
        QStringLiteral("com.au"), QStringLiteral("net.au"), QStringLiteral("org.au"),
        QStringLiteral("gov.au"), QStringLiteral("edu.au"), QStringLiteral("co.nz"),
        QStringLiteral("net.nz"), QStringLiteral("org.nz"), QStringLiteral("co.jp"),
        QStringLiteral("or.jp"),  QStringLiteral("ne.jp"),  QStringLiteral("go.jp"),
        QStringLiteral("co.za"),  QStringLiteral("org.za"), QStringLiteral("com.br"),
        QStringLiteral("net.br"), QStringLiteral("com.cn"), QStringLiteral("net.cn"),
        QStringLiteral("org.cn"), QStringLiteral("gov.cn"), QStringLiteral("co.in"),
        QStringLiteral("com.mx"), QStringLiteral("com.tr"), QStringLiteral("com.sg"),
    };
    return twoLevel.contains(apex);
}

bool inDefaultScope(const QString &host, const QString &seedHost) {
    if (host.isEmpty() || seedHost.isEmpty()) return false;
    const QString h = host.toLower();
    const QString seed = seedHost.toLower();
    if (h == seed) return true;
    const QString apex = apexOf(seed);
    // If the apex collapsed to a public suffix (e.g. a "www.<tld>" seed), only the
    // exact seed host is in scope -- broadening here would crawl the whole TLD.
    // Fail closed, per the .hpp "never broader than the seed's registrable domain".
    if (isPublicSuffix(apex)) return false;
    return h == apex || h.endsWith(QLatin1Char('.') + apex);
}

int effectivePort(const QString &scheme, int port) {
    if (port > 0) return port;                       // explicit port wins (QUrl::port(-1) gives -1 when absent)
    return scheme.compare(QLatin1String("https"), Qt::CaseInsensitive) == 0 ? 443 : 80;
}

bool inDefaultScopeOrigin(const QString &scheme, const QString &host, int port,
                          const QString &seedScheme, const QString &seedHost, int seedPort) {
    // Host dimension first: never broader than the seed's domain tree.
    if (!inDefaultScope(host, seedHost)) return false;
    const int ep  = effectivePort(scheme, port);
    const int sep = effectivePort(seedScheme, seedPort);
    const auto isStdWeb = [](int p) { return p == 80 || p == 443; };
    // Seed on a standard web port (80/443): admit ANY standard-web port on the
    // in-tree host -- so an http<->https hop on the same site (the redirect case)
    // stays in scope -- but REFUSE a non-standard port. A service answering on
    // :8080 / :8443 / :3000 that merely shares the hostname is a different
    // application, and walking it is scope creep (a real engagement violation).
    if (isStdWeb(sep)) return isStdWeb(ep);
    // Seed pinned to a NON-standard port (e.g. an app on :8080): stay on exactly
    // that port -- neither the standard web ports nor another high port are in
    // scope by default.
    return ep == sep;
}

} // namespace Nullock::Core::CrawlerLogic
