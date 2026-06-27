// Pure crawler logic (see crawler_logic.hpp). No I/O; Qt6::Core only -- the
// Crawler QObject in crawler.cpp orchestrates the BFS and HTTP and calls these.

#include "crawler_logic.hpp"

#include <QRegularExpression>

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

bool inDefaultScope(const QString &host, const QString &seedHost) {
    if (host.isEmpty() || seedHost.isEmpty()) return false;
    const QString h = host.toLower();
    const QString seed = seedHost.toLower();
    if (h == seed) return true;
    const QString apex = apexOf(seed);
    return h == apex || h.endsWith(QLatin1Char('.') + apex);
}

} // namespace Nullock::Core::CrawlerLogic
