// Pure, I/O-free helpers for the active CORS tester: the registrable-domain
// heuristic, the (origin,label) probe battery, and the CR/LF-guarded request
// builder. Kept in their OWN translation unit (separate from cors_tester.cpp's
// test(), which pulls HttpClient and thus the whole networking/GUI chain) so the
// unit test can link this logic against Qt6::Core alone.

#include "cors_tester.hpp"

#include <QByteArray>
#include <QSet>
#include <QStringList>

namespace Nullock::Core::CorsTester {

// Best-effort registrable domain (eTLD+1) WITHOUT a full Public Suffix List:
// the last two labels, unless those two are a known multi-label public suffix
// (co.uk, com.au, ...) in which case take three. Used only to synthesize the
// attacker-owned suffix probe origin below; a wrong guess merely yields an
// origin the target won't reflect (a missed test, never a false positive).
// Returns "" for IP literals and single-label / empty hosts -- those have no
// registrable domain an attacker could register a sibling of.
QString registrableDomain(const QString &host) {
    const QString h = host.trimmed().toLower();
    if (h.isEmpty()) return {};
    if (h.contains(':')) return {};                       // IPv6 literal / host:port
    const QStringList labels = h.split('.', Qt::SkipEmptyParts);
    if (labels.size() < 2) return {};                     // single label (localhost) / TLD only
    bool allNumeric = true;                               // IPv4 literal -> no domain
    for (const QString &l : labels) {
        for (const QChar c : l) if (!c.isDigit()) { allNumeric = false; break; }
        if (!allNumeric) break;
    }
    if (allNumeric) return {};
    static const QSet<QString> kTwoLabelSuffixes = {
        "co.uk","org.uk","gov.uk","ac.uk","me.uk","ltd.uk","plc.uk","net.uk",
        "com.au","net.au","org.au","edu.au","gov.au","id.au",
        "co.jp","ne.jp","or.jp","go.jp","ac.jp","ad.jp",
        "co.nz","net.nz","org.nz","govt.nz","ac.nz",
        "com.br","net.br","org.br","gov.br",
        "co.za","org.za","gov.za",
        "co.in","net.in","org.in","gov.in","firm.in",
        "com.mx","org.mx","gob.mx",
        "co.kr","or.kr","go.kr","ne.kr",
        "com.cn","net.cn","org.cn","gov.cn",
        "com.sg","com.hk","com.tw","com.tr","com.ar","com.pl","com.ua",
        "co.id","or.id","go.id","co.il","org.il","gov.il","co.th","in.th",
    };
    if (labels.size() >= 3) {
        const QString lastTwo = labels.at(labels.size() - 2) + "." + labels.last();
        if (kTwoLabelSuffixes.contains(lastTwo))
            return labels.at(labels.size() - 3) + "." + lastTwo;
    }
    return labels.at(labels.size() - 2) + "." + labels.last();
}

// The Origin battery (origin, label) for a target. attacker.example is
// reserved-for-docs and can never be a real allowed origin, so any reflection
// of it is a finding.
QList<QPair<QString, QString>> originSpecs(const QString &host, bool tls) {
    const QString target = host.trimmed();
    QList<QPair<QString, QString>> specs;
    specs << qMakePair(QStringLiteral("https://attacker.example"), QStringLiteral("arbitrary"));
    specs << qMakePair(QStringLiteral("null"), QStringLiteral("null"));
    // Naive contains/startsWith allow-list: target embedded as a PREFIX of an
    // attacker-controlled hostname.
    specs << qMakePair("https://" + target + ".attacker.example",
                       QStringLiteral("subdomain-suffix"));
    // Naive endsWith allow-list: an attacker-OWNED domain whose name ends with
    // the target's registrable domain. attacker-target.com ends with
    // "target.com" but NOT ".target.com", so it slips a bare
    // origin.endsWith("target.com") check while a correct dot-anchored compare
    // rejects it -- and it's a domain the attacker can actually register.
    const QString reg = registrableDomain(target);
    if (!reg.isEmpty())
        specs << qMakePair("https://attacker-" + reg, QStringLiteral("suffix-domain"));
    // FQDN root-dot: a host parser that strips the trailing dot before its
    // allow-list check, then reflects our raw dotted origin.
    specs << qMakePair(QStringLiteral("https://attacker.example."),
                       QStringLiteral("trailing-dot"));
    // The site's OWN host over the other scheme. NOT attacker-controlled, so
    // reflecting it is only exploitable from a network (MITM) position --
    // graded low, never critical, to avoid a false high.
    specs << qMakePair((tls ? QStringLiteral("http://") : QStringLiteral("https://")) + target,
                       QStringLiteral("scheme-swap"));
    return specs;
}

// Build the raw GET, guarding every attacker-influenceable field against CR/LF
// injection exactly as jwt_probe does: a tainted method/host/path/origin aborts
// the request (returns {}); a tainted header is dropped. Keeps a corrupted
// field from splitting the request or smuggling extra headers.
QByteArray buildRequest(const Request &req, const QString &origin) {
    if (req.method.contains('\r')   || req.method.contains('\n'))   return {};
    if (req.basePath.contains('\r') || req.basePath.contains('\n')) return {};
    if (req.host.contains('\r')     || req.host.contains('\n'))     return {};
    if (origin.contains('\r')       || origin.contains('\n'))       return {};
    QByteArray out;
    out  = req.method.toUtf8() + " " + req.basePath.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/cors-tester\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    out += "Origin: " + origin.toUtf8() + "\r\n";
    for (const auto &h : req.headers) {
        const QString k = h.first;
        if (k.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (k.compare("Origin", Qt::CaseInsensitive) == 0) continue;
        if (k.contains('\r') || k.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += k.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

} // namespace Nullock::Core::CorsTester
