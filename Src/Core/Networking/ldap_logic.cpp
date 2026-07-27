// Pure, I/O-free helpers for the LDAP injection probe: the error-signature
// matcher, the block-status classifier, and the CR/LF-guarded request builder.
// Kept in their OWN translation unit (separate from ldap_injection.cpp's test(),
// which pulls HttpClient and the networking/GUI chain) so the unit test can link
// this logic against Qt6::Core alone.

#include "ldap_injection.hpp"

#include <QRegularExpression>

namespace Nullock::Core::LdapInjection {

namespace {
constexpr int kMaxBody = 512 * 1024;

struct Sig { const char *engine; QRegularExpression re; };

const QList<Sig> &signatures() {
    static const auto ci = QRegularExpression::CaseInsensitiveOption;
    static const QList<Sig> s = {
        { "Java/JNDI", QRegularExpression("javax\\.naming\\.|com\\.sun\\.jndi\\.ldap|"
                                          "org\\.springframework\\.ldap|"
                                          "InvalidSearchFilterException|LDAPException", ci) },
        { ".NET",      QRegularExpression("System\\.DirectoryServices|DirectoryServicesCOMException|"
                                          "DirectoryEntry", ci) },
        { "PHP",       QRegularExpression("ldap_(search|bind|list|read|modify|add|delete)\\s*\\(\\)|"
                                          "supplied argument is not a valid ldap", ci) },
        { "Python",   QRegularExpression("ldap\\.(FILTER_ERROR|INVALID_SYNTAX|OPERATIONS_ERROR|"
                                          "INVALID_DN_SYNTAX)|python-ldap", ci) },
        // Generic LDAP error phrasings. The bare "LDAP error" alternative was
        // removed: it matched WAF/edge block pages ("LDAP injection blocked")
        // with no real backend filter break (a false positive). The remaining
        // phrasings are distinctive backend wordings (incl. AD's "search filter
        // is invalid"); generic-only matches are additionally gated on status
        // (see isBlockStatus) so a 4xx block page can't confirm.
        { "generic",  QRegularExpression("Bad search filter|Invalid DN syntax|invalid search filter|"
                                          "search filter is invalid|LDAP: error code", ci) },
    };
    return s;
}
} // namespace

// Match an LDAP error in `body`; returns {engine, fragment} or empty.
QPair<QString, QString> matchError(const QByteArray &body) {
    const QString text = QString::fromUtf8(body.left(kMaxBody));
    for (const Sig &s : signatures()) {
        const auto m = s.re.match(text);
        if (m.hasMatch()) return { QString::fromUtf8(s.engine), m.captured(0) };
    }
    return {};
}

// A status that almost always means an edge/WAF block or rate-limit rather than
// a backend LDAP error. A GENERIC-family match on one of these is rejected (a
// block page mentioning "LDAP" is not a filter break); an engine-specific
// fingerprint -- which a block page won't carry -- is trusted on any status.
bool isBlockStatus(int status) {
    return status == 403 || status == 406 || status == 429
        || status == 451 || status == 501 || status == 503;
}

// Build the raw request, CR/LF-guarding method/host/path (returns {} if any is
// tainted, e.g. an attacker-crafted method from a HAR import reaching the deep
// audit) and dropping any CR/LF-bearing carried header.
QByteArray buildRequest(const Request &req, const QString &query) {
    if (req.method.contains('\r')   || req.method.contains('\n'))   return {};
    if (req.host.contains('\r')     || req.host.contains('\n'))     return {};
    if (req.basePath.contains('\r') || req.basePath.contains('\n')) return {};
    const QString target = query.isEmpty() ? req.basePath : req.basePath + "?" + query;
    if (target.contains('\r') || target.contains('\n')) return {};   // guard the spliced query
    QByteArray out;
    out  = req.method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/ldapi\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

} // namespace Nullock::Core::LdapInjection
