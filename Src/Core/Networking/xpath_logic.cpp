// Pure, I/O-free helpers for the XPath injection probe: the error-signature
// matcher, the block-status classifier, and the CR/LF-guarded request builder.
// Kept in their OWN translation unit (separate from xpath_injection.cpp's test(),
// which pulls HttpClient and the networking/GUI chain) so the unit test can link
// this logic against Qt6::Core alone. Mirrors the ldap_logic.cpp hardening.

#include "xpath_injection.hpp"

#include <QRegularExpression>

namespace Nullock::Core::XpathInjection {

namespace {
constexpr int kMaxBody = 512 * 1024;

struct Sig { const char *engine; QRegularExpression re; };

const QList<Sig> &signatures() {
    static const auto ci = QRegularExpression::CaseInsensitiveOption;
    static const QList<Sig> s = {
        // Engine-specific class / method / module names -- a WAF block page won't
        // carry these, so they are trusted on ANY status.
        { "Java",    QRegularExpression("javax\\.xml\\.xpath|XPathExpressionException|"
                                        "net\\.sf\\.saxon|org\\.apache\\.xpath", ci) },
        // "XPathException" is the .NET class name (Java's distinctive form is
        // XPathExpressionException); attribute it to .NET so the engine label is
        // correct when both substrings could appear.
        { ".NET",    QRegularExpression("System\\.Xml\\.XPath|XPathException", ci) },
        { "PHP",     QRegularExpression("DOMXPath::(query|evaluate)|SimpleXMLElement::xpath|"
                                        "xpath_eval", ci) },
        { "Python",  QRegularExpression("lxml\\.etree\\.XPathEvalError|XPathEvalError", ci) },
        { "libxml2", QRegularExpression("xmlXPath|unregistered (function|variable)", ci) },
        // GENERIC, low-distinctiveness phrasings that a WAF/edge block page or a
        // non-XPath expression parser can also emit ("Error: XPath injection
        // blocked", "Invalid expression token"). These are gated on status (see
        // isBlockStatus) so a 4xx block page can't confirm.
        { "generic", QRegularExpression("(?:Warning|Error).{0,40}XPath|Invalid predicate|"
                                        "Invalid expression token|Expression must evaluate to a node-set", ci) },
    };
    return s;
}
} // namespace

// Match an XPath error in `body`; returns {engine, fragment} or empty.
QPair<QString, QString> matchError(const QByteArray &body) {
    const QString text = QString::fromUtf8(body.left(kMaxBody));
    for (const Sig &s : signatures()) {
        const auto m = s.re.match(text);
        if (m.hasMatch()) return { QString::fromUtf8(s.engine), m.captured(0) };
    }
    return {};
}

// A status that almost always means an edge/WAF block rather than a backend
// XPath error. A GENERIC-family match on one of these is rejected; an
// engine-specific fingerprint is trusted on any status.
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
    out += "User-Agent: Nullock/xpathi\r\n";
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

} // namespace Nullock::Core::XpathInjection
