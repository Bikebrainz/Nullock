#pragma once

// HTTP verb-tampering / method-based access-control bypass (CWE-650:
// Trusting HTTP Permission Methods on the Server Side). A very common
// real bug: an access rule is enforced on GET/POST but the framework
// still routes -- and serves -- HEAD, an alternate verb, a lower-cased
// method, or an X-HTTP-Method-Override'd request. We take a request that
// is currently DENIED (401/403/405) and retry it a dozen ways, flagging
// any that flip to a 2xx -- a confirmed authorization bypass. Burp has
// no native check for this.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::VerbTamper {

struct Bypass {
    QString technique;   // "method:HEAD", "override:X-HTTP-Method-Override", "method-case"
    QString detail;
    int     status = 0;
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString method = QStringLiteral("GET");
    QString basePath;
    QList<QPair<QString, QString>> headers;
    QByteArray body;
};

struct Result {
    int     baselineStatus = 0;
    bool    baselineDenied = false;   // baseline was 401/403/405
    QList<Bypass> bypasses;           // variants that flipped to 2xx
    int     requestsSent = 0;
    QString error;
};

// Probe the request with alternate methods, method-override headers, and
// method case-variation. Only meaningful when the baseline is denied;
// otherwise there's no access control to bypass (baselineDenied=false,
// no bypasses).
Result test(const Request &req);

} // namespace Nullock::Core::VerbTamper
