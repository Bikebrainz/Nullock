#include "request_export.hpp"

#include <QJsonArray>
#include <QJsonDocument>
#include <QUrl>

namespace Nullock::Core::RequestExport {

namespace {

QList<QPair<QString, QString>> parseUrlencoded(const QString &s) {
    QList<QPair<QString, QString>> out;
    for (const QString &kv : s.split('&', Qt::SkipEmptyParts)) {
        const int eq = kv.indexOf('=');
        const QString k = eq >= 0 ? kv.left(eq) : kv;
        const QString v = eq >= 0 ? kv.mid(eq + 1) : QString();
        // application/x-www-form-urlencoded: '+' encodes a space. fromPercentEncoding
        // does NOT fold it, so decode it first -- else the reproduced form sends
        // "a+b" where the capture meant "a b".
        out.append({ QUrl::fromPercentEncoding(QString(k).replace('+', ' ').toUtf8()),
                     QUrl::fromPercentEncoding(QString(v).replace('+', ' ').toUtf8()) });
    }
    return out;
}

// Safe JS string literal (quoted) for embedding in <script>.
QString jsStr(const QString &s) {
    QString q = QString::fromUtf8(
        QJsonDocument(QJsonArray{ s }).toJson(QJsonDocument::Compact));
    q = q.mid(1, q.size() - 2);            // strip the [ ] around the string
    q.replace("<", "\\u003c");             // neutralize </script> and <!--
    return q;
}

bool looksUrlencoded(const QString &body) {
    const QString t = body.trimmed();
    if (t.isEmpty() || t.startsWith('{') || t.startsWith('[')) return false;
    if (t.contains(' ') || t.contains('\n') || t.contains('\t')) return false;
    return t.contains('=');
}

QString shq(const QString &s) {            // POSIX single-quote shell-escape
    QString out = s;
    out.replace("'", "'\\''");
    return "'" + out + "'";
}

} // namespace

QString csrfPoc(const QString &methodIn, const QString &url,
                const QString &contentType, const QString &body, QString &note) {
    QString method = methodIn.toUpper();
    if (method.isEmpty()) method = QStringLiteral("GET");
    const QUrl u(url);
    const QString action =
        u.adjusted(QUrl::RemoveQuery | QUrl::RemoveFragment).toString();
    const QString ct = contentType.toLower();

    auto fields = [](const QList<QPair<QString, QString>> &ps) {
        QString s;
        for (const auto &p : ps)
            s += "  <input type=\"hidden\" name=\"" + p.first.toHtmlEscaped()
               + "\" value=\"" + p.second.toHtmlEscaped() + "\">\n";
        return s;
    };

    QString h;
    h += "<!doctype html>\n<html>\n<head><meta charset=\"utf-8\"><title>CSRF PoC</title></head>\n<body>\n";
    h += "<!-- Nullock CSRF PoC -- auto-submits on load; host on an attacker-controlled page. -->\n";

    if (method == "GET") {
        h += "<form id=\"nlk\" action=\"" + action.toHtmlEscaped() + "\" method=\"GET\">\n";
        h += fields(parseUrlencoded(u.query(QUrl::FullyEncoded)));
        h += "</form>\n";
        note = "GET request -- auto-submitting form.";
    } else if (ct.contains("application/x-www-form-urlencoded")
               || (ct.isEmpty() && looksUrlencoded(body))) {
        h += "<form id=\"nlk\" action=\"" + action.toHtmlEscaped() + "\" method=\""
           + method.toHtmlEscaped() + "\">\n";
        h += fields(parseUrlencoded(body));
        h += "</form>\n";
        note = "Form-urlencoded body -- classic auto-submitting form CSRF.";
    } else if (ct.contains("multipart/form-data")) {
        h += "<form id=\"nlk\" action=\"" + action.toHtmlEscaped() + "\" method=\""
           + method.toHtmlEscaped() + "\" enctype=\"multipart/form-data\">\n</form>\n";
        note = "multipart/form-data -- form scaffold only; re-add the individual "
               "parts/files manually (the raw multipart body cannot be split reliably).";
    } else {
        const QString ctype = contentType.isEmpty()
            ? QStringLiteral("text/plain;charset=UTF-8") : contentType;
        h += "<script>\nfetch(" + jsStr(url) + ", {\n"
             "  method: " + jsStr(method) + ",\n"
             "  credentials: 'include',\n"
             "  headers: { 'Content-Type': " + jsStr(ctype) + " },\n"
             "  body: " + jsStr(body) + "\n"
             "});\n</script>\n";
        note = QString("Body content-type '%1' -- emitted a credentialed fetch() PoC. "
                       "A non-simple Content-Type triggers a CORS preflight the target "
                       "must permit; JSON endpoints that reject text/plain may not be "
                       "exploitable cross-site.").arg(ctype);
    }

    if (h.contains("id=\"nlk\""))
        h += "<script>document.getElementById('nlk').submit();</script>\n";
    h += "</body>\n</html>\n";
    return h;
}

QString curlCommand(const QString &methodIn, const QString &url,
                    const QList<QPair<QString, QString>> &headers,
                    const QString &body) {
    QString method = methodIn.toUpper();
    if (method.isEmpty()) method = QStringLiteral("GET");
    QString c = "curl";
    if (method != "GET" || !body.isEmpty()) c += " -X " + shq(method);   // shell-escape like every other field
    c += " " + shq(url);
    for (const auto &hh : headers) {
        const QString &n = hh.first;
        if (n.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;  // curl sets it
        if (n.compare("Host", Qt::CaseInsensitive) == 0) continue;            // derived from URL
        if (n.startsWith(':')) continue;                                      // HTTP/2 pseudo-headers
        c += " -H " + shq(n + ": " + hh.second);
    }
    if (!body.isEmpty()) c += " --data-raw " + shq(body);
    return c;
}

} // namespace Nullock::Core::RequestExport
