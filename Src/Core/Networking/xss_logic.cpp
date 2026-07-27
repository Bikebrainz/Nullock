// Pure reflected-XSS logic, split out of xss_reflected.cpp so a unit test can
// link it (via Networking) against Qt6::Core alone -- test() and its HttpClient
// (the Qt6::Network chain, reached through Proxy::HttpResponse) stay in
// xss_reflected.cpp. Mirrors the established sibling pattern
// (http_fingerprint_logic.cpp, waf_detect_logic.cpp, ...). Everything here is
// I/O-free: HTML-context classification, the request builder, and query
// assembly operate on primitives (a body QString, a Content-Type string, the
// plain Request struct), never on a parsed response object.

#include "xss_reflected.hpp"

#include <QUrl>
#include <QUrlQuery>

namespace Nullock::Core::XssReflected {

bool isHtmlContentType(const QString &contentTypeLower) {
    // Only HTML (or no Content-Type, which browsers may sniff as HTML) can
    // execute injected markup; a JSON/text/plain reflection is not XSS.
    return contentTypeLower.isEmpty()
        || contentTypeLower.contains("text/html")
        || contentTypeLower.contains("application/xhtml");
}

// Would "<marker>" at offset `at` be parsed as a start tag -- i.e. it's in
// normal element content, NOT inside a comment, a raw-text element, or an open
// tag's attributes? Only that position is exploitable; the rest reflect the
// brackets inertly. A reduced HTML5 tokenizer over body[0..at):
//   - tracks attribute QUOTING so only an UNQUOTED '>' ends a tag (a '>' inside
//     a quoted attribute value must NOT re-enter element content);
//   - treats script/style/textarea/title/xmp/noscript/noframes/noembed as
//     raw-text (a marker inside them is inert), and plaintext as irreversible
//     raw-text that never closes;
//   - closes a raw-text element on "</name" followed by a delimiter (not an
//     exact "</name>"), and closes a comment on "-->" or the bogus "--!>".
bool inExecutingHtmlContext(const QString &body, int at) {
    static const QStringList rawText = {
        "script", "style", "textarea", "title", "xmp", "noscript",
        "noframes", "noembed", "plaintext" };
    auto isDelim = [](QChar c) {
        return c == '>' || c == '/' || c == ' ' || c == '\t'
            || c == '\n' || c == '\f' || c == '\r';
    };
    QString openRaw;       // current raw-text element name, or empty
    bool inComment = false;
    bool inTag = false;    // between '<' and its (unquoted) '>'
    QChar quote = QChar(0); // active attribute-value quote inside a tag, or 0
    const int n = qMin(at, body.size());
    for (int i = 0; i < n; ++i) {
        if (inComment) {
            if (body.mid(i, 3) == QLatin1String("-->")) { inComment = false; i += 2; }
            else if (body.mid(i, 4) == QLatin1String("--!>")) { inComment = false; i += 3; }
            continue;
        }
        if (!openRaw.isEmpty()) {
            // plaintext is irreversible: nothing after it re-enters markup.
            if (openRaw == QLatin1String("plaintext")) continue;
            const QString close = "</" + openRaw;
            if (body.mid(i, close.size()).compare(close, Qt::CaseInsensitive) == 0) {
                const QChar d = (i + close.size() < body.size())
                                ? body[i + close.size()] : QChar('>');
                if (isDelim(d)) {
                    i += close.size() - 1;   // resume at the delimiter
                    openRaw.clear();
                    inTag = false;
                }
            }
            continue;
        }
        const QChar ch = body[i];
        if (inTag) {
            if (quote != QChar(0)) {
                if (ch == quote) quote = QChar(0);
            } else if (ch == '"' || ch == '\'') {
                quote = ch;
            } else if (ch == '>') {
                inTag = false;
            }
            continue;
        }
        // element content
        if (ch == '<') {
            if (body.mid(i, 4) == QLatin1String("<!--")) { inComment = true; i += 3; continue; }
            // Markup declaration ("<!...", e.g. <!DOCTYPE>, <![CDATA[...>, a bogus
            // "<!x=\">") or a PI-like "<?...": HTML tokenizes ALL of these as a
            // BOGUS COMMENT -- consume to the very next '>' with NO attribute
            // quote-tracking. Routing them through the tag branch lets a '"'
            // inside open a fake quoted value that swallows the terminating '>'
            // and hides a following <script> (a false negative). A '>' ends the
            // construct even inside a quoted DOCTYPE identifier (spec: the
            // abrupt-identifier parse error still emits the token there).
            if (i + 1 < body.size() && (body[i + 1] == '!' || body[i + 1] == '?')) {
                const int gt = body.indexOf('>', i + 1);
                if (gt < 0 || gt >= n) { inComment = true; break; }  // reaches past `at` -> at is inert
                i = gt;                                              // loop's ++i steps past '>'
                continue;
            }
            int j = i + 1;
            const bool closing = (j < body.size() && body[j] == '/');
            if (closing) ++j;
            // A tag name MUST start with an ASCII letter (HTML5 tag-open / end-tag-
            // open state). A '<' followed by a space, digit, '=', '<', etc. is a
            // parse error: the '<' is literal character DATA and the next char is
            // reconsumed in the data state. Opening a phantom tag here swallowed a
            // following reflected <marker> -- a false negative on bodies like
            // "1 < 2 <marker>" or "i <3 you <marker>".
            if (j >= body.size() || !body[j].isLetter()) continue;
            QString nameStr;
            while (j < body.size() && body[j].isLetterOrNumber()) { nameStr += body[j].toLower(); ++j; }
            if (!closing && rawText.contains(nameStr)) openRaw = nameStr;
            inTag = true;
            quote = QChar(0);
        }
        // a stray '>' in element content is inert text -- ignore.
    }
    return !inComment && openRaw.isEmpty() && !inTag;
}

QByteArray buildRequest(const Request &req, const QString &query) {
    // Self-protect the request line + Host against CR/LF regardless of caller:
    // a deep-audit path (HAR import / fromHistory) could carry a crafted
    // method/host/basePath, and the baseline query is spliced in raw.
    QString method = req.method; method.remove('\r'); method.remove('\n');
    QString host = req.host;     host.remove('\r'); host.remove('\n');
    QString basePath = req.basePath; basePath.remove('\r'); basePath.remove('\n');
    QString q = query; q.remove('\r'); q.remove('\n');
    const QString target = q.isEmpty() ? basePath : basePath + "?" + q;
    QByteArray out;
    out  = method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/xss\r\n";
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

QString queryWith(const QString &existing, const QString &param, const QString &value) {
    const QByteArray enc = QUrl::toPercentEncoding(value);
    QStringList parts;
    const QUrlQuery q(existing);
    for (const auto &kv : q.queryItems(QUrl::FullyEncoded))
        if (QUrl::fromPercentEncoding(kv.first.toUtf8()) != param)
            parts << kv.first + "=" + kv.second;
    parts << param + "=" + QString::fromUtf8(enc);
    return parts.join('&');
}

} // namespace Nullock::Core::XssReflected
