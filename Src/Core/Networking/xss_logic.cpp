// Pure reflected-XSS logic, split out of xss_reflected.cpp so a unit test can
// link it (via Networking) against Qt6::Core alone -- test() and its HttpClient
// (the Qt6::Network chain, reached through Proxy::HttpResponse) stay in
// xss_reflected.cpp. Mirrors the established sibling pattern
// (http_fingerprint_logic.cpp, waf_detect_logic.cpp, ...). Everything here is
// I/O-free: HTML-context classification, the request builder, and query
// assembly operate on primitives (a body QString, a Content-Type string, the
// plain Request struct), never on a parsed response object.

#include "xss_reflected.hpp"
#include "response_header_values.hpp"

#include <QHash>
#include <QRegularExpression>
#include <QUrl>
#include <QUrlQuery>

namespace Nullock::Core::XssReflected {

namespace {
QString effectiveMediaType(const QString &value) {
    // Chromium keeps the last parseable value across repeated/comma-combined
    // fields. Commas inside quoted parameters do not start a new media type.
    QString effective;
    qsizetype start = 0;
    bool quoted = false, escaped = false;
    auto takeValue = [&](qsizetype end) {
        qsizetype first = start;
        while (first < end && (value[first] == ' ' || value[first] == '\t')) ++first;
        qsizetype last = first;
        while (last < end && value[last] != ' ' && value[last] != '\t'
               && value[last] != ';' && value[last] != '(') ++last;
        QString type = value.mid(first, last - first);
        // Values without a media type do not erase an earlier usable one.
        if (!type.contains('/')) return;
        while (end > first && (value[end - 1] == ' ' || value[end - 1] == '\t')) --end;
        // Chromium ignores a bare wildcard but retains one with parameters as
        // an unknown type, which can then be sniffed when nosniff is absent.
        if (type == "*/*" && last == end) return;
        for (QChar &c : type)
            if (c >= 'A' && c <= 'Z') c = QChar(c.unicode() + ('a' - 'A'));
        effective = type;
    };
    for (qsizetype i = 0; i < value.size(); ++i) {
        const QChar c = value[i];
        if (escaped) { escaped = false; continue; }
        if (quoted && c == '\\') { escaped = true; continue; }
        if (c == '"') { quoted = !quoted; continue; }
        if (c == ',' && !quoted) { takeValue(i); start = i + 1; }
    }
    takeValue(value.size());
    return effective;
}

bool maySniffHtml(const QString &type) {
    return type.isEmpty() || type == "unknown/unknown" || type == "application/unknown" || type == "*/*";
}

bool isHtmlMediaType(const QString &type) {
    return type == "text/html" || type == "application/xhtml+xml";
}
} // namespace

bool isHtmlContentType(const QString &contentType) {
    const QString type = effectiveMediaType(contentType);
    return maySniffHtml(type) || isHtmlMediaType(type);
}

bool canExecuteHtml(const QList<QPair<QString, QString>> &headers) {
    QStringList values;
    for (const auto &h : headers)
        if (h.first.compare("Content-Type", Qt::CaseInsensitive) == 0) values.append(h.second);
    const QString type = effectiveMediaType(values.join(", "));
    if (maySniffHtml(type)) return !ResponseHeaderValues::nosniffForDocuments(headers);
    return isHtmlMediaType(type);
}

namespace {
bool htmlSpace(QChar c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r';
}
bool tagDelimiter(QChar c) { return htmlSpace(c) || c == '/' || c == '>'; }
bool asciiLetter(QChar c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
QString asciiLower(QString text) {
    for (QChar &c : text)
        if (c >= 'A' && c <= 'Z') c = QChar(c.unicode() + ('a' - 'A'));
    return text;
}

struct ContextTag {
    QString name;
    QHash<QString, QString> attributes;
    bool closing = false;
    bool selfClosing = false;
    int end = -1;
};

// Only a complete token before the reflection changes context. Quotes open a
// quoted attribute value after '=', not in an unquoted value or an attribute name.
ContextTag contextTag(const QString &body, int start, int limit) {
    ContextTag tag;
    int i = start + 1;
    if (i < limit && body[i] == '/') { tag.closing = true; ++i; }
    if (i >= limit || !asciiLetter(body[i])) return tag;
    const int nameStart = i;
    while (i < limit && !tagDelimiter(body[i])) ++i;
    tag.name = asciiLower(body.mid(nameStart, i - nameStart));
    while (i < limit) {
        while (i < limit && htmlSpace(body[i])) ++i;
        if (i >= limit) break;
        if (body[i] == '>') { tag.end = i; return tag; }
        if (body[i] == '/') {
            if (++i < limit && body[i] == '>') {
                tag.selfClosing = true; tag.end = i; return tag;
            }
            continue;
        }
        const int attrStart = i++;
        while (i < limit && !tagDelimiter(body[i]) && body[i] != '=') ++i;
        const QString name = asciiLower(body.mid(attrStart, i - attrStart));
        while (i < limit && htmlSpace(body[i])) ++i;
        QString value;
        if (i < limit && body[i] == '=') {
            ++i;
            while (i < limit && htmlSpace(body[i])) ++i;
            if (i >= limit) break;
            const QChar quote = body[i];
            const bool quoted = quote == '"' || quote == '\'';
            if (quoted) ++i;
            const int valueStart = i;
            while (i < limit && (quoted ? body[i] != quote : !htmlSpace(body[i]) && body[i] != '>')) ++i;
            value = body.mid(valueStart, i - valueStart);
            if (quoted) {
                if (i >= limit) break;
                ++i;
            }
        }
        if (!tag.attributes.contains(name)) tag.attributes.insert(name, value);
    }
    return tag;
}

bool htmlAnnotationEncoding(const QString &value) {
    // The named character references in the accepted ASCII MIME types are
    // &sol; and &plus;. Numeric references can encode any of their characters. Decode once.
    static const QRegularExpression references("&(?:#([0-9]+);?|#[xX]([0-9a-fA-F]+);?|sol;|plus;)");
    QString decoded;
    qsizetype copied = 0;
    auto matches = references.globalMatch(value);
    while (matches.hasNext()) {
        const auto match = matches.next();
        decoded += value.mid(copied, match.capturedStart() - copied);
        bool ok = false;
        const uint code = match.captured(0) == "&plus;" ? uint('+')
            : match.captured(0) == "&sol;" ? uint('/')
            : !match.captured(1).isEmpty() ? match.captured(1).toUInt(&ok, 10)
                                          : match.captured(2).toUInt(&ok, 16);
        decoded += QChar((ok || code == '/' || code == '+') && code > 0 && code < 128 ? ushort(code) : ushort(0xfffd));
        copied = match.capturedEnd();
    }
    decoded += value.mid(copied);
    decoded = asciiLower(decoded);
    return decoded == "text/html" || decoded == "application/xhtml+xml";
}

enum class HtmlNamespace { Html, Svg, Math };
struct ContextElement {
    QString name;
    HtmlNamespace space = HtmlNamespace::Html;
    bool integration = false;
};
} // namespace

// A reduced context parser for the probe's reflected tag. Namespace transitions
// follow HTML's foreign-content rules; HTML templates keep their contents inert.
// This does not implement a full tree builder or prove arbitrary script execution.
// https://html.spec.whatwg.org/multipage/parsing.html#parsing-main-inforeign
bool inExecutingHtmlContext(const QString &body, int at) {
    static const QStringList rawText = {"script", "style", "textarea", "title", "xmp",
        "noscript", "noframes", "noembed", "iframe", "plaintext"};
    static const QStringList voidElements = {"area", "base", "basefont", "bgsound", "br", "col",
        "embed", "frame", "hr", "img", "input", "keygen", "link", "meta", "param", "source", "track", "wbr"};
    static const QStringList foreignBreakouts = {"b", "big", "blockquote", "body", "br", "center",
        "code", "dd", "div", "dl", "dt", "em", "embed", "h1", "h2", "h3", "h4", "h5", "h6",
        "head", "hr", "i", "img", "li", "listing", "menu", "meta", "nobr", "ol", "p", "pre",
        "ruby", "s", "small", "span", "strong", "strike", "sub", "sup", "table", "tt", "u", "ul", "var"};
    static const QStringList mathText = {"mi", "mo", "mn", "ms", "mtext"};
    QList<ContextElement> elements;
    QString openRaw;
    int scriptEscape = 0; // 0 = data, 1 = escaped, 2 = double escaped
    int templates = 0;
    const int limit = qMin(at, body.size());
    if (at < 0) return false;
    auto popTo = [&](int index) {
        while (elements.size() > index) {
            const auto element = elements.takeLast();
            if (element.space == HtmlNamespace::Html && element.name == "template") --templates;
        }
    };
    auto starts = [&](int i, const QString &text) {
        return asciiLower(body.mid(i, text.size())) == text;
    };
    for (int i = 0; i < limit; ++i) {
        if (!openRaw.isEmpty()) {
            if (openRaw == "plaintext") return false;
            if (openRaw == "script") {
                if (scriptEscape == 0 && body.mid(i, 4) == "<!--") { scriptEscape = 1; i += 3; continue; }
                if (scriptEscape && body.mid(i, 3) == "-->") { scriptEscape = 0; i += 2; continue; }
                if (scriptEscape == 1 && starts(i, "<script") && i + 7 < body.size()
                    && tagDelimiter(body[i + 7])) { scriptEscape = 2; i += 6; continue; }
                if (scriptEscape == 2) {
                    if (starts(i, "</script") && i + 8 < body.size() && tagDelimiter(body[i + 8])) {
                        scriptEscape = 1; i += 7;
                    }
                    continue;
                }
            }
            const QString close = "</" + openRaw;
            if (!starts(i, close) || i + close.size() >= body.size()
                || !tagDelimiter(body[i + close.size()])) continue;
            const auto tag = contextTag(body, i, limit);
            if (tag.end < 0) return false;
            i = tag.end;
            if (!elements.isEmpty()) popTo(elements.size() - 1);
            openRaw.clear(); scriptEscape = 0;
            continue;
        }
        if (body[i] != '<') continue;
        if (body.mid(i, 4) == "<!--") {
            if (body.mid(i, 5) == "<!-->") { i += 4; continue; }
            if (body.mid(i, 6) == "<!--->") { i += 5; continue; }
            int end = body.indexOf("-->", i + 4), width = 3;
            const int abrupt = body.indexOf("--!>", i + 4);
            if (abrupt >= 0 && (end < 0 || abrupt < end)) { end = abrupt; width = 4; }
            if (end < 0 || end + width > limit) return false;
            i = end + width - 1;
            continue;
        }
        const bool foreign = !elements.isEmpty() && elements.last().space != HtmlNamespace::Html;
        if (foreign && !elements.last().integration && body.mid(i, 9) == "<![CDATA[") {
            const int end = body.indexOf("]]>", i + 9);
            if (end < 0 || end + 3 > limit) return false;
            i = end + 2; continue;
        }
        if (i + 1 < body.size() && (body[i + 1] == '!' || body[i + 1] == '?')) {
            const int end = body.indexOf('>', i + 2);
            if (end < 0 || end >= limit) return false;
            i = end; continue;
        }
        // Invalid end-tag openings become bogus comments, not literal '<' text.
        if (i + 2 < body.size() && body[i + 1] == '/' && !asciiLetter(body[i + 2])) {
            const int end = body.indexOf('>', i + 2);
            if (end < 0 || end >= limit) return false;
            i = end; continue;
        }
        const auto tag = contextTag(body, i, limit);
        if (tag.name.isEmpty()) continue;
        if (tag.end < 0) return false;
        i = tag.end;
        bool html = !foreign || (!tag.closing && elements.last().integration
            && !(elements.last().space == HtmlNamespace::Math && mathText.contains(elements.last().name)
                 && (tag.name == "mglyph" || tag.name == "malignmark")));
        if (foreign && !tag.closing && elements.last().space == HtmlNamespace::Math
            && elements.last().name == "annotation-xml" && tag.name == "svg") html = true;
        const bool breakout = tag.closing ? tag.name == "br" || tag.name == "p"
            : foreignBreakouts.contains(tag.name) || (tag.name == "font"
                && (tag.attributes.contains("color") || tag.attributes.contains("face") || tag.attributes.contains("size")));
        if (!html && breakout) {
            while (!elements.isEmpty() && elements.last().space != HtmlNamespace::Html && !elements.last().integration)
                popTo(elements.size() - 1);
            html = true;
        }
        if (tag.closing) {
            for (int j = elements.size() - 1; j >= 0; --j) {
                if (elements[j].name == tag.name) { popTo(j); break; }
                // Unrelated end tags cannot cross a template's content boundary.
                if (elements[j].space == HtmlNamespace::Html && elements[j].name == "template") break;
            }
            continue;
        }
        HtmlNamespace space = html ? HtmlNamespace::Html : elements.last().space;
        if (html && tag.name == "svg") space = HtmlNamespace::Svg;
        if (html && tag.name == "math") space = HtmlNamespace::Math;
        const bool integration = (space == HtmlNamespace::Svg
                && (tag.name == "title" || tag.name == "desc" || tag.name == "foreignobject"))
            || (space == HtmlNamespace::Math && (mathText.contains(tag.name)
                || (tag.name == "annotation-xml" && htmlAnnotationEncoding(tag.attributes.value("encoding")))));
        if (space != HtmlNamespace::Html && tag.selfClosing) continue;
        if (space == HtmlNamespace::Html && voidElements.contains(tag.name)) continue;
        elements.append({tag.name, space, integration});
        if (space == HtmlNamespace::Html) {
            if (tag.name == "template") ++templates;
            if (rawText.contains(tag.name)) { openRaw = tag.name; scriptEscape = 0; }
        }
    }
    return openRaw.isEmpty() && templates == 0;
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
