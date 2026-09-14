#include "response_header_values.hpp"

#include <QStringList>

namespace Nullock::Core::ResponseHeaderValues {
namespace {
QString trimHttpWhitespace(QString value) {
    qsizetype first = 0, end = value.size();
    auto whitespace = [](QChar c) { return c == ' ' || c == '\t'; };
    while (first < end && whitespace(value[first])) ++first;
    while (end > first && whitespace(value[end - 1])) --end;
    return value.mid(first, end - first);
}

QString asciiLower(QString value) {
    for (QChar &c : value)
        if (c >= 'A' && c <= 'Z') c = QChar(c.unicode() + ('a' - 'A'));
    return value;
}
}

bool nosniffForScriptsAndStyles(const Headers &headers) {
    for (const auto &h : headers) {
        if (h.first.compare("X-Content-Type-Options", Qt::CaseInsensitive) != 0) continue;
        return asciiLower(trimHttpWhitespace(h.second.section(',', 0, 0))) == "nosniff";
    }
    return false;
}

bool nosniffForDocuments(const Headers &headers) {
    bool found = false;
    for (const auto &h : headers) {
        if (h.first.compare("X-Content-Type-Options", Qt::CaseInsensitive) != 0) continue;
        if (found || asciiLower(trimHttpWhitespace(h.second)) != "nosniff") return false;
        found = true;
    }
    return found;
}

QString referrerPolicy(const Headers &headers) {
    static const QStringList known = {"no-referrer", "no-referrer-when-downgrade",
        "same-origin", "origin", "strict-origin", "origin-when-cross-origin",
        "strict-origin-when-cross-origin", "unsafe-url"};
    QString effective;
    for (const auto &h : headers) {
        if (h.first.compare("Referrer-Policy", Qt::CaseInsensitive) != 0) continue;
        for (const auto &part : h.second.split(',')) {
            const QString token = asciiLower(trimHttpWhitespace(part));
            // Malformed syntax invalidates the response header, unlike an
            // unknown future policy keyword. Do not recognize quoted substrings.
            for (QChar c : token)
                if (c != '-' && (c < 'a' || c > 'z')) return {};
            if (known.contains(token)) effective = token;
        }
    }
    return effective;
}
}
