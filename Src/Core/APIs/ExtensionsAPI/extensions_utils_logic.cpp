#include "extensions_utils_logic.hpp"

#include <QByteArray>
#include <QCryptographicHash>
#include <QMap>
#include <QUrl>

namespace Nullock::Core::ExtUtils {

QString base64Encode(const QString &s) {
    return QString::fromLatin1(s.toUtf8().toBase64());
}

QString base64Decode(const QString &s) {
    return QString::fromUtf8(QByteArray::fromBase64(s.toUtf8()));
}

QString urlEncode(const QString &s) {
    // Percent-encode everything except the RFC 3986 unreserved set
    // (ALPHA / DIGIT / -._~). Nothing is left un-encoded implicitly, so the
    // result is safe as a query value or path segment.
    return QString::fromLatin1(s.toUtf8().toPercentEncoding());
}

QString urlDecode(const QString &s) {
    return QString::fromUtf8(QByteArray::fromPercentEncoding(s.toUtf8()));
}

QString hexEncode(const QString &s) {
    return QString::fromLatin1(s.toUtf8().toHex());
}

QString hexDecode(const QString &s) {
    // fromHex ignores whitespace between byte pairs; case-insensitive.
    return QString::fromUtf8(QByteArray::fromHex(s.toUtf8()));
}

QString htmlEncode(const QString &s) {
    QString out;
    out.reserve(s.size());
    for (const QChar c : s) {
        switch (c.unicode()) {
            case '&':  out += QLatin1String("&amp;");  break;
            case '<':  out += QLatin1String("&lt;");   break;
            case '>':  out += QLatin1String("&gt;");   break;
            case '"':  out += QLatin1String("&quot;"); break;
            case '\'': out += QLatin1String("&#39;");  break;
            default:   out += c;                       break;
        }
    }
    return out;
}

QString htmlDecode(const QString &s) {
    QString out;
    out.reserve(s.size());
    int i = 0;
    const int n = s.size();
    while (i < n) {
        if (s[i] != QLatin1Char('&')) { out += s[i++]; continue; }
        const int semi = s.indexOf(QLatin1Char(';'), i + 1);
        // A bare '&' with no terminating ';' within a short window is literal.
        if (semi < 0 || semi - i > 32) { out += s[i++]; continue; }
        const QString ent = s.mid(i + 1, semi - i - 1);   // between & and ;
        QChar decoded;
        bool ok = false;
        if (ent.startsWith(QLatin1Char('#'))) {
            const bool hex = ent.size() > 1
                             && (ent[1] == QLatin1Char('x') || ent[1] == QLatin1Char('X'));
            const QString digits = ent.mid(hex ? 2 : 1);
            uint code = digits.toUInt(&ok, hex ? 16 : 10);
            if (ok && code > 0 && code <= 0x10FFFF) decoded = QChar(code);
            else ok = false;
        } else {
            static const QMap<QString, QChar> named = {
                { QStringLiteral("amp"),  QLatin1Char('&')  },
                { QStringLiteral("lt"),   QLatin1Char('<')  },
                { QStringLiteral("gt"),   QLatin1Char('>')  },
                { QStringLiteral("quot"), QLatin1Char('"')  },
                { QStringLiteral("apos"), QLatin1Char('\'') },
                { QStringLiteral("nbsp"), QChar(0x00A0)     },
            };
            const auto it = named.constFind(ent);
            if (it != named.constEnd()) { decoded = it.value(); ok = true; }
        }
        if (ok) { out += decoded; i = semi + 1; }
        else    { out += s[i++]; }   // not a recognised entity: keep the '&' literal
    }
    return out;
}

static QString hashHex(const QString &s, QCryptographicHash::Algorithm algo) {
    return QString::fromLatin1(
        QCryptographicHash::hash(s.toUtf8(), algo).toHex());
}

QString sha256Hex(const QString &s) { return hashHex(s, QCryptographicHash::Sha256); }
QString sha1Hex(const QString &s)   { return hashHex(s, QCryptographicHash::Sha1); }
QString md5Hex(const QString &s)    { return hashHex(s, QCryptographicHash::Md5); }

} // namespace Nullock::Core::ExtUtils
