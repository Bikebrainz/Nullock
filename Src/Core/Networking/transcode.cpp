#include "transcode.hpp"

#include <QByteArray>
#include <QCryptographicHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QRegularExpression>

namespace Nullock::Core::Transcode {
namespace {

Result ok(const QString &out)  { Result r; r.ok = true;  r.output = out; return r; }
Result err(const QString &e)   { Result r; r.ok = false; r.error  = e;   return r; }

Result base64Encode(const QString &in, bool url) {
    const auto opt = url ? (QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals)
                         :  QByteArray::Base64Encoding;
    return ok(QString::fromLatin1(in.toUtf8().toBase64(opt)));
}
Result base64Decode(const QString &in, bool url) {
    const auto opt = (url ? QByteArray::Base64UrlEncoding : QByteArray::Base64Encoding)
                   | QByteArray::AbortOnBase64DecodingErrors;
    const auto res = QByteArray::fromBase64Encoding(in.trimmed().toLatin1(), opt);
    if (res.decodingStatus != QByteArray::Base64DecodingStatus::Ok)
        return err(QStringLiteral("not valid base64"));
    return ok(QString::fromUtf8(res.decoded));
}

Result urlEncode(const QString &in) {
    return ok(QString::fromLatin1(in.toUtf8().toPercentEncoding()));
}
Result urlDecode(const QString &in) {
    return ok(QString::fromUtf8(QByteArray::fromPercentEncoding(in.toUtf8())));
}

QString htmlEncode(const QString &in) {
    QString o; o.reserve(in.size());
    for (const QChar c : in) {
        switch (c.unicode()) {
            case '&': o += QLatin1String("&amp;");  break;
            case '<': o += QLatin1String("&lt;");   break;
            case '>': o += QLatin1String("&gt;");   break;
            case '"': o += QLatin1String("&quot;"); break;
            case '\'': o += QLatin1String("&#39;"); break;
            default:  o += c;
        }
    }
    return o;
}
Result htmlDecode(const QString &in) {
    auto replaceNumeric = [](QString s, const QRegularExpression &re, int base) {
        QString out; qsizetype last = 0;
        auto it = re.globalMatch(s);
        while (it.hasNext()) {
            const auto m = it.next();
            out += s.mid(last, m.capturedStart() - last);
            bool okc = false;
            const uint cp = m.captured(1).toUInt(&okc, base);
            if (okc && cp <= 0x10FFFFu) {
                if (cp <= 0xFFFFu) out += QChar(char16_t(cp));
                else { const char32_t u = cp; out += QString::fromUcs4(&u, 1); }
            } else {
                out += m.captured(0);
            }
            last = m.capturedEnd();
        }
        out += s.mid(last);
        return out;
    };
    static const QRegularExpression hexRe(QStringLiteral("&#[xX]([0-9a-fA-F]+);"));
    static const QRegularExpression decRe(QStringLiteral("&#(\\d+);"));
    QString o = in;
    o = replaceNumeric(o, hexRe, 16);
    o = replaceNumeric(o, decRe, 10);
    o.replace(QLatin1String("&lt;"), QLatin1String("<"))
     .replace(QLatin1String("&gt;"), QLatin1String(">"))
     .replace(QLatin1String("&quot;"), QLatin1String("\""))
     .replace(QLatin1String("&apos;"), QLatin1String("'"))
     .replace(QLatin1String("&amp;"), QLatin1String("&"));   // amp LAST
    return ok(o);
}

Result hexEncode(const QString &in) {
    return ok(QString::fromLatin1(in.toUtf8().toHex()));
}
Result hexDecode(const QString &in) {
    QString s = in.trimmed();
    s.remove(QLatin1Char(' ')).remove(QLatin1Char('\n'))
     .remove(QLatin1Char('\t')).remove(QLatin1Char('\r'));
    if (s.isEmpty()) return err(QStringLiteral("empty"));
    if (s.size() % 2 != 0) return err(QStringLiteral("hex length must be even"));
    static const QRegularExpression nonHex(QStringLiteral("[^0-9a-fA-F]"));
    if (s.contains(nonHex)) return err(QStringLiteral("contains non-hex characters"));
    return ok(QString::fromUtf8(QByteArray::fromHex(s.toLatin1())));
}

Result unicodeEscape(const QString &in) {
    QString o;
    for (const QChar c : in) {
        const ushort u = c.unicode();
        if (u >= 0x20 && u < 0x7F) o += c;
        else o += QStringLiteral("\\u%1").arg(u, 4, 16, QLatin1Char('0'));
    }
    return ok(o);
}
Result unicodeUnescape(const QString &in) {
    QString o; qsizetype i = 0;
    while (i < in.size()) {
        if (in[i] == QLatin1Char('\\') && i + 5 < in.size() + 1 && i + 1 < in.size()
            && in[i + 1] == QLatin1Char('u') && i + 6 <= in.size()) {
            const QString hex = in.mid(i + 2, 4);
            bool okc = false;
            const ushort cp = hex.toUShort(&okc, 16);
            if (okc && hex.size() == 4) { o += QChar(cp); i += 6; continue; }
        }
        o += in[i];
        ++i;
    }
    return ok(o);
}

Result rot13(const QString &in) {
    QString o = in;
    for (QChar &c : o) {
        if (c >= QLatin1Char('a') && c <= QLatin1Char('z'))
            c = QChar('a' + (c.unicode() - 'a' + 13) % 26);
        else if (c >= QLatin1Char('A') && c <= QLatin1Char('Z'))
            c = QChar('A' + (c.unicode() - 'A' + 13) % 26);
    }
    return ok(o);
}

QString b64urlDecodeStr(const QString &p, bool *good) {
    const auto res = QByteArray::fromBase64Encoding(
        p.toLatin1(), QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);
    *good = (res.decodingStatus == QByteArray::Base64DecodingStatus::Ok);
    return *good ? QString::fromUtf8(res.decoded) : QString();
}

Result jwtDecode(const QString &in) {
    const QStringList parts = in.trimmed().split(QLatin1Char('.'));
    if (parts.size() < 2)
        return err(QStringLiteral("not a JWT (need header.payload[.signature])"));
    bool gh = false, gp = false;
    const QString hdr = b64urlDecodeStr(parts.at(0), &gh);
    const QString pl  = b64urlDecodeStr(parts.at(1), &gp);
    if (!gh || !gp) return err(QStringLiteral("JWT header/payload is not valid base64url"));
    auto pretty = [](const QString &json) {
        QJsonParseError e;
        const auto d = QJsonDocument::fromJson(json.toUtf8(), &e);
        return e.error == QJsonParseError::NoError
            ? QString::fromUtf8(d.toJson(QJsonDocument::Indented)) : json;
    };
    QString out = QStringLiteral("=== HEADER ===\n") + pretty(hdr)
                + QStringLiteral("\n=== PAYLOAD ===\n") + pretty(pl);
    const QString alg = QJsonDocument::fromJson(hdr.toUtf8()).object().value("alg").toString();
    if (alg.compare(QLatin1String("none"), Qt::CaseInsensitive) == 0)
        out += QStringLiteral("\n\n[!] alg=none -- signature not verified; forgeable.");
    else if (alg.startsWith(QLatin1String("HS")))
        out += QStringLiteral("\n\n[i] HMAC (%1) -- brute-forceable if the secret is weak.").arg(alg);
    out += QStringLiteral("\n\n[i] Signature is NOT verified here (no key).");
    return ok(out);
}

Result hashOp(const QString &in, QCryptographicHash::Algorithm alg) {
    return ok(QString::fromLatin1(QCryptographicHash::hash(in.toUtf8(), alg).toHex()));
}

// --- smart-decode detectors ---
bool looksLikeJwt(const QString &s) {
    const QStringList p = s.trimmed().split(QLatin1Char('.'));
    if (p.size() != 3) return false;
    bool good = false;
    const QString hdr = b64urlDecodeStr(p.at(0), &good);
    if (!good) return false;
    QJsonParseError e;
    const auto d = QJsonDocument::fromJson(hdr.toUtf8(), &e);
    return e.error == QJsonParseError::NoError && d.isObject() && d.object().contains("alg");
}
bool looksLikeUrlEncoded(const QString &s) {
    static const QRegularExpression re(QStringLiteral("%[0-9a-fA-F]{2}"));
    return s.contains(re);
}
bool looksLikeHtml(const QString &s) {
    return s.contains(QLatin1String("&lt;")) || s.contains(QLatin1String("&gt;"))
        || s.contains(QLatin1String("&amp;")) || s.contains(QLatin1String("&#"));
}
bool looksLikeBase64(const QString &s) {
    const QString t = s.trimmed();
    if (t.size() < 8 || t.size() % 4 != 0) return false;
    static const QRegularExpression re(QStringLiteral("^[A-Za-z0-9+/]+={0,2}$"));
    if (!re.match(t).hasMatch()) return false;
    const auto res = QByteArray::fromBase64Encoding(
        t.toLatin1(), QByteArray::Base64Encoding | QByteArray::AbortOnBase64DecodingErrors);
    if (res.decodingStatus != QByteArray::Base64DecodingStatus::Ok || res.decoded.isEmpty())
        return false;
    // Require the decoded bytes to be mostly printable -- this both avoids false
    // positives on random text and disambiguates a pure-hex string (which would
    // base64-decode to binary) so it falls through to hex-decode.
    int printable = 0;
    for (const char c : res.decoded)
        if ((static_cast<unsigned char>(c) >= 0x20 && static_cast<unsigned char>(c) < 0x7F)
            || c == '\n' || c == '\t' || c == '\r') ++printable;
    return printable * 10 >= res.decoded.size() * 8;   // >= 80% printable
}
bool looksLikeHex(const QString &s) {
    QString t = s.trimmed();
    t.remove(QLatin1Char(' '));
    if (t.size() < 4 || t.size() % 2 != 0) return false;
    static const QRegularExpression nonHex(QStringLiteral("[^0-9a-fA-F]"));
    return !t.contains(nonHex);
}

} // namespace

QStringList operations() {
    return { QStringLiteral("base64-encode"), QStringLiteral("base64-decode"),
             QStringLiteral("base64url-encode"), QStringLiteral("base64url-decode"),
             QStringLiteral("url-encode"), QStringLiteral("url-decode"),
             QStringLiteral("html-encode"), QStringLiteral("html-decode"),
             QStringLiteral("hex-encode"), QStringLiteral("hex-decode"),
             QStringLiteral("unicode-escape"), QStringLiteral("unicode-unescape"),
             QStringLiteral("rot13"), QStringLiteral("jwt-decode"),
             QStringLiteral("md5"), QStringLiteral("sha1"),
             QStringLiteral("sha256"), QStringLiteral("sha512") };
}

Result apply(const QString &op, const QString &input) {
    const QString o = op.trimmed().toLower();
    if (o == QLatin1String("base64-encode"))    return base64Encode(input, false);
    if (o == QLatin1String("base64-decode"))    return base64Decode(input, false);
    if (o == QLatin1String("base64url-encode")) return base64Encode(input, true);
    if (o == QLatin1String("base64url-decode")) return base64Decode(input, true);
    if (o == QLatin1String("url-encode"))        return urlEncode(input);
    if (o == QLatin1String("url-decode"))        return urlDecode(input);
    if (o == QLatin1String("html-encode"))       return ok(htmlEncode(input));
    if (o == QLatin1String("html-decode"))       return htmlDecode(input);
    if (o == QLatin1String("hex-encode"))        return hexEncode(input);
    if (o == QLatin1String("hex-decode"))        return hexDecode(input);
    if (o == QLatin1String("unicode-escape"))    return unicodeEscape(input);
    if (o == QLatin1String("unicode-unescape"))  return unicodeUnescape(input);
    if (o == QLatin1String("rot13"))             return rot13(input);
    if (o == QLatin1String("jwt-decode"))        return jwtDecode(input);
    if (o == QLatin1String("md5"))    return hashOp(input, QCryptographicHash::Md5);
    if (o == QLatin1String("sha1"))   return hashOp(input, QCryptographicHash::Sha1);
    if (o == QLatin1String("sha256")) return hashOp(input, QCryptographicHash::Sha256);
    if (o == QLatin1String("sha512")) return hashOp(input, QCryptographicHash::Sha512);
    return err(QStringLiteral("unknown operation: %1").arg(op));
}

Result smartDecode(const QString &input, QStringList *chain) {
    QString cur = input;
    QStringList steps;
    for (int iter = 0; iter < 12; ++iter) {
        QString op;
        if (looksLikeJwt(cur))             op = QStringLiteral("jwt-decode");
        else if (looksLikeUrlEncoded(cur)) op = QStringLiteral("url-decode");
        else if (looksLikeHtml(cur))       op = QStringLiteral("html-decode");
        else if (looksLikeBase64(cur))     op = QStringLiteral("base64-decode");
        else if (looksLikeHex(cur))        op = QStringLiteral("hex-decode");
        else break;
        const Result r = apply(op, cur);
        if (!r.ok || r.output == cur) break;   // failed or made no progress
        steps << op;
        cur = r.output;
        if (op == QLatin1String("jwt-decode")) break;   // terminal
    }
    if (chain) *chain = steps;
    Result out;
    if (steps.isEmpty()) { out.ok = false; out.output = input; out.error = QStringLiteral("no encoding detected"); }
    else                 { out.ok = true;  out.output = cur; }
    return out;
}

QStringList identifyHash(const QString &input) {
    const QString s = input.trimmed();
    QStringList out;
    if (s.startsWith(QLatin1String("$2a$")) || s.startsWith(QLatin1String("$2b$"))
        || s.startsWith(QLatin1String("$2y$"))) { out << QStringLiteral("bcrypt"); return out; }
    if (s.startsWith(QLatin1String("$1$")))  { out << QStringLiteral("md5crypt");    return out; }
    if (s.startsWith(QLatin1String("$5$")))  { out << QStringLiteral("sha256crypt"); return out; }
    if (s.startsWith(QLatin1String("$6$")))  { out << QStringLiteral("sha512crypt"); return out; }
    if (s.startsWith(QLatin1String("$argon2"))) { out << QStringLiteral("argon2");   return out; }
    static const QRegularExpression hexOnly(QStringLiteral("^[0-9a-fA-F]+$"));
    if (!hexOnly.match(s).hasMatch()) return out;
    switch (s.size()) {
        case 32:  out << QStringLiteral("MD5") << QStringLiteral("NTLM") << QStringLiteral("MD4"); break;
        case 40:  out << QStringLiteral("SHA-1") << QStringLiteral("RIPEMD-160"); break;
        case 56:  out << QStringLiteral("SHA-224"); break;
        case 64:  out << QStringLiteral("SHA-256") << QStringLiteral("SHA3-256") << QStringLiteral("BLAKE2s"); break;
        case 96:  out << QStringLiteral("SHA-384"); break;
        case 128: out << QStringLiteral("SHA-512") << QStringLiteral("SHA3-512") << QStringLiteral("BLAKE2b"); break;
        default:  break;
    }
    return out;
}

} // namespace Nullock::Core::Transcode
