#include "intruder_rules.hpp"

#include "transcode.hpp"

#include <algorithm>

namespace Nullock::Core::IntruderRules {

QString applyRule(const QString &value, const Rule &rule) {
    const QString op = rule.op.trimmed().toLower();
    if (op.isEmpty()) return value;

    if (op == QLatin1String("prefix"))    return rule.arg + value;
    if (op == QLatin1String("suffix"))    return value + rule.arg;
    if (op == QLatin1String("uppercase")) return value.toUpper();
    if (op == QLatin1String("lowercase")) return value.toLower();
    if (op == QLatin1String("reverse")) {
        // Reverse by CODE POINT, not UTF-16 unit -- a naive std::reverse over
        // QChars swaps a surrogate pair into two lone surrogates, corrupting any
        // non-BMP payload char to U+FFFD on the wire.
        QList<uint> cps = value.toUcs4();
        std::reverse(cps.begin(), cps.end());
        QString s;
        s.reserve(cps.size());
        for (const uint cp : cps) { const char32_t u = cp; s.append(QString::fromUcs4(&u, 1)); }
        return s;
    }
    if (op == QLatin1String("match-replace")) {
        // arg = "find\x1freplace" (US-delimited so both halves can hold any
        // char, including spaces / '=' / newlines a payload might need).
        const int sep = rule.arg.indexOf(QChar(0x1f));
        if (sep < 0) return value;                 // malformed -> no-op
        const QString find = rule.arg.left(sep);
        if (find.isEmpty()) return value;          // never replace the empty string
        const QString repl = rule.arg.mid(sep + 1);
        QString s = value;
        s.replace(find, repl);
        return s;
    }

    // Everything else delegates to the Transcode workbench (base64-encode,
    // base64url-encode, url-encode, hex-encode, html-encode, unicode-escape,
    // rot13, md5, sha1, sha256, sha512, ...). A failed/unknown op leaves the
    // value unchanged so a payload can never silently disappear from the run.
    const Transcode::Result r = Transcode::apply(op, value);
    return r.ok ? r.output : value;
}

QString applyRules(const QString &value, const QList<Rule> &rules) {
    QString out = value;
    for (const Rule &r : rules) out = applyRule(out, r);
    return out;
}

QStringList operations() {
    // Local ops first, then the Transcode ops that make sense as a payload
    // transform: the encode/hash set, plus -- matching Burp's "Decode" payload
    // rule -- the DECODE inverse of each advertised reversible encode. Decode is
    // authored just as often as encode: payload lists frequently arrive
    // pre-encoded (a base64 wordlist, URL-/hex-encoded fuzz strings), and a
    // decode->transform->re-encode chain is a real workflow. The ops already
    // execute (applyRule delegates to Transcode::apply) and fail safe -- a decode
    // of non-decodable input is a no-op (line 46) -- so advertising them adds no
    // risk. Non-payload / non-standard decodes (jwt-decode's multi-line JSON,
    // octal/binary-decode whose encoders aren't advertised) stay unadvertised but
    // still run if named explicitly.
    return {
        QStringLiteral("prefix"), QStringLiteral("suffix"),
        QStringLiteral("uppercase"), QStringLiteral("lowercase"),
        QStringLiteral("reverse"), QStringLiteral("match-replace"),
        QStringLiteral("base64-encode"), QStringLiteral("base64url-encode"),
        QStringLiteral("url-encode"), QStringLiteral("hex-encode"),
        QStringLiteral("html-encode"), QStringLiteral("unicode-escape"),
        QStringLiteral("rot13"),
        QStringLiteral("base64-decode"), QStringLiteral("base64url-decode"),
        QStringLiteral("url-decode"), QStringLiteral("hex-decode"),
        QStringLiteral("html-decode"),
        QStringLiteral("md5"), QStringLiteral("sha1"),
        QStringLiteral("sha256"), QStringLiteral("sha512"),
    };
}

} // namespace Nullock::Core::IntruderRules
