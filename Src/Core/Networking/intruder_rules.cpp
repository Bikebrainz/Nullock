#include "intruder_rules.hpp"

#include "transcode.hpp"

#include <QRegularExpression>
#include <QSet>
#include <algorithm>

namespace Nullock::Core::IntruderRules {

namespace {
// "Propername" / "ProperName": upper-case the FIRST code point; the rest is
// either lowered (lowerRest=true) or kept unchanged. Code-point safe (toUcs4) so
// a leading non-BMP glyph is upper-cased/copied whole, never split into
// surrogates. Matches the caseMod generator's proper-case semantics.
QString properCaseRule(const QString &s, bool lowerRest) {
    const QList<uint> cps = s.toUcs4();
    if (cps.isEmpty()) return s;
    const char32_t first = cps[0];
    QString out = QString::fromUcs4(&first, 1).toUpper();
    QString rest;
    for (int i = 1; i < cps.size(); ++i) { const char32_t u = cps[i]; rest += QString::fromUcs4(&u, 1); }
    out += lowerRest ? rest.toLower() : rest;
    return out;
}
} // namespace

QString applyRule(const QString &value, const Rule &rule) {
    return applyRule(value, rule, value);
}

QString applyRule(const QString &value, const Rule &rule, const QString &original) {
    const QString op = rule.op.trimmed().toLower();
    if (op.isEmpty()) return value;

    if (op == QLatin1String("add-raw-payload")) return value + original;
    if (op == QLatin1String("prefix"))    return rule.arg + value;
    if (op == QLatin1String("suffix"))    return value + rule.arg;
    if (op == QLatin1String("uppercase")) return value.toUpper();
    if (op == QLatin1String("lowercase")) return value.toLower();
    if (op == QLatin1String("propername"))      return properCaseRule(value, /*lowerRest=*/true);
    if (op == QLatin1String("propername-keep")) return properCaseRule(value, /*lowerRest=*/false);
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
    if (op == QLatin1String("regex-replace")) {
        // Burp's match/replace processing rule: match a REGEX and replace each
        // occurrence. arg = "pattern\x1freplacement" (US-delimited). The
        // replacement may reference captured groups Burp-style: $0 = whole match,
        // $1..$9 = groups, $$ = a literal '$'. A missing separator, an empty
        // pattern, or an INVALID regex leaves the value UNCHANGED (never vanish).
        const int sep = rule.arg.indexOf(QChar(0x1f));
        if (sep < 0) return value;
        const QString pat  = rule.arg.left(sep);
        const QString repl = rule.arg.mid(sep + 1);
        if (pat.isEmpty()) return value;
        const QRegularExpression re(pat);
        if (!re.isValid()) return value;               // malformed -> no-op
        QString out;
        qsizetype lastEnd = 0;
        auto it = re.globalMatch(value);
        int guard = 0;
        while (it.hasNext() && guard++ < 200000) {
            const QRegularExpressionMatch m = it.next();
            out += value.mid(lastEnd, m.capturedStart() - lastEnd);   // text before the match
            for (int i = 0; i < repl.size(); ++i) {                   // expand $-references
                if (repl[i] == QLatin1Char('$') && i + 1 < repl.size()) {
                    const QChar c = repl[i + 1];
                    if (c == QLatin1Char('$')) { out += QLatin1Char('$'); ++i; continue; }
                    if (c.isDigit())           { out += m.captured(c.digitValue()); ++i; continue; }
                }
                out += repl[i];
            }
            lastEnd = m.capturedEnd();
        }
        out += value.mid(lastEnd);                     // trailing text after the last match
        return out;
    }
    if (op == QLatin1String("url-encode-chars")) {
        // Burp's "URL-encode these characters" safety net: percent-encode ONLY
        // the characters listed in arg (byte-by-byte over their UTF-8 encoding),
        // leaving every other character verbatim. Distinct from url-encode,
        // which encodes the whole payload. An empty arg is a no-op. Membership
        // and encoding are CODE-POINT-safe: a non-BMP char in the set encodes
        // all of its UTF-8 bytes, and a non-target non-BMP char passes through
        // as its surrogate pair (never split).
        if (rule.arg.isEmpty()) return value;
        QSet<uint> targets;
        for (const uint cp : rule.arg.toUcs4()) targets.insert(cp);
        QString out;
        for (const uint cp : value.toUcs4()) {
            const char32_t u = cp;
            if (targets.contains(cp)) {
                const QByteArray bytes = QString::fromUcs4(&u, 1).toUtf8();
                for (const char c : bytes) {
                    const quint8 b = static_cast<quint8>(c);
                    out += QLatin1Char('%');
                    out += QStringLiteral("%1").arg(b, 2, 16, QLatin1Char('0')).toUpper();
                }
            } else {
                out += QString::fromUcs4(&u, 1);
            }
        }
        return out;
    }

    if (op == QLatin1String("substring") || op == QLatin1String("reverse-substring")) {
        // Burp "Substring" / "Reverse substring" payload-processing:
        //   substring          -> START offset (0-indexed) + optional length
        //                         (omitted length runs to the end);
        //   reverse-substring   -> END offset counted BACKWARDS from the end, and
        //                         length counted backwards from that end offset.
        // arg = "offset" or "offset,length". Operates by CODE POINT (a non-BMP
        // glyph is one unit, never split into surrogates). Indices clamp to the
        // string; an empty / out-of-range result leaves the value UNCHANGED (a
        // payload must never silently vanish from the run).
        const QStringList a = rule.arg.split(QLatin1Char(','));
        bool okOff = false;
        const int off = a.value(0).trimmed().toInt(&okOff);
        if (!okOff || off < 0) return value;                    // need a >= 0 offset
        bool okLen = false;
        const int lenArg = a.size() > 1 ? a.value(1).trimmed().toInt(&okLen) : -1;
        if (a.size() > 1 && (!okLen || lenArg < 0)) return value;  // malformed length -> no-op

        const QList<uint> cps = value.toUcs4();
        const int n = cps.size();
        int start = 0, count = 0;
        if (op == QLatin1String("substring")) {
            start = qMin(off, n);
            count = okLen ? qMin(lenArg, n - start) : (n - start);
        } else {
            const int end = qBound(0, n - off, n);              // window end (from start)
            count = okLen ? qMin(lenArg, end) : end;            // no length -> back to string start
            start = end - count;
        }
        if (count <= 0) return value;                           // empty -> no-op (never vanish)
        QString out;
        out.reserve(count);
        for (int i = start; i < start + count; ++i) {
            const char32_t u = cps[i];
            out.append(QString::fromUcs4(&u, 1));
        }
        return out;
    }

    // Everything else delegates to the Transcode workbench (base64-encode,
    // base64url-encode, url-encode, hex-encode, html-encode, unicode-escape,
    // rot13, md5, sha1, sha256, sha512, ...). A failed/unknown op leaves the
    // value unchanged so a payload can never silently disappear from the run.
    const Transcode::Result r = Transcode::apply(op, value);
    return r.ok ? r.output : value;
}

QString applyRules(const QString &value, const QList<Rule> &rules, bool *skipped) {
    if (skipped) *skipped = false;
    QString out = value;
    for (const Rule &r : rules) {
        if (r.op.trimmed().toLower() == QLatin1String("skip-if-matches")) {
            // Burp's "Skip if matches regex" processing rule: if the running
            // (transformed-so-far) value matches, the payload is DROPPED. Only
            // evaluated when the caller can honor a skip (skipped != nullptr);
            // for a plain transform caller it is a safe no-op so a payload never
            // silently vanishes on a path that can't drop it. An empty or invalid
            // pattern is a no-op (never skip on a malformed rule).
            if (skipped && !r.arg.isEmpty()) {
                const QRegularExpression re(r.arg);
                if (re.isValid() && re.match(out).hasMatch()) { *skipped = true; return out; }
            }
            continue;
        }
        out = applyRule(out, r, value);
    }
    return out;
}

QString applyRules(const QString &value, const QList<Rule> &rules) {
    return applyRules(value, rules, nullptr);
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
        QStringLiteral("propername"), QStringLiteral("propername-keep"),
        QStringLiteral("reverse"), QStringLiteral("match-replace"),
        QStringLiteral("regex-replace"), QStringLiteral("add-raw-payload"),
        QStringLiteral("substring"), QStringLiteral("reverse-substring"),
        QStringLiteral("url-encode-chars"), QStringLiteral("skip-if-matches"),
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
