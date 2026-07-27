#include "processor.hpp"

namespace Nullock::Core::Processor {
namespace {

QString urlEncodeAll(const QString &s) {
    QString o;
    for (const char c : s.toUtf8()) {
        o += QLatin1Char('%');
        o += QStringLiteral("%1").arg(static_cast<uchar>(c), 2, 16, QLatin1Char('0')).toUpper();
    }
    return o;
}
QString doubleUrlEncode(const QString &s) {
    // Canonical double-encoding: url-encode, then re-encode only the '%' signs,
    // so %41 -> %2541 (a double-decoding stack collapses it back to the byte).
    QString once = urlEncodeAll(s);
    once.replace(QLatin1Char('%'), QStringLiteral("%25"));
    return once;
}
QString toggleCase(const QString &s) {
    QString o = s;
    bool up = true;
    for (QChar &c : o) {
        if (c.isLetter()) { c = up ? c.toUpper() : c.toLower(); up = !up; }
    }
    return o;
}
QString htmlHexEntities(const QString &s) {
    // Iterate CODE POINTS (toUcs4), not UTF-16 code units -- emitting one entity
    // per code unit turns a non-BMP payload char into two lone-surrogate refs an
    // HTML parser renders as U+FFFD U+FFFD, not the intended char.
    QString o;
    for (const uint cp : s.toUcs4())
        o += QStringLiteral("&#x%1;").arg(cp, 0, 16);
    return o;
}
QString htmlDecEntities(const QString &s) {
    QString o;
    for (const uint cp : s.toUcs4())
        o += QStringLiteral("&#%1;").arg(cp);
    return o;
}
QString unicodeEscape(const QString &s) {
    QString o;
    for (const QChar c : s)
        o += QStringLiteral("\\u%1").arg(c.unicode(), 4, 16, QLatin1Char('0'));
    return o;
}
QString spaceTo(const QString &s, const QString &rep) {
    QString o = s;
    o.replace(QLatin1Char(' '), rep);
    return o;
}

struct Def { const char *id; const char *note; QString (*fn)(const QString &); };

QString fUrl(const QString &s)      { return urlEncodeAll(s); }
QString fDbl(const QString &s)      { return doubleUrlEncode(s); }
QString fUpper(const QString &s)    { return s.toUpper(); }
QString fToggle(const QString &s)   { return toggleCase(s); }
QString fHex(const QString &s)      { return htmlHexEntities(s); }
QString fDec(const QString &s)      { return htmlDecEntities(s); }
QString fUni(const QString &s)      { return unicodeEscape(s); }
QString fComment(const QString &s)  { return spaceTo(s, QStringLiteral("/**/")); }
QString fTab(const QString &s)      { return spaceTo(s, QStringLiteral("%09")); }
QString fNewline(const QString &s)  { return spaceTo(s, QStringLiteral("%0a")); }
QString fPlus(const QString &s)     { return spaceTo(s, QStringLiteral("+")); }
QString fNul(const QString &s)      { return s + QStringLiteral("%00"); }

const Def kDefs[] = {
    { "url-encode-all",   "every byte %XX -- beats keyword/substring filters",   fUrl },
    { "double-url-encode","%XX -> %25XX -- for double-decoding stacks",           fDbl },
    { "uppercase",        "UPPER -- beats case-sensitive keyword blocklists",     fUpper },
    { "toggle-case",      "AlTeRnAtInG case -- same, but survives some lowercasers", fToggle },
    { "html-hex-entities","&#xHH; per char -- HTML-context / reflected sinks",    fHex },
    { "html-dec-entities","&#DD; per char -- HTML-context variant",               fDec },
    { "unicode-escape",   "\\uXXXX per char -- JS-string sinks",                  fUni },
    { "sql-comment-space","space -> /**/ -- SQL whitespace filters",              fComment },
    { "tab-for-space",    "space -> %09 -- whitespace-normalization gaps",        fTab },
    { "newline-for-space","space -> %0a -- whitespace-normalization gaps",        fNewline },
    { "plus-for-space",   "space -> + -- application/x-www-form-urlencoded",      fPlus },
    { "append-nullbyte",  "trailing %00 -- legacy null-byte truncation",          fNul },
};

} // namespace

QStringList transforms() {
    QStringList out;
    for (const auto &d : kDefs) out << QString::fromLatin1(d.id);
    return out;
}

Variant applyOne(const QString &id, const QString &payload) {
    for (const auto &d : kDefs)
        if (id == QLatin1String(d.id))
            return { QString::fromLatin1(d.id), d.fn(payload), QString::fromLatin1(d.note) };
    return { QStringLiteral("identity"), payload, QStringLiteral("unknown transform; unchanged") };
}

QList<Variant> process(const QString &payload) {
    QList<Variant> out;
    for (const auto &d : kDefs)
        out.append({ QString::fromLatin1(d.id), d.fn(payload), QString::fromLatin1(d.note) });
    return out;
}

} // namespace Nullock::Core::Processor
