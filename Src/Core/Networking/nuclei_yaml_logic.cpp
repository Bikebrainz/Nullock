#include "nuclei_yaml_logic.hpp"

#include <QJsonArray>
#include <QStringList>

namespace Nullock::Core::NucleiYaml {

namespace {

// A significant (non-blank, non-comment) YAML line: its indent + trimmed text +
// the index of the raw source line it came from, so a block scalar can recover
// the exact bytes (blank lines, literal '#', indentation) from `raw`.
struct Line { int indent; QString text; int rawIdx; };

// Tokenized source: the significant lines plus the FULL raw line list
// (\r-chopped + tabs-expanded, but NOT comment-stripped and NOT blank-skipped)
// that block scalars read verbatim from.
struct Ctx { QList<Line> lines; QStringList raw; };

// Strip a trailing "# comment" that is not inside quotes, plus trailing space.
QString stripComment(const QString &raw) {
    bool inS = false, inD = false;
    for (int i = 0; i < raw.size(); ++i) {
        const QChar c = raw[i];
        if (c == '\'' && !inD) inS = !inS;
        else if (c == '"' && !inS) inD = !inD;
        else if (c == '#' && !inS && !inD && (i == 0 || raw[i - 1].isSpace()))
            return raw.left(i);
    }
    return raw;
}

Ctx tokenize(const QString &yaml) {
    Ctx ctx;
    const QStringList raw = yaml.split('\n');
    for (int idx = 0; idx < raw.size(); ++idx) {
        QString ln = raw[idx];
        ln.replace('\t', QStringLiteral("  "));        // tabs -> 2 spaces (lenient)
        if (ln.endsWith('\r')) ln.chop(1);             // CRLF inputs
        ctx.raw.append(ln);                            // keep the raw line for block scalars
        const QString noComment = stripComment(ln);
        const QString trimmed = noComment.trimmed();
        if (trimmed.isEmpty()) continue;
        if (trimmed == QStringLiteral("---")) continue; // doc separator
        int indent = 0;
        while (indent < noComment.size() && noComment[indent] == ' ') ++indent;
        ctx.lines.append({ indent, trimmed, idx });
    }
    return ctx;
}

QString unquote(const QString &s) {
    const QString t = s.trimmed();
    if (t.size() >= 2 &&
        ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith('\'') && t.endsWith('\'')))) {
        QString inner = t.mid(1, t.size() - 2);
        if (t.startsWith('"')) {
            inner.replace(QStringLiteral("\\\""), QStringLiteral("\""));
            inner.replace(QStringLiteral("\\\\"), QStringLiteral("\\"));
            inner.replace(QStringLiteral("\\n"), QStringLiteral("\n"));
            inner.replace(QStringLiteral("\\r"), QStringLiteral("\r"));
            inner.replace(QStringLiteral("\\t"), QStringLiteral("\t"));
        }
        return inner;
    }
    return t;
}

// A bare scalar -> number / bool / string.
QJsonValue scalar(const QString &raw) {
    const QString t = raw.trimmed();
    if (t.isEmpty()) return QJsonValue();
    if (t.startsWith('"') || t.startsWith('\'')) return unquote(t);
    if (t == QLatin1String("true"))  return true;
    if (t == QLatin1String("false")) return false;
    if (t == QLatin1String("null") || t == QLatin1String("~")) return QJsonValue();
    bool ok = false;
    const qlonglong n = t.toLongLong(&ok);
    if (ok) return static_cast<double>(n);
    return t;
}

// Parse a scalar or an inline "[a, b, c]" flow sequence.
QJsonValue scalarOrFlow(const QString &raw) {
    const QString t = raw.trimmed();
    if (t.startsWith('[') && t.endsWith(']')) {
        QJsonArray arr;
        const QString inner = t.mid(1, t.size() - 2).trimmed();
        if (!inner.isEmpty())
            for (const QString &part : inner.split(','))
                arr.append(scalar(part.trimmed()));
        return arr;
    }
    return scalar(t);
}

// Index of the ':' that separates a map key from its value ("key: value" or
// "key:"). Skips ':' inside quotes and requires the ':' to be followed by a
// space or end-of-line (so "http://x" in a value isn't mistaken for a key sep).
int keyColon(const QString &s) {
    bool inS = false, inD = false;
    for (int i = 0; i < s.size(); ++i) {
        const QChar c = s[i];
        if (c == '\'' && !inD) inS = !inS;
        else if (c == '"' && !inS) inD = !inD;
        else if (c == ':' && !inS && !inD &&
                 (i + 1 == s.size() || s[i + 1] == ' '))
            return i;
    }
    return -1;
}

// Is `rest` (the text after "key:") a block-scalar indicator? Sets `style`
// ('|' literal / '>' folded) and `chomp` ('-' strip / '+' keep / null = clip).
bool blockScalarIndicator(const QString &rest, QChar &style, QChar &chomp) {
    const QString t = rest.trimmed();
    if (t.isEmpty() || (t[0] != '|' && t[0] != '>')) return false;
    style = t[0];
    chomp = QChar();
    for (int k = 1; k < t.size(); ++k) {
        if (t[k] == '-' || t[k] == '+') chomp = t[k];
        else if (t[k].isDigit()) { /* explicit indent indicator: ignored */ }
        else return false;                             // trailing junk -> not a clean indicator
    }
    return true;
}

// Read a block scalar from the RAW lines starting at `start`, for a key at
// `keyIndent`. Preserves blank lines + literal '#' + relative indentation.
// Sets `endRaw` to the first raw line NOT part of the block.
QString readBlockScalar(const QStringList &raw, int start, int keyIndent,
                        QChar style, QChar chomp, int &endRaw) {
    QStringList block;                                 // raw block lines (blanks kept)
    int j = start;
    for (; j < raw.size(); ++j) {
        const QString &ln = raw[j];
        if (ln.trimmed().isEmpty()) { block.append(QString()); continue; }
        int ind = 0; while (ind < ln.size() && ln[ind] == ' ') ++ind;
        if (ind <= keyIndent) break;                   // dedent -> block ends
        block.append(ln);
    }
    endRaw = j;

    // Block indentation = least indent among the non-blank lines.
    int blockIndent = -1;
    for (const QString &ln : block) {
        if (ln.trimmed().isEmpty()) continue;
        int ind = 0; while (ind < ln.size() && ln[ind] == ' ') ++ind;
        blockIndent = (blockIndent < 0) ? ind : qMin(blockIndent, ind);
    }
    if (blockIndent < 0) return QString();             // all blank

    QStringList content;                               // dedented content lines
    for (const QString &ln : block)
        content.append(ln.size() >= blockIndent ? ln.mid(blockIndent) : QString());

    // Peel trailing blank lines, counting them for keep-chomping.
    int trailingBlanks = 0;
    while (!content.isEmpty() && content.last().isEmpty()) { content.removeLast(); ++trailingBlanks; }
    if (content.isEmpty()) return QString();

    QString body;
    if (style == '|') {                                // literal: newlines as-is
        body = content.join('\n');
    } else {                                           // folded: join lines with spaces, blank -> newline
        bool prevBlank = true;
        for (const QString &l : content) {
            if (l.isEmpty()) { body += '\n'; prevBlank = true; }
            else { if (!prevBlank) body += ' '; body += l; prevBlank = false; }
        }
    }
    if (chomp == '-') return body;                                       // strip
    if (chomp == '+') return body + QString(1 + trailingBlanks, '\n');   // keep all
    return body + '\n';                                                  // clip (default)
}

// Forward decl for mutual recursion.
QJsonValue parseBlock(Ctx &ctx, int &i, int indent, int &guard);

QJsonArray parseSeq(Ctx &ctx, int &i, int indent, int &guard) {
    QJsonArray arr;
    QList<Line> &lines = ctx.lines;
    while (i < lines.size() && lines[i].indent == indent
           && lines[i].text.startsWith('-') && guard-- > 0) {
        QString rest = lines[i].text.mid(1);           // after '-'
        if (rest.startsWith(' ')) rest = rest.mid(1);
        rest = rest.trimmed();
        const int contentIndent = indent + 2;
        if (rest.isEmpty()) {
            ++i;
            if (i < lines.size() && lines[i].indent > indent)
                arr.append(parseBlock(ctx, i, lines[i].indent, guard));
            else
                arr.append(QJsonValue());
        } else if (keyColon(rest) >= 0) {
            // Map item ("- key: val" + aligned keys). Rewrite this line as the
            // item's content at contentIndent so the whole map parses as one.
            lines[i] = { contentIndent, rest, lines[i].rawIdx };
            arr.append(parseBlock(ctx, i, contentIndent, guard));
        } else {
            // Scalar item ("- value" / "- 200" / "- \"quoted\"").
            arr.append(scalarOrFlow(rest));
            ++i;
        }
    }
    return arr;
}

QJsonObject parseMap(Ctx &ctx, int &i, int indent, int &guard) {
    QJsonObject obj;
    QList<Line> &lines = ctx.lines;
    while (i < lines.size() && lines[i].indent == indent
           && !lines[i].text.startsWith('-') && guard-- > 0) {
        const QString line = lines[i].text;
        const int c = keyColon(line);
        if (c < 0) { ++i; continue; }                  // not a map line; skip
        const QString key = unquote(line.left(c).trimmed());
        const QString rest = line.mid(c + 1).trimmed();
        QChar style, chomp;
        if (!rest.isEmpty() && blockScalarIndicator(rest, style, chomp)) {
            // Block scalar: read the RAW following lines (blanks + literal '#'
            // preserved), not the comment-stripped token stream.
            const int keyIndent = indent;
            const int startRaw = lines[i].rawIdx + 1;
            ++i;                                        // consume the "key: |" token
            int endRaw = startRaw;
            obj.insert(key, readBlockScalar(ctx.raw, startRaw, keyIndent, style, chomp, endRaw));
            // Skip any tokens whose source line fell inside the consumed block.
            while (i < lines.size() && lines[i].rawIdx < endRaw) ++i;
        } else if (!rest.isEmpty()) {
            obj.insert(key, scalarOrFlow(rest));
            ++i;
        } else {
            ++i;
            if (i < lines.size() && lines[i].indent > indent) {
                obj.insert(key, parseBlock(ctx, i, lines[i].indent, guard));
            } else if (i < lines.size() && lines[i].indent == indent
                       && lines[i].text.startsWith('-')) {
                // A sequence at the SAME indent as its key.
                obj.insert(key, parseSeq(ctx, i, indent, guard));
            } else {
                obj.insert(key, QJsonValue());
            }
        }
    }
    return obj;
}

QJsonValue parseBlock(Ctx &ctx, int &i, int indent, int &guard) {
    if (i >= ctx.lines.size() || guard <= 0) return QJsonValue();
    if (ctx.lines[i].text.startsWith('-') && ctx.lines[i].indent == indent)
        return parseSeq(ctx, i, indent, guard);
    return parseMap(ctx, i, indent, guard);
}

// ---- nuclei -> Nullock template mapping --------------------------------

QString firstPath(const QJsonValue &pathVal) {
    if (pathVal.isArray() && !pathVal.toArray().isEmpty())
        return pathVal.toArray().first().toString();
    if (pathVal.isString()) return pathVal.toString();
    return QString();
}

} // namespace

QJsonValue parseYaml(const QString &yaml) {
    Ctx ctx = tokenize(yaml);
    if (ctx.lines.isEmpty()) return QJsonValue();
    int i = 0;
    int guard = 100000;                                // bound pathological input
    return parseBlock(ctx, i, ctx.lines[0].indent, guard);
}

QJsonObject nucleiToTemplate(const QJsonValue &doc) {
    if (!doc.isObject()) return {};
    const QJsonObject root = doc.toObject();

    QJsonObject tpl;
    tpl.insert("id", root.value("id").toString());
    const QJsonObject info = root.value("info").toObject();
    tpl.insert("name", info.value("name").toString());
    tpl.insert("severity", info.value("severity").toString());

    // The request block: nuclei's "http" (new) or "requests" (old), first entry.
    QJsonValue httpVal = root.value("http");
    if (httpVal.isUndefined() || httpVal.isNull()) httpVal = root.value("requests");
    QJsonObject block;
    if (httpVal.isArray() && !httpVal.toArray().isEmpty())
        block = httpVal.toArray().first().toObject();
    else if (httpVal.isObject())
        block = httpVal.toObject();
    if (block.isEmpty()) return tpl;                   // matchers-less: still id/name

    // Matchers / extractors pass through -- the template engine already reads
    // nuclei field names (words/regex/status/patterns, part, condition, negative).
    if (block.contains("matchers-condition"))
        tpl.insert("matchers-condition", block.value("matchers-condition"));
    if (block.contains("matchers"))   tpl.insert("matchers",   block.value("matchers"));
    if (block.contains("extractors")) tpl.insert("extractors", block.value("extractors"));

    // Request: method / path (origin-form: strip a leading {{BaseURL}}) / headers / body.
    QJsonObject request;
    request.insert("method", block.value("method").toString(QStringLiteral("GET")));
    QString path = firstPath(block.value("path"));
    if (path.startsWith(QLatin1String("{{BaseURL}}")))
        path = path.mid(QStringLiteral("{{BaseURL}}").size());
    else if (path.startsWith(QLatin1String("{{RootURL}}")))
        path = path.mid(QStringLiteral("{{RootURL}}").size());
    if (path.isEmpty()) path = QStringLiteral("/");
    request.insert("path", path);
    if (block.contains("headers")) request.insert("headers", block.value("headers"));
    if (block.contains("body"))    request.insert("body", block.value("body").toString());
    tpl.insert("request", request);

    return tpl;
}

QJsonObject nucleiYamlToTemplate(const QString &yaml) {
    return nucleiToTemplate(parseYaml(yaml));
}

} // namespace Nullock::Core::NucleiYaml
