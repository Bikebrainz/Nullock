#include "nuclei_yaml_logic.hpp"

#include <QJsonArray>
#include <QStringList>

namespace Nullock::Core::NucleiYaml {

namespace {

// A significant (non-blank, non-comment) YAML line: its indent + trimmed text.
struct Line { int indent; QString text; };

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

QList<Line> tokenize(const QString &yaml) {
    QList<Line> out;
    const QStringList raw = yaml.split('\n');
    for (QString ln : raw) {
        ln.replace('\t', QStringLiteral("  "));        // tabs -> 2 spaces (lenient)
        // Strip a trailing CR (CRLF inputs) before measuring.
        if (ln.endsWith('\r')) ln.chop(1);
        const QString noComment = stripComment(ln);
        const QString trimmed = noComment.trimmed();
        if (trimmed.isEmpty()) continue;
        if (trimmed == QStringLiteral("---")) continue; // doc separator
        int indent = 0;
        while (indent < noComment.size() && noComment[indent] == ' ') ++indent;
        out.append({ indent, trimmed });
    }
    return out;
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

// Forward decl for mutual recursion.
QJsonValue parseBlock(QList<Line> &lines, int &i, int indent, int &guard);

QJsonArray parseSeq(QList<Line> &lines, int &i, int indent, int &guard) {
    QJsonArray arr;
    while (i < lines.size() && lines[i].indent == indent
           && lines[i].text.startsWith('-') && guard-- > 0) {
        QString rest = lines[i].text.mid(1);           // after '-'
        if (rest.startsWith(' ')) rest = rest.mid(1);
        rest = rest.trimmed();
        const int contentIndent = indent + 2;
        if (rest.isEmpty()) {
            ++i;
            if (i < lines.size() && lines[i].indent > indent)
                arr.append(parseBlock(lines, i, lines[i].indent, guard));
            else
                arr.append(QJsonValue());
        } else if (keyColon(rest) >= 0) {
            // Map item ("- key: val" + aligned keys). Rewrite this line as the
            // item's content at contentIndent so the whole map parses as one.
            lines[i] = { contentIndent, rest };
            arr.append(parseBlock(lines, i, contentIndent, guard));
        } else {
            // Scalar item ("- value" / "- 200" / "- \"quoted\"").
            arr.append(scalarOrFlow(rest));
            ++i;
        }
    }
    return arr;
}

QJsonObject parseMap(QList<Line> &lines, int &i, int indent, int &guard) {
    QJsonObject obj;
    while (i < lines.size() && lines[i].indent == indent
           && !lines[i].text.startsWith('-') && guard-- > 0) {
        const QString line = lines[i].text;
        const int c = keyColon(line);
        if (c < 0) { ++i; continue; }                  // not a map line; skip
        const QString key = unquote(line.left(c).trimmed());
        const QString rest = line.mid(c + 1).trimmed();
        if (!rest.isEmpty()) {
            obj.insert(key, scalarOrFlow(rest));
            ++i;
        } else {
            ++i;
            if (i < lines.size() && lines[i].indent > indent) {
                obj.insert(key, parseBlock(lines, i, lines[i].indent, guard));
            } else if (i < lines.size() && lines[i].indent == indent
                       && lines[i].text.startsWith('-')) {
                // A sequence at the SAME indent as its key.
                obj.insert(key, parseSeq(lines, i, indent, guard));
            } else {
                obj.insert(key, QJsonValue());
            }
        }
    }
    return obj;
}

QJsonValue parseBlock(QList<Line> &lines, int &i, int indent, int &guard) {
    if (i >= lines.size() || guard <= 0) return QJsonValue();
    if (lines[i].text.startsWith('-') && lines[i].indent == indent)
        return parseSeq(lines, i, indent, guard);
    return parseMap(lines, i, indent, guard);
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
    QList<Line> lines = tokenize(yaml);
    if (lines.isEmpty()) return QJsonValue();
    int i = 0;
    int guard = 100000;                                // bound pathological input
    return parseBlock(lines, i, lines[0].indent, guard);
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
