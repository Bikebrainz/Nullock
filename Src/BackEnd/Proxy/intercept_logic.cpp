#include "intercept_logic.hpp"

#include <QJsonObject>
#include <QJsonValue>
#include <QList>
#include <QRegularExpression>

namespace Nullock::Proxy::InterceptLogic {

QByteArray resolveForwardBytes(const QByteArray &originalBytes, const QString &currentText) {
    // Unedited? Forward the captured bytes verbatim -- no lossy round-trip.
    // QString::fromUtf8 is deterministic, so an unedited GUI buffer compares
    // equal to the decode of the original bytes even when that decode contains
    // U+FFFD replacement characters: both sides hold the identical replacements,
    // so equality still holds and we take the verbatim path.
    if (currentText == QString::fromUtf8(originalBytes))
        return originalBytes;

    // Operator edited the text. Re-encode: lossless for an all-UTF-8 request;
    // for an edited binary body some fidelity is unavoidably lost, but that is
    // the operator's explicit action in the editor, not a silent passive defect.
    return currentText.toUtf8();
}

bool interceptQueueHasRoom(int outstanding) {
    if (outstanding < 0) return true;   // defensive: a bad count != "full"
    return outstanding < kMaxPendingIntercepts;
}

namespace {

// The head (start line + headers), split on the first blank line -- terminator
// agnostic (CRLF, bare LF). Returns the head bytes; body is discarded (the
// predicate never inspects it).
QByteArray headOf(const QByteArray &msg) {
    int sep = msg.indexOf("\r\n\r\n");
    if (sep < 0) sep = msg.indexOf("\n\n");
    return (sep < 0) ? msg : msg.left(sep);
}

// True if `needle` is in the comma-separated `csv`. exact = case-insensitive equal
// (methods, extensions, status codes); substring = case-insensitive contains
// (content types). A leading '.' on a list item is stripped (so "css" == ".css").
bool csvHas(const QString &csv, const QString &needle, bool substring) {
    const QStringList items = csv.split(QLatin1Char(','), Qt::SkipEmptyParts);
    for (QString item : items) {
        item = item.trimmed();
        if (item.startsWith(QLatin1Char('.'))) item = item.mid(1);
        if (item.isEmpty()) continue;
        if (substring) { if (needle.contains(item, Qt::CaseInsensitive)) return true; }
        else           { if (needle.compare(item, Qt::CaseInsensitive) == 0) return true; }
    }
    return false;
}

bool ruleMatches(const InterceptRule &r, const InterceptFields &f) {
    bool m = false;
    switch (r.match) {
    case InterceptRule::Match::Any:
        m = true;
        break;
    case InterceptRule::Match::FileExtension:
        m = !f.fileExtension.isEmpty() && csvHas(r.condition, f.fileExtension, false);
        break;
    case InterceptRule::Match::Method:
        m = !f.method.isEmpty() && csvHas(r.condition, f.method, false);
        break;
    case InterceptRule::Match::ContentType:
        m = !f.contentType.isEmpty() && csvHas(r.condition, f.contentType, true);
        break;
    case InterceptRule::Match::StatusCode:
        m = f.statusCode > 0 && csvHas(r.condition, QString::number(f.statusCode), false);
        break;
    case InterceptRule::Match::UrlRegex: {
        const QRegularExpression re(r.condition);
        m = re.isValid() && re.match(f.url).hasMatch();
        break;
    }
    case InterceptRule::Match::HostGlob: {
        const QRegularExpression re(
            QRegularExpression::wildcardToRegularExpression(r.condition),
            QRegularExpression::CaseInsensitiveOption);
        m = re.isValid() && re.match(f.host).hasMatch();
        break;
    }
    case InterceptRule::Match::HasHeader: {
        const QRegularExpression re(r.condition, QRegularExpression::CaseInsensitiveOption);
        if (re.isValid())
            for (const QString &h : f.headerNames)
                if (re.match(h).hasMatch()) { m = true; break; }
        break;
    }
    }
    return r.negate ? !m : m;
}

} // namespace

bool interceptRulesHold(const QVector<InterceptRule> &rules, const InterceptFields &f) {
    bool result = true;   // default when no rule applies -> hold everything
    bool any = false;
    for (const InterceptRule &r : rules) {
        if (!r.enabled) continue;
        const bool applies = (r.dir == InterceptRule::Dir::Both)
            || (f.isResponse ? (r.dir == InterceptRule::Dir::Response)
                             : (r.dir == InterceptRule::Dir::Request));
        if (!applies) continue;
        const bool m = ruleMatches(r, f);
        if (!any) { result = m; any = true; }
        else      { result = (r.op == InterceptRule::BoolOp::And) ? (result && m)
                                                                  : (result || m); }
    }
    return any ? result : true;
}

InterceptFields extractRequestFields(const QByteArray &requestBytes, const QString &host) {
    InterceptFields f;
    f.isResponse = false;
    f.host = host;
    const QList<QByteArray> lines = headOf(requestBytes).split('\n');
    if (!lines.isEmpty()) {
        const QList<QByteArray> parts = lines.first().trimmed().split(' ');
        if (parts.size() >= 2) {
            f.method = QString::fromLatin1(parts[0]).toUpper();
            f.url    = QString::fromLatin1(parts[1]);
        }
    }
    // File extension: last path segment, after the last dot, before any query.
    QString path = f.url;
    const int q = path.indexOf(QLatin1Char('?'));
    if (q >= 0) path = path.left(q);
    const int slash = path.lastIndexOf(QLatin1Char('/'));
    const QString seg = (slash >= 0) ? path.mid(slash + 1) : path;
    const int dot = seg.lastIndexOf(QLatin1Char('.'));
    if (dot >= 0 && dot < seg.size() - 1) f.fileExtension = seg.mid(dot + 1).toLower();
    // Headers.
    for (int i = 1; i < lines.size(); ++i) {
        const QByteArray line = lines[i].trimmed();
        const int colon = line.indexOf(':');
        if (colon <= 0) continue;
        const QString name = QString::fromLatin1(line.left(colon)).trimmed().toLower();
        f.headerNames << name;
        if (name == QLatin1String("content-type"))
            f.contentType = QString::fromLatin1(line.mid(colon + 1)).trimmed().toLower();
        else if (name == QLatin1String("host") && f.host.isEmpty())
            f.host = QString::fromLatin1(line.mid(colon + 1)).trimmed();
    }
    return f;
}

InterceptFields extractResponseFields(const QByteArray &responseBytes, const QString &host) {
    InterceptFields f;
    f.isResponse = true;
    f.host = host;
    const QList<QByteArray> lines = headOf(responseBytes).split('\n');
    if (!lines.isEmpty()) {
        const QList<QByteArray> parts = lines.first().trimmed().split(' ');
        if (parts.size() >= 2) f.statusCode = QString::fromLatin1(parts[1]).toInt();
    }
    for (int i = 1; i < lines.size(); ++i) {
        const QByteArray line = lines[i].trimmed();
        const int colon = line.indexOf(':');
        if (colon <= 0) continue;
        const QString name = QString::fromLatin1(line.left(colon)).trimmed().toLower();
        f.headerNames << name;
        if (name == QLatin1String("content-type"))
            f.contentType = QString::fromLatin1(line.mid(colon + 1)).trimmed().toLower();
    }
    return f;
}

QJsonArray interceptRulesToJson(const QVector<InterceptRule> &rules) {
    static const char *kOps[]     = { "or", "and" };
    static const char *kDirs[]    = { "request", "response", "both" };
    static const char *kMatches[] = { "any", "file-extension", "method", "url-regex",
                                      "host-glob", "content-type", "status-code",
                                      "has-header" };
    QJsonArray arr;
    for (const InterceptRule &r : rules) {
        arr.append(QJsonObject{
            { "enabled",   r.enabled },
            { "op",        QString::fromLatin1(kOps[int(r.op)]) },
            { "match",     QString::fromLatin1(kMatches[int(r.match)]) },
            { "negate",    r.negate },
            { "condition", r.condition },
            { "dir",       QString::fromLatin1(kDirs[int(r.dir)]) },
        });
    }
    return arr;
}

QVector<InterceptRule> interceptRulesFromJson(const QJsonArray &arr) {
    auto opFrom = [](const QString &s) {
        return s == QLatin1String("and") ? InterceptRule::BoolOp::And
                                         : InterceptRule::BoolOp::Or;
    };
    auto dirFrom = [](const QString &s) {
        if (s == QLatin1String("request"))  return InterceptRule::Dir::Request;
        if (s == QLatin1String("response")) return InterceptRule::Dir::Response;
        return InterceptRule::Dir::Both;
    };
    auto matchFrom = [](const QString &s) {
        if (s == QLatin1String("any"))            return InterceptRule::Match::Any;
        if (s == QLatin1String("file-extension")) return InterceptRule::Match::FileExtension;
        if (s == QLatin1String("method"))         return InterceptRule::Match::Method;
        if (s == QLatin1String("host-glob"))      return InterceptRule::Match::HostGlob;
        if (s == QLatin1String("content-type"))   return InterceptRule::Match::ContentType;
        if (s == QLatin1String("status-code"))    return InterceptRule::Match::StatusCode;
        if (s == QLatin1String("has-header"))     return InterceptRule::Match::HasHeader;
        return InterceptRule::Match::UrlRegex;   // safe default for unknown/missing
    };
    QVector<InterceptRule> out;
    for (const QJsonValue &v : arr) {
        const QJsonObject o = v.toObject();
        InterceptRule r;
        r.enabled   = o.value("enabled").toBool(true);
        r.op        = opFrom(o.value("op").toString());
        r.match     = matchFrom(o.value("match").toString());
        r.negate    = o.value("negate").toBool(false);
        r.condition = o.value("condition").toString();
        r.dir       = dirFrom(o.value("dir").toString());
        out.append(r);
    }
    return out;
}

} // namespace Nullock::Proxy::InterceptLogic
