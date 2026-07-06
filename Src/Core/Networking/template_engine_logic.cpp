#include "template_engine_logic.hpp"

#include <QJsonArray>
#include <QRegularExpression>

namespace Nullock::Core::TemplateEngine {

namespace {

QString boundedPartText(const QString &part, const Response &r) {
    QString s;
    if (part == QLatin1String("header")) s = r.headersText;
    else if (part == QLatin1String("all")) s = r.headersText + QLatin1Char('\n') + r.body;
    else s = r.body;                                   // default: body
    return s.size() > kMaxScan ? s.left(kMaxScan) : s;
}

// Coerce a JSON value to a string. Numbers (status codes, sizes) stringify --
// QJsonValue::toString() returns empty for a number, which would silently drop
// e.g. "status":[200], so handle it explicitly.
QString jsonOne(const QJsonValue &e) {
    if (e.isString()) return e.toString();
    if (e.isBool())   return e.toBool() ? QStringLiteral("true") : QStringLiteral("false");
    if (e.isDouble()) {
        const double d = e.toDouble();
        const qint64 asInt = static_cast<qint64>(d);
        if (static_cast<double>(asInt) == d) return QString::number(asInt);  // integral
        return QString::number(d);
    }
    return QString();
}

QStringList jsonStrings(const QJsonValue &v) {
    QStringList out;
    if (v.isArray()) {
        for (const QJsonValue &e : v.toArray()) out.append(jsonOne(e));
    } else if (!v.isNull() && !v.isUndefined() && !v.isObject() && !v.isArray()) {
        out.append(jsonOne(v));
    }
    return out;
}

// Pick the values array from whichever field name is present (nuclei-ish).
QStringList matcherValues(const QJsonObject &o, const QString &type) {
    if (o.contains("values")) return jsonStrings(o.value("values"));
    if (type == QLatin1String("word")   && o.contains("words"))    return jsonStrings(o.value("words"));
    if (type == QLatin1String("regex")  && o.contains("regex"))    return jsonStrings(o.value("regex"));
    if (type == QLatin1String("regex")  && o.contains("patterns")) return jsonStrings(o.value("patterns"));
    if (type == QLatin1String("status") && o.contains("status"))   return jsonStrings(o.value("status"));
    return {};
}

// Evaluate one matcher (before applying `negative`).
bool matcherHits(const Matcher &m, const Response &r) {
    const bool wantAll = (m.condition.trimmed().toLower() == QLatin1String("and"));

    if (m.type == QLatin1String("status")) {
        const QString code = QString::number(r.statusCode);
        // status is inherently OR over the listed codes.
        for (const QString &v : m.values)
            if (v.trimmed() == code) return true;
        return false;
    }

    const QString hay = boundedPartText(m.part, r);
    if (m.values.isEmpty()) return false;

    if (m.type == QLatin1String("word")) {
        for (const QString &w : m.values) {
            const bool present = !w.isEmpty() && hay.contains(w);
            if (wantAll && !present) return false;      // AND: any miss fails
            if (!wantAll && present) return true;        // OR: any hit wins
        }
        return wantAll;   // AND: reached here => all present; OR: none matched
    }

    if (m.type == QLatin1String("regex")) {
        for (const QString &pat : m.values) {
            const QRegularExpression re(pat);
            const bool present = re.isValid() && re.match(hay).hasMatch();
            if (wantAll && !present) return false;
            if (!wantAll && present) return true;
        }
        return wantAll;
    }

    return false;   // unknown matcher type -> no hit
}

} // namespace

Template parseTemplate(const QJsonObject &obj) {
    Template t;
    t.id       = obj.value("id").toString();
    t.name     = obj.value("name").toString();
    t.severity = obj.value("severity").toString();
    const QString mc = obj.value("matchers-condition").toString(
                          obj.value("matchersCondition").toString());
    t.matchersCondition = mc.isEmpty() ? QStringLiteral("and") : mc.toLower();

    for (const QJsonValue &mv : obj.value("matchers").toArray()) {
        const QJsonObject mo = mv.toObject();
        Matcher m;
        m.type      = mo.value("type").toString().toLower();
        m.part      = mo.value("part").toString(QStringLiteral("body")).toLower();
        m.condition = mo.value("condition").toString(QStringLiteral("or")).toLower();
        m.negative  = mo.value("negative").toBool(false);
        m.values    = matcherValues(mo, m.type);
        if (!m.type.isEmpty()) t.matchers.append(m);
    }

    for (const QJsonValue &ev : obj.value("extractors").toArray()) {
        const QJsonObject eo = ev.toObject();
        Extractor e;
        e.type = eo.value("type").toString(QStringLiteral("regex")).toLower();
        e.part = eo.value("part").toString(QStringLiteral("body")).toLower();
        e.name = eo.value("name").toString();
        e.values = eo.contains("regex") ? jsonStrings(eo.value("regex"))
                                        : jsonStrings(eo.value("values"));
        t.extractors.append(e);
    }
    return t;
}

MatchResult evaluate(const Template &tpl, const Response &resp) {
    MatchResult out;

    // Matchers. An empty matcher list matches nothing (a template must assert
    // something to fire).
    if (!tpl.matchers.isEmpty()) {
        const bool wantAll = (tpl.matchersCondition != QLatin1String("or"));
        bool result = wantAll;   // AND starts true, OR starts false
        for (const Matcher &m : tpl.matchers) {
            bool hit = matcherHits(m, resp);
            if (m.negative) hit = !hit;
            if (wantAll) { if (!hit) { result = false; break; } }
            else         { if (hit)  { result = true;  break; } }
        }
        out.matched = result;
    }

    // Extractors run regardless of match (useful for capturing context even on a
    // non-match), collecting the first capture group or whole match.
    for (const Extractor &e : tpl.extractors) {
        if (e.type != QLatin1String("regex") || e.name.isEmpty()) continue;
        const QString hay = boundedPartText(e.part, resp);
        QStringList caps;
        for (const QString &pat : e.values) {
            const QRegularExpression re(pat);
            if (!re.isValid()) continue;
            auto it = re.globalMatch(hay);
            int guard = 0;
            while (it.hasNext() && guard++ < 1000) {    // bound the capture count
                const QRegularExpressionMatch mm = it.next();
                caps.append(mm.lastCapturedIndex() >= 1 ? mm.captured(1) : mm.captured(0));
            }
        }
        if (!caps.isEmpty()) out.extracted.insert(e.name, caps);
    }

    return out;
}

} // namespace Nullock::Core::TemplateEngine
