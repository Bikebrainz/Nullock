#include "intruder_persist_logic.hpp"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonValue>

namespace Nullock::Core::IntruderPersist {

namespace {

// A combo entry may be a null QString ("leave this marker at its default"). JSON
// has no null-vs-empty string, so we map null -> JSON null and a real value ->
// JSON string. This distinction is load-bearing: resend() branches on isNull().
QJsonArray comboToJson(const QStringList &combo) {
    QJsonArray a;
    for (const QString &v : combo)
        a.append(v.isNull() ? QJsonValue(QJsonValue::Null) : QJsonValue(v));
    return a;
}

QStringList comboFromJson(const QJsonArray &a) {
    QStringList out;
    out.reserve(a.size());
    for (const QJsonValue &v : a)
        out.append(v.isNull() ? QString() : v.toString());
    return out;
}

QJsonArray stringsToJson(const QStringList &xs) {
    QJsonArray a;
    for (const QString &s : xs) a.append(s);
    return a;
}

QStringList stringsFromJson(const QJsonArray &a) {
    QStringList out;
    out.reserve(a.size());
    for (const QJsonValue &v : a) out.append(v.toString());
    return out;
}

QJsonArray rulesToJson(const QList<IntruderRules::Rule> &rules) {
    QJsonArray a;
    for (const IntruderRules::Rule &r : rules)
        a.append(QJsonObject{ { "op", r.op }, { "arg", r.arg } });
    return a;
}

QList<IntruderRules::Rule> rulesFromJson(const QJsonArray &a) {
    QList<IntruderRules::Rule> out;
    for (const QJsonValue &v : a) {
        const QJsonObject o = v.toObject();
        out.append({ o.value("op").toString(), o.value("arg").toString() });
    }
    return out;
}

QJsonObject rowToJson(const ResultRow &r) {
    return QJsonObject{
        { "id",        r.id },
        { "payloads",  stringsToJson(r.payloadValues) },
        { "combo",     comboToJson(r.combo) },
        { "status",    r.statusCode },
        { "size",      r.responseSize },
        { "ms",        r.elapsedMs },
        { "err",       r.errorMessage },
        { "complete",  r.complete },
        { "matched",   r.matched },
        { "reflected", r.reflected },
        { "extracted", r.extracted },
    };
}

ResultRow rowFromJson(const QJsonObject &o) {
    ResultRow r;
    r.id            = o.value("id").toInt();
    r.payloadValues = stringsFromJson(o.value("payloads").toArray());
    r.combo         = comboFromJson(o.value("combo").toArray());
    r.statusCode    = o.value("status").toInt();
    r.responseSize  = o.value("size").toInt();
    r.elapsedMs     = o.value("ms").toInt();
    r.errorMessage  = o.value("err").toString();
    r.complete      = o.value("complete").toBool();
    r.matched       = o.value("matched").toBool();
    r.reflected     = o.value("reflected").toBool();
    r.extracted     = o.value("extracted").toString();
    return r;
}

} // namespace

QJsonObject toJson(const SavedRun &run) {
    const RunConfig &c = run.config;

    QJsonObject grepExtract{
        { "regex", c.grepExtract.regex },
        { "start", c.grepExtract.start },
        { "end",   c.grepExtract.end },
    };

    QJsonObject config{
        { "host",        c.host },
        { "port",        c.port },
        { "tls",         c.tls },
        { "template",    c.requestTemplate },
        { "attackType",  c.attackType },
        { "payloadSets", stringsToJson(c.payloadSets) },
        { "rules",       rulesToJson(c.rules) },
        { "grepMatch",   stringsToJson(c.grepMatch) },
        { "grepPayloadReflection", c.grepPayloadReflection },
        { "grepExtract", grepExtract },
        { "concurrency", c.concurrency },
        { "throttleMs",  c.throttleMs },
        { "retries",     c.retries },
    };

    QJsonArray rows;
    for (const ResultRow &r : run.rows) rows.append(rowToJson(r));

    return QJsonObject{
        { "kind",    "nullock.intruder.run" },
        { "version", run.version },
        { "config",  config },
        { "rows",    rows },
    };
}

QByteArray toBytes(const SavedRun &run) {
    return QJsonDocument(toJson(run)).toJson(QJsonDocument::Compact);
}

SavedRun fromJson(const QJsonObject &obj) {
    SavedRun run;
    run.version = obj.contains("version") ? obj.value("version").toInt(kFormatVersion)
                                          : kFormatVersion;

    const QJsonObject config = obj.value("config").toObject();
    RunConfig &c = run.config;
    c.host            = config.value("host").toString();
    c.port            = config.value("port").toInt(443);
    c.tls             = config.value("tls").toBool(true);
    c.requestTemplate = config.value("template").toString();
    c.attackType      = config.value("attackType").toInt();
    c.payloadSets     = stringsFromJson(config.value("payloadSets").toArray());
    c.rules           = rulesFromJson(config.value("rules").toArray());
    c.grepMatch       = stringsFromJson(config.value("grepMatch").toArray());
    c.grepPayloadReflection = config.value("grepPayloadReflection").toBool();

    const QJsonObject ge = config.value("grepExtract").toObject();
    c.grepExtract.regex = ge.value("regex").toString();
    c.grepExtract.start = ge.value("start").toString();
    c.grepExtract.end   = ge.value("end").toString();

    c.concurrency = config.value("concurrency").toInt(10);
    c.throttleMs  = config.value("throttleMs").toInt(0);
    c.retries     = config.value("retries").toInt(0);

    for (const QJsonValue &v : obj.value("rows").toArray())
        run.rows.append(rowFromJson(v.toObject()));

    return run;
}

SavedRun fromBytes(const QByteArray &bytes) {
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(bytes, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject())
        return SavedRun{};                 // malformed -> empty, never a crash
    return fromJson(doc.object());
}

} // namespace Nullock::Core::IntruderPersist
