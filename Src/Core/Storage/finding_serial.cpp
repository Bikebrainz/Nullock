#include "finding_serial.hpp"

#include <QJsonArray>
#include <QJsonValue>

namespace Nullock::Core::FindingSerial {

QJsonObject toJson(const Finding &f) {
    QJsonArray compliance;
    for (const QString &c : f.compliance)
        compliance.append(c);
    return QJsonObject{
        { "id",         f.id },
        { "rowId",      f.rowId },
        // UTC + milliseconds so ordering and de-dup are stable regardless of the
        // machine's local zone between the session that found it and the one that
        // reopens the project.
        { "ts",         f.ts.toUTC().toString(Qt::ISODateWithMs) },
        { "severity",   f.severity },
        { "kind",       f.kind },
        { "summary",    f.summary },
        { "evidence",   f.evidence },
        { "host",       f.host },
        { "url",        f.url },
        { "cwe",        f.cwe },
        { "owasp",      f.owasp },
        { "cvssScore",  f.cvssScore },
        { "cvssVector", f.cvssVector },
        { "compliance", compliance },
        { "fixSummary", f.fixSummary },
        { "confidence", f.confidence },
    };
}

Finding fromJson(const QJsonObject &o) {
    Finding f;
    f.id         = o.value("id").toInt();
    f.rowId      = o.value("rowId").toInt();
    f.ts         = QDateTime::fromString(o.value("ts").toString(), Qt::ISODateWithMs);
    f.severity   = o.value("severity").toString();
    f.kind       = o.value("kind").toString();
    f.summary    = o.value("summary").toString();
    f.evidence   = o.value("evidence").toString();
    f.host       = o.value("host").toString();
    f.url        = o.value("url").toString();
    f.cwe        = o.value("cwe").toString();
    f.owasp      = o.value("owasp").toString();
    f.cvssScore  = o.value("cvssScore").toDouble();
    f.cvssVector = o.value("cvssVector").toString();
    f.compliance.clear();
    for (const QJsonValue &v : o.value("compliance").toArray())
        f.compliance.append(v.toString());
    f.fixSummary = o.value("fixSummary").toString();
    f.confidence = o.value("confidence").toString();
    return f;
}

} // namespace Nullock::Core::FindingSerial
