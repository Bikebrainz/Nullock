#include "control_logic.hpp"

#include <QJsonObject>
#include <QJsonValue>
#include <QRegularExpression>
#include <QSet>
#include <QStringList>
#include <QUrlQuery>

namespace Nullock::Control::ControlLogic {

bool isHostAllowed(const QString &hostHdr, quint16 port) {
    if (hostHdr.isEmpty()) return true;
    const QString portStr = QString::number(port);
    static const auto buildAllowed = [](const QString &p) {
        return QSet<QString>{
            "127.0.0.1:" + p,
            "localhost:" + p,
            "[::1]:" + p,
            // Some clients omit the port when it's the default; we never listen
            // on 80 by default, but allow plain loopback hostnames just in case.
            QStringLiteral("127.0.0.1"),
            QStringLiteral("localhost"),
            QStringLiteral("[::1]"),
        };
    };
    const QSet<QString> allowed = buildAllowed(portStr);
    return allowed.contains(hostHdr.toLower());
}

bool isMethodAllowed(const QString &method) {
    static const QStringList kAllowed = {
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"
    };
    return kAllowed.contains(method);
}

bool isReadMethod(const QString &method) {
    return method == "GET" || method == "HEAD" || method == "OPTIONS";
}

bool isRequestAuthorized(const QString &method, const QString &origin,
                         const QString &nullockHdr, quint16 port) {
    if (isReadMethod(method)) return true;
    const QString portStr = QString::number(port);
    const bool originOk = (origin == "http://127.0.0.1:" + portStr
                        || origin == "http://localhost:" + portStr);
    const bool tokenOk  = (nullockHdr == "1" || nullockHdr.toLower() == "true");
    return originOk || tokenOk;
}

QString bearerToken(const QString &authHeaderValue) {
    const QString v = authHeaderValue.trimmed();
    static const QString scheme = QStringLiteral("bearer");
    if (v.size() <= scheme.size()) return {};
    if (v.left(scheme.size()).toLower() != scheme) return {};
    if (!v.at(scheme.size()).isSpace()) return {};   // must be "Bearer <token>"
    return v.mid(scheme.size()).trimmed();
}

bool constantTimeEquals(const QString &a, const QString &b) {
    const QByteArray ab = a.toUtf8();
    const QByteArray bb = b.toUtf8();
    if (ab.isEmpty() || bb.isEmpty()) return ab.isEmpty() && bb.isEmpty();
    // Fold the length difference into the accumulator, then compare every byte
    // (indexing modulo each length so a size mismatch never short-circuits the
    // loop). diff stays non-zero if any byte or the lengths differ.
    unsigned diff = static_cast<unsigned>(ab.size()) ^ static_cast<unsigned>(bb.size());
    const int n = qMax(ab.size(), bb.size());
    for (int i = 0; i < n; ++i) {
        const unsigned ca = static_cast<unsigned char>(ab.at(i % ab.size()));
        const unsigned cb = static_cast<unsigned char>(bb.at(i % bb.size()));
        diff |= (ca ^ cb);
    }
    return diff == 0;
}

bool isTokenAuthorized(const QString &authHeaderValue, const QString &configuredToken) {
    if (configuredToken.isEmpty()) return false;          // auth disabled -> not authorized here
    const QString presented = bearerToken(authHeaderValue);
    if (presented.isEmpty()) return false;
    return constantTimeEquals(presented, configuredToken);
}

QString mdCodeSpanSafe(const QString &s) {
    QString out;
    out.reserve(s.size());
    for (const QChar ch : s) {
        const ushort u = ch.unicode();
        if (u == '`') continue;              // can't be escaped inside a code span -> drop
        if (u < 0x20 || u == 0x7F) { out += QLatin1Char(' '); continue; }  // control -> space
        out += ch;
    }
    return out;
}

QString mdTextSafe(const QString &s) {
    static const QString kMeta = QStringLiteral("\\`*_[]()<>|!#");
    QString out;
    out.reserve(s.size() + 8);
    for (const QChar ch : s) {
        const ushort u = ch.unicode();
        if (u < 0x20 || u == 0x7F) { out += QLatin1Char(' '); continue; }  // control -> space (no new line/list/heading)
        if (kMeta.contains(ch)) out += QLatin1Char('\\');                  // backslash-escape inline metacharacters
        out += ch;
    }
    return out;
}

QString xmlAttrEscape(const QString &s) {
    QString out;
    out.reserve(s.size());
    for (const QChar c : s) {
        const ushort u = c.unicode();
        // Control chars (incl. CR/LF/tab) -> space: a raw control byte would let
        // attacker content break attribute framing, and many XML parsers reject
        // or mangle them inside an attribute value.
        if (u < 0x20) { out += QLatin1Char(' '); continue; }
        switch (u) {
        case '&':  out += QStringLiteral("&amp;");  break;
        case '<':  out += QStringLiteral("&lt;");   break;
        case '>':  out += QStringLiteral("&gt;");   break;
        case '"':  out += QStringLiteral("&quot;"); break;
        case '\'': out += QStringLiteral("&apos;"); break;
        default:   out += c;
        }
    }
    return out;
}

QString findingsJsonToXml(const QJsonArray &findings, const QString &project,
                          const QString &generatedIso) {
    // Emit an already-escaped attribute ` name="val"`, or "" when val is empty
    // (so absent enrichment doesn't litter the document with empty attributes).
    auto attr = [](const QString &name, const QString &val) -> QString {
        if (val.isEmpty()) return QString();
        return QStringLiteral(" %1=\"%2\"").arg(name, xmlAttrEscape(val));
    };
    // Emit `    <tag>escaped</tag>\n`, or "" when the value is empty.
    auto el = [](const QString &tag, const QString &val) -> QString {
        if (val.isEmpty()) return QString();
        return QStringLiteral("    <%1>%2</%1>\n").arg(tag, xmlAttrEscape(val));
    };
    auto str = [](const QJsonObject &f, const char *k) {
        return f.value(QLatin1String(k)).toString();
    };

    QString out = QStringLiteral("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out += QStringLiteral("<nullockReport project=\"%1\" generated=\"%2\" issueCount=\"%3\">\n")
               .arg(xmlAttrEscape(project), xmlAttrEscape(generatedIso),
                    QString::number(findings.size()));
    for (const QJsonValue &v : findings) {
        const QJsonObject f = v.toObject();
        const double cvss = f.value(QLatin1String("cvssScore")).toDouble();

        out += QStringLiteral("  <issue");
        out += attr(QStringLiteral("severity"),   str(f, "severity"));
        out += attr(QStringLiteral("confidence"), str(f, "confidence"));
        // A CVSS base score is 0-10; only emit a positive score (0.0 means the
        // finding carries no CVSS). One decimal matches the CVSS v3.1 convention.
        if (cvss > 0.0)
            out += QStringLiteral(" cvss=\"%1\"")
                       .arg(xmlAttrEscape(QString::number(cvss, 'f', 1)));
        if (f.value(QLatin1String("fixed")).toBool())
            out += QStringLiteral(" fixed=\"true\"");
        out += QStringLiteral(">\n");

        out += el(QStringLiteral("name"),        str(f, "kind"));
        out += el(QStringLiteral("host"),        str(f, "host"));
        out += el(QStringLiteral("url"),         str(f, "url"));
        out += el(QStringLiteral("cwe"),         str(f, "cwe"));
        out += el(QStringLiteral("owasp"),       str(f, "owasp"));
        out += el(QStringLiteral("detail"),      str(f, "summary"));
        out += el(QStringLiteral("remediation"), str(f, "fixSummary"));
        out += QStringLiteral("  </issue>\n");
    }
    out += QStringLiteral("</nullockReport>\n");
    return out;
}

bool hasRequestSmugglingChars(const QString &s) {
    for (const QChar ch : s) {
        const ushort u = ch.unicode();
        if (u == '\r' || u == '\n' || u == '\0') return true;
    }
    return false;
}

QString safeJoin(const QString &dir, const QString &rel) {
    // Strip leading slashes, refuse "..", confine to dir.
    QString r = rel;
    while (r.startsWith('/') || r.startsWith('\\')) r.remove(0, 1);
    if (r.contains("..")) return {};
    return dir + "/" + r;
}

bool looksLikeCatastrophicRegex(const QString &pattern) {
    // (1) Nested unbounded quantifier: a quantifier INSIDE a group whose group
    //     is itself unbounded-quantified -- (a+)+ / (a*)* / (a{2,})+.
    static const QRegularExpression kNestedQuant(
        QStringLiteral(R"(\([^)]*[*+]\)[*+]|\([^)]*\{\d+,\}\)[*+])"),
        QRegularExpression::NoPatternOption);
    if (kNestedQuant.match(pattern).hasMatch()) return true;
    // (2) Alternation with two IDENTICAL adjacent branches under an unbounded
    //     quantifier -- (a|a)+, (\d|\d)+, ([ab]|[ab])+, (a|a|a)+. The \1
    //     backreference matches "a branch immediately followed by the SAME
    //     branch"; the trailing [^)]* allows further alternatives before the
    //     group closes and *requires* an outer + / * so a benign unquantified
    //     (a|a) isn't flagged, while disjoint (foo|bar)+ / (a|b)+ never match.
    static const QRegularExpression kDupAltBranch(
        QStringLiteral(R"(\(([^|)]+)\|\1[^)]*\)[*+])"),
        QRegularExpression::NoPatternOption);
    if (kDupAltBranch.match(pattern).hasMatch()) return true;
    return false;
}

int searchRowForIteration(int n, int i) {
    // Newest-first: iteration 0 is the last (newest) row. Clamp defensively so a
    // caller can never turn an out-of-range i into a negative model row.
    if (n <= 0) return 0;
    if (i < 0) i = 0;
    if (i >= n) i = n - 1;
    return n - 1 - i;
}

bool searchTruncated(int scanned, int total) {
    return scanned < total;
}

int severityRank(const QString &sev) {
    const QString s = sev.toLower();
    if (s == QLatin1String("critical")) return 5;
    if (s == QLatin1String("high"))     return 4;
    if (s == QLatin1String("medium"))   return 3;
    if (s == QLatin1String("low"))      return 2;
    if (s == QLatin1String("info"))     return 1;
    return 0;   // unknown / empty
}

QString sarifLevelForSeverity(const QString &sev) {
    const QString s = sev.toLower();
    if (s == QLatin1String("critical") || s == QLatin1String("high"))
        return QStringLiteral("error");
    if (s == QLatin1String("low") || s == QLatin1String("info"))
        return QStringLiteral("note");
    return QStringLiteral("warning");   // medium / unknown / empty
}

QByteArray pemCertToDer(const QByteArray &pem) {
    const QString s = QString::fromLatin1(pem);
    static const QString kBegin = QStringLiteral("-----BEGIN CERTIFICATE-----");
    static const QString kEnd   = QStringLiteral("-----END CERTIFICATE-----");
    const int b = s.indexOf(kBegin);
    if (b < 0) return {};
    const int bodyStart = b + kBegin.size();
    const int e = s.indexOf(kEnd, bodyStart);
    if (e < 0) return {};
    QString b64 = s.mid(bodyStart, e - bodyStart);
    b64.remove(QRegularExpression(QStringLiteral("\\s")));   // strip newlines/spaces
    if (b64.isEmpty()) return {};
    const auto res = QByteArray::fromBase64Encoding(
        b64.toLatin1(), QByteArray::Base64Encoding | QByteArray::AbortOnBase64DecodingErrors);
    if (res.decodingStatus != QByteArray::Base64DecodingStatus::Ok) return {};
    return res.decoded;
}

int confidenceRank(const QString &conf) {
    const QString c = conf.trimmed().toLower();
    if (c == QLatin1String("confirmed") || c == QLatin1String("certain")) return 4;
    if (c == QLatin1String("firm")      || c == QLatin1String("high"))    return 3;
    if (c == QLatin1String("medium"))                                     return 2;
    if (c == QLatin1String("tentative") || c == QLatin1String("possible")
        || c == QLatin1String("low"))                                     return 1;
    return 0;   // unknown / empty
}

bool findingPasses(const QString &severity, const QString &confidence,
                   const QString &kind, bool fixed,
                   int minSeverityRank, int minConfidenceRank,
                   const QSet<QString> &includeKinds,
                   const QSet<QString> &excludeKinds,
                   bool includeFixed) {
    if (severityRank(severity) < minSeverityRank) return false;
    if (minConfidenceRank > 0 && confidenceRank(confidence) < minConfidenceRank) return false;
    if (!includeKinds.isEmpty() && !includeKinds.contains(kind)) return false;
    if (excludeKinds.contains(kind)) return false;
    if (!includeFixed && fixed) return false;
    return true;
}

QJsonArray filterFindings(const QJsonArray &findings,
                          int minSeverityRank, int minConfidenceRank,
                          const QSet<QString> &includeKinds,
                          const QSet<QString> &excludeKinds,
                          bool includeFixed) {
    QJsonArray out;
    for (const QJsonValue &v : findings) {
        const QJsonObject f = v.toObject();
        if (findingPasses(f.value(QLatin1String("severity")).toString(),
                          f.value(QLatin1String("confidence")).toString(),
                          f.value(QLatin1String("kind")).toString(),
                          f.value(QLatin1String("fixed")).toBool(),
                          minSeverityRank, minConfidenceRank,
                          includeKinds, excludeKinds, includeFixed))
            out.append(f);
    }
    return out;
}

namespace {
QSet<QString> csvToSet(const QString &csv) {
    QSet<QString> s;
    const QStringList parts = csv.split(QLatin1Char(','), Qt::SkipEmptyParts);
    for (const QString &part : parts) {
        const QString k = part.trimmed();
        if (!k.isEmpty()) s.insert(k);
    }
    return s;
}
QSet<QString> jsonArrOrCsvToSet(const QJsonValue &v) {
    QSet<QString> s;
    if (v.isArray()) {
        for (const QJsonValue &e : v.toArray()) {
            const QString k = e.toString().trimmed();
            if (!k.isEmpty()) s.insert(k);
        }
    } else if (v.isString()) {
        s = csvToSet(v.toString());
    }
    return s;
}
} // namespace

ReportFilterCriteria reportFilterFromQuery(const QUrlQuery &q) {
    ReportFilterCriteria c;
    if (q.hasQueryItem(QStringLiteral("minSeverity")))
        c.minSeverityRank = severityRank(q.queryItemValue(QStringLiteral("minSeverity")));
    if (q.hasQueryItem(QStringLiteral("minConfidence")))
        c.minConfidenceRank = confidenceRank(q.queryItemValue(QStringLiteral("minConfidence")));
    c.includeKinds = csvToSet(q.queryItemValue(QStringLiteral("includeKinds")));
    c.excludeKinds = csvToSet(q.queryItemValue(QStringLiteral("excludeKinds")));
    c.includeFixed = q.queryItemValue(QStringLiteral("includeFixed"))
                         .compare(QLatin1String("false"), Qt::CaseInsensitive) != 0;
    return c;
}

ReportFilterCriteria reportFilterFromJson(const QJsonObject &body) {
    ReportFilterCriteria c;
    if (body.contains(QLatin1String("minSeverity")))
        c.minSeverityRank = severityRank(body.value(QLatin1String("minSeverity")).toString());
    if (body.contains(QLatin1String("minConfidence")))
        c.minConfidenceRank = confidenceRank(body.value(QLatin1String("minConfidence")).toString());
    c.includeKinds = jsonArrOrCsvToSet(body.value(QLatin1String("includeKinds")));
    c.excludeKinds = jsonArrOrCsvToSet(body.value(QLatin1String("excludeKinds")));
    // includeFixed defaults true; only an explicit false (bool or "false") drops fixed.
    if (body.contains(QLatin1String("includeFixed"))) {
        const QJsonValue iv = body.value(QLatin1String("includeFixed"));
        c.includeFixed = iv.isBool() ? iv.toBool()
                                     : iv.toString().compare(QLatin1String("false"), Qt::CaseInsensitive) != 0;
    }
    return c;
}

QJsonArray applyReportFilter(const QJsonArray &findings, const QUrlQuery &q) {
    const ReportFilterCriteria c = reportFilterFromQuery(q);
    return filterFindings(findings, c.minSeverityRank, c.minConfidenceRank,
                          c.includeKinds, c.excludeKinds, c.includeFixed);
}

// ---- Configuration import/export document envelope ------------------------
QJsonObject buildConfigDocument(const QJsonObject &sections) {
    return QJsonObject{
        { QStringLiteral("format"),   QStringLiteral("nullock-config") },
        { QStringLiteral("version"),  kConfigVersion },
        { QStringLiteral("sections"), sections },
    };
}

bool validateConfigDocument(const QJsonObject &doc, QString &error) {
    if (doc.value(QStringLiteral("format")).toString() != QLatin1String("nullock-config")) {
        error = QStringLiteral("not a Nullock configuration file (missing/!= format tag)");
        return false;
    }
    // Absent version = malformed; a version NEWER than we understand is refused
    // rather than half-applied (forward-incompat safety).
    const QJsonValue ver = doc.value(QStringLiteral("version"));
    if (!ver.isDouble()) {
        error = QStringLiteral("configuration file has no numeric version");
        return false;
    }
    if (ver.toInt() > kConfigVersion) {
        error = QStringLiteral("configuration is from a newer version of Nullock "
                               "(v%1 > v%2); upgrade to import it")
                    .arg(ver.toInt()).arg(kConfigVersion);
        return false;
    }
    if (!doc.value(QStringLiteral("sections")).isObject()) {
        error = QStringLiteral("configuration file has no sections object");
        return false;
    }
    error.clear();
    return true;
}

QJsonObject configSection(const QJsonObject &doc, const QString &name) {
    return doc.value(QStringLiteral("sections")).toObject()
              .value(name).toObject();
}

QStringList configSectionNames(const QJsonObject &doc) {
    return doc.value(QStringLiteral("sections")).toObject().keys();
}

} // namespace Nullock::Control::ControlLogic
