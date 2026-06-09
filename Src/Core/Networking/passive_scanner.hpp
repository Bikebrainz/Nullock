#pragma once

#include "proxy_server.hpp"

#include <QDateTime>
#include <QList>
#include <QMutex>
#include <QObject>
#include <QString>

namespace Nullock::Core {

// One observation from the passive scanner. id is monotonic. rowId is
// the matching ProxyModel row (history table); the React UI uses it to
// jump to the offending request when the user clicks a finding.
//
// Enriched fields (cwe, owasp, cvss*, compliance) are populated by
// FindingEnricher::enrich() right after addFinding(). They default
// empty when no mapping is registered for the kind.
struct Finding {
    int        id        = 0;
    int        rowId     = 0;
    QDateTime  ts;
    QString    severity;     // "info" | "low" | "medium" | "high" | "critical"
    QString    kind;         // short stable key, e.g. "missing-csp"
    QString    summary;      // one-line description shown in the list
    QString    evidence;     // longer text: header line, query string, etc.
    QString    host;
    QString    url;
    // Enrichment (Burp Pro parity + open-data leverage)
    QString    cwe;          // "CWE-79" etc.
    QString    owasp;        // "A03:2021-Injection"
    double     cvssScore     = 0.0;     // CVSS v3.1 base score 0-10
    QString    cvssVector;   // full vector string
    QStringList compliance;  // ["PCI-DSS-6.5.7", "SOC2-CC6.1"]
    QString    fixSummary;   // one-sentence fix guidance
};

// Passive scanner consumes every response that flows through the proxy
// and emits Findings for common security issues. Nothing here makes new
// requests -- it only looks at what we've already captured -- so it's
// safe to leave on permanently.
class PassiveScanner : public QObject {
    Q_OBJECT
    Q_PROPERTY(int count READ count NOTIFY findingsChanged)
public:
    explicit PassiveScanner(QObject *parent = nullptr);

    int   count() const;
    QList<Finding> findings(int limit = 500) const;

    // The proxy emits a 1-based rowId via ProxyModel; we accept the same.
    void  setNextRowId(int n);  // optional; app.cpp keeps a counter

public slots:
    // Wired to ProxyServer::responseReceived.
    void onResponseReceived(const Nullock::Proxy::HttpRequest &req,
                            const Nullock::Proxy::HttpResponse &resp);

    Q_INVOKABLE void clear();
    // Direct finding emit, for callers that aren't a response (e.g. the
    // active scanner / probe path). rowId points at the originating
    // history row so the UI's click-to-jump still works.
    Q_INVOKABLE void reportFinding(int rowId,
                                   const QString &severity,
                                   const QString &kind,
                                   const QString &summary,
                                   const QString &evidence,
                                   const QString &host,
                                   const QString &url);

signals:
    void findingsChanged();

private:
    void   addFinding(int rowId,
                      const Nullock::Proxy::HttpRequest &req,
                      const Nullock::Proxy::HttpResponse &resp,
                      const QString &severity,
                      const QString &kind,
                      const QString &summary,
                      const QString &evidence);

    QString headerOf(const QList<QPair<QString, QString>> &headers,
                     const QString &name) const;
    QList<QString> allHeaderValues(const QList<QPair<QString, QString>> &headers,
                                   const QString &name) const;
    void   checkResponse(int rowId,
                         const Nullock::Proxy::HttpRequest &req,
                         const Nullock::Proxy::HttpResponse &resp);

    mutable QMutex m_mutex;
    QList<Finding> m_findings;
    int            m_nextId    = 1;
    int            m_nextRowId = 1;
};

} // namespace Nullock::Core
