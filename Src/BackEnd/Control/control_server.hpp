#pragma once

#include <QHostAddress>
#include <QObject>
#include <QString>

class QTcpServer;
class QTcpSocket;

namespace Nullock::Proxy {
class ProxyServer;
class CertAuthority;
class InterceptController;
}
namespace Nullock::FrontEnd {
class ProxyModel;
class ProxyFilterModel;
class SiteMapModel;
class ThemesManager;
}
namespace Nullock::Core {
class ProjectStore;
class Repeater;
class Intruder;
class ExtensionsApi;
class PassiveScanner;
class PortScanner;
class ReconEngine;
class SessionManager;
class OastServer;
class OastCorrelator;
class DnsSink;
class SessionRules;
class Crawler;
class UpdateChecker;
}

namespace Nullock::Control {

// Bundle of pointers the control server needs to read state and route
// actions. App constructs this and hands it to the server.
struct Wiring {
    Nullock::Proxy::ProxyServer        *proxy        = nullptr;
    Nullock::Proxy::CertAuthority      *ca           = nullptr;
    Nullock::Proxy::InterceptController *intercept   = nullptr;
    Nullock::FrontEnd::ProxyModel      *history      = nullptr;
    Nullock::FrontEnd::ProxyFilterModel *historyView = nullptr;
    Nullock::FrontEnd::SiteMapModel    *siteMap      = nullptr;
    Nullock::FrontEnd::ThemesManager   *themes       = nullptr;
    Nullock::Core::ProjectStore        *projectStore = nullptr;
    Nullock::Core::Repeater            *repeater     = nullptr;
    Nullock::Core::Intruder            *intruder     = nullptr;
    Nullock::Core::ExtensionsApi       *extensions   = nullptr;
    Nullock::Core::PassiveScanner      *scanner      = nullptr;
    Nullock::Core::PortScanner         *portScanner  = nullptr;
    Nullock::Core::ReconEngine         *recon        = nullptr;
    Nullock::Core::SessionManager      *sessions     = nullptr;
    Nullock::Core::OastServer          *oast         = nullptr;
    Nullock::Core::OastCorrelator      *oastCorrelator = nullptr;
    Nullock::Core::DnsSink             *dnsSink      = nullptr;
    Nullock::Core::SessionRules        *sessionRules = nullptr;
    Nullock::Core::Crawler             *crawler      = nullptr;
    Nullock::Core::UpdateChecker       *updates      = nullptr;
    QString                              uiDir;       // path to ui-v2/
};

// HTTP/1.1 server on 127.0.0.1:port. Serves static files from uiDir for
// requests like GET /Nullock.html, and routes /api/* to JSON handlers
// backed by the wired backend pointers.
class ControlServer : public QObject {
    Q_OBJECT
public:
    explicit ControlServer(const Wiring &w, QObject *parent = nullptr);

    // Configure the bearer token that gates the API. Empty (default) = auth
    // disabled (loopback + CSRF only). MUST be called before start() when
    // binding off-loopback; start() refuses a non-loopback bind without one.
    void setApiToken(const QString &token) { m_apiToken = token; }

    bool start(const QHostAddress &address = QHostAddress::LocalHost,
               quint16 port = 9000);
    void stop();
    bool isRunning() const;
    quint16 listeningPort() const;

private slots:
    void onNewConnection();

private slots:
    void bumpSeq();  // any backend change -> mutating snapshot fingerprint

private:
    void handle(QTcpSocket *socket);
    // ScopeGuard: true if `host` is non-empty and the project marks it out of
    // scope -- so active scans/payloads refuse it. False when no proxy/scope
    // model exists (allow) so headless use is unaffected.
    bool blocksScope(const QString &host) const;
    QByteArray buildSnapshot() const;
    quint64    snapshotSeq() const { return m_seq; }
    QByteArray buildHistoryRow(int id, bool wantRequest) const;
    QByteArray staticResponse(const QString &path) const;
    QByteArray apiResponse(const QString &method, const QString &path,
                           const QByteArray &body,
                           const QString &query) const;

    Wiring     m_wiring;
    QTcpServer *m_server = nullptr;
    quint64    m_seq = 1;
    QString    m_apiToken;              // bearer token; empty = auth disabled
    bool       m_tokenMandatory = false; // true when bound off-loopback: token required for EVERY request
};

// One-shot CI scan gate (no server, no event loop). Runs the deep-audit battery
// against `url` synchronously, evaluates the findings against a `failOn`
// severity threshold (see Nullock::Core::CiGate), prints a summary to stdout
// (one NDJSON line when `ndjson` is true, else a human table), and RETURNS the
// process exit code: 0 = pass (no finding at/above the threshold), 1 = fail.
// A malformed URL prints an error and returns 2. Requires a live
// QCoreApplication (for blocking sockets) but does NOT need app->exec().
int runGateScan(const QString &url, const QString &failOn, bool ndjson);

} // namespace Nullock::Control
