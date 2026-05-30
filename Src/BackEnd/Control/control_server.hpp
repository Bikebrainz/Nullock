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
    QString                              uiDir;       // path to ui-v2/
};

// HTTP/1.1 server on 127.0.0.1:port. Serves static files from uiDir for
// requests like GET /Nullock.html, and routes /api/* to JSON handlers
// backed by the wired backend pointers.
class ControlServer : public QObject {
    Q_OBJECT
public:
    explicit ControlServer(const Wiring &w, QObject *parent = nullptr);

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
};

} // namespace Nullock::Control
