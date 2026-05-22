#pragma once

#include "networking.hpp"
#include "proxy_server.hpp"

#include <QObject>
#include <QString>

namespace Nullock::FrontEnd {
class ProxyModel;
}

namespace Nullock::Core {

class Repeater : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString host         READ host         WRITE setHost         NOTIFY targetChanged)
    Q_PROPERTY(int     port         READ port         WRITE setPort         NOTIFY targetChanged)
    Q_PROPERTY(bool    useTls       READ useTls       WRITE setUseTls       NOTIFY targetChanged)
    Q_PROPERTY(QString requestText  READ requestText  WRITE setRequestText  NOTIFY requestTextChanged)
    Q_PROPERTY(QString responseText READ responseText                       NOTIFY responseChanged)
    Q_PROPERTY(QString statusLine   READ statusLine                         NOTIFY responseChanged)
    Q_PROPERTY(bool    busy         READ busy                               NOTIFY busyChanged)
public:
    explicit Repeater(Nullock::FrontEnd::ProxyModel *historyModel,
                      QObject *parent = nullptr);

    QString host() const { return m_host; }
    int     port() const { return m_port; }
    bool    useTls() const { return m_useTls; }
    QString requestText() const { return m_requestText; }
    QString responseText() const { return m_responseText; }
    QString statusLine() const { return m_statusLine; }
    bool    busy() const { return m_busy; }

    void setHost(const QString &h);
    void setPort(int p);
    void setUseTls(bool tls);
    void setRequestText(const QString &t);

    Q_INVOKABLE void loadFromHistory(int row);
    Q_INVOKABLE void send();
    Q_INVOKABLE void clear();

signals:
    void targetChanged();
    void requestTextChanged();
    void responseChanged();
    void busyChanged();

private:
    Nullock::FrontEnd::ProxyModel *m_model;
    HttpClient m_client;

    QString m_host;
    int     m_port = 443;
    bool    m_useTls = true;
    QString m_requestText;
    QString m_responseText;
    QString m_statusLine;
    bool    m_busy = false;
};

} // namespace Nullock::Core
