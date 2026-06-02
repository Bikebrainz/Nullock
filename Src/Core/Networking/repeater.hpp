#pragma once

#include "networking.hpp"
#include "proxy_server.hpp"

#include <QList>
#include <QObject>
#include <QString>

namespace Nullock::FrontEnd {
class ProxyModel;
}

namespace Nullock::Core {

// One repeater session. The Repeater owns a list of these so the user
// can keep multiple in-flight reproductions side by side -- pin one
// while editing another, compare two responses, etc.
struct RepeaterTab {
    QString name;
    QString host;
    int     port = 443;
    bool    useTls = true;
    QString requestText;
    QString responseText;
    QString statusLine;
};

class Repeater : public QObject {
    Q_OBJECT
    // The single-state properties below all read from the *active* tab.
    // QML bindings written before multi-tab existed keep working.
    Q_PROPERTY(QString host         READ host         WRITE setHost         NOTIFY targetChanged)
    Q_PROPERTY(int     port         READ port         WRITE setPort         NOTIFY targetChanged)
    Q_PROPERTY(bool    useTls       READ useTls       WRITE setUseTls       NOTIFY targetChanged)
    Q_PROPERTY(QString requestText  READ requestText  WRITE setRequestText  NOTIFY requestTextChanged)
    Q_PROPERTY(QString responseText READ responseText                       NOTIFY responseChanged)
    Q_PROPERTY(QString statusLine   READ statusLine                         NOTIFY responseChanged)
    Q_PROPERTY(bool    busy         READ busy                               NOTIFY busyChanged)
    Q_PROPERTY(int     activeTab    READ activeTab    NOTIFY tabsChanged)
    Q_PROPERTY(int     tabCount     READ tabCount     NOTIFY tabsChanged)
public:
    explicit Repeater(Nullock::FrontEnd::ProxyModel *historyModel,
                      QObject *parent = nullptr);

    QString host() const         { return activeTab_().host; }
    int     port() const         { return activeTab_().port; }
    bool    useTls() const       { return activeTab_().useTls; }
    QString requestText() const  { return activeTab_().requestText; }
    QString responseText() const { return activeTab_().responseText; }
    QString statusLine() const   { return activeTab_().statusLine; }
    bool    busy() const         { return m_busy; }
    int     activeTab() const    { return m_active; }
    int     tabCount() const     { return m_tabs.size(); }
    const QList<RepeaterTab> &tabs() const { return m_tabs; }

    void setHost(const QString &h);
    void setPort(int p);
    void setUseTls(bool tls);
    void setRequestText(const QString &t);

    Q_INVOKABLE void loadFromHistory(int row);
    Q_INVOKABLE void send();
    Q_INVOKABLE void clear();
    // Reset every tab back to a single blank tab. Wire this to
    // ProjectStore::historyShouldClear so a project switch wipes any
    // request still loaded from the previous engagement; otherwise the
    // user could open the Repeater after switching projects, see the
    // last engagement's request still loaded, and hit Send without
    // realising they're firing into the wrong target (or leaking the
    // previous client's Authorization headers).
public slots:
    void clearAll();
public:

    // Tab management. Send-to-repeater from the proxy detail view goes
    // through addTabFromHistory so a fresh tab opens automatically.
    Q_INVOKABLE int  addTab(const QString &name = QString());
    Q_INVOKABLE int  addTabFromHistory(int row);
    Q_INVOKABLE bool closeTab(int index);
    Q_INVOKABLE bool setActiveTab(int index);
    Q_INVOKABLE bool renameTab(int index, const QString &name);
    Q_INVOKABLE int  duplicateTab(int index);

signals:
    void targetChanged();
    void requestTextChanged();
    void responseChanged();
    void busyChanged();
    void tabsChanged();

private:
    RepeaterTab       &activeTab_();
    const RepeaterTab &activeTab_() const;
    void               emitAllSlots();
    QString            autoTabName(const QString &host, const QString &request) const;

    Nullock::FrontEnd::ProxyModel *m_model;
    HttpClient m_client;

    QList<RepeaterTab> m_tabs;
    int                m_active = 0;
    bool               m_busy = false;
};

} // namespace Nullock::Core
