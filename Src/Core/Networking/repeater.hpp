#pragma once

#include "networking.hpp"
#include "proxy_server.hpp"

#include <QJsonObject>
#include <QList>
#include <QObject>
#include <QString>

namespace Nullock::FrontEnd {
class ProxyModel;
}

namespace Nullock::Core {

// One past send in a Repeater tab: the request that went out and the response it
// got, with a timestamp. The tab keeps a list so the operator can navigate prior
// sends (Burp's per-tab history), compare them, and re-load one.
struct RepeaterHistoryEntry {
    QString request;
    QString response;
    QString statusLine;
    QString sentAt;      // ISO-8601 UTC
};

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
    // Free-text engagement notes, e.g. "testing IDOR on order id" -- purely
    // client-facing bookkeeping, never sent on the wire or read by send().
    QString notes;
    // Prior sends in this tab (newest last), capped. Session-only: deliberately
    // NOT part of exportState()/project.json, which it would bloat with response
    // bodies -- re-sending reproduces them.
    QList<RepeaterHistoryEntry> history;
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
    // Recompute Content-Length from the actual body before each send (Burp's
    // "Update Content-Length", on by default). Turn OFF to send the bytes
    // verbatim -- e.g. a deliberately-malformed Content-Length for a CL/TE
    // request-smuggling test.
    Q_PROPERTY(bool autoContentLength READ autoContentLength WRITE setAutoContentLength NOTIFY autoContentLengthChanged)
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
    bool    autoContentLength() const { return m_autoContentLength; }
    const QList<RepeaterTab> &tabs() const { return m_tabs; }

    // Full multi-tab state as JSON, for project-file persistence. exportState
    // captures the request side (name/host/port/tls/request/notes/statusLine) +
    // the active index; the response BODY is omitted so project.json stays small
    // (re-sending reproduces it). importState REPLACES all tabs; an empty array
    // resets to a single blank tab so a reopened project never shows the previous
    // engagement's staged requests.
    QJsonObject exportState() const;
    Q_INVOKABLE void importState(const QJsonObject &state);

    // Per-tab send history (newest last). historyCount() is the active tab's; each
    // send appends {request, response, statusLine, sentAt}. loadHistoryAt() loads a
    // past entry back into the active tab's request/response for review or re-send.
    Q_INVOKABLE int  historyCount() const;
    Q_INVOKABLE bool loadHistoryAt(int index);

    void setHost(const QString &h);
    void setPort(int p);
    void setUseTls(bool tls);
    void setRequestText(const QString &t);
    Q_INVOKABLE void setAutoContentLength(bool on);

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
    Q_INVOKABLE bool setTabNotes(int index, const QString &notes);

signals:
    void targetChanged();
    void requestTextChanged();
    void responseChanged();
    void busyChanged();
    void tabsChanged();
    void autoContentLengthChanged();

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
    bool               m_autoContentLength = true;   // Burp-parity default
};

} // namespace Nullock::Core
