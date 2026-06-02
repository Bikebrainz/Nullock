#pragma once

#include "proxy_server.hpp"

#include <QDateTime>
#include <QFile>
#include <QObject>
#include <QString>
#include <QStringList>

namespace Nullock::Core {

struct ProjectMeta {
    QString   name;
    QStringList inScope;
    QStringList outOfScope;
    QString   notes;
    QDateTime created;
    QDateTime updated;
    QList<Nullock::Proxy::MatchReplaceRule> rules;
};

class ProjectStore : public QObject {
    Q_OBJECT
    Q_PROPERTY(bool isOpen READ isOpen NOTIFY openedChanged)
    Q_PROPERTY(QString currentPath READ currentPath NOTIFY openedChanged)
    Q_PROPERTY(QStringList inScopeList READ inScope NOTIFY scopeChanged)
    Q_PROPERTY(QStringList outOfScopeList READ outOfScope NOTIFY scopeChanged)
public:
    explicit ProjectStore(QObject *parent = nullptr);
    ~ProjectStore() override;

    Q_INVOKABLE bool open(const QString &projectDir);
    Q_INVOKABLE void close();
    Q_INVOKABLE bool saveMetadata();
    Q_INVOKABLE QString defaultProjectDir() const;

    // Project management. Projects live as sibling dirs under
    //   <AppData>/projects/<name>
    // listProjects() returns names (not full paths); openByName/createProject
    // resolve under that root.
    Q_INVOKABLE QString projectsRoot() const;
    Q_INVOKABLE QStringList listProjects() const;
    Q_INVOKABLE bool openByName(const QString &name);
    Q_INVOKABLE bool createProject(const QString &name);

    // Re-reads history.ndjson and writes it back as HTTP Archive 1.2
    // (https://w3c.github.io/web-performance/specs/HAR/Overview.html).
    // If outPath is empty, defaults to <project>/exports/history_<ts>.har.
    // Returns the absolute output path on success, empty string on failure.
    Q_INVOKABLE QString exportHar(const QString &outPath = {});

    // Redaction policy for HAR / Postman / Copy-as exports. When on
    // (default), known sensitive headers (Authorization, Cookie, Set-Cookie,
    // X-API-Key, etc.) are replaced with "<redacted: N chars>" before
    // leaving the process. Lets a tester share a HAR with a triager or
    // colleague without also sharing their session.
    void setExportRedact(bool on) { m_exportRedact = on; }
    bool exportRedact() const { return m_exportRedact; }

    // Read a HAR file and replay each entry through the entryLoaded signal
    // (so anything wired to it -- ProxyModel, etc -- picks it up) plus
    // append to our own history.ndjson. Returns number of entries imported,
    // or -1 on error. Accepts either a path or raw JSON bytes.
    Q_INVOKABLE int importHar(const QString &harPath);
    int importHarBytes(const QByteArray &harJson);

    Q_INVOKABLE QStringList inScope() const   { return m_meta.inScope; }
    Q_INVOKABLE QStringList outOfScope() const { return m_meta.outOfScope; }
    Q_INVOKABLE QString notes() const { return m_meta.notes; }

    // Mutate scope from the GUI. Each setter persists to project.json and
    // fires scopeChanged so the proxy can re-apply the rules live.
    Q_INVOKABLE void setInScope(const QStringList &globs);
    Q_INVOKABLE void setOutOfScope(const QStringList &globs);
    Q_INVOKABLE void setNotes(const QString &notes);
    Q_INVOKABLE void addInScope(const QString &glob);
    Q_INVOKABLE void removeInScope(const QString &glob);
    Q_INVOKABLE void addOutOfScope(const QString &glob);
    Q_INVOKABLE void removeOutOfScope(const QString &glob);

    // Match & replace rules. The id is a 1-based row number stable for the
    // session (regenerated on load). Rules are persisted in project.json.
    QList<Nullock::Proxy::MatchReplaceRule> rules() const { return m_meta.rules; }
    void  setRules(const QList<Nullock::Proxy::MatchReplaceRule> &rules);
    int   addRule(const Nullock::Proxy::MatchReplaceRule &rule);
    bool  updateRule(int index, const Nullock::Proxy::MatchReplaceRule &rule);
    bool  removeRule(int index);
    bool  toggleRule(int index);
    bool  moveRule(int from, int to);

    bool isOpen() const { return m_history.isOpen(); }
    QString currentPath() const { return m_dir; }
    const ProjectMeta &metadata() const { return m_meta; }

    void setMetadata(const ProjectMeta &meta);

public slots:
    // Append one round-trip to history.ndjson. Wire this to
    // ProxyServer::responseReceived.
    void appendEntry(const Nullock::Proxy::HttpRequest &request,
                     const Nullock::Proxy::HttpResponse &response);

signals:
    void openedChanged();
    void entryLoaded(const Nullock::Proxy::HttpRequest &request,
                     const Nullock::Proxy::HttpResponse &response);
    void errorOccurred(const QString &message);
    void scopeChanged(const QStringList &inScope, const QStringList &outOfScope);
    void rulesChanged(const QList<Nullock::Proxy::MatchReplaceRule> &rules);
    // Emitted right before open() begins replacing history. Wire to
    // ProxyModel::clear and any other downstream caches that should
    // discard the previous project's state.
    void historyShouldClear();

private:
    bool ensureMetadata();
    void streamExistingHistory();

    QString    m_dir;
    QFile      m_history;
    ProjectMeta m_meta;
    // Redact known-sensitive headers in exports by default. Override per
    // session via setExportRedact(false) when the user explicitly wants
    // the raw values (e.g. importing the HAR back into another instance
    // of Nullock).
    bool m_exportRedact = true;
};

} // namespace Nullock::Core
