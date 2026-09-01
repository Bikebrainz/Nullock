#pragma once

#include "history_index.hpp"
#include "passive_scanner.hpp"   // Nullock::Core::Finding
#include "proxy_server.hpp"

#include <QDateTime>
#include <QFile>
#include <QJsonArray>
#include <QJsonObject>
#include <QMutex>
#include <QObject>
#include <QSet>
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
    // Repeater multi-tab state (opaque JSON owned by the Repeater), so a reopened
    // project restores its staged requests. Serialized under "repeater".
    QJsonObject repeaterState;
    // Proxy intercept match rules (opaque JSON owned by InterceptLogic), so a
    // reopened project restores which messages it holds. Serialized under
    // "interceptRules".
    QJsonArray interceptRules;
    // "Update Content-Length on edit" toggle for the intercept editor (Burp
    // default ON). Persisted under "interceptAutoContentLength" so a security
    // posture the operator turned OFF isn't silently re-armed to ON on reopen.
    bool interceptAutoContentLength = true;
    // "Fix missing/superfluous new lines at end of request" toggle for the
    // intercept editor (Burp default ON). Persisted under
    // "interceptAutoFixNewlines" for the same reopen-must-not-silently-re-arm
    // reason as interceptAutoContentLength.
    bool interceptAutoFixNewlines = true;
    // "Log out-of-scope traffic" toggle (Burp logs everything by default;
    // Nullock's default is OFF -- see ProxyServer::logOutOfScope). Persisted
    // under "logOutOfScope" so a project reopen restores the operator's choice
    // instead of silently reverting to the restricted-to-scope default.
    bool logOutOfScope = false;
    // Named session login macros (opaque JSON owned by SessionRules; see
    // sessionMacrosToJson), so a reopened project restores its recorded login
    // sequences + their auto-re-auth conditions. Serialized under "sessionMacros".
    QJsonArray sessionMacros;
    // Advanced scope rules (opaque JSON owned by ScopeLogic), so a reopened
    // project restores its include/exclude scope rules. Serialized under
    // "advancedScope".
    QJsonArray advancedScope;
    // Hosts ("host:port") the operator allow-listed to accept an INVALID upstream
    // TLS cert on (a self-signed / expired staging box). Serialized under
    // "acceptInvalidUpstreamHosts". Default (missing key) = EMPTY = verify every
    // upstream: this is a security posture, so it must FAIL CLOSED, never inherit a
    // relaxed default. Restored into the live proxy on open().
    QJsonArray acceptInvalidUpstreamHosts;
    // Session-handling RULES (extract-a-value / inject-a-{{var}}), opaque JSON
    // owned by SessionRules (sessionRulesToJson). Serialized under "sessionRules".
    QJsonArray sessionRulesJson;
    // Captured cookie jar (opaque JSON owned by SessionManager). Serialized under
    // "cookieJar"; saved at project-close / quit (not every response) like the
    // Repeater tabs, and restored (expired cookies dropped) on reopen.
    QJsonArray cookieJar;
    // Scanner triage that must outlive the append-only findings.ndjson: issue
    // KINDS the operator suppressed (never shown again) and the identity KEYS of
    // individual findings marked false-positive. Applied at display time, so
    // clearing either brings findings back with no re-scan. Under "suppressedKinds"
    // / "falsePositiveKeys".
    QStringList suppressedKinds;
    QStringList falsePositiveKeys;
    // Per-finding severity overrides ({ "key":<identityKey>, "severity":<level> }
    // objects) and the identity keys of soft-DELETED findings (hidden from the
    // list, restorable). Both applied at display time, like the sets above.
    QJsonArray  severityOverrides;
    QStringList deletedKeys;
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
    // Re-stream <project>/findings.ndjson, emitting findingRestored per finding.
    // open() already does this, but the very first project is opened before the
    // scanner exists, so app.cpp calls this once after wiring to repopulate it.
    Q_INVOKABLE void restoreFindings();
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

    // Redaction policy for THE HAR EXPORT (exportHar). When on (default), known
    // sensitive headers (Authorization, Cookie, Set-Cookie, X-API-Key, etc.)
    // are replaced with "<redacted: N chars>" before leaving the process, so a
    // tester can share a HAR with a triager without also sharing their session.
    //
    // This flag governs the HAR path ONLY. The other exporters redact on their
    // own terms: /api/export/postman applies the SAME header set but toggles it
    // per-request with ?raw=1 (defaulting to redacted), and /api/request/curl
    // does NOT redact at all -- a copied curl command is meant to be re-run and
    // needs the real Authorization/Cookie to work. Callers sharing a curl line
    // are handing over live credentials, by design.
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

    // Repeater multi-tab state, persisted in project.json under "repeater" so a
    // reopened project restores its staged requests. Opaque JSON (the Repeater
    // owns the shape) so Storage needn't depend on repeater.hpp. setRepeaterState
    // persists immediately; app.cpp saves the OUTGOING project's state on
    // projectClosing() (before the switch wipe) and on app quit.
    void setRepeaterState(const QJsonObject &state);
    QJsonObject repeaterState() const { return m_meta.repeaterState; }

    // Proxy intercept rules, persisted in project.json under "interceptRules".
    // Opaque JSON (InterceptLogic owns the shape). setInterceptRules persists
    // immediately; open() emits interceptRulesChanged so app.cpp can push them
    // into the live InterceptController.
    void setInterceptRules(const QJsonArray &rules);
    QJsonArray interceptRules() const { return m_meta.interceptRules; }

    // Intercept "Update Content-Length on edit" toggle, persisted under
    // "interceptAutoContentLength". setInterceptAutoContentLength persists
    // immediately; open() emits interceptAutoContentLengthChanged so app.cpp can
    // push it into the live InterceptController.
    void setInterceptAutoContentLength(bool on);
    bool interceptAutoContentLength() const { return m_meta.interceptAutoContentLength; }

    // Intercept "Fix missing/superfluous new lines at end of request" toggle,
    // persisted under "interceptAutoFixNewlines". setInterceptAutoFixNewlines
    // persists immediately; open() emits interceptAutoFixNewlinesChanged so
    // app.cpp can push it into the live InterceptController.
    void setInterceptAutoFixNewlines(bool on);
    bool interceptAutoFixNewlines() const { return m_meta.interceptAutoFixNewlines; }

    // "Log out-of-scope traffic" toggle, persisted under "logOutOfScope".
    // setLogOutOfScope persists immediately; open() emits logOutOfScopeChanged
    // so app.cpp can push it into the live ProxyServer.
    void setLogOutOfScope(bool on);
    bool logOutOfScope() const { return m_meta.logOutOfScope; }

    // Session login macros, persisted in project.json under "sessionMacros".
    // Opaque JSON (SessionRules::sessionMacrosToJson owns the shape).
    // setSessionMacros persists immediately; open() emits sessionMacrosChanged so
    // app.cpp can push them into the live SessionRules.
    void setSessionMacros(const QJsonArray &macros);
    QJsonArray sessionMacros() const { return m_meta.sessionMacros; }

    // Advanced scope rules, persisted in project.json under "advancedScope".
    // Opaque JSON (ScopeLogic owns the shape). setAdvancedScope persists
    // immediately + emits advancedScopeChanged (the live proxy re-applies every
    // edit, like the simple glob scope does); open() emits it too so a reopen
    // restores the rules.
    void setAdvancedScope(const QJsonArray &rules);
    QJsonArray advancedScope() const { return m_meta.advancedScope; }

    // Accept-invalid-upstream-cert host allow-list, persisted under
    // "acceptInvalidUpstreamHosts". setAcceptInvalidUpstreamHosts persists
    // immediately + emits acceptInvalidHostsChanged (the live proxy re-applies);
    // open() emits it unconditionally (incl. empty) so switching to a project that
    // never set it RESETS the live proxy to empty rather than bleeding the prior
    // engagement's relaxed posture forward.
    void setAcceptInvalidUpstreamHosts(const QJsonArray &hosts);
    QJsonArray acceptInvalidUpstreamHosts() const { return m_meta.acceptInvalidUpstreamHosts; }

    // Session-handling rules, persisted in project.json under "sessionRules".
    // setSessionRulesJson persists immediately (the live SessionRules is updated
    // separately by the API handler); open() emits sessionRulesJsonChanged so a
    // reopen restores them into the live engine.
    void setSessionRulesJson(const QJsonArray &rules);
    QJsonArray sessionRulesJson() const { return m_meta.sessionRulesJson; }

    // Cookie jar, persisted in project.json under "cookieJar". setCookieJar
    // persists only (called at project-close / quit); open() emits cookieJarChanged
    // so a reopen restores it into the live SessionManager.
    void setCookieJar(const QJsonArray &jar);
    QJsonArray cookieJar() const { return m_meta.cookieJar; }

    // Scanner triage, persisted in project.json. setKindSuppressed adds/removes an
    // issue kind from the never-show set; setFindingFalsePositive adds/removes a
    // finding identity key (FindingTriageLogic::findingKey) from the FP set. Both
    // persist immediately and are idempotent. Accessors return snapshot copies.
    void setKindSuppressed(const QString &kind, bool suppressed);
    void setFindingFalsePositive(const QString &key, bool falsePositive);
    // Per-finding severity override (empty severity clears it) + soft-delete.
    // Both persist immediately + emit triageChanged.
    void setFindingSeverity(const QString &key, const QString &severity);
    void setFindingDeleted(const QString &key, bool deleted);
    QStringList suppressedKinds() const    { return m_meta.suppressedKinds; }
    QStringList falsePositiveKeys() const  { return m_meta.falsePositiveKeys; }
    QJsonArray  severityOverrides() const  { return m_meta.severityOverrides; }
    QStringList deletedKeys() const        { return m_meta.deletedKeys; }

public slots:
    // Append one round-trip to history.ndjson. Wire this to
    // ProxyServer::responseReceived.
    void appendEntry(const Nullock::Proxy::HttpRequest &request,
                     const Nullock::Proxy::HttpResponse &response);

    // Append one scan finding to findings.ndjson so it survives app close /
    // project reopen. Wire to PassiveScanner::findingAdded. Deduped by identity
    // key (kind+host+url+summary, matching the baseline) so a re-discovered or
    // restored finding is never written twice. No-op when no project is open.
    void appendFinding(const Finding &f);

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
    // Emitted once per finding streamed back from findings.ndjson on open() /
    // restoreFindings(). Wire to PassiveScanner::ingestFinding so a reopened
    // project's findings panel repopulates.
    void findingRestored(const Finding &f);
    // Emitted at the TOP of open() (before historyShouldClear) when a project is
    // already open, so app.cpp can save the OUTGOING project's Repeater tabs to
    // its own file before the switch wipes them -- no cross-engagement leak.
    void projectClosing();
    // Emitted at the END of open() with the freshly-loaded project's Repeater
    // state. Wire to Repeater::importState to restore the incoming project's tabs.
    void repeaterStateChanged(const QJsonObject &state);
    // Emitted at the END of open() with the freshly-loaded project's intercept
    // rules. Wire (via InterceptLogic::interceptRulesFromJson) to
    // InterceptController::setInterceptRules.
    void interceptRulesChanged(const QJsonArray &rules);
    // Emitted at the END of open() with the freshly-loaded project's intercept
    // "Update Content-Length" toggle. Wire to InterceptController::setAutoContentLength.
    void interceptAutoContentLengthChanged(bool on);
    // Emitted at the END of open() with the freshly-loaded project's intercept
    // "Fix missing/superfluous new lines" toggle. Wire to
    // InterceptController::setAutoFixNewlines.
    void interceptAutoFixNewlinesChanged(bool on);
    // Emitted at the END of open() with the freshly-loaded project's
    // "log out-of-scope traffic" toggle. Wire to ProxyServer::setLogOutOfScope.
    void logOutOfScopeChanged(bool on);
    // Emitted at the END of open() with the freshly-loaded project's session
    // login macros. Wire (via Nullock::Core::sessionMacrosFromJson) to
    // SessionRules::setMacros so a reopened project restores them.
    void sessionMacrosChanged(const QJsonArray &macros);
    // Emitted at the END of open() with the freshly-loaded project's session
    // rules. Wire (via Nullock::Core::sessionRulesFromJson) to SessionRules::setRules.
    void sessionRulesJsonChanged(const QJsonArray &rules);
    // Emitted at the END of open() with the freshly-loaded project's cookie jar.
    // Wire to SessionManager::importJson so a reopen restores it.
    void cookieJarChanged(const QJsonArray &jar);
    // Emitted when the finding-triage sets (suppressed kinds / false-positive
    // keys) change, so the control server can bump its snapshot fingerprint.
    void triageChanged();
    // Emitted whenever the advanced scope rules change (setter + open()), so
    // app.cpp re-applies them to the live proxy and the snapshot bumps.
    void advancedScopeChanged(const QJsonArray &rules);
    // Emitted whenever the accept-invalid-upstream-cert host list changes (setter +
    // open(), unconditionally incl. empty), so app.cpp re-applies it to the live
    // proxy and the snapshot bumps.
    void acceptInvalidHostsChanged(const QJsonArray &hosts);

private:
    bool ensureMetadata();
    void streamExistingHistory();
    void streamExistingFindings();

    QString    m_dir;
    QFile      m_history;
    ProjectMeta m_meta;
    // Redact known-sensitive headers in exports by default. Override per
    // session via setExportRedact(false) when the user explicitly wants
    // the raw values (e.g. importing the HAR back into another instance
    // of Nullock).
    bool m_exportRedact = true;
    // Guards every touch of m_history (open / close / write / flush).
    // Without it, a worker thread mid-appendEntry() races a main-thread
    // close() during project switch: the worker writes into a closed
    // QFile whose FD may have been recycled by the OS to (worst case)
    // the CA private key or a theme JSON the app just opened to write.
    mutable QMutex m_historyMutex;
    // SQLite-backed metadata index over the rows written to ndjson.
    // Drives /api/history/find for fast filtering over very large
    // histories (200k+ rows). Optional -- if the open fails we keep
    // going without the index.
    HistoryIndex m_historyIndex;
    int          m_nextRowId = 1;
    // findings.ndjson: per-project scan-finding persistence, mirroring the
    // history stream above. m_findingsMutex guards BOTH the file and the dedup
    // key set -- a worker-thread findingAdded can race a main-thread project
    // switch (open/close) exactly as appendEntry races close().
    QFile          m_findingsFile;
    mutable QMutex m_findingsMutex;
    QSet<QString>  m_findingKeys;   // identity keys already persisted this project

public:
    HistoryIndex *historyIndex() { return &m_historyIndex; }
};

} // namespace Nullock::Core
