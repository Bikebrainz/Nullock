#include "project_store.hpp"

#include "finding_serial.hpp"
#include "project_logic.hpp"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QMutexLocker>
#include <QStandardPaths>
#include <QTextStream>

namespace Nullock::Core {

namespace {

constexpr int kSchemaVersion = 1;

QJsonArray headersToJson(const QList<QPair<QString, QString>> &headers) {
    QJsonArray arr;
    for (const auto &h : headers) {
        QJsonArray kv;
        kv.append(h.first);
        kv.append(h.second);
        arr.append(kv);
    }
    return arr;
}

QList<QPair<QString, QString>> headersFromJson(const QJsonArray &arr) {
    QList<QPair<QString, QString>> out;
    for (const QJsonValue &v : arr) {
        const QJsonArray kv = v.toArray();
        if (kv.size() == 2)
            out.append({ kv.at(0).toString(), kv.at(1).toString() });
    }
    return out;
}

QJsonObject requestToJson(const Nullock::Proxy::HttpRequest &r) {
    QJsonObject o;
    o["method"]      = r.method;
    o["host"]        = r.host;
    o["port"]        = r.port;
    o["path"]        = r.path;
    o["target"]      = r.target;
    o["httpVersion"] = r.httpVersion;
    o["headers"]     = headersToJson(r.headers);
    o["body_b64"]    = QString::fromLatin1(r.body.toBase64());
    return o;
}

QJsonObject responseToJson(const Nullock::Proxy::HttpResponse &r) {
    QJsonObject o;
    o["httpVersion"]  = r.httpVersion;
    o["statusCode"]   = r.statusCode;
    o["reasonPhrase"] = r.reasonPhrase;
    o["headers"]      = headersToJson(r.headers);
    o["body_b64"]     = QString::fromLatin1(r.body.toBase64());
    o["peerAddress"]  = r.peerAddress;
    o["wasTls"]       = r.wasTls;
    return o;
}

Nullock::Proxy::HttpRequest requestFromJson(const QJsonObject &o) {
    Nullock::Proxy::HttpRequest r;
    r.method      = o.value("method").toString();
    r.host        = o.value("host").toString();
    r.port        = static_cast<quint16>(o.value("port").toInt(80));
    r.path        = o.value("path").toString();
    r.target      = o.value("target").toString();
    r.httpVersion = o.value("httpVersion").toString();
    r.headers     = headersFromJson(o.value("headers").toArray());
    r.body        = QByteArray::fromBase64(o.value("body_b64").toString().toLatin1());
    return r;
}

Nullock::Proxy::HttpResponse responseFromJson(const QJsonObject &o) {
    Nullock::Proxy::HttpResponse r;
    r.httpVersion  = o.value("httpVersion").toString();
    r.statusCode   = o.value("statusCode").toInt();
    r.reasonPhrase = o.value("reasonPhrase").toString();
    r.headers      = headersFromJson(o.value("headers").toArray());
    r.body         = QByteArray::fromBase64(o.value("body_b64").toString().toLatin1());
    r.peerAddress  = o.value("peerAddress").toString();
    r.wasTls       = o.value("wasTls").toBool();
    return r;
}

} // namespace

ProjectStore::ProjectStore(QObject *parent) : QObject(parent) {}
ProjectStore::~ProjectStore() { close(); }

QString ProjectStore::defaultProjectDir() const {
    return projectsRoot() + "/default";
}

QString ProjectStore::projectsRoot() const {
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
           + "/projects";
}

QStringList ProjectStore::listProjects() const {
    QDir root(projectsRoot());
    if (!root.exists()) return {};
    QStringList names;
    for (const QFileInfo &fi : root.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot,
                                                  QDir::Name)) {
        names.append(fi.fileName());
    }
    return names;
}

// The strict project-name whitelist (the path-traversal guard) is pure and lives
// in project_logic.cpp so it can be unit-tested against Qt6::Core alone.
using ProjectLogic::isValidProjectName;

bool ProjectStore::openByName(const QString &name) {
    if (!isValidProjectName(name)) return false;
    const QString dir = projectsRoot() + "/" + name;
    if (!QFileInfo::exists(dir)) return false;  // use createProject() for new
    return open(dir);
}

bool ProjectStore::createProject(const QString &name) {
    if (!isValidProjectName(name)) return false;
    const QString dir = projectsRoot() + "/" + name;
    if (QFileInfo::exists(dir)) {
        // already exists -- just open it instead of failing.
        return open(dir);
    }
    if (!QDir().mkpath(dir)) {
        emit errorOccurred("could not create project dir: " + dir);
        return false;
    }
    return open(dir);
}

bool ProjectStore::open(const QString &projectDir) {
    // Save the OUTGOING project's Repeater tabs (app.cpp handles projectClosing)
    // BEFORE historyShouldClear wipes them -- only when a project is already open,
    // so a switch neither loses staged requests nor leaks them into the next one.
    if (!m_dir.isEmpty())
        emit projectClosing();
    // Tell downstream consumers (ProxyModel, scanner, etc.) to drop their
    // copy of the previous project's state BEFORE close() wipes m_dir.
    emit historyShouldClear();

    close();

    m_dir = projectDir;
    if (!QDir().mkpath(m_dir)) {
        emit errorOccurred("could not create project dir: " + m_dir);
        return false;
    }

    if (!ensureMetadata()) {
        emit errorOccurred("could not read or initialize project metadata");
        return false;
    }

    streamExistingHistory();

    {
        // Same mutex covers open() so a concurrent appendEntry() can't
        // squeeze a write in while we're swapping the underlying file.
        QMutexLocker lk(&m_historyMutex);
        m_history.setFileName(m_dir + "/history.ndjson");
        if (!m_history.open(QIODevice::WriteOnly | QIODevice::Append)) {
            emit errorOccurred("could not open history.ndjson for append: "
                               + m_history.errorString());
            return false;
        }
    }

    // Restore this project's persisted scan findings (findingRestored -> scanner
    // ingest), then open findings.ndjson for append. Read BEFORE we hold our own
    // append handle. Non-fatal on open failure: a locked/unwritable findings file
    // disables persistence this session but must not block using the project.
    streamExistingFindings();
    {
        QMutexLocker lk(&m_findingsMutex);
        m_findingsFile.setFileName(m_dir + "/findings.ndjson");
        if (!m_findingsFile.open(QIODevice::WriteOnly | QIODevice::Append))
            emit errorOccurred("could not open findings.ndjson for append: "
                               + m_findingsFile.errorString());
    }

    // Open the SQLite-backed metadata index next to the ndjson. Failures
    // here are non-fatal -- the rest of the project keeps working, just
    // without /api/history/find acceleration.
    m_historyIndex.open(m_dir);
    // Resume row numbering after the rows this project already has. This rests
    // on two invariants that are true today but silent, so state them:
    //   1. HistoryIndex ids ARE ProxyModel ids -- the same 1-based counter feeds
    //      both, so continuing from the index's count keeps them aligned.
    //   2. rowCount() is a COUNT, and it stands in for MAX(id) only because ids
    //      are dense from 1 and rows are never deleted from the index. If row
    //      deletion is ever added, this must become MAX(id)+1, or a reused id
    //      will collide with an evicted-but-referenced row.
    // Corollary: a history.ndjson that outlives its history-index.sqlite (index
    // rebuilt, file deleted) starts the two sides out of step -- the ndjson has
    // N rows, the fresh index reports 0, and numbering restarts at 1.
    m_nextRowId = m_historyIndex.rowCount() + 1;

    // Tell downstream consumers (ProxyServer) to refresh their copy of
    // scope and rules with whatever this project specifies. Without this,
    // switching projects would carry the previous project's settings.
    emit openedChanged();
    emit scopeChanged(m_meta.inScope, m_meta.outOfScope);
    emit rulesChanged(m_meta.rules);
    // Restore the incoming project's Repeater tabs (app.cpp -> Repeater::importState).
    // Fires AFTER historyShouldClear->clearAll wiped the outgoing tabs, so the panel
    // shows this project's staged requests and nothing from the previous engagement.
    emit repeaterStateChanged(m_meta.repeaterState);
    emit interceptRulesChanged(m_meta.interceptRules);
    emit interceptAutoContentLengthChanged(m_meta.interceptAutoContentLength);
    emit sessionMacrosChanged(m_meta.sessionMacros);
    emit sessionRulesJsonChanged(m_meta.sessionRulesJson);
    emit cookieJarChanged(m_meta.cookieJar);
    emit advancedScopeChanged(m_meta.advancedScope);
    emit acceptInvalidHostsChanged(m_meta.acceptInvalidUpstreamHosts);
    return true;
}

void ProjectStore::close() {
    m_historyIndex.close();
    {
        QMutexLocker lk(&m_historyMutex);
        if (m_history.isOpen()) m_history.close();
    }
    {
        // Drop the findings handle + dedup set so the next project starts clean
        // (and can't be written into the previous project's file).
        QMutexLocker lk(&m_findingsMutex);
        if (m_findingsFile.isOpen()) m_findingsFile.close();
        m_findingKeys.clear();
    }
    if (!m_dir.isEmpty()) {
        m_dir.clear();
        emit openedChanged();
    }
}

bool ProjectStore::ensureMetadata() {
    const QString path = m_dir + "/project.json";
    QFileInfo info(path);
    if (info.exists()) {
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly)) return false;
        const QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
        if (!doc.isObject()) return false;
        const QJsonObject o = doc.object();
        m_meta.name    = o.value("name").toString();
        m_meta.notes   = o.value("notes").toString();
        m_meta.created = QDateTime::fromString(o.value("created").toString(), Qt::ISODateWithMs);
        m_meta.updated = QDateTime::fromString(o.value("updated").toString(), Qt::ISODateWithMs);
        m_meta.inScope.clear();
        for (const QJsonValue &v : o.value("inScope").toArray())
            m_meta.inScope.append(v.toString());
        m_meta.outOfScope.clear();
        for (const QJsonValue &v : o.value("outOfScope").toArray())
            m_meta.outOfScope.append(v.toString());
        m_meta.rules.clear();
        // Imported-rule quarantine. A project.json shared by a colleague
        // (or, less innocently, mailed by an attacker) can carry M&R
        // rules that exfil credentials -- e.g. host=".*" + section=
        // ReqHeader + find="^Cookie: (.*)$" + replace adds a clone
        // header that gets echoed by any in-scope target. We can't tell
        // intent at load time, so we heuristically quarantine the rule
        // shape that's most often weaponised: a catch-all host pattern
        // combined with a credential-header touch. Quarantined rules
        // arrive in the rules table with enabled=false and a comment
        // explaining why, so the user has to look at each one and
        // re-enable consciously.
        static const QStringList kCredentialMarkers = {
            "cookie", "set-cookie", "authorization",
            "proxy-authorization", "bearer", "x-api-key",
            "x-auth-token", "x-csrf-token", "x-xsrf-token",
            "x-session-id", "x-amz-security-token",
        };
        auto isWildcardHost = [](const QString &g) {
            const QString t = g.trimmed();
            return t.isEmpty() || t == "*" || t == ".*" || t == "**";
        };
        auto looksCredential = [&](const QString &s) {
            const QString lower = s.toLower();
            for (const QString &m : kCredentialMarkers)
                if (lower.contains(m)) return true;
            return false;
        };
        for (const QJsonValue &v : o.value("rules").toArray()) {
            const QJsonObject r = v.toObject();
            Nullock::Proxy::MatchReplaceRule rule;
            rule.enabled         = r.value("enabled").toBool(true);
            rule.name            = r.value("name").toString();
            rule.hostGlob        = r.value("hostGlob").toString();
            rule.section         = static_cast<Nullock::Proxy::MatchReplaceRule::Section>(
                                      r.value("section").toInt(1));
            rule.find            = r.value("find").toString();
            rule.replace         = r.value("replace").toString();
            rule.caseInsensitive = r.value("caseInsensitive").toBool(true);
            rule.literal         = r.value("literal").toBool(false);
            rule.comment         = r.value("comment").toString();
            if (rule.enabled
                && isWildcardHost(rule.hostGlob)
                && (looksCredential(rule.find) || looksCredential(rule.replace))) {
                rule.enabled = false;
                const QString tag = QStringLiteral(
                    " [QUARANTINED on load: catch-all host + credential-header touch. "
                    "Review and re-enable if intentional.]");
                if (!rule.comment.contains("QUARANTINED"))
                    rule.comment.append(tag);
            }
            m_meta.rules.append(rule);
        }
        m_meta.repeaterState = o.value("repeater").toObject();
        m_meta.interceptRules = o.value("interceptRules").toArray();
        // Default ON when the key is absent (older projects predate the toggle);
        // an explicit false persists and is honored.
        m_meta.interceptAutoContentLength =
            o.value("interceptAutoContentLength").toBool(true);
        m_meta.sessionMacros = o.value("sessionMacros").toArray();
        m_meta.advancedScope = o.value("advancedScope").toArray();
        // Missing key -> empty array = FAIL CLOSED (verify every upstream). Never a
        // truthy default: a keyless/older project must not silently accept bad certs.
        m_meta.acceptInvalidUpstreamHosts = o.value("acceptInvalidUpstreamHosts").toArray();
        m_meta.sessionRulesJson = o.value("sessionRules").toArray();
        m_meta.cookieJar = o.value("cookieJar").toArray();
        m_meta.suppressedKinds.clear();
        for (const QJsonValue &v : o.value("suppressedKinds").toArray())
            m_meta.suppressedKinds.append(v.toString());
        m_meta.falsePositiveKeys.clear();
        for (const QJsonValue &v : o.value("falsePositiveKeys").toArray())
            m_meta.falsePositiveKeys.append(v.toString());
        m_meta.severityOverrides = o.value("severityOverrides").toArray();
        m_meta.deletedKeys.clear();
        for (const QJsonValue &v : o.value("deletedKeys").toArray())
            m_meta.deletedKeys.append(v.toString());
        return true;
    }

    m_meta = {};
    m_meta.name    = QFileInfo(m_dir).fileName();
    m_meta.created = QDateTime::currentDateTimeUtc();
    m_meta.updated = m_meta.created;
    return saveMetadata();
}

bool ProjectStore::saveMetadata() {
    if (m_dir.isEmpty()) return false;
    QJsonObject o;
    o["v"]       = kSchemaVersion;
    o["name"]    = m_meta.name;
    o["notes"]   = m_meta.notes;
    o["created"] = m_meta.created.toUTC().toString(Qt::ISODateWithMs);
    m_meta.updated = QDateTime::currentDateTimeUtc();
    o["updated"] = m_meta.updated.toUTC().toString(Qt::ISODateWithMs);
    QJsonArray inS;  for (const QString &s : m_meta.inScope)    inS.append(s);
    QJsonArray outS; for (const QString &s : m_meta.outOfScope) outS.append(s);
    o["inScope"]    = inS;
    o["outOfScope"] = outS;
    QJsonArray rulesArr;
    for (const auto &r : m_meta.rules) {
        QJsonObject ro;
        ro["enabled"]         = r.enabled;
        ro["name"]            = r.name;
        ro["hostGlob"]        = r.hostGlob;
        ro["section"]         = static_cast<int>(r.section);
        ro["find"]            = r.find;
        ro["replace"]         = r.replace;
        ro["caseInsensitive"] = r.caseInsensitive;
        ro["literal"]         = r.literal;
        ro["comment"]         = r.comment;
        rulesArr.append(ro);
    }
    o["rules"] = rulesArr;
    o["repeater"] = m_meta.repeaterState;
    o["interceptRules"] = m_meta.interceptRules;
    o["interceptAutoContentLength"] = m_meta.interceptAutoContentLength;
    o["sessionMacros"] = m_meta.sessionMacros;
    o["advancedScope"] = m_meta.advancedScope;
    o["acceptInvalidUpstreamHosts"] = m_meta.acceptInvalidUpstreamHosts;
    o["sessionRules"]  = m_meta.sessionRulesJson;
    o["cookieJar"]     = m_meta.cookieJar;
    o["suppressedKinds"]   = QJsonArray::fromStringList(m_meta.suppressedKinds);
    o["falsePositiveKeys"] = QJsonArray::fromStringList(m_meta.falsePositiveKeys);
    o["severityOverrides"] = m_meta.severityOverrides;
    o["deletedKeys"]       = QJsonArray::fromStringList(m_meta.deletedKeys);

    QFile f(m_dir + "/project.json");
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
    f.write(QJsonDocument(o).toJson(QJsonDocument::Indented));
    return true;
}

void ProjectStore::setRepeaterState(const QJsonObject &state) {
    m_meta.repeaterState = state;
    saveMetadata();
}

void ProjectStore::setInterceptRules(const QJsonArray &rules) {
    m_meta.interceptRules = rules;
    saveMetadata();
}

void ProjectStore::setInterceptAutoContentLength(bool on) {
    if (m_meta.interceptAutoContentLength == on) return;
    m_meta.interceptAutoContentLength = on;
    saveMetadata();
}

void ProjectStore::setSessionMacros(const QJsonArray &macros) {
    m_meta.sessionMacros = macros;
    saveMetadata();
}

void ProjectStore::setAdvancedScope(const QJsonArray &rules) {
    m_meta.advancedScope = rules;
    saveMetadata();
    emit advancedScopeChanged(m_meta.advancedScope);
}

void ProjectStore::setAcceptInvalidUpstreamHosts(const QJsonArray &hosts) {
    m_meta.acceptInvalidUpstreamHosts = hosts;
    saveMetadata();
    emit acceptInvalidHostsChanged(m_meta.acceptInvalidUpstreamHosts);
}

void ProjectStore::setSessionRulesJson(const QJsonArray &rules) {
    m_meta.sessionRulesJson = rules;
    saveMetadata();   // persist only; the API handler already updated the live engine
}

void ProjectStore::setCookieJar(const QJsonArray &jar) {
    m_meta.cookieJar = jar;
    saveMetadata();   // persist only (called at project-close / quit)
}

void ProjectStore::setKindSuppressed(const QString &kind, bool suppressed) {
    if (kind.isEmpty()) return;
    const bool present = m_meta.suppressedKinds.contains(kind);
    if (suppressed && !present)       m_meta.suppressedKinds.append(kind);
    else if (!suppressed && present)  m_meta.suppressedKinds.removeAll(kind);
    else return;                                   // no change -> no rewrite
    saveMetadata();
    emit triageChanged();
}

void ProjectStore::setFindingFalsePositive(const QString &key, bool falsePositive) {
    if (key.isEmpty()) return;
    const bool present = m_meta.falsePositiveKeys.contains(key);
    if (falsePositive && !present)       m_meta.falsePositiveKeys.append(key);
    else if (!falsePositive && present)  m_meta.falsePositiveKeys.removeAll(key);
    else return;
    saveMetadata();
    emit triageChanged();
}

void ProjectStore::setFindingSeverity(const QString &key, const QString &severity) {
    if (key.isEmpty()) return;
    // Rebuild the array without this key, then re-add if a non-empty severity was
    // given (an empty severity clears the override).
    QJsonArray next;
    bool changed = false;
    for (const QJsonValue &v : m_meta.severityOverrides) {
        if (v.toObject().value("key").toString() == key) { changed = true; continue; }
        next.append(v);
    }
    if (!severity.isEmpty()) {
        next.append(QJsonObject{ { "key", key }, { "severity", severity } });
        changed = true;
    }
    if (!changed) return;
    m_meta.severityOverrides = next;
    saveMetadata();
    emit triageChanged();
}

void ProjectStore::setFindingDeleted(const QString &key, bool deleted) {
    if (key.isEmpty()) return;
    const bool present = m_meta.deletedKeys.contains(key);
    if (deleted && !present)       m_meta.deletedKeys.append(key);
    else if (!deleted && present)  m_meta.deletedKeys.removeAll(key);
    else return;
    saveMetadata();
    emit triageChanged();
}

void ProjectStore::setMetadata(const ProjectMeta &meta) {
    m_meta = meta;
    saveMetadata();
    emit scopeChanged(m_meta.inScope, m_meta.outOfScope);
}

void ProjectStore::setInScope(const QStringList &globs) {
    m_meta.inScope = globs;
    saveMetadata();
    emit scopeChanged(m_meta.inScope, m_meta.outOfScope);
}

void ProjectStore::setOutOfScope(const QStringList &globs) {
    m_meta.outOfScope = globs;
    saveMetadata();
    emit scopeChanged(m_meta.inScope, m_meta.outOfScope);
}

void ProjectStore::setNotes(const QString &notes) {
    m_meta.notes = notes;
    saveMetadata();
}

void ProjectStore::addInScope(const QString &glob) {
    if (glob.isEmpty() || m_meta.inScope.contains(glob)) return;
    m_meta.inScope.append(glob);
    saveMetadata();
    emit scopeChanged(m_meta.inScope, m_meta.outOfScope);
}

void ProjectStore::removeInScope(const QString &glob) {
    if (!m_meta.inScope.removeOne(glob)) return;
    saveMetadata();
    emit scopeChanged(m_meta.inScope, m_meta.outOfScope);
}

void ProjectStore::addOutOfScope(const QString &glob) {
    if (glob.isEmpty() || m_meta.outOfScope.contains(glob)) return;
    m_meta.outOfScope.append(glob);
    saveMetadata();
    emit scopeChanged(m_meta.inScope, m_meta.outOfScope);
}

void ProjectStore::removeOutOfScope(const QString &glob) {
    if (!m_meta.outOfScope.removeOne(glob)) return;
    saveMetadata();
    emit scopeChanged(m_meta.inScope, m_meta.outOfScope);
}

void ProjectStore::setRules(const QList<Nullock::Proxy::MatchReplaceRule> &rules) {
    m_meta.rules = rules;
    saveMetadata();
    emit rulesChanged(m_meta.rules);
}

int ProjectStore::addRule(const Nullock::Proxy::MatchReplaceRule &rule) {
    m_meta.rules.append(rule);
    saveMetadata();
    emit rulesChanged(m_meta.rules);
    return m_meta.rules.size() - 1;
}

bool ProjectStore::updateRule(int index, const Nullock::Proxy::MatchReplaceRule &rule) {
    if (index < 0 || index >= m_meta.rules.size()) return false;
    m_meta.rules[index] = rule;
    saveMetadata();
    emit rulesChanged(m_meta.rules);
    return true;
}

bool ProjectStore::removeRule(int index) {
    if (index < 0 || index >= m_meta.rules.size()) return false;
    m_meta.rules.removeAt(index);
    saveMetadata();
    emit rulesChanged(m_meta.rules);
    return true;
}

bool ProjectStore::toggleRule(int index) {
    if (index < 0 || index >= m_meta.rules.size()) return false;
    m_meta.rules[index].enabled = !m_meta.rules[index].enabled;
    saveMetadata();
    emit rulesChanged(m_meta.rules);
    return true;
}

bool ProjectStore::moveRule(int from, int to) {
    if (from < 0 || from >= m_meta.rules.size()) return false;
    if (to   < 0 || to   >= m_meta.rules.size()) return false;
    if (from == to) return true;
    m_meta.rules.move(from, to);
    saveMetadata();
    emit rulesChanged(m_meta.rules);
    return true;
}

void ProjectStore::streamExistingHistory() {
    const QString path = m_dir + "/history.ndjson";
    if (!QFileInfo::exists(path)) return;

    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return;

    QTextStream in(&f);
    int line = 0;
    while (!in.atEnd()) {
        ++line;
        const QByteArray rawLine = in.readLine().toUtf8();
        if (rawLine.trimmed().isEmpty()) continue;

        const QJsonDocument doc = QJsonDocument::fromJson(rawLine);
        if (!doc.isObject()) {
            emit errorOccurred(QString("history.ndjson line %1: not a JSON object").arg(line));
            continue;
        }
        const QJsonObject o = doc.object();
        const auto req  = requestFromJson(o.value("request").toObject());
        const auto resp = responseFromJson(o.value("response").toObject());
        emit entryLoaded(req, resp);
    }
}

void ProjectStore::appendEntry(const Nullock::Proxy::HttpRequest &request,
                               const Nullock::Proxy::HttpResponse &response) {
    // Build the line outside the lock so the JSON encode doesn't block
    // another thread's response that's racing for the same write slot.
    QJsonObject o;
    o["v"]        = kSchemaVersion;
    o["ts"]       = request.timestamp.toUTC().toString(Qt::ISODateWithMs);
    o["request"]  = requestToJson(request);
    o["response"] = responseToJson(response);
    const QByteArray line = QJsonDocument(o).toJson(QJsonDocument::Compact) + "\n";

    // Hold m_historyMutex across the isOpen() check and the actual
    // write+flush. Without this, a main-thread close() during project
    // switch can drop the file between our check and our write, and on
    // Windows the OS may have already recycled the FD by then.
    int rowId;
    {
        QMutexLocker lk(&m_historyMutex);
        if (!m_history.isOpen()) return;
        m_history.write(line);
        m_history.flush();
        rowId = m_nextRowId++;
    }
    // Mirror metadata into the SQLite index for /api/history/find. Done
    // outside the file mutex so the index write doesn't serialize the
    // hot ndjson append path. HistoryIndex carries its own mutex.
    m_historyIndex.append(rowId, request, response);
}

namespace {
// Identity key for a finding: kind+host+url+summary, US-delimited. Deliberately
// the SAME shape the baseline (control_server /api/baseline) keys on, so the two
// durable finding artifacts dedup identically.
QString findingKey(const Finding &f) {
    const QChar sep(QChar(0x1f));
    return f.kind + sep + f.host + sep + f.url + sep + f.summary;
}
} // namespace

void ProjectStore::appendFinding(const Finding &f) {
    // Encode outside the lock so the JSON work doesn't block a racing writer.
    const QByteArray line =
        QJsonDocument(FindingSerial::toJson(f)).toJson(QJsonDocument::Compact) + "\n";
    const QString key = findingKey(f);

    // Hold m_findingsMutex across the isOpen() check and the write+flush, exactly
    // like appendEntry -- a main-thread project switch can drop the file between
    // our check and our write (and on Windows recycle the FD).
    QMutexLocker lk(&m_findingsMutex);
    if (!m_findingsFile.isOpen()) return;      // no project open -> nothing to do
    if (m_findingKeys.contains(key)) return;   // already persisted -> idempotent
    m_findingKeys.insert(key);
    m_findingsFile.write(line);
    m_findingsFile.flush();
}

void ProjectStore::streamExistingFindings() {
    const QString path = m_dir + "/findings.ndjson";
    if (!QFileInfo::exists(path)) return;

    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return;

    QTextStream in(&f);
    int line = 0;
    while (!in.atEnd()) {
        ++line;
        const QByteArray rawLine = in.readLine().toUtf8();
        if (rawLine.trimmed().isEmpty()) continue;

        const QJsonDocument doc = QJsonDocument::fromJson(rawLine);
        if (!doc.isObject()) {
            emit errorOccurred(QString("findings.ndjson line %1: not a JSON object").arg(line));
            continue;
        }
        const Finding fnd = FindingSerial::fromJson(doc.object());
        {
            // Seed the dedup set so a finding re-discovered after restore is not
            // appended again. Guarded like appendFinding.
            QMutexLocker lk(&m_findingsMutex);
            m_findingKeys.insert(findingKey(fnd));
        }
        emit findingRestored(fnd);
    }
}

void ProjectStore::restoreFindings() {
    streamExistingFindings();
}

namespace {

// Headers that an export should redact unless the caller explicitly
// asks for raw values. These names carry credentials that the user
// almost certainly does not mean to share with a triager / colleague /
// support ticket when they attach a HAR. The threat model: testers
// routinely paste/upload HAR files; a raw export turns "here's the
// bug" into "here's my session for your prod app, also for OAuth, also
// for our jenkins". Redacting by default trades a little debugging
// pain for a much smaller leak surface.
static bool isSensitiveHeader(const QString &name) {
    static const QSet<QString> kSensitive = {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
        "x-session-id",
        "x-amz-security-token",
        "x-goog-iam-authorization-token",
    };
    return kSensitive.contains(name.toLower());
}

QJsonArray harHeaders(const QList<QPair<QString, QString>> &headers, bool redact) {
    QJsonArray arr;
    for (const auto &kv : headers) {
        QJsonObject h;
        h["name"] = kv.first;
        if (redact && isSensitiveHeader(kv.first)) {
            // Preserve ONLY the length, so a consumer can tell the header was
            // present without seeing the value or anything derived from it. No
            // prefix or hash of the secret is emitted -- a prefix would leak the
            // start of a bearer token, which is exactly what redaction is for.
            const QString v = kv.second;
            h["value"] = QString("<redacted: %1 chars>").arg(v.size());
        } else {
            h["value"] = kv.second;
        }
        arr.append(h);
    }
    return arr;
}

QJsonArray harQueryString(const QString &path) {
    QJsonArray arr;
    const int q = path.indexOf('?');
    if (q < 0 || q + 1 >= path.size()) return arr;
    const QString query = path.mid(q + 1);
    for (const QString &pair : query.split('&', Qt::SkipEmptyParts)) {
        const int eq = pair.indexOf('=');
        QJsonObject p;
        if (eq >= 0) {
            p["name"]  = pair.left(eq);
            p["value"] = pair.mid(eq + 1);
        } else {
            p["name"]  = pair;
            p["value"] = "";
        }
        arr.append(p);
    }
    return arr;
}

QString findContentType(const QList<QPair<QString, QString>> &headers) {
    for (const auto &kv : headers)
        if (kv.first.compare("Content-Type", Qt::CaseInsensitive) == 0)
            return kv.second;
    return {};
}

QJsonObject harRequest(const Nullock::Proxy::HttpRequest &r, bool wasTls,
                       bool redact) {
    QJsonObject o;
    o["method"]      = r.method;
    o["url"]         = (wasTls ? QStringLiteral("https://") : QStringLiteral("http://"))
                       + r.host
                       + ((r.port == 80 || r.port == 443) ? QString() : QString(":%1").arg(r.port))
                       + r.path;
    o["httpVersion"] = r.httpVersion;
    o["headers"]     = harHeaders(r.headers, redact);
    o["queryString"] = harQueryString(r.path);
    o["cookies"]     = QJsonArray();
    if (!r.body.isEmpty()) {
        QJsonObject post;
        post["mimeType"] = findContentType(r.headers);
        post["text"]     = QString::fromUtf8(r.body);
        o["postData"]    = post;
    }
    o["headersSize"] = -1;
    o["bodySize"]    = r.body.size();
    return o;
}

QJsonObject harResponse(const Nullock::Proxy::HttpResponse &r, bool redact) {
    QJsonObject content;
    content["size"]     = r.body.size();
    content["mimeType"] = findContentType(r.headers);
    content["text"]     = QString::fromUtf8(r.body);
    QJsonObject o;
    o["status"]      = r.statusCode;
    o["statusText"]  = r.reasonPhrase;
    o["httpVersion"] = r.httpVersion;
    o["headers"]     = harHeaders(r.headers, redact);
    o["cookies"]     = QJsonArray();
    o["content"]     = content;
    o["redirectURL"] = "";
    o["headersSize"] = -1;
    o["bodySize"]    = r.body.size();
    return o;
}

} // namespace

QString ProjectStore::exportHar(const QString &outPathIn) {
    if (m_dir.isEmpty()) {
        emit errorOccurred("exportHar: no project open");
        return {};
    }

    QString outPath = outPathIn;
    if (outPath.isEmpty()) {
        const QString exportDir = m_dir + "/exports";
        QDir().mkpath(exportDir);
        const QString stamp = QDateTime::currentDateTimeUtc()
                                  .toString("yyyyMMdd-HHmmss");
        outPath = exportDir + "/history_" + stamp + ".har";
    }

    QFile in(m_dir + "/history.ndjson");
    QJsonArray entries;
    if (in.open(QIODevice::ReadOnly | QIODevice::Text)) {
        while (!in.atEnd()) {
            const QByteArray line = in.readLine().trimmed();
            if (line.isEmpty()) continue;
            const QJsonDocument doc = QJsonDocument::fromJson(line);
            if (!doc.isObject()) continue;
            const QJsonObject src = doc.object();
            const auto req  = requestFromJson(src.value("request").toObject());
            const auto resp = responseFromJson(src.value("response").toObject());

            QJsonObject entry;
            entry["startedDateTime"] = src.value("ts").toString();
            entry["time"]            = 0;
            entry["request"]         = harRequest(req, resp.wasTls, m_exportRedact);
            entry["response"]        = harResponse(resp, m_exportRedact);
            entry["cache"]           = QJsonObject();
            QJsonObject timings;
            timings["send"]    = -1;
            timings["wait"]    = -1;
            timings["receive"] = -1;
            entry["timings"]   = timings;
            entry["serverIPAddress"] = resp.peerAddress;
            entries.append(entry);
        }
    }

    QJsonObject log;
    log["version"] = "1.2";
    QJsonObject creator;
    creator["name"]    = "Nullock";
    creator["version"] = "0.1";
    log["creator"] = creator;
    log["entries"] = entries;
    QJsonObject root;
    root["log"] = log;

    QFile out(outPath);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        emit errorOccurred("exportHar: could not open " + outPath + " -- " + out.errorString());
        return {};
    }
    out.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    return outPath;
}

namespace {

Nullock::Proxy::HttpRequest harEntryToRequest(const QJsonObject &entry) {
    Nullock::Proxy::HttpRequest req;
    const QJsonObject r = entry.value("request").toObject();
    req.method      = r.value("method").toString();
    req.httpVersion = r.value("httpVersion").toString();
    if (req.httpVersion.isEmpty()) req.httpVersion = QStringLiteral("HTTP/1.1");

    // Parse the URL out into host / port / path.
    const QUrl url(r.value("url").toString());
    req.host = url.host();
    req.port = static_cast<quint16>(url.port(url.scheme() == "https" ? 443 : 80));
    req.path = url.path(QUrl::FullyEncoded);
    if (url.hasQuery()) req.path += "?" + url.query(QUrl::FullyEncoded);
    if (req.path.isEmpty()) req.path = "/";
    req.target = r.value("url").toString();
    for (const QJsonValue &h : r.value("headers").toArray()) {
        const QJsonObject ho = h.toObject();
        req.headers.append({ ho.value("name").toString(), ho.value("value").toString() });
    }
    const QString postText = r.value("postData").toObject().value("text").toString();
    if (!postText.isEmpty()) req.body = postText.toUtf8();
    req.timestamp = QDateTime::fromString(entry.value("startedDateTime").toString(), Qt::ISODateWithMs);
    if (!req.timestamp.isValid()) req.timestamp = QDateTime::currentDateTime();
    return req;
}

Nullock::Proxy::HttpResponse harEntryToResponse(const QJsonObject &entry) {
    Nullock::Proxy::HttpResponse resp;
    const QJsonObject r = entry.value("response").toObject();
    resp.httpVersion  = r.value("httpVersion").toString();
    if (resp.httpVersion.isEmpty()) resp.httpVersion = QStringLiteral("HTTP/1.1");
    resp.statusCode   = r.value("status").toInt();
    resp.reasonPhrase = r.value("statusText").toString();
    for (const QJsonValue &h : r.value("headers").toArray()) {
        const QJsonObject ho = h.toObject();
        resp.headers.append({ ho.value("name").toString(), ho.value("value").toString() });
    }
    const QString contentText = r.value("content").toObject().value("text").toString();
    if (!contentText.isEmpty()) resp.body = contentText.toUtf8();
    resp.peerAddress = entry.value("serverIPAddress").toString();
    const QUrl url(entry.value("request").toObject().value("url").toString());
    resp.wasTls = (url.scheme() == "https");
    return resp;
}

} // namespace

int ProjectStore::importHarBytes(const QByteArray &harJson) {
    const QJsonDocument doc = QJsonDocument::fromJson(harJson);
    if (!doc.isObject()) return -1;
    const QJsonObject log = doc.object().value("log").toObject();
    const QJsonArray entries = log.value("entries").toArray();

    int imported = 0;
    for (const QJsonValue &v : entries) {
        const QJsonObject entry = v.toObject();
        const auto req  = harEntryToRequest(entry);
        const auto resp = harEntryToResponse(entry);
        emit entryLoaded(req, resp);
        // Mirror into our own history.ndjson so subsequent restarts /
        // exports see the imported entries too.
        appendEntry(req, resp);
        ++imported;
    }
    return imported;
}

int ProjectStore::importHar(const QString &harPath) {
    // Defence in depth against `/api/har/import` being used to read
    // arbitrary local files. The path API is a convenience for the QML
    // bridge; the React UI / CLI uses the `har` JSON body shape instead
    // (importHarBytes) and gets here through that bypass-proof route.
    // Reject UNC paths, anything not a regular file, and oversize files.
    const QFileInfo fi(harPath);
    if (!fi.exists() || !fi.isFile() || !fi.isReadable()) {
        emit errorOccurred("importHar: not a readable file: " + harPath);
        return -1;
    }
    if (harPath.startsWith("\\\\") || harPath.startsWith("//")) {
        emit errorOccurred("importHar: UNC paths refused");
        return -1;
    }
    // 256 MB ceiling -- HAR files this big are pathological.
    constexpr qint64 kMaxHarBytes = 256LL * 1024 * 1024;
    if (fi.size() > kMaxHarBytes) {
        emit errorOccurred("importHar: file too large (>256 MB)");
        return -1;
    }
    QFile f(harPath);
    if (!f.open(QIODevice::ReadOnly)) {
        emit errorOccurred("importHar: cannot open " + harPath);
        return -1;
    }
    return importHarBytes(f.readAll());
}

} // namespace Nullock::Core
