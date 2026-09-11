#include "project_store.hpp"
#include <QCoreApplication>

#include "finding_serial.hpp"
#include "project_logic.hpp"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
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
constexpr qsizetype kMaxWorkspaceBytes = 64 * 1024 * 1024;

bool validWorkspace(const QByteArray &bytes) {
    if (bytes.size() > kMaxWorkspaceBytes) return false;
    const auto doc = QJsonDocument::fromJson(bytes);
    if (!doc.isObject()) return false;
    const auto object = doc.object();
    return object.isEmpty() || (object.value("config").isObject() && object.value("rows").isArray());
}

constexpr qsizetype kMaxAnnotationsBytes = 1024 * 1024;
QString annotationError(const QJsonObject &note) {
    static const QSet<QString> colors{"", "red", "orange", "yellow", "green",
        "cyan", "blue", "purple", "pink", "gray"};
    for (auto it = note.begin(); it != note.end(); ++it) {
        if (it.key() != "color" && it.key() != "comment") return "Unknown annotation field";
        if (!it.value().isString()) return "Annotation fields must be strings";
    }
    if (!colors.contains(note.value("color").toString())) return "Unknown highlight color";
    if (note.value("comment").toString().size() > 4096) return "Comments are limited to 4096 characters";
    return {};
}
QJsonObject harAnnotation(const QJsonObject &entry) {
    auto note = entry.value("_nullockAnnotation").toObject();
    if (entry.contains("comment")) note["comment"] = entry.value("comment");
    if (annotationError(note).isEmpty() && note.value("color").toString().isEmpty()
        && note.value("comment").toString().isEmpty()) return {};
    return note;
}

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
    return qEnvironmentVariable("NULLOCK_DATA_DIR", QStandardPaths::writableLocation(QStandardPaths::AppDataLocation))
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
    if (!prepareSwitch()) return false;
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

bool ProjectStore::prepareSwitch() {
    m_lastError.clear();
    if (m_switchGuard && !m_switchGuard()) {
        m_lastError = "Project is busy. Finish active requests/scans and close proxy connections before switching or clearing history.";
        emit errorOccurred(m_lastError);
        return false;
    }
    return true;
}

bool ProjectStore::clearHistory() {
    if (!isOpen() || !prepareSwitch()) return false;
    QMutexLocker historyLock(&m_historyMutex);
    QMutexLocker findingsLock(&m_findingsMutex);
    const QString suffix = ".clear-backup-" + QUuid::createUuid().toString(QUuid::WithoutBraces);
    const QString historyPath = m_history.fileName();
    const QString findingsPath = m_findingsFile.fileName();
    const QString oldEpoch = m_meta.historyEpoch;
    const auto oldAnnotations = m_meta.historyAnnotations;
    bool historyMoved = false, findingsMoved = false;
    // Keep the original archives until every replacement is writable. Renaming
    // is independent of archive size and allows rollback on an ordinary I/O error.
    m_history.flush();
    m_findingsFile.flush();
    m_history.close();
    m_findingsFile.close();
    auto fail = [&] {
        m_history.close();
        m_findingsFile.close();
        bool restored = true;
        if (historyMoved) {
            if (QFile::exists(historyPath)) restored &= QFile::remove(historyPath);
            restored &= QFile::rename(historyPath + suffix, historyPath);
        }
        if (findingsMoved) {
            if (QFile::exists(findingsPath)) restored &= QFile::remove(findingsPath);
            restored &= QFile::rename(findingsPath + suffix, findingsPath);
        }
        restored &= m_history.open(QIODevice::WriteOnly | QIODevice::Append);
        restored &= m_findingsFile.open(QIODevice::WriteOnly | QIODevice::Append);
        m_meta.historyEpoch = oldEpoch;
        m_meta.historyAnnotations = oldAnnotations;
        m_lastError = restored ? "Could not clear project history; original archives retained"
            : "Could not restore history; recover the .clear-backup files in the project directory";
        emit errorOccurred(m_lastError);
        return false;
    };
    historyMoved = QFile::rename(historyPath, historyPath + suffix);
    if (!historyMoved) return fail();
    findingsMoved = QFile::rename(findingsPath, findingsPath + suffix);
    if (!findingsMoved) return fail();
    if (!m_history.open(QIODevice::WriteOnly | QIODevice::Append)
        || !m_findingsFile.open(QIODevice::WriteOnly | QIODevice::Append)) return fail();
    m_meta.historyEpoch = QUuid::createUuid().toString(QUuid::WithoutBraces);
    m_meta.historyAnnotations = {};
    if (!saveMetadata()) return fail();
    if (!m_historyIndex.clear()) {
        fail();
        saveMetadata();
        return false;
    }
    QFile::remove(historyPath + suffix);
    QFile::remove(findingsPath + suffix);
    m_nextRowId = 1;
    m_archiveAnnotations = {};
    m_annotationsRevision = QUuid::createUuid().toString(QUuid::WithoutBraces);
    m_findingKeys.clear();
    m_historyGeneration = QUuid::createUuid().toString(QUuid::WithoutBraces);
    emit historyCleared();
    return true;
}

bool ProjectStore::open(const QString &projectDir) {
    if (!prepareSwitch()) return false;
    if (projectDir.trimmed().isEmpty() || !QDir().mkpath(projectDir)) {
        m_lastError = "Could not create project directory: " + projectDir;
        emit errorOccurred(m_lastError);
        return false;
    }
    // Check the incoming workspace before clearing the current one. Legacy
    // projects have no file and start with the Intruder's default state.
    QByteArray incomingWorkspace = "{}";
    QFile workspace(projectDir + "/intruder.json");
    if (workspace.exists()) {
        if (!workspace.open(QIODevice::ReadOnly) || workspace.size() > kMaxWorkspaceBytes) {
            m_lastError = "Could not read Intruder workspace; current project retained";
            emit errorOccurred(m_lastError);
            return false;
        }
        incomingWorkspace = workspace.readAll();
        workspace.close();
        if (!validWorkspace(incomingWorkspace)) {
            m_lastError = "Invalid Intruder workspace; current project retained";
            emit errorOccurred(m_lastError);
            return false;
        }
    }
    if (isOpen() && m_workspaceSave && !m_workspaceSave()) return false;
    // Reopening the same project must restore the state just saved, rather than
    // the previous file read during preflight above.
    if (isOpen() && QFileInfo(m_dir).canonicalFilePath() == QFileInfo(projectDir).canonicalFilePath())
        incomingWorkspace = m_intruderWorkspace;
    m_historyGeneration = QUuid::createUuid().toString(QUuid::WithoutBraces);
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
    m_intruderWorkspace = incomingWorkspace;
    if (!QDir().mkpath(m_dir)) {
        emit errorOccurred("could not create project dir: " + m_dir);
        return false;
    }

    if (!ensureMetadata()) {
        emit errorOccurred("could not read or initialize project metadata");
        return false;
    }

    if (m_meta.historyEpoch.isEmpty()) {
        m_meta.historyEpoch = QUuid::createUuid().toString(QUuid::WithoutBraces);
        saveMetadata();
    }
    m_historyIndex.open(m_dir);
    m_historyIndex.beginRebuild();
    m_nextRowId = 1;
    m_archiveAnnotations = {};
    m_annotationsRevision = QUuid::createUuid().toString(QUuid::WithoutBraces);
    streamExistingHistory();
    m_historyIndex.endRebuild();

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
    emit intruderWorkspaceChanged(m_intruderWorkspace);
    emit interceptRulesChanged(m_meta.interceptRules);
    emit interceptAutoContentLengthChanged(m_meta.interceptAutoContentLength);
    emit interceptAutoFixNewlinesChanged(m_meta.interceptAutoFixNewlines);
    emit logOutOfScopeChanged(m_meta.logOutOfScope);
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
        m_meta.historyEpoch = o.value("historyEpoch").toString();
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
        m_meta.historyAnnotations = o.value("historyAnnotations").toObject();
        if (QJsonDocument(m_meta.historyAnnotations).toJson(QJsonDocument::Compact).size() > kMaxAnnotationsBytes)
            return false;
        for (auto it = m_meta.historyAnnotations.begin(); it != m_meta.historyAnnotations.end(); ++it) {
            bool validId = false;
            const int id = it.key().toInt(&validId);
            if (!validId || id <= 0 || QString::number(id) != it.key()) return false;
            if (!it.value().isNull() && (!it.value().isObject()
                || !annotationError(it.value().toObject()).isEmpty())) return false;
        }
        m_meta.interceptRules = o.value("interceptRules").toArray();
        // Default ON when the key is absent (older projects predate the toggle);
        // an explicit false persists and is honored.
        m_meta.interceptAutoContentLength =
            o.value("interceptAutoContentLength").toBool(true);
        // Same absent-key-means-Burp-default-ON contract as interceptAutoContentLength.
        m_meta.interceptAutoFixNewlines =
            o.value("interceptAutoFixNewlines").toBool(true);
        // Default OFF when the key is absent (older projects predate the toggle),
        // matching ProxyServer's own restricted-to-scope-by-default posture.
        m_meta.logOutOfScope = o.value("logOutOfScope").toBool(false);
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
    o["historyEpoch"] = m_meta.historyEpoch;
    o["historyAnnotations"] = m_meta.historyAnnotations;
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
    o["interceptAutoFixNewlines"] = m_meta.interceptAutoFixNewlines;
    o["logOutOfScope"] = m_meta.logOutOfScope;
    o["sessionMacros"] = m_meta.sessionMacros;
    o["advancedScope"] = m_meta.advancedScope;
    o["acceptInvalidUpstreamHosts"] = m_meta.acceptInvalidUpstreamHosts;
    o["sessionRules"]  = m_meta.sessionRulesJson;
    o["cookieJar"]     = m_meta.cookieJar;
    o["suppressedKinds"]   = QJsonArray::fromStringList(m_meta.suppressedKinds);
    o["falsePositiveKeys"] = QJsonArray::fromStringList(m_meta.falsePositiveKeys);
    o["severityOverrides"] = m_meta.severityOverrides;
    o["deletedKeys"]       = QJsonArray::fromStringList(m_meta.deletedKeys);

    QSaveFile f(m_dir + "/project.json");
    if (!f.open(QIODevice::WriteOnly)) return false;
    const QByteArray bytes = QJsonDocument(o).toJson(QJsonDocument::Indented);
    if (f.write(bytes) != bytes.size()) return false;
    return f.commit();
}

void ProjectStore::setRepeaterState(const QJsonObject &state) {
    m_meta.repeaterState = state;
    saveMetadata();
}

bool ProjectStore::saveIntruderWorkspace(const QByteArray &state) {
    if (!isOpen() || !validWorkspace(state)) {
        m_lastError = "Could not save Intruder workspace: no open project or invalid/oversized state";
        emit errorOccurred(m_lastError);
        return false;
    }
    QSaveFile file(m_dir + "/intruder.json");
    if (!file.open(QIODevice::WriteOnly) || file.write(state) != state.size() || !file.commit()) {
        m_lastError = "Could not save Intruder workspace; keep this project open and retry or export the attack";
        emit errorOccurred(m_lastError);
        return false;
    }
    m_intruderWorkspace = state;
    m_lastError.clear();
    return true;
}

QJsonObject ProjectStore::historyAnnotations() const {
    if (!isOpen()) return {};
    auto notes = m_archiveAnnotations;
    for (auto it = m_meta.historyAnnotations.begin(); it != m_meta.historyAnnotations.end(); ++it) {
        if (it.value().isNull()) notes.remove(it.key());
        else notes[it.key()] = it.value();
    }
    return notes;
}

bool ProjectStore::annotateHistory(int id, const QJsonObject &patch) {
    m_lastError = annotationError(patch);
    if (!m_lastError.isEmpty()) return false;
    if (!isOpen() || id <= 0 || id >= m_nextRowId) {
        m_lastError = "History row not found in this project";
        return false;
    }
    if (patch.isEmpty()) { m_lastError = "Supply a color or comment"; return false; }
    const auto key = QString::number(id);
    auto note = historyAnnotations().value(key).toObject();
    for (auto it = patch.begin(); it != patch.end(); ++it) note[it.key()] = it.value();
    const auto previous = m_meta.historyAnnotations;
    if (note.value("color").toString().isEmpty() && note.value("comment").toString().isEmpty()) {
        if (m_archiveAnnotations.contains(key)) m_meta.historyAnnotations[key] = QJsonValue::Null;
        else m_meta.historyAnnotations.remove(key);
    } else m_meta.historyAnnotations[key] = note;
    if (QJsonDocument(m_meta.historyAnnotations).toJson(QJsonDocument::Compact).size() > kMaxAnnotationsBytes
        || QJsonDocument(historyAnnotations()).toJson(QJsonDocument::Compact).size() > kMaxAnnotationsBytes) {
        m_meta.historyAnnotations = previous;
        m_lastError = "Project annotations exceed the 1 MiB limit";
        return false;
    }
    if (!saveMetadata()) {
        m_meta.historyAnnotations = previous;
        m_lastError = "Could not save annotation; the previous note is unchanged";
        return false;
    }
    m_annotationsRevision = QUuid::createUuid().toString(QUuid::WithoutBraces);
    emit annotationsChanged();
    return true;
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

void ProjectStore::setInterceptAutoFixNewlines(bool on) {
    if (m_meta.interceptAutoFixNewlines == on) return;
    m_meta.interceptAutoFixNewlines = on;
    saveMetadata();
}

void ProjectStore::setLogOutOfScope(bool on) {
    if (m_meta.logOutOfScope == on) return;
    m_meta.logOutOfScope = on;
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
        const auto note = o.value("annotation").toObject();
        if (!note.isEmpty() && annotationError(note).isEmpty())
            m_archiveAnnotations[QString::number(m_nextRowId)] = note;
        m_historyIndex.append(m_nextRowId++, req, resp);
        emit entryLoaded(req, resp);
    }
}

void ProjectStore::appendEntry(const Nullock::Proxy::HttpRequest &request,
                               const Nullock::Proxy::HttpResponse &response) {
    appendAnnotatedEntry(request, response, {});
}

bool ProjectStore::appendAnnotatedEntry(const Nullock::Proxy::HttpRequest &request,
                                       const Nullock::Proxy::HttpResponse &response,
                                       const QJsonObject &annotation) {
    // Build the line outside the lock so the JSON encode doesn't block
    // another thread's response that's racing for the same write slot.
    QJsonObject o;
    o["v"]        = kSchemaVersion;
    o["ts"]       = request.timestamp.toUTC().toString(Qt::ISODateWithMs);
    o["request"]  = requestToJson(request);
    o["response"] = responseToJson(response);
    if (!annotation.isEmpty()) o["annotation"] = annotation;
    const QByteArray line = QJsonDocument(o).toJson(QJsonDocument::Compact) + "\n";

    // Hold m_historyMutex across the isOpen() check and the actual
    // write+flush. Without this, a main-thread close() during project
    // switch can drop the file between our check and our write, and on
    // Windows the OS may have already recycled the FD by then.
    int rowId;
    {
        QMutexLocker lk(&m_historyMutex);
        if (!m_history.isOpen()) return false;
        const auto previousSize = m_history.size();
        if (m_history.write(line) != line.size() || !m_history.flush()) {
            m_history.resize(previousSize);
            m_lastError = "Could not append project history";
            emit errorOccurred(m_lastError);
            return false;
        }
        rowId = m_nextRowId++;
    }
    // Mirror metadata into the SQLite index for /api/history/find. Done
    // outside the file mutex so the index write doesn't serialize the
    // hot ndjson append path. HistoryIndex carries its own mutex.
    m_historyIndex.append(rowId, request, response);
    if (!annotation.isEmpty()) {
        m_archiveAnnotations[QString::number(rowId)] = annotation;
        m_annotationsRevision = QUuid::createUuid().toString(QUuid::WithoutBraces);
        emit annotationsChanged();
    }
    return true;
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

// Query/body PARAM keys that carry credentials. A redacted HAR export must
// scrub these from the URL, the queryString array, and form/JSON bodies -- the
// same intent as isSensitiveHeader, extended past headers. Without it a captured
// ?access_token=... / X-Amz-Signature=... , an OAuth `code`, or a bearer in a
// JSON/form login body survives verbatim into the artifact redaction exists to
// make shareable.
static bool isSensitiveParamKey(const QString &name) {
    static const QSet<QString> k = {
        "token", "access_token", "access-token", "refresh_token", "id_token",
        "auth", "authorization", "api_key", "apikey", "x-api-key", "key",
        "client_secret", "secret", "password", "passwd", "pwd", "session",
        "sessionid", "sid", "jwt", "code", "signature", "sig",
        "x-amz-signature", "x-amz-security-token",
    };
    return k.contains(name.trimmed().toLower());
}

static QString harRedactMarker(int n) {
    return QStringLiteral("<redacted: %1 chars>").arg(n);
}

// Redact sensitive VALUES (by key) in an &-joined query/form string.
static QString redactParamString(const QString &s) {
    QStringList out;
    const QStringList pairs = s.split('&', Qt::KeepEmptyParts);
    for (const QString &pair : pairs) {
        const int eq = pair.indexOf('=');
        if (eq >= 0 && isSensitiveParamKey(pair.left(eq)))
            out << pair.left(eq) + "=" + harRedactMarker(pair.size() - eq - 1);
        else
            out << pair;
    }
    return out.join('&');
}

// Recursively redact values of sensitive KEYS in a JSON value (depth-bounded).
static QJsonValue redactJsonValue(const QJsonValue &v, int depth) {
    if (depth > 12) return v;
    if (v.isObject()) {
        const QJsonObject in = v.toObject();
        QJsonObject o;
        for (auto it = in.begin(); it != in.end(); ++it) {
            if (isSensitiveParamKey(it.key()) && it.value().isString())
                o[it.key()] = harRedactMarker(it.value().toString().size());
            else
                o[it.key()] = redactJsonValue(it.value(), depth + 1);
        }
        return o;
    }
    if (v.isArray()) {
        const QJsonArray in = v.toArray();
        QJsonArray a;
        for (const QJsonValue &e : in) a.append(redactJsonValue(e, depth + 1));
        return a;
    }
    return v;
}

// Redact a request/response body by its content-type. Form bodies scrub by
// param key; JSON bodies scrub by object key. An unrecognised/opaque body is
// left as-is (we can't reliably locate a secret in it) -- header + query
// redaction still covers the common credential vectors.
static QString redactBody(const QByteArray &body, const QString &contentType, bool redact) {
    if (!redact || body.isEmpty()) return QString::fromUtf8(body);
    const QString ct = contentType.toLower();
    if (ct.contains("application/x-www-form-urlencoded"))
        return redactParamString(QString::fromUtf8(body));
    if (ct.contains("json")) {
        QJsonParseError err{};
        const QJsonDocument d = QJsonDocument::fromJson(body, &err);
        if (err.error == QJsonParseError::NoError) {
            if (d.isObject())
                return QString::fromUtf8(QJsonDocument(redactJsonValue(QJsonValue(d.object()), 0).toObject()).toJson(QJsonDocument::Compact));
            if (d.isArray())
                return QString::fromUtf8(QJsonDocument(redactJsonValue(QJsonValue(d.array()), 0).toArray()).toJson(QJsonDocument::Compact));
        }
    }
    return QString::fromUtf8(body);
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

QJsonArray harQueryString(const QString &path, bool redact) {
    QJsonArray arr;
    const int q = path.indexOf('?');
    if (q < 0 || q + 1 >= path.size()) return arr;
    const QString query = path.mid(q + 1);
    for (const QString &pair : query.split('&', Qt::SkipEmptyParts)) {
        const int eq = pair.indexOf('=');
        QJsonObject p;
        if (eq >= 0) {
            p["name"]  = pair.left(eq);
            const QString val = pair.mid(eq + 1);
            p["value"] = (redact && isSensitiveParamKey(pair.left(eq)))
                             ? harRedactMarker(val.size()) : val;
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

void harBody(QJsonObject &out, const QByteArray &body, const QString &type,
             bool redact, const QString &encodingKey) {
    const QString text = QString::fromUtf8(body);
    if (text.toUtf8() != body || body.contains('\0')) {
        out["text"] = QString::fromLatin1(body.toBase64());
        out[encodingKey] = "base64";
    } else {
        out["text"] = redactBody(body, type, redact);
    }
}

QByteArray importHarBody(const QJsonObject &content) {
    const QString encoding = content.value("encoding").toString(content.value("_encoding").toString());
    const QByteArray text = content.value("text").toString().toUtf8();
    return encoding == "base64" ? QByteArray::fromBase64(text, QByteArray::AbortOnBase64DecodingErrors) : text;
}

QJsonObject harRequest(const Nullock::Proxy::HttpRequest &r, bool wasTls,
                       bool redact) {
    QJsonObject o;
    o["method"]      = r.method;
    // Redact credential-bearing params out of the URL's query, too -- not just
    // the queryString array below (both derive from r.path's query).
    QString urlPath = r.path;
    if (redact) {
        const int q = urlPath.indexOf('?');
        if (q >= 0 && q + 1 < urlPath.size())
            urlPath = urlPath.left(q + 1) + redactParamString(urlPath.mid(q + 1));
    }
    o["url"]         = (wasTls ? QStringLiteral("https://") : QStringLiteral("http://"))
                       + r.host
                       + ((r.port == 80 || r.port == 443) ? QString() : QString(":%1").arg(r.port))
                       + urlPath;
    o["httpVersion"] = r.httpVersion;
    o["headers"]     = harHeaders(r.headers, redact);
    o["queryString"] = harQueryString(r.path, redact);
    o["cookies"]     = QJsonArray();
    if (!r.body.isEmpty()) {
        QJsonObject post;
        const QString ct = findContentType(r.headers);
        post["mimeType"] = ct;
        harBody(post, r.body, ct, redact, "_encoding");
        o["postData"]    = post;
    }
    o["headersSize"] = -1;
    o["bodySize"]    = r.body.size();
    return o;
}

QJsonObject harResponse(const Nullock::Proxy::HttpResponse &r, bool redact) {
    QJsonObject content;
    const QString ct = findContentType(r.headers);
    content["size"]     = r.body.size();
    content["mimeType"] = ct;
    // A login/token response body carries the credential too (e.g. a JSON
    // {"access_token":"..."}) -- redact by key like the request body.
    harBody(content, r.body, ct, redact, "encoding");
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
    const auto annotations = historyAnnotations();
    int rowId = 0;
    if (in.open(QIODevice::ReadOnly | QIODevice::Text)) {
        while (!in.atEnd()) {
            const QByteArray line = in.readLine().trimmed();
            if (line.isEmpty()) continue;
            const QJsonDocument doc = QJsonDocument::fromJson(line);
            if (!doc.isObject()) continue;
            const QJsonObject src = doc.object();
            const auto annotation = annotations.value(QString::number(++rowId)).toObject();
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
            if (!annotation.isEmpty()) {
                entry["_nullockAnnotation"] = annotation;
                entry["comment"] = annotation.value("comment").toString();
            }
            entries.append(entry);
        }
    }

    QJsonObject log;
    log["version"] = "1.2";
    QJsonObject creator;
    creator["name"]    = "Nullock";
    creator["version"] = QCoreApplication::applicationVersion();
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
    req.body = importHarBody(r.value("postData").toObject());
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
    resp.body = importHarBody(r.value("content").toObject());
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

    // Validate every encoded body before mutating the project (atomic rejection).
    auto prospectiveNotes = historyAnnotations();
    int prospectiveId = m_nextRowId;
    for (const auto &value : entries) {
        const auto entry = value.toObject();
        if (entry.contains("_nullockAnnotation") && !entry.value("_nullockAnnotation").isObject()) return -1;
        const auto note = harAnnotation(entry);
        if (!annotationError(note).isEmpty()) return -1;
        if (!note.isEmpty()) prospectiveNotes[QString::number(prospectiveId)] = note;
        ++prospectiveId;
        const QList<QJsonObject> bodies{entry.value("request").toObject().value("postData").toObject(),
            entry.value("response").toObject().value("content").toObject()};
        for (const auto &body : bodies) {
            const auto encoding = body.value("encoding").toString(body.value("_encoding").toString());
            if (!encoding.isEmpty() && encoding != "base64") return -1;
            if (encoding == "base64" && !QByteArray::fromBase64Encoding(body.value("text").toString().toLatin1(),
                    QByteArray::AbortOnBase64DecodingErrors)) return -1;
        }
    }
    if (QJsonDocument(prospectiveNotes).toJson(QJsonDocument::Compact).size() > kMaxAnnotationsBytes) return -1;
    int imported = 0;
    for (const QJsonValue &v : entries) {
        const QJsonObject entry = v.toObject();
        const auto req  = harEntryToRequest(entry);
        const auto resp = harEntryToResponse(entry);
        // Mirror into our own history.ndjson so subsequent restarts /
        // exports see the imported entries too.
        if (!appendAnnotatedEntry(req, resp, harAnnotation(entry))) return -1;
        emit entryLoaded(req, resp);
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
