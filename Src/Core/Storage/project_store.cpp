#include "project_store.hpp"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
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
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
           + "/projects/default";
}

bool ProjectStore::open(const QString &projectDir) {
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

    m_history.setFileName(m_dir + "/history.ndjson");
    if (!m_history.open(QIODevice::WriteOnly | QIODevice::Append)) {
        emit errorOccurred("could not open history.ndjson for append: "
                           + m_history.errorString());
        return false;
    }

    emit openedChanged();
    return true;
}

void ProjectStore::close() {
    if (m_history.isOpen()) m_history.close();
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

    QFile f(m_dir + "/project.json");
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
    f.write(QJsonDocument(o).toJson(QJsonDocument::Indented));
    return true;
}

void ProjectStore::setMetadata(const ProjectMeta &meta) {
    m_meta = meta;
    saveMetadata();
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
    if (!m_history.isOpen()) return;

    QJsonObject o;
    o["v"]        = kSchemaVersion;
    o["ts"]       = request.timestamp.toUTC().toString(Qt::ISODateWithMs);
    o["request"]  = requestToJson(request);
    o["response"] = responseToJson(response);

    const QByteArray line = QJsonDocument(o).toJson(QJsonDocument::Compact) + "\n";
    m_history.write(line);
    m_history.flush();
}

} // namespace Nullock::Core
