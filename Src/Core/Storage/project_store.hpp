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
};

class ProjectStore : public QObject {
    Q_OBJECT
    Q_PROPERTY(bool isOpen READ isOpen NOTIFY openedChanged)
    Q_PROPERTY(QString currentPath READ currentPath NOTIFY openedChanged)
public:
    explicit ProjectStore(QObject *parent = nullptr);
    ~ProjectStore() override;

    Q_INVOKABLE bool open(const QString &projectDir);
    Q_INVOKABLE void close();
    Q_INVOKABLE bool saveMetadata();
    Q_INVOKABLE QString defaultProjectDir() const;

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

private:
    bool ensureMetadata();
    void streamExistingHistory();

    QString    m_dir;
    QFile      m_history;
    ProjectMeta m_meta;
};

} // namespace Nullock::Core
