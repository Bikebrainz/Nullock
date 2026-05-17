#pragma once

#include <QByteArray>
#include <QHash>
#include <QMutex>
#include <QObject>
#include <QString>
#include <QStringList>

namespace Nullock::Proxy {

struct LeafCert {
    QByteArray certPem;
    QByteArray keyPem;
    bool valid() const { return !certPem.isEmpty() && !keyPem.isEmpty(); }
};

class CertAuthority : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString caCertPath READ caCertPath CONSTANT)
    Q_PROPERTY(QString caDir READ caDir CONSTANT)
    Q_PROPERTY(bool hasOpenssl READ hasOpenssl CONSTANT)
public:
    explicit CertAuthority(QString caDir = {}, QObject *parent = nullptr);

    Q_INVOKABLE bool ensureCa();

    QString caDir() const { return m_caDir; }
    QString caCertPath() const { return m_caCertPath; }
    QString caKeyPath() const { return m_caKeyPath; }
    bool hasOpenssl() const { return !m_opensslExe.isEmpty(); }

    LeafCert leafCertFor(const QString &host);

private:
    bool runOpenssl(const QStringList &args, QByteArray *stderrOut = nullptr);
    static QString findOpensslExe();
    static QString defaultCaDir();

    QString m_caDir;
    QString m_caCertPath;
    QString m_caKeyPath;
    QString m_opensslExe;
    QHash<QString, LeafCert> m_cache;
    QMutex m_mutex;
};

} // namespace Nullock::Proxy
