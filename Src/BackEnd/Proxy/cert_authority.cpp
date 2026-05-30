#include "cert_authority.hpp"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QMutexLocker>
#include <QProcess>
#include <QStandardPaths>

namespace Nullock::Proxy {

namespace {

constexpr int kStartTimeoutMs = 5'000;
constexpr int kRunTimeoutMs   = 30'000;

QString sanitize(const QString &host) {
    QString out;
    out.reserve(host.size());
    for (QChar c : host) {
        const bool ok = c.isLetterOrNumber() || c == '-' || c == '.' || c == '_';
        out.append(ok ? c : QChar('_'));
    }
    return out;
}

// Strict DNS-host validation. A malicious client that drives a
// CONNECT to "evil\nbasicConstraints = CA:TRUE" could otherwise inject
// extension lines into the SAN config file, and "evil/CN=bank.com" could
// graft extra DN fields onto the cert subject. Cheap to add, defense in
// depth -- if the client's target isn't a real hostname, refuse to mint.
bool isValidHostForCert(const QString &host) {
    if (host.isEmpty() || host.size() > 253) return false;
    for (QChar c : host) {
        if (c.isLetterOrNumber()) continue;
        if (c == QChar('-') || c == QChar('.') || c == QChar('_')) continue;
        return false;
    }
    // No leading/trailing dot, no double dot.
    if (host.startsWith('.') || host.endsWith('.')) return false;
    if (host.contains("..")) return false;
    return true;
}

} // namespace

CertAuthority::CertAuthority(QString caDir, QObject *parent)
    : QObject(parent),
      m_caDir(caDir.isEmpty() ? defaultCaDir() : caDir),
      m_opensslExe(findOpensslExe()) {
    QDir().mkpath(m_caDir);
    m_caCertPath = m_caDir + "/ca.pem";
    m_caKeyPath  = m_caDir + "/ca.key";
}

QString CertAuthority::defaultCaDir() {
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/ca";
}

QString CertAuthority::findOpensslExe() {
    static const QStringList candidates = {
        QStringLiteral("C:/Program Files/OpenSSL-Win64/bin/openssl.exe"),
        QStringLiteral("C:/Program Files (x86)/OpenSSL-Win64/bin/openssl.exe"),
    };
    for (const QString &c : candidates)
        if (QFileInfo::exists(c)) return c;

    QProcess p;
    p.start(QStringLiteral("openssl"), { QStringLiteral("version") });
    if (p.waitForStarted(1500) && p.waitForFinished(2000) && p.exitCode() == 0)
        return QStringLiteral("openssl");
    return {};
}

bool CertAuthority::runOpenssl(const QStringList &args, QByteArray *stderrOut) {
    if (m_opensslExe.isEmpty()) return false;
    QProcess p;
    p.setProgram(m_opensslExe);
    p.setArguments(args);
    p.start();
    if (!p.waitForStarted(kStartTimeoutMs)) return false;
    if (!p.waitForFinished(kRunTimeoutMs)) {
        p.kill();
        return false;
    }
    if (stderrOut) *stderrOut = p.readAllStandardError();
    return p.exitCode() == 0;
}

bool CertAuthority::ensureCa() {
    if (m_opensslExe.isEmpty()) return false;
    if (QFileInfo::exists(m_caCertPath) && QFileInfo::exists(m_caKeyPath))
        return true;

    if (!runOpenssl({ "genrsa", "-out", m_caKeyPath, "2048" }))
        return false;

    return runOpenssl({
        "req", "-x509", "-new", "-nodes",
        "-key", m_caKeyPath,
        "-out", m_caCertPath,
        "-days", "3650",
        "-subj", "/CN=Nullock Local Root CA/O=Nullock",
    });
}

LeafCert CertAuthority::leafCertFor(const QString &host) {
    // Refuse anything that doesn't look like a real DNS hostname before
    // we feed it into openssl args and the SAN ext file.
    if (!isValidHostForCert(host)) return {};

    QMutexLocker lock(&m_mutex);

    if (auto it = m_cache.find(host); it != m_cache.end())
        return it.value();

    if (!ensureCa()) return {};

    const QString safe     = sanitize(host);
    const QString leavesDir   = m_caDir + "/leaves";
    const QString persistCert = leavesDir + "/" + safe + ".pem";
    const QString persistKey  = leavesDir + "/" + safe + ".key";

    // If we minted this host before and the files are still on disk, reuse
    // them. Avoids ~100 ms of openssl forks on every restart.
    if (QFileInfo::exists(persistCert) && QFileInfo::exists(persistKey)) {
        LeafCert cached;
        QFile certFile(persistCert);
        if (certFile.open(QFile::ReadOnly)) cached.certPem = certFile.readAll();
        QFile keyFile(persistKey);
        if (keyFile.open(QFile::ReadOnly)) cached.keyPem = keyFile.readAll();
        if (cached.valid()) {
            m_cache.insert(host, cached);
            return cached;
        }
    }

    QDir().mkpath(leavesDir);

    const QString keyPath  = m_caDir + "/_leaf_" + safe + ".key";
    const QString csrPath  = m_caDir + "/_leaf_" + safe + ".csr";
    const QString certPath = m_caDir + "/_leaf_" + safe + ".pem";
    const QString extPath  = m_caDir + "/_leaf_" + safe + ".ext";

    auto cleanup = [&] {
        QFile::remove(keyPath);
        QFile::remove(csrPath);
        QFile::remove(certPath);
        QFile::remove(extPath);
    };

    // Write a minimal SAN extension file. Bypasses OpenSSL's default
    // openssl.cnf, which on some installs fails with "unknown extension
    // name HOME" when -copy_extensions is used.
    {
        QFile extFile(extPath);
        if (!extFile.open(QFile::WriteOnly | QFile::Truncate)) {
            cleanup();
            return {};
        }
        const QString contents = QStringLiteral(
            "subjectAltName = DNS:%1\n"
            "basicConstraints = critical, CA:FALSE\n"
            "keyUsage = critical, digitalSignature, keyEncipherment\n"
            "extendedKeyUsage = serverAuth\n").arg(host);
        extFile.write(contents.toUtf8());
    }

    if (!runOpenssl({
            "req", "-new", "-nodes",
            "-newkey", "rsa:2048",
            "-keyout", keyPath,
            "-out", csrPath,
            "-subj", "/CN=" + host,
        })) {
        cleanup();
        return {};
    }

    if (!runOpenssl({
            "x509", "-req",
            "-in", csrPath,
            "-CA", m_caCertPath,
            "-CAkey", m_caKeyPath,
            "-CAcreateserial",
            "-days", "365",
            "-out", certPath,
            "-extfile", extPath,
        })) {
        cleanup();
        return {};
    }

    LeafCert result;
    QFile keyFile(keyPath);
    if (keyFile.open(QFile::ReadOnly)) result.keyPem = keyFile.readAll();
    QFile certFile(certPath);
    if (certFile.open(QFile::ReadOnly)) result.certPem = certFile.readAll();

    cleanup();

    if (result.valid()) {
        // Persist to leaves/ so subsequent runs (or subsequent connections
        // after the in-memory cache is cleared) skip the openssl forks.
        QFile out;
        out.setFileName(persistCert);
        if (out.open(QFile::WriteOnly | QFile::Truncate)) out.write(result.certPem);
        out.close();
        out.setFileName(persistKey);
        if (out.open(QFile::WriteOnly | QFile::Truncate)) out.write(result.keyPem);
        out.close();

        m_cache.insert(host, result);
    }
    return result;
}

} // namespace Nullock::Proxy
