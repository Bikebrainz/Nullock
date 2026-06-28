#include "cert_authority.hpp"

#include "cert_logic.hpp"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QMutexLocker>
#include <QProcess>
#include <QStandardPaths>

#ifdef Q_OS_WIN
#include <windows.h>
#include <accctrl.h>
#include <aclapi.h>
#endif

namespace Nullock::Proxy {

namespace {

constexpr int kStartTimeoutMs = 5'000;
constexpr int kRunTimeoutMs   = 30'000;

// Tighten the CA private key file's ACL so only the current OS user can
// read it. The CA cert is installed in the user's browser as a trusted
// root, so anyone who reads ca.key can forge certs for ANY host the user
// trusts -- bank.com, gmail.com, internal corp SSO -- and serve them
// with a valid TLS lock to the user's browser. Without lockdown, the
// default DACL on %APPDATA% allows the user (and any process running
// as the user, including unrelated installers / extensions / malware
// that lives in the same profile) to slurp the key.
//
// POSIX: chmod 0600.
// Windows: rewrite the DACL to a single ACE granting the current user
//   GENERIC_ALL, with inheritance disabled. The owner field is left at
//   whatever opensssl wrote, which on Windows is the user that ran us.
void lockdownPrivateKeyFile(const QString &path) {
    if (path.isEmpty() || !QFileInfo::exists(path)) return;
#ifdef Q_OS_WIN
    // Resolve the current user's SID. NULL DACL is famously dangerous;
    // we build an explicit DACL with one ACE.
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return;
    DWORD tokenInfoLen = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &tokenInfoLen);
    if (tokenInfoLen == 0) { CloseHandle(hToken); return; }
    QByteArray tokenBuf(static_cast<int>(tokenInfoLen), Qt::Uninitialized);
    if (!GetTokenInformation(hToken, TokenUser,
            tokenBuf.data(), tokenInfoLen, &tokenInfoLen)) {
        CloseHandle(hToken); return;
    }
    CloseHandle(hToken);
    TOKEN_USER *tu = reinterpret_cast<TOKEN_USER *>(tokenBuf.data());

    EXPLICIT_ACCESSW ea = {};
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode        = SET_ACCESS;
    ea.grfInheritance       = NO_INHERITANCE;
    ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType  = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName    = reinterpret_cast<LPWSTR>(tu->User.Sid);

    PACL pNewDacl = nullptr;
    if (SetEntriesInAclW(1, &ea, nullptr, &pNewDacl) != ERROR_SUCCESS) return;

    // Disable DACL inheritance so the parent dir's ACEs don't continue
    // to grant access alongside our explicit ACE.
    const std::wstring wpath = path.toStdWString();
    SetNamedSecurityInfoW(const_cast<LPWSTR>(wpath.c_str()),
                          SE_FILE_OBJECT,
                          DACL_SECURITY_INFORMATION
                            | PROTECTED_DACL_SECURITY_INFORMATION,
                          nullptr, nullptr, pNewDacl, nullptr);
    LocalFree(pNewDacl);
#else
    QFile::setPermissions(path,
        QFile::ReadOwner | QFile::WriteOwner);
#endif
}

// isValidHostForCert() + sanitize() (the host-injection guard) are pure and live
// in cert_logic.cpp so they can be unit-tested against Qt6::Core alone.
using CertLogic::isValidHostForCert;
using CertLogic::sanitize;

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
    if (QFileInfo::exists(m_caCertPath) && QFileInfo::exists(m_caKeyPath)) {
        // On every startup, re-assert owner-only ACL on the key file.
        // Previous installs may have written it under the default
        // (inherited) permissions, in which case any process running as
        // the same user could read ca.key and forge certs for any host
        // the user trusts. Pre-existing keys get tightened in place.
        lockdownPrivateKeyFile(m_caKeyPath);
        return true;
    }

    if (!runOpenssl({ "genrsa", "-out", m_caKeyPath, "2048" }))
        return false;
    // Lock the freshly-generated key down to owner read+write only. On
    // Windows we drop the inherited DACL and re-add a single ACE for
    // the current user; on POSIX this becomes chmod 0600 via
    // QFile::setPermissions.
    lockdownPrivateKeyFile(m_caKeyPath);

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
