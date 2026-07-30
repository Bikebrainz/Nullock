#include "marketplace.hpp"

#include "networking.hpp"
#include "../APIs/ExtensionsAPI/extension_perms_logic.hpp"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>

namespace Nullock::Core {

using namespace Nullock::Core::MarketplaceLogic;

namespace {

// One place that turns a trusted https URL into bytes. Both the catalog fetch
// and the script download go through here so neither can accidentally skip the
// trust check or the size cap.
struct Fetched {
    bool       ok = false;
    QByteArray body;
    QString    error;
    int        status = 0;
};

Fetched fetchTrusted(const QString &url, int maxBytes) {
    Fetched f;

    QString host, target;
    if (!splitTrustedUrl(url, &host, &target)) {
        // Deliberately names the allow-list: a user who self-hosts a fork needs
        // to know why their URL was refused, and there is nothing secret about
        // which hosts we trust.
        f.error = QStringLiteral("refusing to fetch %1 -- marketplace downloads "
                                 "are limited to https on %2")
                      .arg(url, trustedHosts().join(QStringLiteral(", ")));
        return f;
    }

    QByteArray req;
    req += "GET " + target.toUtf8() + " HTTP/1.1\r\n";
    req += "Host: " + host.toUtf8() + "\r\n";
    req += "User-Agent: nullock-marketplace/1.0\r\n";
    req += "Accept: */*\r\n";
    // identity, deliberately. The catalog's sha256 is the digest of the SCRIPT,
    // so what we hash has to be the script and not a gzip frame of it. Asking
    // for no encoding keeps the bytes we verify identical to the bytes the
    // publisher hashed, instead of making integrity depend on whether the
    // client's Content-Encoding decode ran.
    req += "Accept-Encoding: identity\r\n";
    req += "Connection: close\r\n\r\n";

    HttpClient client;
    const auto res = client.send(host, 443, true, req);
    if (!res.ok) {
        f.error = QStringLiteral("fetch failed: %1").arg(res.errorMessage);
        return f;
    }

    f.status = res.parsed.statusCode;
    if (f.status != 200) {
        // No redirect following. A 3xx from an allow-listed host would point
        // somewhere we have not vetted, and silently following it is exactly
        // how a host allow-list gets bypassed.
        f.error = QStringLiteral("HTTP %1 from %2").arg(f.status).arg(host);
        return f;
    }

    // bodyForInspection() returns the Content-Encoding-decoded copy when there
    // is one and the raw wire bytes otherwise. Combined with the identity
    // request above, that means we hash the script either way -- if a server
    // compresses regardless, we still verify the decoded form the publisher
    // hashed rather than failing every install with a digest mismatch.
    const QByteArray &body = res.parsed.bodyForInspection();
    if (body.size() > maxBytes) {
        f.error = QStringLiteral("response is %1 bytes, over the %2 limit")
                      .arg(body.size()).arg(maxBytes);
        return f;
    }

    f.body = body;
    f.ok = true;
    return f;
}

} // namespace

QString Marketplace::defaultCatalogUrl() {
    return QStringLiteral("https://bikebrainz.github.io/Nullock/marketplace/marketplace.json");
}

Marketplace::FetchResult Marketplace::fetchCatalog(const QString &catalogUrl) {
    FetchResult r;
    const QString url = catalogUrl.isEmpty() ? defaultCatalogUrl() : catalogUrl;

    const Fetched f = fetchTrusted(url, kMaxCatalogBytes);
    r.httpStatus = f.status;
    if (!f.ok) { r.error = f.error; return r; }

    r.catalog = parseCatalog(f.body);
    if (!r.catalog.error.isEmpty()) { r.error = r.catalog.error; return r; }

    r.ok = true;
    return r;
}

Marketplace::InstallResult Marketplace::install(const CatalogEntry &entry,
                                                const QString &extensionsDir,
                                                bool confirmedMutatingInstall) {
    InstallResult r;

    const QString fileName = safeScriptFileName(entry.id);
    if (fileName.isEmpty()) {
        r.error = QStringLiteral("extension id %1 is not a safe filename").arg(entry.id);
        return r;
    }
    if (!isWellFormedSha256(entry.sha256)) {
        // Fail closed. An entry with no usable digest is not installable at all,
        // because "download it anyway" is precisely the capability an attacker
        // who can edit the catalog would want.
        r.error = QStringLiteral("catalog entry for %1 has no usable sha256; "
                                 "refusing to install unverifiable code").arg(entry.id);
        return r;
    }

    const Fetched f = fetchTrusted(entry.url, kMaxScriptBytes);
    r.httpStatus = f.status;
    if (!f.ok) { r.error = f.error; return r; }

    if (!verifyIntegrity(f.body, entry.sha256)) {
        r.error = QStringLiteral("integrity check FAILED for %1: catalog says "
                                 "sha256 %2, downloaded bytes hash to %3. Not "
                                 "installing.")
                      .arg(entry.id, entry.sha256, sha256Hex(f.body));
        return r;
    }
    r.sha256 = sha256Hex(f.body);
    r.bytes  = int(f.body.size());

    // Consent is derived from the bytes we just verified, never from the
    // catalog's description of them.
    const QSet<QString> effective =
        ExtensionPerms::parsePermissions(QString::fromUtf8(f.body));

    const InstallAudit audit = auditInstall(entry, f.body, effective);
    r.warnings             = audit.warnings;
    r.effectivePermissions = audit.effectivePermissions;
    r.mutatesTraffic       = audit.mutatesTraffic;
    if (!audit.ok) { r.error = audit.blocker; return r; }

    if (audit.mutatesTraffic && !confirmedMutatingInstall) {
        r.error = QStringLiteral("confirmation required: this extension requests "
                                 "%1 and can rewrite traffic in flight")
                      .arg(audit.effectivePermissions.join(QStringLiteral(", ")));
        return r;
    }

    if (!QDir().mkpath(extensionsDir)) {
        r.error = QStringLiteral("could not create %1").arg(extensionsDir);
        return r;
    }

    // QSaveFile so a failed or interrupted write cannot leave a truncated script
    // behind -- the engine loads whatever is in this directory at reload, and
    // half a file is a syntax error at best.
    const QString dest = QDir(extensionsDir).absoluteFilePath(fileName);
    QSaveFile out(dest);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        r.error = QStringLiteral("could not open %1 for writing").arg(dest);
        return r;
    }
    if (out.write(f.body) != f.body.size() || !out.commit()) {
        r.error = QStringLiteral("could not write %1").arg(dest);
        return r;
    }

    r.installedPath = dest;
    r.ok = true;
    return r;
}

bool Marketplace::uninstall(const QString &id, const QString &extensionsDir,
                            QString *error) {
    const QString fileName = safeScriptFileName(id);
    if (fileName.isEmpty()) {
        if (error) *error = QStringLiteral("%1 is not a safe extension id").arg(id);
        return false;
    }

    const QDir dir(extensionsDir);
    const QString target = dir.absoluteFilePath(fileName);

    // Belt and braces over safeScriptFileName: confirm the resolved path really
    // is a regular file sitting directly in extensionsDir. A symlink pointing
    // out of the directory would resolve elsewhere, and this is a delete.
    const QFileInfo fi(target);
    if (!fi.exists() || !fi.isFile()) {
        if (error) *error = QStringLiteral("%1 is not installed").arg(id);
        return false;
    }
    const QString canonicalDir  = QFileInfo(extensionsDir).canonicalFilePath();
    const QString canonicalFile = fi.canonicalFilePath();
    if (canonicalDir.isEmpty() || canonicalFile.isEmpty()
        || QFileInfo(canonicalFile).absolutePath() != canonicalDir) {
        if (error) *error = QStringLiteral("%1 does not resolve inside the "
                                           "extensions directory").arg(id);
        return false;
    }

    if (!QFile::remove(canonicalFile)) {
        if (error) *error = QStringLiteral("could not remove %1").arg(canonicalFile);
        return false;
    }
    return true;
}

QStringList Marketplace::installedFiles(const QString &extensionsDir) {
    QDir d(extensionsDir);
    if (!d.exists()) return {};
    return d.entryList({ QStringLiteral("*.js") }, QDir::Files, QDir::Name);
}

QList<QPair<QString, QString>> Marketplace::installedVersions(const QString &extensionsDir) {
    QList<QPair<QString, QString>> out;
    QDir d(extensionsDir);
    if (!d.exists()) return out;

    for (const QString &f : d.entryList({ QStringLiteral("*.js") }, QDir::Files, QDir::Name)) {
        QFile file(d.absoluteFilePath(f));
        if (!file.open(QIODevice::ReadOnly)) continue;
        // Only the head: the version directive is a header comment and reading
        // whole scripts here would make listing cost proportional to their size.
        const QString head = QString::fromUtf8(file.read(64 * 1024));
        const QString v = parseInstalledVersion(head);
        if (!v.isEmpty()) out.append({ f.left(f.size() - 3), v });
    }
    return out;
}

} // namespace Nullock::Core
