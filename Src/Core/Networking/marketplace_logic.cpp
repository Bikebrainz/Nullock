#include "marketplace_logic.hpp"

#include "update_check.hpp"      // UpdateLogic::compareSemver -- one semver impl, not two

#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMap>
#include <QRegularExpression>
#include <QUrl>

namespace Nullock::Core::MarketplaceLogic {

namespace {

// Pull a bounded string out of untrusted JSON. Every field the catalog supplies
// is eventually rendered somewhere, so nothing is allowed to be unbounded.
QString str(const QJsonObject &o, const char *key, int maxLen = 512) {
    return o.value(QLatin1String(key)).toString().left(maxLen);
}

QStringList strList(const QJsonObject &o, const char *key, int maxItems = 32) {
    QStringList out;
    const QJsonArray a = o.value(QLatin1String(key)).toArray();
    for (const QJsonValue &v : a) {
        if (!v.isString()) continue;
        out.append(v.toString().left(64));
        if (out.size() >= maxItems) break;
    }
    return out;
}

// Windows treats these as devices no matter the extension or the directory, so
// "CON.js" is not a file. Checked case-insensitively against the stem.
bool isReservedDeviceName(const QString &stem) {
    static const QStringList kReserved = {
        QStringLiteral("con"), QStringLiteral("prn"), QStringLiteral("aux"),
        QStringLiteral("nul"),
        QStringLiteral("com1"), QStringLiteral("com2"), QStringLiteral("com3"),
        QStringLiteral("com4"), QStringLiteral("com5"), QStringLiteral("com6"),
        QStringLiteral("com7"), QStringLiteral("com8"), QStringLiteral("com9"),
        QStringLiteral("lpt1"), QStringLiteral("lpt2"), QStringLiteral("lpt3"),
        QStringLiteral("lpt4"), QStringLiteral("lpt5"), QStringLiteral("lpt6"),
        QStringLiteral("lpt7"), QStringLiteral("lpt8"), QStringLiteral("lpt9"),
    };
    return kReserved.contains(stem.toLower());
}

} // namespace

// ---- catalog ------------------------------------------------------------

Catalog parseCatalog(const QByteArray &json) {
    Catalog c;

    if (json.isEmpty()) {
        c.error = QStringLiteral("catalog is empty");
        return c;
    }
    if (json.size() > kMaxCatalogBytes) {
        c.error = QStringLiteral("catalog is larger than %1 bytes").arg(kMaxCatalogBytes);
        return c;
    }

    QJsonParseError err {};
    const QJsonDocument doc = QJsonDocument::fromJson(json, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) {
        c.error = QStringLiteral("catalog is not valid JSON: %1").arg(err.errorString());
        return c;
    }

    const QJsonObject root = doc.object();
    c.version = root.value(QStringLiteral("version")).toInt();
    c.updated = str(root, "updated", 32);

    const QJsonArray arr = root.value(QStringLiteral("extensions")).toArray();
    if (arr.isEmpty()) {
        c.error = QStringLiteral("catalog lists no extensions");
        return c;
    }

    QSet<QString> seen;
    int dropped = 0;

    for (const QJsonValue &v : arr) {
        if (c.entries.size() >= kMaxEntries) break;
        if (!v.isObject()) { ++dropped; continue; }
        const QJsonObject o = v.toObject();

        CatalogEntry e;
        e.id      = str(o, "id", 64);
        e.name    = str(o, "name", 128);
        e.summary = str(o, "summary", 2048);
        e.version = str(o, "version", 32);
        e.author  = str(o, "author", 128);
        e.url     = str(o, "url", 2048);
        e.sha256  = str(o, "sha256", 64).trimmed().toLower();
        e.categories = strList(o, "categories");
        e.hooks      = strList(o, "hooks");
        e.declaredPermissions = strList(o, "permissions", 8);
        e.minVersion = str(o, "minVersion", 32).trimmed();

        // Every one of these is a hard requirement. A entry that fails any of
        // them is not "partially usable" -- it is an entry we cannot safely
        // fetch or verify, so it is dropped rather than shown greyed out.
        if (safeScriptFileName(e.id).isEmpty())  { ++dropped; continue; }
        if (!isTrustedAssetUrl(e.url))           { ++dropped; continue; }
        if (!isWellFormedSha256(e.sha256))       { ++dropped; continue; }
        if (seen.contains(e.id))                 { ++dropped; continue; }

        seen.insert(e.id);
        c.entries.append(e);
    }

    if (c.entries.isEmpty()) {
        c.error = QStringLiteral("catalog had %1 entries but none were usable "
                                 "(each needs a safe id, an https allow-listed "
                                 "url, and a sha256)").arg(arr.size());
    }
    return c;
}

// ---- transport trust ----------------------------------------------------

QStringList trustedHosts() {
    // Deliberately short. Each entry here is a party that can hand this process
    // code to execute, so adding one is a security decision and the test asserts
    // this exact list to make an accidental widening fail loudly.
    return {
        QStringLiteral("raw.githubusercontent.com"),   // extension sources
        QStringLiteral("bikebrainz.github.io"),        // the published catalog
    };
}

bool isTrustedAssetUrl(const QString &url) {
    const QUrl u(url.trimmed(), QUrl::StrictMode);
    if (!u.isValid()) return false;
    if (u.scheme().compare(QLatin1String("https"), Qt::CaseInsensitive) != 0) return false;

    // "https://raw.githubusercontent.com@evil.tld/x" parses with host evil.tld.
    // Reject any userinfo outright rather than reasoning about it.
    if (!u.userInfo().isEmpty()) return false;

    // An explicit port other than 443 would let a compromised catalog point at
    // some other listener on an allow-listed name.
    if (u.port(443) != 443) return false;

    const QString host = u.host().toLower();
    if (host.isEmpty()) return false;

    for (const QString &t : trustedHosts()) {
        if (host == t) return true;
        if (host.endsWith(QLatin1Char('.') + t)) return true;   // dot-anchored
    }
    return false;
}

bool splitTrustedUrl(const QString &url, QString *host, QString *requestTarget) {
    if (!isTrustedAssetUrl(url)) return false;
    const QUrl u(url.trimmed(), QUrl::StrictMode);

    QString target = u.path(QUrl::FullyEncoded);
    if (target.isEmpty()) target = QStringLiteral("/");
    const QString q = u.query(QUrl::FullyEncoded);
    if (!q.isEmpty()) target += QLatin1Char('?') + q;

    if (host)          *host = u.host().toLower();
    if (requestTarget) *requestTarget = target;
    return true;
}

// ---- integrity ----------------------------------------------------------

QString sha256Hex(const QByteArray &data) {
    return QString::fromLatin1(
        QCryptographicHash::hash(data, QCryptographicHash::Sha256).toHex());
}

bool isWellFormedSha256(const QString &s) {
    if (s.size() != 64) return false;
    for (QChar ch : s) {
        const char c = ch.toLatin1();
        const bool hex = (c >= '0' && c <= '9')
                      || (c >= 'a' && c <= 'f')
                      || (c >= 'A' && c <= 'F');
        if (!hex) return false;
    }
    return true;
}

bool verifyIntegrity(const QByteArray &data, const QString &expected) {
    // A missing or malformed expectation is a failure, not a pass. This is the
    // single most important line in the file: if this ever returns true for an
    // empty `expected`, an attacker who can strip a field from the catalog can
    // install anything.
    if (!isWellFormedSha256(expected)) return false;
    return sha256Hex(data).compare(expected, Qt::CaseInsensitive) == 0;
}

// ---- path confinement ---------------------------------------------------

QString safeScriptFileName(const QString &id) {
    const QString s = id.trimmed();
    if (s.isEmpty() || s.size() > 64) return {};

    // Allow-list the character set rather than blocking known-bad ones. This is
    // what makes '/', '\\', ':', NUL, and every Unicode separator unreachable
    // without having to enumerate them.
    for (QChar ch : s) {
        const char c = ch.toLatin1();
        const bool ok = (c >= 'a' && c <= 'z')
                     || (c >= 'A' && c <= 'Z')
                     || (c >= '0' && c <= '9')
                     || c == '_' || c == '-' || c == '.';
        if (!ok) return {};
    }

    // "." and ".." pass the character check but are not names.
    if (s == QLatin1String(".") || s == QLatin1String("..")) return {};
    // A leading dot means a hidden file with no visible name.
    if (s.startsWith(QLatin1Char('.'))) return {};
    // Trailing dot/space are stripped by the Windows filesystem, so "evil." and
    // "evil" are the same file -- refuse the ambiguity.
    if (s.endsWith(QLatin1Char('.'))) return {};
    if (isReservedDeviceName(s.section(QLatin1Char('.'), 0, 0))) return {};

    return s + QStringLiteral(".js");
}

// ---- install audit ------------------------------------------------------

InstallAudit auditInstall(const CatalogEntry &entry,
                          const QByteArray &script,
                          const QSet<QString> &effectiveFromScript) {
    InstallAudit a;

    if (safeScriptFileName(entry.id).isEmpty()) {
        a.blocker = QStringLiteral("extension id %1 is not a safe filename")
                        .arg(entry.id);
        return a;
    }
    if (script.isEmpty()) {
        a.blocker = QStringLiteral("downloaded script is empty");
        return a;
    }
    if (script.size() > kMaxScriptBytes) {
        a.blocker = QStringLiteral("downloaded script is %1 bytes, over the %2 limit")
                        .arg(script.size()).arg(kMaxScriptBytes);
        return a;
    }

    // The authority is the script. Sort so the UI and the tests see a stable
    // order rather than QSet's.
    a.effectivePermissions = QStringList(effectiveFromScript.begin(),
                                         effectiveFromScript.end());
    a.effectivePermissions.sort();

    // Compare case-insensitively: the catalog is hand-maintained JSON and
    // "modify-requests" vs "Modify-Requests" is a typo, not a new capability.
    QSet<QString> declared;
    for (const QString &d : entry.declaredPermissions)
        declared.insert(d.trimmed().toLower());

    for (const QString &p : a.effectivePermissions) {
        if (!declared.contains(p.toLower()))
            a.undeclaredPermissions.append(p);
        if (p.compare(QLatin1String("modify-requests"), Qt::CaseInsensitive) == 0
         || p.compare(QLatin1String("modify-responses"), Qt::CaseInsensitive) == 0)
            a.mutatesTraffic = true;
    }

    if (!a.undeclaredPermissions.isEmpty()) {
        a.warnings.append(
            QStringLiteral("the script asks for %1, which the catalog entry did "
                           "not list -- the script's own directive is what takes "
                           "effect")
                .arg(a.undeclaredPermissions.join(QStringLiteral(", "))));
    }
    if (a.mutatesTraffic) {
        a.warnings.append(
            QStringLiteral("this extension can REWRITE traffic in flight, not "
                           "just observe it"));
    }
    if (entry.summary.trimmed().isEmpty()) {
        a.warnings.append(QStringLiteral("catalog entry has no description"));
    }

    a.ok = true;
    return a;
}

// ---- merge --------------------------------------------------------------

QString parseInstalledVersion(const QString &jsSource) {
    // Same spirit as the permissions directive: a line comment the author writes.
    // Bounded scan so a large file cannot stall the merge.
    static const QRegularExpression re(
        QStringLiteral(R"(^[ \t]*//[ \t]*(?:@)?nullock[:-]version[ \t]+v?([0-9][0-9A-Za-z.\-+]*))"),
        QRegularExpression::MultilineOption | QRegularExpression::CaseInsensitiveOption);
    const auto m = re.match(jsSource.left(64 * 1024));
    return m.hasMatch() ? m.captured(1) : QString();
}

bool isVersionCompatible(const QString &minVersion, const QString &currentVersion) {
    // No requirement, or no known running version -> don't gate (fail open to
    // "compatible" so a missing version string never hides a usable extension).
    if (minVersion.trimmed().isEmpty() || currentVersion.trimmed().isEmpty())
        return true;
    // Compatible when running >= required.
    return UpdateLogic::compareSemver(currentVersion, minVersion) >= 0;
}

QList<MergedEntry> merge(const Catalog &catalog,
                         const QStringList &installedFiles,
                         const QList<QPair<QString, QString>> &installedVersions,
                         const QString &currentVersion) {
    QMap<QString, QString> versionOf;
    for (const auto &kv : installedVersions) versionOf.insert(kv.first, kv.second);

    QSet<QString> installedIds;
    for (const QString &f : installedFiles) {
        if (!f.endsWith(QLatin1String(".js"), Qt::CaseInsensitive)) continue;
        installedIds.insert(f.left(f.size() - 3));
    }

    QList<MergedEntry> out;
    QSet<QString> covered;

    for (const CatalogEntry &e : catalog.entries) {
        MergedEntry m;
        m.entry = e;
        // [B31] compatibility gate: an entry requiring a newer Nullock than the
        // one running is flagged incompatible with a user-facing reason. (The UI
        // greys it + disables Install; an already-installed copy keeps running.)
        if (!isVersionCompatible(e.minVersion, currentVersion)) {
            m.compatible = false;
            m.incompatReason = QStringLiteral("requires Nullock >= ") + e.minVersion;
        }
        if (installedIds.contains(e.id)) {
            covered.insert(e.id);
            m.installedVersion = versionOf.value(e.id);
            // An unknown installed version is reported as Installed rather than
            // UpdateAvailable. Nagging about an update we cannot actually
            // establish would train the user to click through the confirm
            // prompt, which is the one thing protecting them here.
            if (!m.installedVersion.isEmpty() && !e.version.isEmpty()
                && UpdateLogic::compareSemver(m.installedVersion, e.version) < 0) {
                m.state = InstallState::UpdateAvailable;
            } else {
                m.state = InstallState::Installed;
            }
        } else {
            m.state = InstallState::NotInstalled;
        }
        out.append(m);
    }

    // Anything on disk the catalog does not know about. Shown, never hidden --
    // the engine is going to load it regardless, so the user should be able to
    // see it in the same list.
    for (const QString &id : installedIds) {
        if (covered.contains(id)) continue;
        MergedEntry m;
        m.entry.id      = id;
        m.entry.name    = id;
        m.entry.version = versionOf.value(id);
        m.entry.summary = QStringLiteral("Installed locally; not in the catalog.");
        m.installedVersion = versionOf.value(id);
        m.state = InstallState::Local;
        out.append(m);
    }

    return out;
}

} // namespace Nullock::Core::MarketplaceLogic
