#pragma once

// Extension marketplace -- the I/O half. Fetches the catalog, downloads an
// extension, verifies it, and writes it into the extensions directory.
//
// Every trust decision this makes is delegated to MarketplaceLogic (pure,
// tested). This TU is deliberately dumb: it does sockets and files, and it is
// not allowed to decide that something is safe. If you find yourself adding an
// `if` here that grants rather than refuses, it belongs next door.
//
// THREADING: fetchCatalog() and install() both do blocking TLS I/O and are
// called from the control server's request handler, which already runs off the
// GUI thread. They do not touch the QJSEngine -- reloading extensions after an
// install is the caller's job, through ExtensionsApi::reload(), which marshals
// to the engine's own thread itself.

#include "marketplace_logic.hpp"

#include <QByteArray>
#include <QString>

namespace Nullock::Core {

class Marketplace {
public:
    // Where the catalog is published. Must satisfy
    // MarketplaceLogic::isTrustedAssetUrl(); anything else is refused at fetch
    // time rather than trusted because it was set locally.
    static QString defaultCatalogUrl();

    struct FetchResult {
        bool                          ok = false;
        MarketplaceLogic::Catalog     catalog;
        QString                       error;
        int                           httpStatus = 0;
    };

    // Blocking. Downloads and parses the catalog. Never writes to disk.
    static FetchResult fetchCatalog(const QString &catalogUrl = QString());

    struct InstallResult {
        bool        ok = false;
        QString     error;          // user-facing; empty on success
        QString     installedPath;  // absolute, on success
        QString     sha256;         // of what we actually wrote
        QStringList warnings;       // from the audit -- shown, not fatal
        QStringList effectivePermissions;
        bool        mutatesTraffic = false;
        int         httpStatus = 0;
        int         bytes = 0;
    };

    // Blocking. Download `entry`, verify its digest against the catalog's,
    // audit it, and -- only if all of that passes -- write it into
    // `extensionsDir`.
    //
    // `confirmedMutatingInstall` is the user's explicit answer to "this
    // extension can rewrite your traffic, proceed?". When the audit finds a
    // traffic-mutating capability and this is false, the install is REFUSED and
    // the result carries the audit so the caller can prompt and call again. A
    // caller that hardcodes true has removed the only consent gate in the
    // feature.
    static InstallResult install(const MarketplaceLogic::CatalogEntry &entry,
                                 const QString &extensionsDir,
                                 bool confirmedMutatingInstall);

    // Remove an installed extension by catalog id. Refuses any id that is not a
    // safe filename, and refuses to delete anything that does not resolve to a
    // regular file directly inside `extensionsDir`.
    static bool uninstall(const QString &id, const QString &extensionsDir,
                          QString *error = nullptr);

    // Read `extensionsDir` and report the installed basenames plus whatever
    // version directive each script carries. Used to merge against the catalog.
    static QStringList installedFiles(const QString &extensionsDir);
    static QList<QPair<QString, QString>> installedVersions(const QString &extensionsDir);
};

} // namespace Nullock::Core
