#pragma once

// Extension marketplace -- the pure half.
//
// WHAT THIS IS DEFENDING. A marketplace install downloads JavaScript and runs it
// inside the proxy's QJSEngine. That engine sees every request and response the
// user's browser makes, which on a live engagement means session cookies, bearer
// tokens, and request bodies. There is no sandbox that makes shipping the wrong
// bytes here survivable, so the trust decisions have to be made BEFORE the file
// lands in the extensions directory. That is what this module is.
//
// PURE: bytes and strings in, decisions out. Qt6::Core only, no I/O, no network.
// marketplace.cpp holds the HttpClient/QFile side and calls into here for every
// decision it makes.
//
// The model, in the order the checks matter:
//
//   1. INTEGRITY IS PINNED. The catalog declares a sha256 for every extension.
//      Install downloads the script, hashes it, and refuses on any mismatch. So
//      compromising the CDN that serves the .js is NOT sufficient -- an attacker
//      also has to control the catalog. An entry with no sha256 is not
//      installable at all; it is a malformed entry, not a permissive one.
//
//   2. TRANSPORT IS PINNED. https only, and only to an allow-listed host. A
//      catalog that hands us http://, a javascript: URL, a userinfo-@ bypass, or
//      a look-alike host is rejected before any socket is opened.
//
//   3. PATHS ARE CONFINED. Every filename is derived from the catalog's `id`,
//      which is remote attacker-influenced data the moment the catalog is
//      compromised. safeScriptFileName() rejects anything that could escape the
//      extensions directory -- separators, "..", drive letters, UNC prefixes,
//      ADS colons, reserved DOS device names -- rather than trying to sanitise
//      it into something safe.
//
//   4. CONSENT COMES FROM THE BYTES, NOT THE CATALOG. The catalog's claim about
//      what an extension does is marketing copy from an untrusted source. The
//      permissions that actually take effect are the ones ExtensionPerms parses
//      out of the script itself. installAudit() re-derives them from the
//      DOWNLOADED source and reports any capability the script asks for that the
//      catalog did not advertise, so "quietly add modify-requests in v1.0.1"
//      surfaces at the confirm prompt instead of never.
//
// Nothing here installs or auto-updates on its own. Every transition is a
// user action.

#include <QByteArray>
#include <QList>
#include <QSet>
#include <QString>
#include <QStringList>

namespace Nullock::Core::MarketplaceLogic {

// Hard ceilings. A hostile or broken catalog must not be able to make us
// allocate without bound.
inline constexpr int kMaxCatalogBytes = 1 * 1024 * 1024;   // 1 MiB of JSON
inline constexpr int kMaxScriptBytes  = 2 * 1024 * 1024;   // 2 MiB per extension
inline constexpr int kMaxEntries      = 500;

// One extension as the catalog describes it. Everything in here is UNTRUSTED
// input that happens to have passed shape validation -- `summary` and `author`
// in particular are free text from a remote file and must be escaped by whoever
// renders them.
struct CatalogEntry {
    QString     id;              // stable key; also the on-disk basename
    QString     name;
    QString     summary;
    QString     version;
    QString     author;
    QStringList categories;
    QString     url;             // https, allow-listed host
    QString     sha256;          // lowercase hex, 64 chars. REQUIRED.
    QStringList hooks;
    // What the catalog CLAIMS the extension will ask for. Advisory only -- the
    // authority is what parsePermissions() finds in the downloaded script.
    QStringList declaredPermissions;
};

struct Catalog {
    int                version = 0;
    QString            updated;
    QList<CatalogEntry> entries;
    // Empty on success. On failure the entries list is empty and this says why,
    // in language fit to show a user.
    QString            error;
};

// Installed state of one id, as merged for display.
enum class InstallState {
    NotInstalled,
    Installed,        // present, and the catalog offers the same version
    UpdateAvailable,  // present, and the catalog offers a newer version
    Local,            // present on disk but absent from the catalog (hand-written
                      // extension, or one pulled from the catalog after release)
};

struct MergedEntry {
    CatalogEntry entry;
    InstallState state = InstallState::NotInstalled;
    QString      installedVersion;   // empty unless known
};

// ---- catalog ------------------------------------------------------------

// Parse and VALIDATE a catalog document. Rejects, rather than repairs, anything
// malformed: this is a trust boundary, and a parser that guesses at intent is
// how a bad entry becomes an installed entry. An entry missing a usable id, url
// or sha256 is dropped and does not appear in the result; a document that is not
// a JSON object, exceeds kMaxCatalogBytes, or has no usable entries yields an
// error instead.
Catalog parseCatalog(const QByteArray &json);

// ---- transport trust ----------------------------------------------------

// The only hosts an asset or catalog may be fetched from. Kept as a function
// rather than a constant so the test can assert the exact list -- a silent
// addition here widens the trust boundary for the whole feature.
QStringList trustedHosts();

// https, host on the allow-list (exact match or a subdomain of it), no userinfo
// component, no explicit non-443 port. Anything else is false.
//
// The userinfo rule matters: "https://raw.githubusercontent.com@evil.tld/x" has
// host evil.tld, and a substring check on the allow-listed name would accept it.
bool isTrustedAssetUrl(const QString &url);

// Split a trusted https URL into the pieces HttpClient::send needs. Returns
// false (and leaves the outputs untouched) if the URL is not trusted, so a
// caller cannot skip the check by calling this directly.
bool splitTrustedUrl(const QString &url, QString *host, QString *requestTarget);

// ---- integrity ----------------------------------------------------------

// Lowercase hex sha256 of `data`.
QString sha256Hex(const QByteArray &data);

// True iff sha256Hex(data) equals `expected`, compared case-insensitively.
// An empty or malformed `expected` is FALSE, never true: a missing hash must
// fail closed. Length-independent comparison is not required here (the digest
// is public), but the malformed-input rejection is.
bool verifyIntegrity(const QByteArray &data, const QString &expected);

// True iff `s` is exactly 64 hex characters.
bool isWellFormedSha256(const QString &s);

// ---- path confinement ---------------------------------------------------

// Map a catalog id to the basename it may be written as, or an empty string if
// the id is not safe to put on a filesystem. REJECTS rather than sanitises:
//   * anything outside [A-Za-z0-9._-]
//   * any form of "." or ".." as the whole name
//   * a leading dot (hidden files / no visible name)
//   * names longer than 64 chars
//   * Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9),
//     with or without an extension -- writing to one of those is not a file
//     write at all on Windows.
// An empty return means "refuse to install", never "use a default".
QString safeScriptFileName(const QString &id);

// ---- install audit ------------------------------------------------------

// What we learned by looking at the bytes we actually downloaded, as opposed to
// what the catalog said about them. This is what the confirm prompt should show.
struct InstallAudit {
    bool        ok = false;          // safe to proceed at all
    QString     blocker;             // non-empty => refuse; user-facing reason
    QStringList effectivePermissions; // parsed from the SCRIPT (authoritative)
    QStringList undeclaredPermissions;// in the script but NOT in the catalog
    bool        mutatesTraffic = false; // asks for modify-requests/-responses
    QStringList warnings;             // surface, but do not block
};

// Decide whether `script` (already integrity-verified against `entry`) may be
// installed, and what the user should be told first.
//
// `effectiveFromScript` is the permission set ExtensionPerms::parsePermissions()
// found in the downloaded source. It is passed in rather than parsed here so
// this TU stays free of the APIs layer -- one source of truth for the directive
// grammar, no second parser to drift.
//
// Blocks on: empty script, oversized script, an unsafe id. Warns on: an
// undeclared capability, a capability that mutates traffic, an empty catalog
// summary. An undeclared capability is deliberately a WARNING and not a block --
// the script's own directive is what the engine enforces either way, so the
// honest thing is to show the user the real answer rather than to pretend the
// catalog's copy was binding.
InstallAudit auditInstall(const CatalogEntry &entry,
                          const QByteArray &script,
                          const QSet<QString> &effectiveFromScript);

// ---- merge --------------------------------------------------------------

// Join the catalog against what is on disk. `installedFiles` are basenames as
// found in the extensions dir (e.g. "aws_sigv4.js"); `installedVersions` maps id
// -> version where a version could be determined, and may be empty.
//
// An installed file with no catalog entry becomes a Local entry rather than
// being hidden, so a user can always see everything the engine will load --
// including a hand-written script, and including one that has been withdrawn
// from the catalog since it was installed.
QList<MergedEntry> merge(const Catalog &catalog,
                         const QStringList &installedFiles,
                         const QList<QPair<QString, QString>> &installedVersions);

// Read the `// nullock:version 1.2.3` directive an installed script may carry,
// so an update can be detected without trusting a filename. Empty when absent.
QString parseInstalledVersion(const QString &jsSource);

} // namespace Nullock::Core::MarketplaceLogic
