#pragma once

// Background update check via GitHub Releases (free, no infra).
//
// On startup we fire one HTTPS GET to
//   https://api.github.com/repos/Bikebrainz/Nullock/releases/latest
// and compare the returned tag_name against the locally-compiled
// version. If newer, we surface the result via /api/snapshot (the UI
// shows a small "Update X.Y.Z available" pill in the chrome).
//
// Self-update download is intentionally NOT automated. We show the
// user a link to the release notes + assets and let them re-install
// in their own time. Auto-applying updates in a security-critical
// MITM proxy is the kind of thing that ends with a tweet titled "I
// just got owned by my pentest tool."
//
// Disable with --no-update-check (or NULLOCK_NO_UPDATE=1 env var).
// Honours an offline mode + treats any 4xx/5xx/timeout as "no update,
// move on" -- never blocks startup, never prompts errors.

#include <QFuture>
#include <QMutex>
#include <QObject>
#include <QString>

namespace Nullock::Core {

// --- Pure update-check logic, exposed for the unit test (no I/O; in
//     update_check_logic.cpp, links Qt6::Core alone -- doCheck()'s HttpClient work
//     stays in update_check.cpp).
namespace UpdateLogic {
// Semver precedence: <0 if a is older than b, 0 if equal, >0 if newer. Tolerant of
// a leading "v", build metadata (+...), short/long cores, and non-numeric fields
// (treated as 0). Pre-release ordering follows semver §11 -- crucially a normal
// release outranks its own pre-release (1.3.0 > 1.3.0-rc1), so a user on an rc IS
// told about the final release.
int  compareSemver(const QString &a, const QString &b);
// True iff `url` is an HTTPS github.com page -- the only kind of release link the
// UI should open (defense-in-depth against a tampered/unexpected html_url field).
bool isTrustedReleaseUrl(const QString &url);
// Read NULLOCK_NO_UPDATE. The documented spelling is =1, and the old test was
// merely "is the variable non-empty" -- so NULLOCK_NO_UPDATE=0 turned the update
// check OFF, which is the opposite of what anyone writing it means. Falsey values
// (empty, 0, false, no, off, in any case, surrounded by whitespace) do NOT
// disable; anything else does, so a stray NULLOCK_NO_UPDATE=yes still works.
bool noUpdateRequested(const QString &envValue);
} // namespace UpdateLogic

struct UpdateInfo {
    bool    available  = false;
    QString currentVersion;
    QString latestVersion;
    QString releaseUrl;     // GitHub release page
    QString releaseNotes;   // Markdown body of the release
    QString publishedAt;    // ISO 8601
    QString error;          // populated on any failure (logged, not shown)
};

class UpdateChecker : public QObject {
    Q_OBJECT
public:
    explicit UpdateChecker(QObject *parent = nullptr) : QObject(parent) {}
    ~UpdateChecker() override;   // stop-join: the check worker must not outlive us

    // Run the check on a worker thread; the result is published via
    // updated() AND made available via lastResult() so the snapshot
    // builder can poll it any time.
    void checkAsync(const QString &currentVersion);
    UpdateInfo lastResult() const;

signals:
    void updated(const UpdateInfo &info);

private:
    static UpdateInfo doCheck(const QString &currentVersion);
    UpdateInfo m_last;
    mutable QMutex m_mu;
    QFuture<void> m_worker;   // handle to the check worker, joined in ~UpdateChecker()
};

} // namespace Nullock::Core
