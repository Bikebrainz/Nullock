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

#include <QMutex>
#include <QObject>
#include <QString>

namespace Nullock::Core {

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
};

} // namespace Nullock::Core
