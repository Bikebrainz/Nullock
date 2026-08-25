#pragma once

// OAST correlation -- the half of Burp Collaborator that actually makes
// it worth money. The OAST sink (oast_server) logs inbound callbacks;
// on its own that's just a list the user has to eyeball. The correlator
// closes the loop:
//
//   1. When a probe (or a manual mint) embeds a callback URL into a
//      payload, it registers the token here with the originating context
//      (which row, which param, which probe).
//   2. The correlator listens for OAST hits. When a callback arrives
//      carrying a registered token, it auto-emits a *confirmed* finding
//      linked back to that row -- no polling, no manual matching.
//
// A confirmed out-of-band interaction is the strongest signal a scanner
// can produce: the target actually reached out to infrastructure we
// control. That's a true positive by construction, which is why it's
// graded high and why this is the feature that puts us level with (and,
// being free + self-hosted, above) Collaborator.

#include "oast_server.hpp"
#include "oast_origin.hpp"

#include <QHash>
#include <QMutex>
#include "finding_sink.hpp"

#include <QObject>
#include <QSet>
#include <QString>

namespace Nullock::Core {

// See finding_sink.hpp: depending on the interface keeps APIs off Networking.
// OastOrigin now lives in oast_origin.hpp (Core-only) so the pure persistence
// serializer can reach it without the QtNetwork chain.

class OastCorrelator : public QObject {
    Q_OBJECT
public:
    explicit OastCorrelator(QObject *parent = nullptr) : QObject(parent) {}

    // Optional -- without a scanner, a confirmed hit is recorded but no
    // finding is emitted (it still shows in /api/oast/poll).
    void setScanner(IFindingSink *s) { m_scanner = s; }

    // Register a token at (or just before) fire time. Thread-safe: probe
    // workers call this from QtConcurrent threads.
    void registerToken(const QString &token, const OastOrigin &origin);

    // Persistence across restarts: point the correlator at a JSON file. Loads any
    // saved (token -> origin) registrations and the already-confirmed set on the
    // spot, so a callback that arrives AFTER a restart still correlates to the
    // token minted before it, and an interaction already reported is never
    // re-reported. Subsequent registerToken / confirmed-hit changes are written
    // back atomically. Passing an empty path disables persistence. Thread-safe.
    void setPersistPath(const QString &path);

    int registeredCount() const;
    int confirmedCount() const;

public slots:
    // Connect to OastServer::hitReceived. Runs on the OAST server's
    // thread (the main thread); reportFinding is mutex-guarded so that's
    // safe.
    void onHit(const OastHit &hit);

private:
    // Write the current registry + confirmed set to m_persistPath (atomic
    // temp-then-rename). Caller must hold m_mutex.
    void saveLocked() const;

    mutable QMutex              m_mutex;
    QHash<QString, OastOrigin>  m_tokens;      // token -> origin
    QSet<QString>               m_confirmed;   // tokens already reported
    IFindingSink               *m_scanner = nullptr;
    QString                     m_persistPath; // empty -> persistence disabled
};

} // namespace Nullock::Core
