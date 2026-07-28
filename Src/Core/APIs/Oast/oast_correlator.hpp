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

#include <QHash>
#include <QMutex>
#include "finding_sink.hpp"

#include <QObject>
#include <QSet>
#include <QString>

namespace Nullock::Core {

// See finding_sink.hpp: depending on the interface keeps APIs off Networking.

struct OastOrigin {
    int     rowId = 0;     // history row that fired the payload (0 = manual)
    QString host;          // target host the payload was sent to
    QString param;         // parameter / location the token was embedded in
    QString url;           // the callback URL we embedded
    QString kind;          // probe kind, e.g. "ssrf-oast"
    QString note;          // optional free-text label (manual mints)
};

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

    int registeredCount() const;
    int confirmedCount() const;

public slots:
    // Connect to OastServer::hitReceived. Runs on the OAST server's
    // thread (the main thread); reportFinding is mutex-guarded so that's
    // safe.
    void onHit(const OastHit &hit);

private:
    mutable QMutex              m_mutex;
    QHash<QString, OastOrigin>  m_tokens;      // token -> origin
    QSet<QString>               m_confirmed;   // tokens already reported
    IFindingSink               *m_scanner = nullptr;
};

} // namespace Nullock::Core
