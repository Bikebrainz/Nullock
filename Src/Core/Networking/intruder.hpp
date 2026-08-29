#pragma once

#include "networking.hpp"
#include "intruder_rules.hpp"
#include "intruder_grep.hpp"
#include "intruder_pool_logic.hpp"
#include "intruder_persist_logic.hpp"
#include "redirect_logic.hpp"

#include <QAbstractListModel>
#include <QFuture>
#include <QList>
#include <QSet>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QThreadPool>

#include <atomic>
#include <functional>

namespace Nullock::FrontEnd {
class ProxyModel;
}

namespace Nullock::Core {

// One row in the Intruder results table -- the substituted payload(s), the
// response stats once it lands, and an error if the request failed. With
// multiple marker positions a row carries one value per position; `payload`
// is the human-readable join of them, `payloads` the per-position list.
class IntruderAttack : public QObject {
    Q_OBJECT
    Q_PROPERTY(int         id            MEMBER m_id            CONSTANT)
    Q_PROPERTY(QString     payload       MEMBER m_payload       CONSTANT)
    Q_PROPERTY(QStringList payloads      MEMBER m_payloadValues CONSTANT)
    Q_PROPERTY(int         statusCode    MEMBER m_statusCode    NOTIFY changed)
    Q_PROPERTY(int         responseSize  MEMBER m_responseSize  NOTIFY changed)
    Q_PROPERTY(int         elapsedMs     MEMBER m_elapsedMs     NOTIFY changed)
    Q_PROPERTY(QString     errorMessage  MEMBER m_errorMessage  NOTIFY changed)
    Q_PROPERTY(bool        complete      MEMBER m_complete      NOTIFY changed)
    // Grep columns (Burp "Grep - Match" / "Grep - Extract"): did the response
    // hit any configured match needle, and the value pulled out of it.
    Q_PROPERTY(bool        matched       MEMBER m_matched       NOTIFY changed)
    Q_PROPERTY(bool        reflected     MEMBER m_reflected     NOTIFY changed)
    Q_PROPERTY(QString     extracted     MEMBER m_extracted     NOTIFY changed)
public:
    explicit IntruderAttack(QObject *parent = nullptr) : QObject(parent) {}

    int         m_id = 0;
    // Raw combination as the engine produced it -- a null entry means "leave
    // this marker at its default". Kept verbatim so resend() re-fires the
    // exact same request; never shown to the UI directly.
    QStringList m_combo;
    // Display values, one per position (nulls resolved to "(default)").
    QStringList m_payloadValues;
    QString     m_payload;        // m_payloadValues joined with " / "
    int         m_statusCode = 0;
    int         m_responseSize = 0;
    int         m_elapsedMs = 0;
    QString     m_errorMessage;
    bool        m_complete = false;
    bool        m_matched = false;   // any grep-match needle hit this response
    bool        m_reflected = false; // a payload of this row echoed in the response
    QString     m_extracted;         // grep-extract value (empty if none)
signals:
    void changed();
};

// Multi-mode Intruder (Burp-parity): take a request template containing one
// or more marker pairs (§...§), generate a request per attack-type
// combination of the configured payload set(s), fire them, and aggregate the
// results. Runs the attack on a worker thread so the GUI keeps breathing.
//
//   Sniper        one payload set, each marker fuzzed one at a time
//   Battering ram one payload set, same payload in every marker
//   Pitchfork     one set per marker, zipped by index (min length)
//   Cluster bomb  one set per marker, cartesian product
//
// The combination + substitution logic lives in IntruderEngine (pure,
// unit-tested); this class owns the target/state and the firing loop.
class SessionRules;

class Intruder : public QAbstractListModel {
    Q_OBJECT
    Q_PROPERTY(QString     host             READ host             WRITE setHost             NOTIFY targetChanged)
    Q_PROPERTY(int         port             READ port             WRITE setPort             NOTIFY targetChanged)
    Q_PROPERTY(bool        useTls           READ useTls           WRITE setUseTls           NOTIFY targetChanged)
    Q_PROPERTY(QString     requestTemplate  READ requestTemplate  WRITE setRequestTemplate  NOTIFY templateChanged)
    Q_PROPERTY(QString     payloads         READ payloads         WRITE setPayloads         NOTIFY payloadsChanged)
    Q_PROPERTY(QStringList payloadSets      READ payloadSets      WRITE setPayloadSets      NOTIFY payloadsChanged)
    Q_PROPERTY(int         attackType       READ attackType       WRITE setAttackType       NOTIFY attackTypeChanged)
    Q_PROPERTY(int         positionCount    READ positionCount                              NOTIFY templateChanged)
    Q_PROPERTY(bool        running          READ running                                    NOTIFY runningChanged)
    Q_PROPERTY(int         completedCount   READ completedCount                             NOTIFY progressChanged)
    Q_PROPERTY(int         totalCount       READ totalCount                                 NOTIFY progressChanged)
public:
    // Mirror of IntruderEngine::AttackType (same order) so QML can bind an
    // int and the control API can round-trip a name.
    enum AttackType {
        Sniper = 0,
        BatteringRam,
        Pitchfork,
        ClusterBomb,
    };
    Q_ENUM(AttackType)

    enum Roles {
        IdRole = Qt::UserRole + 1,
        PayloadRole,
        PayloadsRole,
        StatusRole,
        SizeRole,
        TimeRole,
        ErrorRole,
        CompleteRole,
        MatchedRole,
        ReflectedRole,
        ExtractedRole,
    };

    explicit Intruder(Nullock::FrontEnd::ProxyModel *historyModel,
                      QObject *parent = nullptr);
    ~Intruder() override;

    // QAbstractListModel
    int rowCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

    QString host() const { return m_host; }
    int     port() const { return m_port; }
    bool    useTls() const { return m_useTls; }
    QString requestTemplate() const { return m_template; }
    // The "payloads" alias is payload set 0 -- the single list used by Sniper
    // and Battering ram, and the first column for Pitchfork / Cluster bomb.
    QString     payloads() const { return m_payloadSets.isEmpty() ? QString() : m_payloadSets.constFirst(); }
    QStringList payloadSets() const { return m_payloadSets; }
    int     attackType() const { return m_attackType; }
    int     positionCount() const;
    bool    running() const { return m_running; }
    int     completedCount() const { return m_completedCount; }
    int     totalCount() const { return static_cast<int>(m_attacks.size()); }

    void setHost(const QString &h);
    void setPort(int p);
    void setUseTls(bool tls);
    void setRequestTemplate(const QString &t);
    void setPayloads(const QString &p);
    void setPayloadSets(const QStringList &s);
    void setAttackType(int t);
    // Payload-processing rule chain (Burp-parity): each non-null payload value is
    // threaded through these transforms before it's substituted into the request.
    // A single global chain applied to every position (v1). Operator-configured.
    void setPayloadRules(const QList<Nullock::Core::IntruderRules::Rule> &rules);
    // Burp "URL-encode these characters" GLOBAL safety net: when non-empty, a
    // url-encode-chars step over this character set is appended to EVERY
    // payload's processing chain (applied LAST, after the per-position rules).
    // Empty = off. Kept separate from the saved rule chain so it can't be
    // double-applied on save/resume.
    void setGlobalEncodeChars(const QString &chars);
    // Session-handling rules scoped to Intruder are applied to each fired request
    // (only rewriting the bytes when a rule matches). Optional; nullptr = off.
    void setSessionRules(SessionRules *sr) { m_sessionRules = sr; }
    // Result-grep config (Burp-parity): after each response lands it's scanned
    // for these match needles (any-hit -> matched=true) and this extract spec
    // (regex capture or start/end delimiters -> extracted). Both are bounded and
    // safe against malformed regex / huge bodies (see IntruderGrep). Empty
    // needles / empty spec = column stays off.
    void setGrepMatch(const QStringList &needles);
    // Burp "Grep - Payloads": when on, each result row is flagged (reflected) if
    // one of its submitted payloads echoes literally in the response body -- the
    // automatic reflection column, no hand-built per-payload match needle needed.
    void setGrepPayloadReflection(bool on);
    void setGrepExtract(const Nullock::Core::IntruderGrep::ExtractSpec &spec);

    // Burp "Recursive grep" payload type: instead of a fixed wordlist, each
    // request's payload is the value the grep-EXTRACT spec pulls out of the
    // PREVIOUS response -- so a CSRF token / one-time nonce / sequential id can be
    // walked forward across a chain of requests (the classic anti-CSRF-bruteforce
    // and state-machine-walking attack). The FIRST request uses `seed` (Burp's
    // "initial payload for first request", may be empty); the run is inherently
    // SERIAL (each request depends on the prior response) and bounded to `count`
    // requests, stopping early if a response yields no extract (the chain ended).
    // Reuses the grep-extract spec set via setGrepExtract as the payload source.
    void setRecursiveGrep(bool on);
    void setRecursiveGrepSeed(const QString &seed);
    void setRecursiveGrepCount(int count);
    bool recursiveGrep() const { return m_recursiveGrep; }
    // Request-pool config (Burp-parity "resource pool"): how many requests may be
    // in flight at once, and an optional inter-dispatch delay (rate limit). Both
    // are clamped (see IntruderPool) so a caller can't spawn unbounded threads or
    // park the run. Concurrency 1 == the old fully-serial behaviour.
    void setMaxConcurrency(int n);
    void setThrottleMs(int ms);
    int  maxConcurrency() const { return m_maxConcurrency; }
    int  throttleMs() const { return m_throttleMs; }
    // Burp-parity "retry on network failure": how many times a request is
    // re-sent after a NETWORK-level failure (connect refused/timeout/reset),
    // never after an HTTP error status. Clamped (see IntruderPool); 0 = off
    // (Burp-parity default -- no retry).
    void setMaxRetries(int n);
    int  maxRetries() const { return m_maxRetries; }
    // Follow 3xx after each fired request (Burp's "Follow redirections"): the
    // recorded result (status / length / grep) becomes the FINAL hop's. Policy is
    // a RedirectLogic::FollowPolicy (0=never..3=always); processCookies threads
    // Set-Cookie through the chain. Cap: kMaxRedirectHops per request.
    static constexpr int kMaxRedirectHops = 10;
    void setFollowRedirects(int policy);
    void setProcessCookies(bool on);
    int  followRedirects() const { return m_followPolicy; }
    bool processCookies() const  { return m_followCookies; }
    // Scope predicate for the "in-scope" follow policy (Intruder holds no proxy
    // pointer). app.cpp wires it to ProxyServer::isInScope. Unset -> in-scope
    // follows nothing (fail-closed).
    void setScopeChecker(std::function<bool(const QString &)> fn) { m_inScope = std::move(fn); }

    // Per-set helpers for QML multi-position editing. Indices past the end
    // grow the list; reads past the end return an empty string.
    Q_INVOKABLE QString payloadSetAt(int i) const;
    Q_INVOKABLE void    setPayloadSetAt(int i, const QString &v);
    // Resize the payload-set list to match the number of markers in the
    // current template (preserving existing sets), so Pitchfork / Cluster
    // bomb get one editable column per position. Always keeps at least one.
    Q_INVOKABLE void    syncSetsToPositions();

    Q_INVOKABLE void loadFromHistory(int row);
    // Save/resume (Burp "save attack"): serialize the whole run -- target,
    // template, payloads, rules, grep, pool config, and every result row -- to
    // JSON bytes, and restore it. loadRun refuses while an attack is running and
    // does NOT re-fire; it just repopulates the table (resend() still works
    // because the raw combo, nulls included, round-trips).
    Q_INVOKABLE QByteArray saveRun() const;
    Q_INVOKABLE bool       loadRun(const QByteArray &bytes);
    Q_INVOKABLE void start();
    // The "Resume" half of save/resume: after loadRun repopulates a partially-
    // fired attack, re-fire ONLY the rows that never completed (already-complete
    // rows keep their results). Reuses the normal worker, skipping the completed
    // indices. No-ops (returns false) if an attack is running, there are no rows,
    // the run is recursive-grep (unresumable), or every row is already complete.
    Q_INVOKABLE bool resume();
    Q_INVOKABLE void stop();
    Q_INVOKABLE void clear();
    // Re-fires a single result row with its existing payload combination
    // against the current template/target. Quietly no-ops if the row index
    // is out of range or if a full attack is already running.
    Q_INVOKABLE bool resend(int row);

    // Wipe everything -- host, port, template, payloads, and results.
    // Wire to ProjectStore::historyShouldClear so a project switch
    // doesn't leave the previous engagement's target loaded.
public slots:
    void clearAll();
public:

signals:
    void targetChanged();
    void templateChanged();
    void payloadsChanged();
    void attackTypeChanged();
    void runningChanged();
    void progressChanged();

private:
    void attackFinished(int row);
    // Recursive-grep run parameters, copied off the GUI thread like every other
    // config value. enabled=false -> ordinary combos run.
    struct RecursiveSpec { bool enabled = false; QString seed; int count = 0; };
    void runWorker(const QList<QStringList> &combos,
                   const QString &templateCopy,
                   const QString &host, int port, bool useTls,
                   const QList<Nullock::Core::IntruderRules::Rule> &rules,
                   const QStringList &grepMatch,
                   bool grepReflection,
                   const Nullock::Core::IntruderGrep::ExtractSpec &grepExtract,
                   int concurrency, int throttleMs, int retries,
                   int followPolicy, bool followCookies,
                   std::function<bool(const QString &)> inScope,
                   const RecursiveSpec &recursive,
                   const QSet<int> &skipRows);

    Nullock::FrontEnd::ProxyModel *m_model;

    QString m_host;
    int     m_port = 443;
    bool    m_useTls = true;
    QString m_template;
    // Canonical payload sets, each a newline-separated block. Index 0 is the
    // "payloads" alias. Empty list == no payloads configured.
    QStringList m_payloadSets;
    QList<Nullock::Core::IntruderRules::Rule> m_payloadRules;
    QString m_globalEncodeChars;   // Burp "URL-encode these characters" set (empty=off)
    QStringList m_grepMatch;                              // grep-match needles
    bool    m_grepPayloadReflection = false;             // flag reflected payloads
    Nullock::Core::IntruderGrep::ExtractSpec m_grepExtract; // grep-extract spec
    bool    m_recursiveGrep = false;                     // recursive-grep payload mode
    QString m_recursiveGrepSeed;                         // first request's payload
    int     m_recursiveGrepCount = 10;                   // number of chained requests
    SessionRules *m_sessionRules = nullptr;
    int     m_maxConcurrency = Nullock::Core::IntruderPool::kDefaultConcurrency;
    int     m_throttleMs = 0;                            // inter-dispatch delay
    int     m_maxRetries = Nullock::Core::IntruderPool::kDefaultRetries; // retries on network failure
    int     m_followPolicy  = 0;                         // RedirectLogic::FollowNever (off, Burp default)
    bool    m_followCookies = true;                      // "Process cookies in redirections"
    std::function<bool(const QString &)> m_inScope;
    int     m_attackType = Sniper;

    QList<IntruderAttack *> m_attacks;
    bool    m_running = false;
    // Written from the GUI thread (start/stop/dtor), read from the worker
    // thread's fire loop -- must be atomic to avoid a data race + torn read.
    std::atomic<bool> m_stopRequested { false };
    int     m_completedCount = 0;
    // Handles to the off-thread workers, joined in ~Intruder() so neither can
    // touch m_attacks after we begin tearing it down. attack and resend are
    // separate so a resend future isn't lost when start() overwrites it.
    QFuture<void> m_worker;
    QFuture<void> m_resendWorker;
    // Owned request pool for a concurrent attack. The dispatcher (m_worker)
    // submits per-request tasks here and blocks on waitForDone() before it
    // returns, so joining m_worker in the dtor transitively joins every in-flight
    // request BEFORE m_attacks is freed. Only the attack path uses it; resend
    // stays on the global pool.
    QThreadPool m_pool;
};

} // namespace Nullock::Core
