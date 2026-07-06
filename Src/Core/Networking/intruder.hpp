#pragma once

#include "networking.hpp"
#include "intruder_rules.hpp"

#include <QAbstractListModel>
#include <QFuture>
#include <QList>
#include <QObject>
#include <QString>
#include <QStringList>

#include <atomic>

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

    // Per-set helpers for QML multi-position editing. Indices past the end
    // grow the list; reads past the end return an empty string.
    Q_INVOKABLE QString payloadSetAt(int i) const;
    Q_INVOKABLE void    setPayloadSetAt(int i, const QString &v);
    // Resize the payload-set list to match the number of markers in the
    // current template (preserving existing sets), so Pitchfork / Cluster
    // bomb get one editable column per position. Always keeps at least one.
    Q_INVOKABLE void    syncSetsToPositions();

    Q_INVOKABLE void loadFromHistory(int row);
    Q_INVOKABLE void start();
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
    void runWorker(const QList<QStringList> &combos,
                   const QString &templateCopy,
                   const QString &host, int port, bool useTls,
                   const QList<Nullock::Core::IntruderRules::Rule> &rules);

    Nullock::FrontEnd::ProxyModel *m_model;

    QString m_host;
    int     m_port = 443;
    bool    m_useTls = true;
    QString m_template;
    // Canonical payload sets, each a newline-separated block. Index 0 is the
    // "payloads" alias. Empty list == no payloads configured.
    QStringList m_payloadSets;
    QList<Nullock::Core::IntruderRules::Rule> m_payloadRules;
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
};

} // namespace Nullock::Core
