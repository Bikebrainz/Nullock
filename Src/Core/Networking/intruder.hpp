#pragma once

#include "networking.hpp"

#include <QAbstractListModel>
#include <QList>
#include <QObject>
#include <QString>
#include <QStringList>

namespace Nullock::FrontEnd {
class ProxyModel;
}

namespace Nullock::Core {

// One row in the Intruder results table -- the substituted payload, the
// response stats once it lands, and an error if the request failed.
class IntruderAttack : public QObject {
    Q_OBJECT
    Q_PROPERTY(int     id            MEMBER m_id            CONSTANT)
    Q_PROPERTY(QString payload       MEMBER m_payload       CONSTANT)
    Q_PROPERTY(int     statusCode    MEMBER m_statusCode    NOTIFY changed)
    Q_PROPERTY(int     responseSize  MEMBER m_responseSize  NOTIFY changed)
    Q_PROPERTY(int     elapsedMs     MEMBER m_elapsedMs     NOTIFY changed)
    Q_PROPERTY(QString errorMessage  MEMBER m_errorMessage  NOTIFY changed)
    Q_PROPERTY(bool    complete      MEMBER m_complete      NOTIFY changed)
public:
    explicit IntruderAttack(QObject *parent = nullptr) : QObject(parent) {}

    int     m_id = 0;
    QString m_payload;
    int     m_statusCode = 0;
    int     m_responseSize = 0;
    int     m_elapsedMs = 0;
    QString m_errorMessage;
    bool    m_complete = false;
signals:
    void changed();
};

// Sniper-mode Intruder: take a request template containing one marker pair
// (§...§), substitute each payload from the list, fire one request per
// payload, and aggregate the results. Runs the attack on a worker thread
// so the GUI keeps breathing.
class Intruder : public QAbstractListModel {
    Q_OBJECT
    Q_PROPERTY(QString host             READ host             WRITE setHost             NOTIFY targetChanged)
    Q_PROPERTY(int     port             READ port             WRITE setPort             NOTIFY targetChanged)
    Q_PROPERTY(bool    useTls           READ useTls           WRITE setUseTls           NOTIFY targetChanged)
    Q_PROPERTY(QString requestTemplate  READ requestTemplate  WRITE setRequestTemplate  NOTIFY templateChanged)
    Q_PROPERTY(QString payloads         READ payloads         WRITE setPayloads         NOTIFY payloadsChanged)
    Q_PROPERTY(bool    running          READ running                                    NOTIFY runningChanged)
    Q_PROPERTY(int     completedCount   READ completedCount                             NOTIFY progressChanged)
    Q_PROPERTY(int     totalCount       READ totalCount                                 NOTIFY progressChanged)
public:
    enum Roles {
        IdRole = Qt::UserRole + 1,
        PayloadRole,
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
    QString payloads() const { return m_payloads; }
    bool    running() const { return m_running; }
    int     completedCount() const { return m_completedCount; }
    int     totalCount() const { return m_attacks.size(); }

    void setHost(const QString &h);
    void setPort(int p);
    void setUseTls(bool tls);
    void setRequestTemplate(const QString &t);
    void setPayloads(const QString &p);

    Q_INVOKABLE void loadFromHistory(int row);
    Q_INVOKABLE void start();
    Q_INVOKABLE void stop();
    Q_INVOKABLE void clear();

signals:
    void targetChanged();
    void templateChanged();
    void payloadsChanged();
    void runningChanged();
    void progressChanged();

private:
    void attackFinished(int row);
    void runWorker(const QStringList &payloadsCopy,
                   const QString &templateCopy,
                   const QString &host, int port, bool useTls);

    Nullock::FrontEnd::ProxyModel *m_model;

    QString m_host;
    int     m_port = 443;
    bool    m_useTls = true;
    QString m_template;
    QString m_payloads;

    QList<IntruderAttack *> m_attacks;
    bool    m_running = false;
    bool    m_stopRequested = false;
    int     m_completedCount = 0;
};

} // namespace Nullock::Core
