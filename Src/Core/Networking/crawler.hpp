#pragma once

// Link-following crawler. Starts from a seed URL, fetches it, extracts
// hrefs / src / form actions, queues anything in-scope, repeats.
//
// Compared to content-discovery (which guesses paths from a wordlist
// against one host), the crawler builds the actual attack surface map
// by following what's actually linked. Closes the major Burp delta
// on day-one engagement work.
//
// Behaviour:
//   * Respects the project's scope (only enqueues in-scope URLs).
//   * Skips well-known dead-ends (mailto:, javascript:, data:, tel:).
//   * Bounded breadth-first walk -- caps total pages, queue size, and
//     per-host depth. Stays polite by default with a configurable
//     throttle between requests.
//   * Emits each fetched response into the normal proxy History via
//     entryLoaded so the rest of the toolchain (scanner, passive
//     findings, repeater) sees them as if they were captured normally.

#include "networking.hpp"
#include "proxy_server.hpp"

#include <QObject>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QQueue>

namespace Nullock::Core {

class Crawler : public QObject {
    Q_OBJECT
    Q_PROPERTY(bool running    READ running    NOTIFY runningChanged)
    Q_PROPERTY(int  visited    READ visited    NOTIFY progressChanged)
    Q_PROPERTY(int  queued     READ queued     NOTIFY progressChanged)
    Q_PROPERTY(QString seed    READ seed       NOTIFY seedChanged)
public:
    explicit Crawler(QObject *parent = nullptr);

    bool    running() const { return m_running; }
    int     visited() const { return m_visited; }
    int     queued()  const { return m_queue.size(); }
    QString seed()    const { return m_seed; }

    // Inject the project's scope checker so the crawler refuses to
    // walk out-of-scope hosts. Set by App at wire time.
    using ScopeFn = std::function<bool(const QString &host)>;
    void setScopeChecker(ScopeFn f) { m_scope = std::move(f); }

    // Start a fresh crawl from <seed>. Cancels any running walk first.
    // Returns false if the seed isn't a parseable URL.
    Q_INVOKABLE bool start(const QString &seed,
                           int maxPages = 200,
                           int maxDepth = 4,
                           int throttleMs = 200);
    Q_INVOKABLE void stop();

signals:
    void runningChanged();
    void progressChanged();
    void seedChanged();
    void entryLoaded(const Nullock::Proxy::HttpRequest &req,
                     const Nullock::Proxy::HttpResponse &resp);
    void errorOccurred(const QString &msg);

private:
    struct PendingUrl {
        QString url;
        int     depth = 0;
    };

    void crawlOne(const PendingUrl &u);
    void extractAndEnqueue(const QString &fromUrl, const QByteArray &body, int depth);

    bool      m_running = false;
    bool      m_stopRequested = false;
    QString   m_seed;
    int       m_maxPages = 200;
    int       m_maxDepth = 4;
    int       m_throttleMs = 200;
    int       m_visited = 0;
    QSet<QString>    m_seenUrls;
    QQueue<PendingUrl> m_queue;
    ScopeFn   m_scope;
};

} // namespace Nullock::Core
