#include "crawler.hpp"

#include "crawler_logic.hpp"
#include "networking.hpp"

#include <QDateTime>
#include <QThread>
#include <QUrl>
#include <QtConcurrent/QtConcurrentRun>

namespace Nullock::Core {

bool Crawler::inScope(const QString &scheme, const QString &host, int port) const {
    // Injected checker wins; otherwise fail closed to the seed's own domain tree
    // AND origin port. A null checker must NEVER mean "everything is in scope".
    if (m_scope) return m_scope(scheme, host, port);
    return CrawlerLogic::inDefaultScopeOrigin(scheme, host, port,
                                              m_seedScheme, m_seedHost, m_seedPort);
}

Crawler::Crawler(QObject *parent) : QObject(parent) {}

Crawler::~Crawler() {
    // Stop-join. The BFS worker captures `this` and touches non-atomic members
    // (m_queue, m_seenUrls, m_visited) between blocking fetches. If we let this
    // object be destroyed while the worker is mid-crawl, those accesses become a
    // use-after-free. Signal stop, then block until the worker has fully
    // returned. The loop checks m_stopRequested every iteration, so this waits
    // out at most one in-flight fetch, not the whole crawl.
    m_stopRequested.storeRelease(1);
    if (m_worker.isRunning()) m_worker.waitForFinished();
}

bool Crawler::start(const QString &seed, int maxPages, int maxDepth, int throttleMs) {
    // Refuse if a previous crawl is still in flight. The caller has to
    // stop() and wait. Without this, two starts would race -- one
    // worker thread mid-crawlOne() while the other is overwriting
    // m_queue / m_seenUrls.
    if (m_running.loadAcquire() != 0) {
        emit errorOccurred("crawler: a crawl is already running; stop() first");
        return false;
    }
    QUrl u(seed);
    if (!u.isValid() || u.scheme().isEmpty() || u.host().isEmpty()) {
        emit errorOccurred("crawler: invalid seed URL");
        return false;
    }
    // Canonicalize the seed through the SAME pipeline as discovered links (http(s)
    // allow-list, fragment strip, "/" path) so the seed's self-links dedupe and
    // the start page isn't fetched twice.
    QString seedHost;
    const QString canonSeed = CrawlerLogic::canonicalLink(seed, u, seedHost);
    if (canonSeed.isEmpty()) {
        emit errorOccurred("crawler: seed must be an http(s) URL");
        return false;
    }
    m_seed       = seed;
    m_seedHost   = seedHost;
    m_seedScheme = u.scheme().toLower();
    m_seedPort   = u.port(-1);          // -1 when absent -> resolved to the scheme default in logic
    // Scope-check the SEED before any fetch. With an injected checker an
    // out-of-scope seed is rejected; with none, the seed defines its own scope.
    if (!inScope(m_seedScheme, seedHost, m_seedPort)) {
        emit errorOccurred("crawler: seed host is out of scope");
        return false;
    }
    m_maxPages   = qBound(1, maxPages, 5000);
    m_maxDepth   = qBound(0, maxDepth, 10);
    m_throttleMs = qBound(0, throttleMs, 60'000);
    m_visited    = 0;
    m_seenUrls.clear();
    m_queue.clear();
    m_queue.enqueue({ canonSeed, 0 });
    m_seenUrls.insert(canonSeed);
    m_stopRequested.storeRelease(0);
    m_running.storeRelease(1);
    emit seedChanged();
    emit runningChanged();
    emit progressChanged();

    // Run the BFS off-thread so the GUI / control API stay responsive.
    // Keep the future so ~Crawler() can join the worker (see the destructor).
    m_worker = QtConcurrent::run([this]() {
        while (m_running.loadAcquire() != 0
               && m_stopRequested.loadAcquire() == 0
               && m_visited < m_maxPages
               && !m_queue.isEmpty()) {
            const PendingUrl u = m_queue.dequeue();
            emit progressChanged();
            crawlOne(u);
            ++m_visited;
            emit progressChanged();
            if (m_throttleMs > 0) QThread::msleep(m_throttleMs);
        }
        m_running.storeRelease(0);
        emit runningChanged();
        emit progressChanged();
    });
    return true;
}

void Crawler::stop() {
    m_stopRequested.storeRelease(1);
}

void Crawler::crawlOne(const PendingUrl &u) {
    const QUrl url(u.url);
    const QString host = url.host();
    const bool useTls  = url.scheme().compare("https", Qt::CaseInsensitive) == 0;
    const quint16 port = static_cast<quint16>(url.port(useTls ? 443 : 80));

    // Build the request bytes manually -- HEAD requests are cheaper for
    // surface walking, but they don't return bodies and we want bodies
    // to extract links. So GET it is.
    QString p = url.path(QUrl::FullyEncoded);
    if (p.isEmpty()) p = "/";
    if (url.hasQuery()) p += "?" + url.query(QUrl::FullyEncoded);

    QByteArray reqBytes;
    reqBytes += "GET " + p.toUtf8() + " HTTP/1.1\r\n";
    reqBytes += "Host: " + host.toUtf8() + "\r\n";
    reqBytes += "User-Agent: nullock-crawler/1.0\r\n";
    reqBytes += "Accept: text/html,*/*;q=0.5\r\n";
    reqBytes += "Connection: close\r\n\r\n";

    HttpClient client;
    auto res = client.send(host, port, useTls, reqBytes);
    if (!res.ok) return;

    // Surface as a captured row so scanner / history pick it up.
    Nullock::Proxy::HttpRequest req;
    req.timestamp = QDateTime::currentDateTime();
    req.method = "GET";
    req.host   = host;
    req.port   = port;
    req.path   = p;
    req.target = p;
    req.httpVersion = "HTTP/1.1";
    req.headers.append(qMakePair(QStringLiteral("Host"), host));
    req.headers.append(qMakePair(QStringLiteral("User-Agent"),
                                 QStringLiteral("nullock-crawler/1.0")));
    emit entryLoaded(req, res.parsed);

    // Don't follow further if max depth reached.
    if (u.depth >= m_maxDepth) return;
    extractAndEnqueue(u.url, res.parsed.body, u.depth + 1);
}

void Crawler::extractAndEnqueue(const QString &fromUrl, const QByteArray &body, int depth) {
    // Naive HTML link extraction. Handles href / src / action (quoted AND
    // unquoted) across tags. Doesn't run JS so heavily-SPA targets won't yield
    // many links -- a fundamental limitation of static crawling. The body is
    // capped at 4 MB but cut at a tag boundary so a straddling link isn't lost.
    const QString text = QString::fromUtf8(
        CrawlerLogic::truncateBodyAtTag(body, 4 * 1024 * 1024));
    // Honor <base href> for relative-link resolution.
    const QUrl base = CrawlerLogic::resolveBase(text, QUrl(fromUrl));

    // href/src/action + srcset (responsive images), meta-refresh redirects, and
    // GET-form parameter surfaces -- all resolved + scoped through one path.
    QStringList refs = CrawlerLogic::extractRawLinks(text);
    refs += CrawlerLogic::extractSrcset(text);
    refs += CrawlerLogic::extractMetaRefresh(text);
    refs += CrawlerLogic::extractFormGets(text);
    for (const QString &href : refs) {
        if (m_seenUrls.size() >= 50'000) break;
        QString host;
        const QString canon = CrawlerLogic::canonicalLink(href, base, host);
        if (canon.isEmpty()) continue;              // non-http(s) / unparseable
        // Scope FIRST: an out-of-scope link must neither be enqueued NOR consume
        // a seen-slot toward the cap. inScope() is fail-closed when unconfigured.
        // The canonical URL carries the resolved scheme/port for the origin check.
        const QUrl cu(canon);
        if (!inScope(cu.scheme(), host, cu.port(-1))) continue;
        if (m_seenUrls.contains(canon)) continue;
        m_seenUrls.insert(canon);
        m_queue.enqueue({ canon, depth });
    }
    emit progressChanged();
}

} // namespace Nullock::Core
