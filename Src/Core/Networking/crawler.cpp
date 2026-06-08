#include "crawler.hpp"

#include "networking.hpp"

#include <QDateTime>
#include <QRegularExpression>
#include <QThread>
#include <QUrl>
#include <QtConcurrent/QtConcurrentRun>

namespace Nullock::Core {

Crawler::Crawler(QObject *parent) : QObject(parent) {}

bool Crawler::start(const QString &seed, int maxPages, int maxDepth, int throttleMs) {
    stop();
    QUrl u(seed);
    if (!u.isValid() || u.scheme().isEmpty() || u.host().isEmpty()) {
        emit errorOccurred("crawler: invalid seed URL");
        return false;
    }
    m_seed       = seed;
    m_maxPages   = qBound(1, maxPages, 5000);
    m_maxDepth   = qBound(0, maxDepth, 10);
    m_throttleMs = qBound(0, throttleMs, 60'000);
    m_visited    = 0;
    m_seenUrls.clear();
    m_queue.clear();
    m_queue.enqueue({ seed, 0 });
    m_seenUrls.insert(seed);
    m_stopRequested = false;
    m_running = true;
    emit seedChanged();
    emit runningChanged();
    emit progressChanged();

    // Run the BFS off-thread so the GUI / control API stay responsive.
    (void)QtConcurrent::run([this]() {
        while (m_running && !m_stopRequested
               && m_visited < m_maxPages
               && !m_queue.isEmpty()) {
            const PendingUrl u = m_queue.dequeue();
            emit progressChanged();
            crawlOne(u);
            ++m_visited;
            emit progressChanged();
            if (m_throttleMs > 0) QThread::msleep(m_throttleMs);
        }
        m_running = false;
        emit runningChanged();
        emit progressChanged();
    });
    return true;
}

void Crawler::stop() {
    m_stopRequested = true;
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
    // Naive HTML link extraction. Handles href / src / action across
    // tags. Doesn't run JS so heavily-SPA targets won't yield many
    // links -- that's a fundamental limitation of static crawling.
    // Cap body scanned at 4 MB.
    const QString text = QString::fromUtf8(body.left(4 * 1024 * 1024));
    static const QRegularExpression rx(
        R"#((?:href|src|action)\s*=\s*["']([^"']+)["'])#",
        QRegularExpression::CaseInsensitiveOption);

    auto it = rx.globalMatch(text);
    const QUrl base(fromUrl);
    while (it.hasNext() && m_seenUrls.size() < 50'000) {
        const QString href = it.next().captured(1).trimmed();
        if (href.isEmpty()) continue;
        // Skip non-HTTP schemes.
        const QString lower = href.toLower();
        if (lower.startsWith("mailto:") || lower.startsWith("tel:")
            || lower.startsWith("javascript:") || lower.startsWith("data:")
            || lower.startsWith("blob:") || lower.startsWith("#")) continue;

        QUrl abs = base.resolved(QUrl(href));
        if (!abs.isValid() || abs.host().isEmpty()) continue;
        // Strip fragments -- they don't affect what the server sees.
        abs.setFragment(QString());
        const QString final = abs.toString();
        if (m_seenUrls.contains(final)) continue;
        m_seenUrls.insert(final);

        // Scope check: don't walk hosts that aren't in scope.
        if (m_scope && !m_scope(abs.host())) continue;

        m_queue.enqueue({ final, depth });
    }
    emit progressChanged();
}

} // namespace Nullock::Core
