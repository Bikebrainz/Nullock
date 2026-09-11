#include "outbound_scope.hpp"
#include <QMutex>
#include <QMutexLocker>
#include <QUrl>

namespace Nullock::Core::OutboundScope {
namespace {
QMutex mutex;
Checker checker;
}
Registration::Registration(Checker fn) {
    QMutexLocker lock(&mutex);
    checker = std::move(fn);
}
Registration::~Registration() {
    QMutexLocker lock(&mutex);
    checker = {};
}
bool allows(const Target &target) {
    Checker current;
    { QMutexLocker lock(&mutex); current = checker; }
    return !current || (target.port > 0 && target.port <= 65535
        && !target.host.trimmed().isEmpty() && current(target));
}
bool allowsUrl(const QString &host, int port, bool tls, const QString &target) {
    Target t{host, port, tls ? 2 : 1, {}};
    // Evaluate the actual socket destination, never an absolute-form authority
    // supplied in fuzz bytes. Require both the wire path and its decoded,
    // dot-segment-normalized form, so encoding cannot escape a path restriction.
    if (target.startsWith('/')) t.path = target.section('?', 0, 0).section('#', 0, 0);
    else {
        const QUrl u(target, QUrl::StrictMode);
        if (u.isValid() && (u.scheme() == "http" || u.scheme() == "https") && !u.host().isEmpty())
            t.path = u.path(QUrl::FullyEncoded).isEmpty() ? QStringLiteral("/") : u.path(QUrl::FullyEncoded);
    }
    if (!allows(t)) return false;
    if (t.path.isNull()) return true;
    QUrl normalized;
    normalized.setPath(QUrl::fromPercentEncoding(t.path.toUtf8()), QUrl::DecodedMode);
    t.path = normalized.adjusted(QUrl::NormalizePathSegments).path(QUrl::FullyDecoded);
    if (t.path.isEmpty()) t.path = QStringLiteral("/");
    return allows(t);
}
bool allowsRequest(const QString &host, int port, bool tls, const QByteArray &request) {
    const QByteArray line = request.left(request.indexOf('\n') < 0 ? request.size() : request.indexOf('\n')).trimmed();
    const int first = line.indexOf(' '), last = line.lastIndexOf(' ');
    const QString target = first >= 0 && last > first
        ? QString::fromLatin1(line.mid(first + 1, last - first - 1)) : QString();
    return allowsUrl(host, port, tls, target);
}
} // namespace Nullock::Core::OutboundScope
