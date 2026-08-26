#include "repeater.hpp"

#include "Proxy/proxy_model.hpp"
#include "chain_runner.hpp"
#include "networking_logic.hpp"
#include "session_rules.hpp"

#include <QDateTime>
#include <QElapsedTimer>
#include <QJsonArray>
#include <QJsonValue>

namespace Nullock::Core {

namespace {
RepeaterTab makeBlankTab(const QString &name = "tab 1") {
    RepeaterTab t;
    t.name = name;
    return t;
}
} // namespace

Repeater::Repeater(Nullock::FrontEnd::ProxyModel *historyModel, QObject *parent)
    : QObject(parent), m_model(historyModel) {
    // Always have at least one tab so the QML/React bindings have
    // something to read on first paint.
    m_tabs.append(makeBlankTab());
}

RepeaterTab &Repeater::activeTab_() {
    if (m_active < 0 || m_active >= m_tabs.size()) {
        if (m_tabs.isEmpty()) m_tabs.append(makeBlankTab());
        m_active = 0;
    }
    return m_tabs[m_active];
}

const RepeaterTab &Repeater::activeTab_() const {
    static RepeaterTab blank;
    if (m_active < 0 || m_active >= m_tabs.size()) return blank;
    return m_tabs[m_active];
}

void Repeater::emitAllSlots() {
    emit targetChanged();
    emit requestTextChanged();
    emit responseChanged();
    emit tabsChanged();
}

QString Repeater::autoTabName(const QString &host, const QString &request) const {
    // Pull the request-line path so the tab is more useful than just "tab 4".
    // "GET /foo/bar HTTP/1.1" -> "GET /foo/bar @ host" trimmed to ~36 chars.
    QString firstLine = request.section('\n', 0, 0).trimmed();
    if (firstLine.size() > 60) firstLine = firstLine.left(57) + "...";
    if (firstLine.isEmpty()) return host.isEmpty() ? QStringLiteral("tab") : host;
    QString name = firstLine + " @ " + host;
    return name.left(48);
}

void Repeater::setHost(const QString &h) {
    auto &t = activeTab_();
    if (h == t.host) return;
    const QString oldHost = t.host;
    t.host = h;
    // Keep the request's Host header pointed at the new target -- unless the
    // user deliberately aimed it elsewhere (host-header-injection testing), in
    // which case rewriteHostHeader leaves it be.
    const QString synced = NetworkingLogic::rewriteHostHeader(t.requestText, oldHost, h);
    if (synced != t.requestText) {
        t.requestText = synced;
        emit requestTextChanged();
    }
    emit targetChanged();
}
void Repeater::setPort(int p) {
    auto &t = activeTab_();
    if (p == t.port) return;
    t.port = p;
    emit targetChanged();
}
void Repeater::setUseTls(bool tls) {
    auto &t = activeTab_();
    if (tls == t.useTls) return;
    t.useTls = tls;
    if (t.port == 80 && t.useTls)        t.port = 443;
    else if (t.port == 443 && !t.useTls) t.port = 80;
    emit targetChanged();
}
void Repeater::setRequestText(const QString &txt) {
    auto &t = activeTab_();
    if (txt == t.requestText) return;
    t.requestText = txt;
    emit requestTextChanged();
}

void Repeater::loadFromHistory(int row) {
    if (!m_model) return;
    const QString host = m_model->hostAt(row);
    if (host.isEmpty()) return;

    auto &t = activeTab_();
    t.host        = host;
    t.port        = m_model->portAt(row);
    t.useTls      = m_model->tlsAt(row);
    t.requestText = m_model->requestRawAt(row);
    if (t.name.isEmpty() || t.name.startsWith("tab "))
        t.name = autoTabName(t.host, t.requestText);

    emit targetChanged();
    emit requestTextChanged();
    emit tabsChanged();
}

void Repeater::clear() {
    auto &t = activeTab_();
    t.requestText.clear();
    t.responseText.clear();
    t.statusLine.clear();
    t.elapsedMs     = -1;
    t.responseBytes = -1;
    emit requestTextChanged();
    emit responseChanged();
}

void Repeater::clearAll() {
    m_tabs.clear();
    m_tabs.append(makeBlankTab());
    m_active = 0;
    emit tabsChanged();
    emit requestTextChanged();
    emit responseChanged();
}

void Repeater::send() {
    if (m_busy) return;
    auto &t = activeTab_();
    if (t.host.isEmpty() || t.requestText.isEmpty()) return;

    m_busy = true;
    emit busyChanged();

    // Normalize line endings to CRLF as the wire format expects.
    QString normalized = t.requestText;
    normalized.replace("\r\n", "\n");
    normalized.replace("\n", "\r\n");
    // Make sure we end with a blank line before any body.
    if (!normalized.contains("\r\n\r\n"))
        normalized += "\r\n\r\n";
    QByteArray bytes = normalized.toUtf8();
    // Recompute Content-Length from the actual body (Burp's default) unless the
    // user turned it off to hand-craft a desync. The chain runner's audited helper
    // also collapses a duplicate Content-Length and drops it under
    // Transfer-Encoding: chunked -- both request-smuggling vectors.
    if (m_autoContentLength)
        bytes = ChainRunner::normalizeContentLength(bytes);
    // Apply session-handling rules scoped to Repeater (inject a captured token /
    // cookie). Only rewrites the bytes if a rule actually fires; otherwise the
    // request goes on the wire byte-for-byte.
    if (m_sessionRules)
        m_sessionRules->applyToRequestBytes(bytes, t.host, SessionRulesLogic::ToolRepeater);

    // Time the whole network round-trip (including any followed redirects below).
    // This is the signal for blind SQLi / blind command injection / race work, so
    // it is measured around the blocking send(s) and surfaced with the response.
    QElapsedTimer roundTrip;
    roundTrip.start();
    auto result = m_client.send(t.host,
                                static_cast<quint16>(t.port),
                                t.useTls,
                                bytes);

    // Follow 3xx redirects when configured (Burp's "Follow redirections"). Each
    // hop is resolved + built by the pure redirect logic and sent to the resolved
    // target; the response pane shows the FINAL hop, with a note of how many were
    // followed. Cookie threading ("Process cookies in redirections") carries the
    // original request's cookies plus every Set-Cookie along the chain.
    int redirectHops = 0;
    if (m_followPolicy != RedirectLogic::FollowNever && result.ok) {
        namespace RL = Nullock::Core::RedirectLogic;
        QUrl current    = RL::requestUrl(t.useTls, t.host, t.port, bytes);
        QString method  = RL::requestMethod(bytes);
        QByteArray body;
        {
            const int hb = bytes.indexOf("\r\n\r\n");
            if (hb >= 0) body = bytes.mid(hb + 4);
        }
        QHash<QString, QString> jar;
        // Seed the jar with the original request's own Cookie header so a pre-set
        // session cookie survives the follow (buildFollowRequest emits only jar
        // cookies).
        if (m_followCookies) {
            const int hb = bytes.indexOf("\r\n\r\n");
            const QByteArray head = hb >= 0 ? bytes.left(hb) : bytes;
            for (const QByteArray &line : head.split('\n')) {
                QByteArray l = line.endsWith('\r') ? line.left(line.size() - 1) : line;
                const int c = l.indexOf(':');
                if (c < 0) continue;
                if (QString::fromUtf8(l.left(c)).trimmed().compare("Cookie", Qt::CaseInsensitive) != 0) continue;
                for (const QByteArray &pair : l.mid(c + 1).split(';')) {
                    const int eq = pair.indexOf('=');
                    if (eq <= 0) continue;
                    jar.insert(QString::fromUtf8(pair.left(eq)).trimmed(),
                               QString::fromUtf8(pair.mid(eq + 1)).trimmed());
                }
            }
        }
        while (redirectHops < kMaxRedirectHops && result.ok
               && RL::isRedirectStatus(result.parsed.statusCode)) {
            QString loc;
            for (const auto &h : result.parsed.headers)
                if (h.first.compare("Location", Qt::CaseInsensitive) == 0) { loc = h.second; break; }
            const QUrl next = RL::resolveRedirect(current, loc);
            if (next.isEmpty()) break;
            const QString nextHost = next.host();
            const bool nextInScope = m_inScope ? m_inScope(nextHost) : false;
            if (!RL::followAllowed(RL::FollowPolicy(m_followPolicy),
                                   current.host(), nextHost, nextInScope))
                break;
            if (m_followCookies) RL::mergeSetCookies(jar, result.parsed.headers);
            const int status = result.parsed.statusCode;
            const QString nextMethod  = RL::methodAfterRedirect(status, method);
            const QByteArray nextBody = RL::redirectPreservesBody(status) ? body : QByteArray();
            const QString cookieHdr   = m_followCookies ? RL::renderCookieHeader(jar) : QString();
            const QByteArray nextReq  = RL::buildFollowRequest(next, nextMethod, cookieHdr, nextBody);
            const bool nextTls  = next.scheme().compare("https", Qt::CaseInsensitive) == 0;
            const int  nextPort = next.port(nextTls ? 443 : 80);
            result  = m_client.send(nextHost, static_cast<quint16>(nextPort), nextTls, nextReq);
            current = next;
            method  = nextMethod;
            body    = nextBody;
            ++redirectHops;
        }
    }

    // Capture the round-trip time BEFORE response processing (gzip decode / status
    // formatting) so the number reflects the network, not local work. Byte length
    // is the final raw response as received (0 on a total transport failure).
    t.elapsedMs     = roundTrip.elapsed();
    t.responseBytes = result.rawResponse.size();

    if (result.ok) {
        // Unpack gzip/deflate for the response view: keep the original header
        // block verbatim (including the Content-Encoding header itself, so the
        // user can see the body WAS compressed) and swap in the decoded body
        // in place of the compressed bytes that would otherwise render as
        // binary mojibake. result.rawResponse (the wire bytes) is untouched --
        // this only changes what's displayed. No-op (falls through to the
        // fromUtf8 branch) when there was nothing to decode or decoding failed.
        const int headerEnd = result.rawResponse.indexOf("\r\n\r\n");
        if (headerEnd >= 0 && !result.parsed.decodedBody.isEmpty()) {
            const QByteArray headBlock = result.rawResponse.left(headerEnd + 4);
            t.responseText = QString::fromUtf8(headBlock) + QString::fromUtf8(result.parsed.decodedBody);
        } else {
            t.responseText = QString::fromUtf8(result.rawResponse);
        }
        t.statusLine   = QString("%1 %2 %3")
                             .arg(result.parsed.httpVersion)
                             .arg(result.parsed.statusCode)
                             .arg(result.parsed.reasonPhrase);
    } else {
        t.responseText = "[error] " + result.errorMessage;
        t.statusLine   = "error";
    }
    if (redirectHops > 0)
        t.statusLine += QString("  [followed %1 redirect%2]")
                            .arg(redirectHops).arg(redirectHops == 1 ? "" : "s");

    // Record this send in the tab's history (newest last), capped so a long
    // session can't grow it unbounded.
    {
        RepeaterHistoryEntry h;
        h.request       = t.requestText;
        h.response      = t.responseText;
        h.statusLine    = t.statusLine;
        h.sentAt        = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
        h.elapsedMs     = t.elapsedMs;
        h.responseBytes = t.responseBytes;
        t.history.append(h);
        constexpr int kMaxTabHistory = 100;
        while (t.history.size() > kMaxTabHistory) t.history.removeFirst();
    }

    m_busy = false;
    emit responseChanged();
    emit busyChanged();
    emit tabsChanged(); // status line for the strip
}

int Repeater::historyCount() const {
    return activeTab_().history.size();
}

bool Repeater::loadHistoryAt(int index) {
    auto &t = activeTab_();
    if (index < 0 || index >= t.history.size()) return false;
    const RepeaterHistoryEntry &h = t.history.at(index);
    t.requestText   = h.request;
    t.responseText  = h.response;
    t.statusLine    = h.statusLine;
    t.elapsedMs     = h.elapsedMs;
    t.responseBytes = h.responseBytes;
    emit requestTextChanged();
    emit responseChanged();
    emit tabsChanged();
    return true;
}

void Repeater::setAutoContentLength(bool on) {
    if (m_autoContentLength == on) return;
    m_autoContentLength = on;
    emit autoContentLengthChanged();
}

void Repeater::setFollowRedirects(int policy) {
    // Clamp to the valid FollowPolicy range (never..always); anything else = never.
    if (policy < RedirectLogic::FollowNever || policy > RedirectLogic::FollowAlways)
        policy = RedirectLogic::FollowNever;
    if (m_followPolicy == policy) return;
    m_followPolicy = policy;
    emit followRedirectsChanged();
}

void Repeater::setProcessCookies(bool on) {
    if (m_followCookies == on) return;
    m_followCookies = on;
    emit followRedirectsChanged();
}

QJsonObject Repeater::exportState() const {
    QJsonArray arr;
    for (const RepeaterTab &t : m_tabs) {
        arr.append(QJsonObject{
            { "name",       t.name },
            { "host",       t.host },
            { "port",       t.port },
            { "tls",        t.useTls },
            { "request",    t.requestText },
            { "notes",      t.notes },
            { "statusLine", t.statusLine },
        });
    }
    // responseText is deliberately omitted -- a response body can be megabytes and
    // project.json is a small metadata file rewritten on every change; the request
    // side is what a reopen needs, and re-sending reproduces the response.
    return QJsonObject{ { "activeTab", m_active }, { "tabs", arr } };
}

void Repeater::importState(const QJsonObject &state) {
    QList<RepeaterTab> restored;
    for (const QJsonValue &v : state.value("tabs").toArray()) {
        const QJsonObject o = v.toObject();
        RepeaterTab t;
        t.name        = o.value("name").toString();
        t.host        = o.value("host").toString();
        t.port        = o.value("port").toInt(443);
        t.useTls      = o.value("tls").toBool(true);
        t.requestText = o.value("request").toString();
        t.notes       = o.value("notes").toString();
        t.statusLine  = o.value("statusLine").toString();
        restored.append(t);
    }
    // Never leave zero tabs: a project with no saved Repeater state (or a cleared
    // one) shows a single blank tab, not the previous engagement's requests.
    if (restored.isEmpty())
        restored.append(makeBlankTab());
    m_tabs   = restored;
    m_active = qBound(0, state.value("activeTab").toInt(), m_tabs.size() - 1);
    emit tabsChanged();
    emitAllSlots();
}

int Repeater::addTab(const QString &name) {
    RepeaterTab t = makeBlankTab(name.isEmpty()
                                  ? QString("tab %1").arg(m_tabs.size() + 1)
                                  : name);
    m_tabs.append(t);
    m_active = m_tabs.size() - 1;
    emitAllSlots();
    return m_active;
}

int Repeater::addTabFromHistory(int row) {
    if (!m_model) return -1;
    const QString host = m_model->hostAt(row);
    if (host.isEmpty()) return -1;

    RepeaterTab t;
    t.host        = host;
    t.port        = m_model->portAt(row);
    t.useTls      = m_model->tlsAt(row);
    t.requestText = m_model->requestRawAt(row);
    t.name        = autoTabName(t.host, t.requestText);
    m_tabs.append(t);
    m_active = m_tabs.size() - 1;
    emitAllSlots();
    return m_active;
}

int Repeater::addTabFromHistoryById(int id) {
    // Resolve by STABLE finding id, not a window row index: after the in-memory
    // window evicts old rows, id-1 no longer equals the row index, so the
    // index-based path silently loads the WRONG row (or none). Uses the *ById
    // accessors which map id -> current index via m_firstId.
    if (!m_model) return -1;
    const QString host = m_model->hostById(id);
    if (host.isEmpty()) return -1;

    RepeaterTab t;
    t.host        = host;
    t.port        = m_model->portById(id);
    t.useTls      = m_model->tlsById(id);
    t.requestText = m_model->requestRawById(id);
    t.name        = autoTabName(t.host, t.requestText);
    m_tabs.append(t);
    m_active = m_tabs.size() - 1;
    emitAllSlots();
    return m_active;
}

bool Repeater::closeTab(int index) {
    if (index < 0 || index >= m_tabs.size()) return false;
    // Keep at least one tab around -- if the user closes the last one
    // we replace it with a blank rather than vanishing the panel.
    m_tabs.removeAt(index);
    if (m_tabs.isEmpty()) m_tabs.append(makeBlankTab());
    if (m_active >= m_tabs.size()) m_active = m_tabs.size() - 1;
    if (m_active < 0)              m_active = 0;
    emitAllSlots();
    return true;
}

bool Repeater::setActiveTab(int index) {
    if (index < 0 || index >= m_tabs.size()) return false;
    if (index == m_active) return true;
    m_active = index;
    emitAllSlots();
    return true;
}

bool Repeater::renameTab(int index, const QString &name) {
    if (index < 0 || index >= m_tabs.size()) return false;
    m_tabs[index].name = name;
    emit tabsChanged();
    return true;
}

bool Repeater::setTabNotes(int index, const QString &notes) {
    if (index < 0 || index >= m_tabs.size()) return false;
    m_tabs[index].notes = notes;
    emit tabsChanged();
    return true;
}

int Repeater::duplicateTab(int index) {
    if (index < 0 || index >= m_tabs.size()) return -1;
    RepeaterTab copy = m_tabs[index];
    copy.name = m_tabs[index].name + " (copy)";
    copy.responseText.clear();
    copy.statusLine.clear();
    m_tabs.append(copy);
    m_active = m_tabs.size() - 1;
    emitAllSlots();
    return m_active;
}

} // namespace Nullock::Core
