#include "repeater.hpp"

#include "Proxy/proxy_model.hpp"

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
    t.host = h;
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
    const QByteArray bytes = normalized.toUtf8();

    const auto result = m_client.send(t.host,
                                      static_cast<quint16>(t.port),
                                      t.useTls,
                                      bytes);

    if (result.ok) {
        t.responseText = QString::fromUtf8(result.rawResponse);
        t.statusLine   = QString("%1 %2 %3")
                             .arg(result.parsed.httpVersion)
                             .arg(result.parsed.statusCode)
                             .arg(result.parsed.reasonPhrase);
    } else {
        t.responseText = "[error] " + result.errorMessage;
        t.statusLine   = "error";
    }

    m_busy = false;
    emit responseChanged();
    emit busyChanged();
    emit tabsChanged(); // status line for the strip
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
