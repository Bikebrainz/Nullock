#include "repeater.hpp"

#include "Proxy/proxy_model.hpp"

namespace Nullock::Core {

Repeater::Repeater(Nullock::FrontEnd::ProxyModel *historyModel, QObject *parent)
    : QObject(parent), m_model(historyModel) {}

void Repeater::setHost(const QString &h) {
    if (h == m_host) return;
    m_host = h;
    emit targetChanged();
}
void Repeater::setPort(int p) {
    if (p == m_port) return;
    m_port = p;
    emit targetChanged();
}
void Repeater::setUseTls(bool tls) {
    if (tls == m_useTls) return;
    m_useTls = tls;
    if (m_port == 80 && m_useTls)        m_port = 443;
    else if (m_port == 443 && !m_useTls) m_port = 80;
    emit targetChanged();
}
void Repeater::setRequestText(const QString &t) {
    if (t == m_requestText) return;
    m_requestText = t;
    emit requestTextChanged();
}

void Repeater::loadFromHistory(int row) {
    if (!m_model) return;
    const QString host = m_model->hostAt(row);
    if (host.isEmpty()) return;

    m_host    = host;
    m_port    = m_model->portAt(row);
    m_useTls  = m_model->tlsAt(row);
    m_requestText = m_model->requestRawAt(row);

    emit targetChanged();
    emit requestTextChanged();
}

void Repeater::clear() {
    m_requestText.clear();
    m_responseText.clear();
    m_statusLine.clear();
    emit requestTextChanged();
    emit responseChanged();
}

void Repeater::send() {
    if (m_busy || m_host.isEmpty() || m_requestText.isEmpty()) return;

    m_busy = true;
    emit busyChanged();

    // Normalize line endings to CRLF as the wire format expects.
    QString normalized = m_requestText;
    normalized.replace("\r\n", "\n");
    normalized.replace("\n", "\r\n");
    // Make sure we end with a blank line before any body.
    if (!normalized.contains("\r\n\r\n"))
        normalized += "\r\n\r\n";
    const QByteArray bytes = normalized.toUtf8();

    const auto result = m_client.send(m_host,
                                      static_cast<quint16>(m_port),
                                      m_useTls,
                                      bytes);

    if (result.ok) {
        m_responseText = QString::fromUtf8(result.rawResponse);
        m_statusLine   = QString("%1 %2 %3")
                             .arg(result.parsed.httpVersion)
                             .arg(result.parsed.statusCode)
                             .arg(result.parsed.reasonPhrase);
    } else {
        m_responseText = "[error] " + result.errorMessage;
        m_statusLine   = "error";
    }

    m_busy = false;
    emit responseChanged();
    emit busyChanged();
}

} // namespace Nullock::Core
