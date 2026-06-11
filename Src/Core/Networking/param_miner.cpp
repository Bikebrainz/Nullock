#include "param_miner.hpp"
#include "networking.hpp"

#include <QRandomGenerator>
#include <QUrl>
#include <functional>

namespace Nullock::Core::ParamMiner {

namespace {

// A short, unique, regex-inert canary for one candidate. Collisions
// would mis-attribute reflection, so include the index + random bits.
QString canaryFor(int idx) {
    const quint32 r = QRandomGenerator::global()->generate();
    return QString("qm%1z%2").arg(idx).arg(r, 6, 16, QChar('0'));
}

// Percent-encode minimally for a query/body value.
QString enc(const QString &s) {
    return QString::fromUtf8(QUrl::toPercentEncoding(s));
}

// Build a raw HTTP request that adds `params` (name -> canary value) to
// the target, as query (GET) or x-www-form-urlencoded body (POST).
QByteArray buildRequest(const Request &req,
                        const QList<QPair<QString, QString>> &params) {
    const bool post = req.method.compare("POST", Qt::CaseInsensitive) == 0;
    QString path = req.basePath.isEmpty() ? QStringLiteral("/") : req.basePath;

    QString extra;
    for (const auto &p : params) {
        if (!extra.isEmpty()) extra += "&";
        extra += enc(p.first) + "=" + enc(p.second);
    }

    QByteArray body;
    if (post) {
        body = extra.toUtf8();
    } else if (!extra.isEmpty()) {
        path += (path.contains('?') ? "&" : "?") + extra;
    }

    QByteArray out;
    out  = req.method.toUtf8() + " " + path.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/param-miner\r\n";
    out += "Accept: */*\r\n";
    // Identity encoding: we scan the body for our canary and the HTTP
    // client doesn't inflate gzip/deflate, so a compressed response would
    // hide reflections (false clean).
    out += "Accept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    if (post) {
        out += "Content-Type: application/x-www-form-urlencoded\r\n";
        out += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    out += body;
    return out;
}

} // namespace

Result mine(const Request &req, const QStringList &candidates, int batchSize) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }
    if (batchSize < 1)  batchSize = 1;
    if (batchSize > 50) batchSize = 50;

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);

    auto send = [&](const QList<QPair<QString, QString>> &params)
                    -> HttpClient::SendResult {
        ++result.requestsSent;
        return client.send(req.host, port, req.tls, buildRequest(req, params));
    };

    // Baseline (no added params). Two samples to gauge status stability:
    // if a target's status isn't even stable without us touching it, the
    // status signal is noise and we must not trust it.
    const auto base1 = send({});
    if (!base1.ok) { result.error = "baseline request failed: " + base1.errorMessage; return result; }
    const int baseStatus = base1.parsed.statusCode;
    const auto base2 = send({});
    const bool statusStable = base2.ok && base2.parsed.statusCode == baseStatus;

    // Control probe with a junk param name no real app handles. If the
    // target reacts to *it*, the corresponding signal can't tell a real
    // param from any random one -- so disable that signal rather than
    // flag the entire wordlist. This is what stops the classic param-miner
    // false-positive flood against targets that 400/404/500 on any unknown
    // param, or echo every param value back.
    bool statusUsable     = statusStable;
    bool reflectionUsable = true;
    {
        const QString junkName   = "nlkx" + canaryFor(-1);
        const QString junkCanary = canaryFor(-2);
        const auto ctrl = send({{ junkName, junkCanary }});
        if (ctrl.ok) {
            if (ctrl.parsed.statusCode != baseStatus) statusUsable = false;
            if (QString::fromUtf8(ctrl.parsed.body).contains(junkCanary))
                reflectionUsable = false;
        }
    }
    result.statusSignalUsable     = statusUsable;
    result.reflectionSignalUsable = reflectionUsable;

    // Recursively isolate which subset of `batch` flips the status away
    // from baseline. Returns the offending single names.
    std::function<void(const QList<QPair<QString, QString>> &)> isolate =
        [&](const QList<QPair<QString, QString>> &batch) {
            if (batch.isEmpty()) return;
            if (batch.size() == 1) {
                const auto r = send(batch);
                if (r.ok && r.parsed.statusCode != baseStatus) {
                    result.found.append({ batch[0].first, "status-change", false,
                                          baseStatus, r.parsed.statusCode });
                }
                return;
            }
            const int mid = batch.size() / 2;
            const QList<QPair<QString, QString>> left  = batch.mid(0, mid);
            const QList<QPair<QString, QString>> right = batch.mid(mid);
            const auto lr = send(left);
            if (lr.ok && lr.parsed.statusCode != baseStatus) isolate(left);
            const auto rr = send(right);
            if (rr.ok && rr.parsed.statusCode != baseStatus) isolate(right);
            // If neither half alone reproduced the flip it's an interaction
            // effect or noise; we don't guess (avoids false positives).
        };

    // Walk candidates in batches.
    for (int start = 0; start < candidates.size(); start += batchSize) {
        const QStringList names = candidates.mid(start, batchSize);
        QList<QPair<QString, QString>> params;
        QStringList canaries;
        for (int i = 0; i < names.size(); ++i) {
            const QString c = canaryFor(start + i);
            params.append({ names[i], c });
            canaries.append(c);
        }
        result.candidatesTried += names.size();

        const auto r = send(params);
        if (!r.ok) continue;

        // Reflection: a candidate's canary echoed back = reflected param.
        // Skipped when the control proved the target echoes any param.
        if (reflectionUsable) {
            const QString body = QString::fromUtf8(r.parsed.body);
            for (int i = 0; i < names.size(); ++i) {
                if (body.contains(canaries[i])) {
                    result.found.append({ names[i], "reflected", true,
                                          baseStatus, r.parsed.statusCode });
                }
            }
        }

        // Status flip somewhere in this batch -> isolate the cause.
        // Skipped when baseline was unstable or the target flips on any param.
        if (statusUsable && r.parsed.statusCode != baseStatus)
            isolate(params);
    }

    return result;
}

QStringList defaultWordlist() {
    return QStringList{
        "debug","test","admin","source","redirect","callback","id","user",
        "userid","user_id","account","page","sort","order","filter","q",
        "query","search","lang","locale","format","view","mode","action",
        "type","key","token","api_key","apikey","access","access_token",
        "role","env","environment","config","cmd","exec","file","filename",
        "path","dir","url","uri","next","ref","referer","preview","draft",
        "internal","beta","feature","feature_flag","flag","override","force",
        "bypass","disable","enable","show","hide","include","exclude","fields",
        "expand","embed","with","raw","pretty","verbose","trace","log",
        "level","limit","offset","count","per_page","page_size","status",
        "state","active","deleted","archived","public","private","visible",
        "json","xml","csv","callback_url","return_url","redirect_uri","dest",
        "destination","target","host","domain","port","proxy","fetch","load",
        "render","template","theme","skin","style","color","width","height",
        "secret","password","passwd","pwd","auth","authorization","session",
        "sid","csrf","nonce","sig","signature","hash","checksum","version",
        "v","api_version","client","client_id","app","app_id","tenant","org",
        "organization","group","team","project","workspace","scope","context",
    };
}

} // namespace Nullock::Core::ParamMiner
