#include "param_miner.hpp"
#include "networking.hpp"

#include <functional>

namespace Nullock::Core::ParamMiner {

// (canaryFor, enc, buildRequest, canaryReflected, statusFlipConfirmed live in
// param_logic.cpp so the regression test can exercise them without the network.)

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
            if (canaryReflected(ctrl.parsed.body, ctrl.parsed.headers, junkCanary))
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
                if (!r.ok || r.parsed.statusCode == baseStatus) return;
                // Re-confirm before reporting: re-fetch the baseline (catch
                // drift) and re-send the single param (catch a transient flap).
                const auto reBase = send({});
                const auto r2 = send(batch);
                if (!reBase.ok || !r2.ok) return;
                if (statusFlipConfirmed(r.parsed.statusCode, reBase.parsed.statusCode,
                                        r2.parsed.statusCode, baseStatus))
                    result.found.append({ batch[0].first, "status-change", false,
                                          baseStatus, r2.parsed.statusCode });
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

        // Reflection: a candidate's canary echoed back (body OR a response
        // header) = reflected param. Skipped when the control proved the
        // target echoes any param.
        if (reflectionUsable) {
            for (int i = 0; i < names.size(); ++i) {
                if (canaryReflected(r.parsed.body, r.parsed.headers, canaries[i])) {
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
