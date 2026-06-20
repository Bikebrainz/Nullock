#include "mass_assign.hpp"
#include "networking.hpp"

#include <QJsonDocument>
#include <QJsonObject>
#include <QRandomGenerator>
#include <QUrl>

namespace Nullock::Core::MassAssign {

namespace {

QString markerFor(int idx) {
    const quint32 r = QRandomGenerator::global()->generate();
    return QString("max%1z%2").arg(idx).arg(r, 8, 16, QChar('0'));
}

// (looksJson, acceptedStatus, buildRequest live in mass_assign_logic.cpp so the
// regression test can exercise them without the network stack.)

} // namespace

Result test(const Request &req, const QStringList &fields, int batchSize) {
    Result result;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }
    if (batchSize < 1)  batchSize = 1;
    if (batchSize > 40) batchSize = 40;

    const bool json = looksJson(req.body, req.contentType);
    result.bodyKind = json ? "json" : "form";

    // Pre-parse the original body ONCE; per-batch we only insert fields.
    // A JSON body must be a top-level object -- injecting fields into an
    // array/scalar would discard the real payload and corrupt the probe.
    QJsonObject baseObj;
    QByteArray  baseForm;
    if (json) {
        const QByteArray t = req.body.trimmed();
        if (!t.isEmpty()) {
            const QJsonDocument d = QJsonDocument::fromJson(t);
            if (!d.isObject()) {
                result.error = "JSON body must be a top-level object to inject fields";
                return result;
            }
            baseObj = d.object();
        }
    } else {
        baseForm = req.body.trimmed();
    }

    auto makeBody = [&](const QList<QPair<QString, QString>> &inject) -> QByteArray {
        if (json) {
            QJsonObject o = baseObj;
            for (const auto &p : inject) o.insert(p.first, p.second);
            return QJsonDocument(o).toJson(QJsonDocument::Compact);
        }
        QByteArray out = baseForm;
        for (const auto &p : inject) {
            if (!out.isEmpty() && !out.endsWith('&')) out += '&';
            out += QUrl::toPercentEncoding(p.first) + "=" + QUrl::toPercentEncoding(p.second);
        }
        return out;
    };

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    auto send = [&](const QByteArray &body) {
        ++result.requestsSent;
        return client.send(req.host, port, req.tls, buildRequest(req, json, body));
    };

    // Markers are pure ASCII hex, so scan the raw bytes -- no need to
    // transcode the (possibly large) body to a QString per batch.
    auto scan = [&](const QByteArray &body,
                    const QList<QPair<QString, QString>> &inject) {
        for (const auto &p : inject)
            if (body.contains(p.second.toLatin1()))
                result.found.append({ p.first, p.second });
    };

    // Control: a junk field no model binds. If the server echoes its
    // marker, the endpoint reflects every field we send (a raw echo, not a
    // model serialization) -> reflection can't discriminate, so disable it
    // rather than flag the whole list. (Inherent limit: an endpoint that
    // returns your full request body verbatim can't be confirmed this way;
    // reflectionUsable=false is the honest "can't tell" signal.)
    {
        const QString junkMarker = markerFor(-2);
        const auto ctrl = send(makeBody({{ "nlk_ctl_" + markerFor(-1), junkMarker }}));
        if (ctrl.ok && ctrl.parsed.body.contains(junkMarker.toLatin1()))
            result.reflectionUsable = false;
    }
    if (!result.reflectionUsable) return result;

    // A marker only proves binding if it comes back in a SUCCESS (2xx)
    // response. A field echoed in a 4xx validation error ("invalid value X for
    // role") was rejected, not bound -- scanning that would fabricate a finding.
    auto accepted = [](const HttpClient::SendResult &x) {
        return x.ok && acceptedStatus(x.parsed.statusCode);
    };

    for (int start = 0; start < fields.size(); start += batchSize) {
        const QStringList names = fields.mid(start, batchSize);
        QList<QPair<QString, QString>> inject;
        for (int i = 0; i < names.size(); ++i)
            inject.append({ names[i], markerFor(start + i) });
        result.fieldsTried += names.size();

        const auto r = send(makeBody(inject));
        if (!r.ok) continue;
        // Type-strict servers (is_admin expects a bool, balance an int)
        // may 4xx the whole batch over one mistyped string marker, masking
        // the string-typed fields that WOULD bind. On a rejection, fall
        // back to one field per request so a single bad field can't hide
        // the rest -- but still only count a field accepted on its own 2xx.
        if (r.parsed.statusCode >= 400 && inject.size() > 1) {
            for (const auto &p : inject) {
                const auto rr = send(makeBody({ p }));
                if (accepted(rr)) scan(rr.parsed.body, { p });
            }
        } else if (accepted(r)) {
            scan(r.parsed.body, inject);
        }
    }

    return result;
}

QStringList defaultFields() {
    return QStringList{
        "role", "roles", "is_admin", "isAdmin", "admin", "is_superuser",
        "superuser", "is_staff", "staff", "permissions", "permission",
        "scopes", "scope", "grants", "privilege", "privileges",
        "is_verified", "verified", "email_verified", "is_active", "active",
        "enabled", "disabled", "status", "state", "approved", "is_approved",
        "confirmed", "is_confirmed", "balance", "credit", "credits", "wallet",
        "points", "price", "amount", "discount", "cost", "total",
        "owner", "owner_id", "user_id", "userId", "account_id", "accountId",
        "organization_id", "org_id", "tenant_id", "group_id", "team_id",
        "plan", "tier", "subscription", "subscription_tier", "level",
        "quota", "limit", "rate_limit", "is_premium", "premium", "vip",
        "created_by", "updated_by", "internal", "is_internal", "debug",
        "id", "uuid", "guid", "external_id", "ssn", "tax_id",
    };
}

} // namespace Nullock::Core::MassAssign
