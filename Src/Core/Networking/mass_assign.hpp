#pragma once

// Mass-assignment / auto-binding tester (OWASP API #6: Mass Assignment).
// Burp has no native scanner for this. Many frameworks bind a request
// body straight onto a model -- so a create/update endpoint that accepts
// {"name":"x"} may silently also accept {"name":"x","role":"admin",
// "is_verified":true,"balance":99999}. We probe a write request with a
// battery of privileged field names and detect the ones the server
// accepts by looking for our unique marker value echoed back in a
// SUCCESSFUL (2xx) response (the object was serialized back with our value).
//
// A control field (a junk name no model has) runs first: if the server
// echoes IT too, the endpoint reflects every field and the signal can't
// discriminate -- so we disable it rather than flag the whole list, the
// same guard the parameter miner uses.
//
// Scope / honest limits:
//  - Markers are string values, so this confirms string-typed privileged
//    fields that bind and echo (role="admin", plan="enterprise", ...).
//    Strictly-typed bool/int fields (is_admin:true, balance:99999) may be
//    rejected/coerced and so can't be confirmed by string-marker echo.
//  - Only the SUCCESS path counts: a marker echoed in a 4xx validation error
//    ("invalid value X for role") is reflection, NOT binding, so we scan only
//    2xx responses.
//  - Echo in a 2xx is strong evidence but not proof of PERSISTENCE (a server
//    could echo input it didn't store); a follow-up re-fetch would confirm.
//  - An endpoint that returns your full request body verbatim trips the
//    control and reports reflectionUsable=false -- the honest "can't tell".

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

namespace Nullock::Core::MassAssign {

struct Found {
    QString field;       // the privileged field that was accepted
    QString marker;      // the unique value we injected and saw echoed
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString method = QStringLiteral("POST");   // POST/PUT/PATCH
    QString basePath;
    QList<QPair<QString, QString>> headers;     // auth/session ride here
    QByteArray body;                            // original request body
    QString  contentType;                       // hint; sniffed if empty
};

struct Result {
    QList<Found> found;
    int     requestsSent = 0;
    int     fieldsTried = 0;
    bool    reflectionUsable = true;   // false if the endpoint echoes any field
    QString bodyKind;                  // "json" | "form"
    QString error;
};

// Inject each candidate field (with a unique marker) into the request
// body and report the ones echoed back in a 2xx response. batchSize fields
// ride per request.
Result test(const Request &req, const QStringList &fields, int batchSize = 20);

// Curated default list of privileged / sensitive field names.
QStringList defaultFields();

// ---------------------------------------------------------------------------
// Pure helpers (no network) -- split out so a regression test can exercise the
// build / classification logic against Qt6::Core alone.

// Does this body look like JSON (vs form-urlencoded)? Honors an explicit
// content-type, else sniffs the leading byte.
bool looksJson(const QByteArray &body, const QString &contentType);

// A response status that indicates the write was ACCEPTED (2xx). A marker
// echoed in any other status is reflection, not binding.
bool acceptedStatus(int status);

// The reflection control is usable only when it completed AND the junk field was
// not echoed. A control that failed at transport is inconclusive -> not usable
// (fail-closed), so the probe bails instead of reporting on a raw-echo endpoint.
bool reflectionControlUsable(bool controlOk, bool junkEchoed);

// Build the raw write request. Returns empty if method/host/path or a carried
// header carries a CR/LF (request-line / header injection guard).
QByteArray buildRequest(const Request &req, bool json, const QByteArray &body);

} // namespace Nullock::Core::MassAssign
