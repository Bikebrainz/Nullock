#pragma once

// Mass-assignment / auto-binding tester (OWASP API #6: Mass Assignment).
// Burp has no native scanner for this. Many frameworks bind a request
// body straight onto a model -- so a create/update endpoint that accepts
// {"name":"x"} may silently also accept {"name":"x","role":"admin",
// "is_verified":true,"balance":99999}. We probe a write request with a
// battery of privileged field names and detect the ones the server
// accepts by looking for our unique marker value echoed back in the
// response (the object was stored with our injected field).
//
// A control field (a junk name no model has) runs first: if the server
// echoes IT too, the endpoint reflects every field and the signal can't
// discriminate -- so we disable it rather than flag the whole list, the
// same guard the parameter miner uses.
//
// Scope / honest limits: markers are string values, so this confirms
// string-typed privileged fields that bind and echo (role="admin",
// plan="enterprise", status="active", owner=...). Strictly-typed bool/int
// fields (is_admin:true, balance:99999) may be rejected or coerced and so
// can't be confirmed by marker echo -- but a type-strict 4xx on one field
// no longer masks the rest, because a rejected batch is retried one field
// at a time. An endpoint that returns your full request body verbatim
// (rather than a model serialization) trips the control and reports
// reflectionUsable=false -- the honest "can't tell" signal.

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
// body and report the ones echoed back. batchSize fields ride per request.
Result test(const Request &req, const QStringList &fields, int batchSize = 20);

// Curated default list of privileged / sensitive field names.
QStringList defaultFields();

} // namespace Nullock::Core::MassAssign
