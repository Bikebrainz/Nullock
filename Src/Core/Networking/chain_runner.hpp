#pragma once

// Repeater chains -- multi-step request sequences with variable passing.
//
// Burp's Repeater fires one request at a time; chaining auth -> action
// means copy-pasting tokens by hand or wiring session-handling macros.
// A chain runner makes the common case first-class: define an ordered
// list of requests, extract values from each response (JSON path /
// header / cookie / regex / status), and substitute them as {{var}}
// into later requests. One call runs the whole sequence and reports
// every step. Postman/Hoppscotch have this; Burp doesn't, natively.
//
// This is the headless engine. The control server exposes it at
// POST /api/chain/run and the CLI wraps it as `nullock chain <file>`.

#include "proxy_server.hpp"

#include <QByteArray>
#include <QHash>
#include <QJsonObject>
#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::ChainRunner {

struct Extract {
    QString var;                 // bag key to store the value under
    enum From { Header, Cookie, Json, Regex, Status } from = Header;
    QString key;                 // header/cookie name, dotted json path, or
                                 // regex (first capture group). Unused for Status.
};

struct Step {
    QString        name;
    QString        host;
    int            port = 443;
    bool           tls  = true;
    QByteArray     request;      // raw HTTP/1.1 request, may contain {{var}}
    QList<Extract> extracts;
};

struct StepResult {
    QString                name;
    bool                   ok = false;
    int                    status = 0;
    qint64                 ms = 0;
    int                    requestSize = 0;
    int                    responseSize = 0;
    QString                error;
    QHash<QString, QString> extracted;   // vars pulled from THIS step
    QByteArray             responsePreview;  // first 2 KiB of the response
};

struct Result {
    QList<StepResult>       steps;
    QHash<QString, QString> vars;         // final accumulated bag
};

// Runs steps sequentially, threading the variable bag forward. Before
// each step, {{var}} placeholders in its request bytes (and host) are
// replaced from the bag, and Content-Length is recomputed so expanded
// tokens don't desync the body length. A step whose request fails to
// send records the error; by default the chain stops there, unless
// continueOnError is set.
Result run(const QList<Step> &steps, bool continueOnError = false);

// --- Pure request/response-mutation helpers, exposed for the unit test (no I/O;
//     in chain_runner_logic.cpp, links Qt6::Core alone -- extractOne()/run()'s
//     HttpClient work stays in chain_runner.cpp).
//   findHeader / findCookieValue -- case-insensitive header / cookie lookup.
//   jsonPathGet           -- dotted/$ JSONPath get; exact integer text preserved.
//   sanitizeExtractedValue-- strip CR/LF/C0 from a target-derived value before it
//                            is substituted (kills the header-injection / request-
//                            split / CL-desync smuggling primitive).
//   substituteStr         -- {{var}} expansion over TEXT (no re-scan of inserted).
//   substituteBytes       -- {{var}} expansion over RAW request bytes: preserves a
//                            binary body / 0x80-0xFF bytes (a fromUtf8/toUtf8 round
//                            trip would replace them with U+FFFD and corrupt the
//                            request put on the wire); values spliced in as UTF-8.
//   normalizeContentLength-- recompute Content-Length; reconcile Transfer-Encoding
//                            (chunked drops CL) and collapse duplicate CL headers;
//                            boundary detection tolerant of bare-LF framing.
QString    findHeader(const QList<QPair<QString, QString>> &headers, const QString &name);
QString    findCookieValue(const QString &raw, const QString &name);
QString    jsonPathGet(const QByteArray &body, const QString &path);
QString    sanitizeExtractedValue(const QString &v);
QString    substituteStr(const QString &in, const QHash<QString, QString> &vars);
QByteArray substituteBytes(const QByteArray &in, const QHash<QString, QString> &vars);
QByteArray normalizeContentLength(const QByteArray &req);

// --- Macro recorder ---------------------------------------------------------
// Build one replayable chain STEP (the /api/chain/run JSON shape:
// { name, host, port, tls, request, extract:[] }) from a captured raw request.
// The step name is derived from the request line ("METHOD path", query stripped);
// extract[] starts empty -- the operator wires value-passing after recording.
// Pure: the control server reads the selected history rows, serializes each, and
// calls this to assemble the macro that POSTs straight back to /api/chain/run.
QJsonObject buildChainStep(const QByteArray &rawRequest, const QString &host,
                           int port, bool tls);

} // namespace Nullock::Core::ChainRunner
