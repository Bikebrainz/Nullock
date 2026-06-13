#pragma once

// XML External Entity injection (CWE-611). An XML parser that resolves external
// entities lets an attacker define <!ENTITY x SYSTEM "file:///etc/passwd"> and
// read arbitrary files (or reach internal hosts -- SSRF). We send a body whose
// DOCTYPE pulls a known local file into a reflected entity and confirm by that
// file's content signature appearing in the response (absent from a benign
// baseline). The signature is remote file content, never present in the
// request, so an endpoint that merely echoes the payload can't false-positive.
//
// Scope (in-band): needs the app to reflect the parsed entity value. Misses
// (a) blind/OOB XXE with no reflection -- use the OAST blast tool; (b) parsers
// that schema-validate and reject the generic <r> root before resolving
// entities; (c) apps that only reflect a specific named field.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::XxeInjection {

struct Hit {
    QString technique;   // "file-passwd", "file-winini"
    QString target;      // "/etc/passwd" | "c:/windows/win.ini"
    QString evidence;    // the matched signature fragment
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString method = QStringLiteral("POST");
    QString basePath;
    QString contentType;                        // defaults to application/xml
    QList<QPair<QString, QString>> headers;
};

struct Result {
    bool    vulnerable = false;
    QList<Hit> hits;
    int     requestsSent = 0;
    int     baselineStatus = 0;
    QString error;
};

// POST a crafted XML body whose external entity targets a local file and flag
// any whose response carries that file's content signature.
Result test(const Request &req);

} // namespace Nullock::Core::XxeInjection
