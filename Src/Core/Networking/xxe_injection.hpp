#pragma once

// XML External Entity injection (CWE-611). An XML parser that resolves external
// entities lets an attacker define <!ENTITY x SYSTEM "file:///etc/passwd"> and
// read arbitrary files (or reach internal hosts -- SSRF). We send a body whose
// DOCTYPE pulls a known local file into a reflected entity and confirm by that
// file's content signature appearing in the response (absent from a benign
// baseline). The signature is remote file content, never present in the
// request, so an endpoint that merely echoes the payload can't false-positive.
//
// Confirmation is hardened against a disallow-doctype server whose error page
// carries a file-shaped string: alongside the benign baseline we send an
// inert-DOCTYPE control (same DOCTYPE shell, internal entity, no SYSTEM) and
// require the signature to appear in the SYSTEM response (status < 500) but in
// NEITHER the baseline NOR the inert control. Payloads cover DOCTYPE external
// entities AND XInclude (parse=text), which reads files on parsers that block
// DOCTYPE but still process XInclude.
//
// Scope (in-band): needs the app to reflect the parsed entity value. Misses
// (a) blind/OOB XXE with no reflection -- use the OAST blast tool; (b) parsers
// that schema-validate and reject the generic <r> root before resolving
// entities; (c) apps that only reflect a specific named field; (d) files with
// XML-special chars (<, &) that break raw entity expansion -- the PHP
// php://filter base64 variant for those is a follow-up.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QRegularExpression>
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

// --- Pure helpers, exposed for the unit test (no network I/O) ---------------
// The first match of `re` in the body (bounded), or "".
QString matchSig(const QRegularExpression &re, const QByteArray &body);
// Confirm a real external-entity read: signature in the SYSTEM response
// (status < 500) but absent from both the benign baseline and the inert-DOCTYPE
// control. Returns the matched signature, or "" if not confirmed.
QString confirmReadSig(const QRegularExpression &sig,
                       const QByteArray &systemBody, int systemStatus,
                       const QByteArray &baselineBody, const QByteArray &inertBody);
// Build the XML POST, CR/LF-guarding method/host/path/Content-Type (returns {}
// if any is tainted) and dropping any CR/LF-bearing carried header.
QByteArray buildRequest(const Request &req, const QByteArray &body);

} // namespace Nullock::Core::XxeInjection
