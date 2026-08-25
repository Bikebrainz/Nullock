#pragma once

// HTTP method enumeration (read-only). Reads the `Allow` header to see which
// methods the server advertises and flags the dangerous ones -- write methods
// (PUT/DELETE/PATCH), WebDAV (PROPFIND/MKCOL/COPY/MOVE/LOCK), and TRACE.
//
// Allow is harvested from TWO sources and merged, because relying on OPTIONS
// alone produces false negatives: many servers omit Allow on OPTIONS but DO
// return it on a 405 Method Not Allowed, so a deliberately-bogus method is sent
// and its Allow folded in. The probes are decoupled -- a proxy can block OPTIONS
// while the methods themselves work, so a failed/empty OPTIONS does not abort
// the 405 harvest or the TRACE family.
//
// Cross-Site Tracing is confirmed with non-mutating echo probes: TRACE, IIS's
// TRACK alias, and a TRACE carrying `Max-Forwards: 0` (which surfaces a proxy
// that echoes on the hop). Deliberately does NOT actively PUT/DELETE -- that
// would modify server state; advertised write methods are reported, and the
// operator can confirm intrusively if authorized.

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

namespace Nullock::Core::MethodAudit {

struct Finding { QString kind; QString severity; QString detail; };

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString basePath;
    QString query;
    QList<QPair<QString, QString>> headers;
};

struct Result {
    int         optionsStatus = 0;
    QStringList allowed;          // methods from the Allow header
    bool        traceEnabled = false;
    QList<Finding> findings;
    QString     error;
};

// Send OPTIONS (+ a TRACE echo probe) and report dangerous advertised methods.
Result audit(const Request &req);

// --- Pure helpers, exposed for the unit test (no network I/O; in method_audit_logic.cpp) ---
//   buildReq            -- render a request, stripping CR/LF from method/host/path/query.
//   parseAllow          -- split an Allow value into a deduped, upper-cased list.
//   mergeAllow          -- fold a second Allow value (e.g. harvested from a 405)
//                          into an already-parsed list, deduped.
//   dangerousWriteMethods / dangerousWebdavMethods -- the dangerous subset of an allowed list.
//   traceEchoed         -- did a body echo our request for the given verb (XST)?
//                          The verb token defaults to TRACE; pass "TRACK" for the
//                          IIS alias.
QByteArray buildReq(const Request &req, const QString &method);
QStringList parseAllow(const QString &allowHeader);
QStringList mergeAllow(const QStringList &existing, const QString &allowHeader);
QStringList dangerousWriteMethods(const QStringList &allowed);
QStringList dangerousWebdavMethods(const QStringList &allowed);
bool traceEchoed(const QString &body, const QString &method = QStringLiteral("TRACE"));

// Pure verdict: given the merged Allow list and the three XST echo results,
// produce the findings audit() emits (kind + severity + detail), in the order
// dangerous-write, webdav, trace, track. Isolated from the network path so the
// which-input-yields-which-finding-KIND mapping is unit-testable (audit() only
// harvests Allow / runs the echo probes, then calls this).
QList<Finding> classifyMethods(const QStringList &allowed,
                               bool traceEcho, bool maxFwdEcho, bool trackEcho);

} // namespace Nullock::Core::MethodAudit
