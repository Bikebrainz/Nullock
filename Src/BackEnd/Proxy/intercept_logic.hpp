#pragma once

#include <QByteArray>
#include <QJsonArray>
#include <QString>
#include <QStringList>
#include <QVector>

// Pure resolve-the-outgoing-bytes logic for the intercept controller, split out
// of intercept.cpp so a unit test can link it against Qt6::Core alone (the rest
// of intercept.cpp pulls QObject / QSemaphore / cross-thread machinery).
namespace Nullock::Proxy::InterceptLogic {

// Decide the bytes to forward upstream after the operator resolves an
// intercepted request.
//   originalBytes - the exact bytes pend() captured: request line + headers +
//                   the RAW body. The body may be binary (file upload, gzip,
//                   protobuf, any 0x80..0xFF).
//   currentText   - the QString the GUI holds when Forward fires. It equals
//                   QString::fromUtf8(originalBytes) unless the operator edited
//                   it in the intercept editor.
//
// Why this exists: decoding the request to a QString for display and then
// re-encoding it via toUtf8() is LOSSY for any non-UTF-8 body -- each
// undecodable byte collapses to U+FFFD, so the re-encoded body differs from the
// original AND its length no longer matches the Content-Length header. On a
// PASSIVE forward (operator never touched the bytes) that silently corrupts the
// body and desyncs the upstream stream -- defeating the core promise of an
// intercepting proxy: faithful pass-through.
//
// Fix: when the operator did not change the text, forward the ORIGINAL bytes
// byte-for-byte. Only when the text was actually edited do we re-encode, because
// editing inherently routes through QString and that loss is the operator's
// explicit, visible choice -- not a silent passive bug.
//
// (Note: an EDITED forward whose Content-Length no longer matches the new body
// is left as the operator typed it. That is intentional -- a pentest proxy must
// let the operator emit a deliberately desynced request to TEST smuggling; we
// only refuse to introduce a mismatch the operator never asked for.)
QByteArray resolveForwardBytes(const QByteArray &originalBytes, const QString &currentText);

// Same resolution as resolveForwardBytes, but also reports whether the operator
// actually EDITED the message (currentText != decode(originalBytes)). The
// `edited` bit is the SINGLE source of truth for "was this touched": the
// Content-Length auto-update gate below consumes exactly this bit, so the
// verbatim-passthrough decision and the recompute decision can never drift (a
// drift would recompute CL over bytes we promised to forward untouched). The
// one-argument resolveForwardBytes() above is a thin wrapper over this that
// returns only .bytes, kept for callers/tests that don't need the flag.
struct ForwardResult {
    QByteArray bytes;
    bool       edited = false;
};
ForwardResult resolveForward(const QByteArray &originalBytes, const QString &currentText);

// Should the intercept path recompute Content-Length before forwarding?
//   dropped   - the operator dropped the message (never touch a dropped message)
//   isRequest - only REQUESTS are auto-updated. A RESPONSE's Content-Length
//               cannot be safely recomputed at this layer: a HEAD response, or a
//               204/304/1xx, legitimately carries a Content-Length with an EMPTY
//               body, and the intercept layer processing response bytes cannot
//               see the paired request method to tell a HEAD-200 apart -- so
//               recomputing would rewrite that CL to 0 and truncate the client.
//   autoCL    - the operator's "Update Content-Length" toggle (Burp default ON)
//   edited    - ForwardResult::edited; an unedited message forwards verbatim
// A pure predicate so EVERY guard is unit-testable + mutation-provable, rather
// than living as impure glue in the controller where a flipped guard passes
// every test.
bool shouldRecomputeContentLength(bool dropped, bool isRequest, bool autoCL, bool edited);

// Bring an edited request's Content-Length into line with its ACTUAL body --
// surgically, WITHOUT destroying the deliberate-desync structures a pentester
// intercepts a request to test. This is deliberately NOT
// ChainRunner::normalizeContentLength: that helper HARDENS a request against
// smuggling -- it drops Content-Length under Transfer-Encoding: chunked,
// collapses duplicate Content-Length headers, and rewrites every line terminator
// to CRLF -- which are the exact CL.TE / TE.CL / dup-CL / bare-LF probes an
// operator edits an intercepted request in order to send. Reusing it on the
// default-ON forward path would silently neutralise those probes with no signal.
// Contract instead:
//   * Transfer-Encoding: chunked present in the head, OR more than one
//     Content-Length header  -> return the bytes VERBATIM (preserve the probe).
//   * exactly one Content-Length -> replace ONLY its numeric value with the real
//     body byte length, preserving that line's terminator and the header name.
//   * no Content-Length and a non-empty body -> add ONE Content-Length header
//     (Burp-parity convenience), using the head's own line terminator.
//   * no Content-Length and an empty body -> unchanged.
// Never rewrites an unrelated line's terminator; never canonicalises a header
// name. Pure (QByteArray only) -- no dependency on the Networking library, so the
// Proxy layer stays free of a cross-library link edge.
QByteArray recomputeContentLength(const QByteArray &req);

// Hard cap on simultaneously-parked intercepted requests. Intercept blocks one
// worker thread (~1MB stack on Windows) and pins the full request bytes (auth
// headers, cookies, body) per parked request, resolvable only one-at-a-time at
// operator pace. Without a cap, a client behind the proxy (a browser opening
// many sockets, or a page firing thousands of fetch()es) floods faster than the
// operator can click, exhausting threads/memory. Matches the codebase's other
// buffer caps (kMaxHeaderBytes / kMaxChunkBytes / kMaxBufferBytes). On overflow
// the request is auto-forwarded (operator-visible passthrough) rather than
// silently exhausting the host.
inline constexpr int kMaxPendingIntercepts = 256;

// Is there room to park another intercepted request? `outstanding` is the count
// already parked: m_queue.size() + (m_current ? 1 : 0). Returns false once the
// cap is reached, signalling the caller to auto-forward instead of enqueue.
// Defensive against a negative count (treated as empty -> room available).
bool interceptQueueHasRoom(int outstanding);

// --- Intercept match rules (Burp's "Intercept Client/Server Requests" rules) ---
// A rule list decides which in-scope messages are HELD for manual editing, in
// place of the old global all-or-nothing toggle. The decision engine is a pure
// fold so it unit-tests + mutation-proves without the proxy's worker threads.

struct InterceptRule {
    bool enabled = true;
    // Combines with the running result of the rules above it, evaluated
    // left-to-right with NO precedence -- exactly like Burp's rule table.
    enum class BoolOp { Or, And };
    BoolOp op = BoolOp::Or;
    // Which field to test.
    enum class Match {
        Any,            // matches every message (a base "intercept all" rule)
        FileExtension,  // condition = comma list, e.g. "css,png,gif,js"
        Method,         // condition = comma list, e.g. "GET,HEAD"
        UrlRegex,       // condition = a regular expression over the request target
        HostGlob,       // condition = a wildcard host, e.g. "*.example.com"
        ContentType,    // condition = comma list, substring-matched, e.g. "json,xml"
        StatusCode,     // response: condition = comma list, e.g. "200,301,404"
        HasHeader       // condition = a regex over header NAMES (lowercased)
    };
    Match match = Match::UrlRegex;
    bool negate = false;         // "does NOT match"
    QString condition;
    // Which direction this rule applies to.
    enum class Dir { Request, Response, Both };
    Dir dir = Dir::Both;
};

// Fields extracted from a raw message: the sole input to the predicate, which
// keeps it pure + trivially testable. Byte parsing lives in extract*Fields below.
struct InterceptFields {
    bool        isResponse = false;
    QString     method;         // request only, upper-case
    QString     url;            // request target (path or absolute-URI)
    QString     host;
    QString     fileExtension;  // lowercased, no dot, from the URL path's last seg
    QString     contentType;    // Content-Type value, lowercased
    int         statusCode = 0; // response only
    QStringList headerNames;    // lowercased, for HasHeader
};

// Should this message be HELD for manual editing, given the rule list? Walks the
// enabled rules that apply to the message's direction and folds their per-rule
// match with And/Or, left to right (Burp semantics). With NO applicable rules the
// message is held -- interception is already gated by the global toggle + scope
// upstream, so an empty rule list means "hold everything", matching Burp.
bool interceptRulesHold(const QVector<InterceptRule> &rules, const InterceptFields &f);

// Parse the testable fields out of raw request / response bytes (pure). `host` is
// the connection's host (used when the message carries no Host header).
InterceptFields extractRequestFields(const QByteArray &requestBytes, const QString &host);
InterceptFields extractResponseFields(const QByteArray &responseBytes, const QString &host);

// JSON wire form of the rule list, shared by the control API (/api/intercept/rules)
// and project persistence (project.json "interceptRules") so the two never diverge.
// Enums serialize as stable lowercase strings. Unknown values default safely.
QJsonArray interceptRulesToJson(const QVector<InterceptRule> &rules);
QVector<InterceptRule> interceptRulesFromJson(const QJsonArray &arr);

} // namespace Nullock::Proxy::InterceptLogic
