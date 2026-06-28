#pragma once

#include <QByteArray>
#include <QString>

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

} // namespace Nullock::Proxy::InterceptLogic
