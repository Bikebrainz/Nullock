// Regression corpus for the intercept controller's outgoing-byte resolver.
//
// An intercepting proxy must pass traffic through faithfully. The controller
// decodes each captured request to a QString for the editor and, on Forward,
// produced m_text.toUtf8(). That round-trip is LOSSY for any non-UTF-8 body
// (file upload, gzip, protobuf, raw 0x80..0xFF): each undecodable byte becomes
// U+FFFD, so the re-encoded body differs from the original AND its length no
// longer matches Content-Length -- silently corrupting the body and desyncing
// the upstream stream on a *passive* forward the operator never touched.
//
// resolveForwardBytes() fixes it: unedited -> forward the captured bytes
// verbatim; edited -> re-encode (the operator's explicit choice). This test
// first PROVES the naive round-trip corrupts (so the fix is necessary), then
// locks the corrected behaviour.
//
// Run via:  ctest -R intercept_logic -V

#include "intercept_logic.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QJsonArray>
#include <QJsonObject>
#include <QString>

#include <cstdio>

using namespace Nullock::Proxy::InterceptLogic;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}

// The naive round-trip the fix replaces -- used to prove the bug is real.
QByteArray naiveRoundTrip(const QByteArray &bytes) {
    return QString::fromUtf8(bytes).toUtf8();
}

// A request with a binary body and a matching Content-Length.
QByteArray binaryRequest(const QByteArray &body) {
    QByteArray req;
    req += "POST /upload HTTP/1.1\r\n";
    req += "Host: target.example\r\n";
    req += "Content-Type: application/octet-stream\r\n";
    req += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
    req += "\r\n";
    req += body;
    return req;
}

// Extract the integer value of the (first) Content-Length header.
int declaredContentLength(const QByteArray &req) {
    const int h = req.indexOf("Content-Length: ");
    if (h < 0) return -1;
    const int v = h + int(sizeof("Content-Length: ") - 1);
    const int eol = req.indexOf("\r\n", v);
    return req.mid(v, eol - v).trimmed().toInt();
}

// Length of the body (everything past the blank line).
int actualBodyLength(const QByteArray &req) {
    const int sep = req.indexOf("\r\n\r\n");
    if (sep < 0) return -1;
    return req.size() - (sep + 4);
}

// A response with a binary body and a matching Content-Length. Response-side
// interception (pendResponse) reuses the SAME resolveForwardBytes() as the
// request side, so the faithful-passthrough / edited-re-encode guarantees must
// hold verbatim for a status line + response headers + body too.
QByteArray binaryResponse(const QByteArray &body) {
    QByteArray resp;
    resp += "HTTP/1.1 200 OK\r\n";
    resp += "Content-Type: application/octet-stream\r\n";
    resp += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
    resp += "\r\n";
    resp += body;
    return resp;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ===== ground truth: the naive round-trip really corrupts binary =====
    // A lone 0x80 / 0xFF is not valid UTF-8 -> fromUtf8 yields U+FFFD ->
    // toUtf8 emits 3 bytes (EF BF BD). The round-trip is lossy in BOTH content
    // and length. This is the bug the resolver exists to prevent.
    {
        QByteArray bin;
        bin.append(char(0x80)).append(char(0xFF)).append(char(0x00)).append(char(0xC0));
        chk("ground-truth: naive round-trip CHANGES a binary blob", naiveRoundTrip(bin) != bin);
        chk("ground-truth: naive round-trip GROWS the byte count", naiveRoundTrip(bin).size() != bin.size());
    }

    // ===== unedited forward preserves bytes verbatim =====================
    {
        // valid-UTF-8 request, operator did not edit it.
        const QByteArray req = "GET /a HTTP/1.1\r\nHost: x\r\n\r\n";
        const QByteArray out = resolveForwardBytes(req, QString::fromUtf8(req));
        chk("unedited ascii: bytes preserved exactly", out == req);
    }
    {
        // binary body, unedited -> MUST be byte-for-byte identical.
        QByteArray body;
        for (int b = 0; b < 256; ++b) body.append(char(b));   // every byte value
        const QByteArray req = binaryRequest(body);
        const QByteArray out = resolveForwardBytes(req, QString::fromUtf8(req));
        chk("unedited binary: full 0..255 body preserved verbatim", out == req);
        chk("unedited binary: not the corrupting naive path", out == req && out != naiveRoundTrip(req));
    }
    {
        // the Content-Length invariant the bug used to break.
        QByteArray body;
        body.append(char(0x80)).append(char(0x81)).append("PNG\x89", 4).append(char(0xFF));
        const QByteArray req = binaryRequest(body);
        const QByteArray out = resolveForwardBytes(req, QString::fromUtf8(req));
        chk("unedited binary: Content-Length still matches body", declaredContentLength(out) == actualBodyLength(out));
        chk("unedited binary: naive path WOULD have broken Content-Length",
            declaredContentLength(naiveRoundTrip(req)) != actualBodyLength(naiveRoundTrip(req)));
    }
    {
        // embedded NUL in body, unedited -> preserved.
        QByteArray body("a\0b\0c", 5);
        const QByteArray req = binaryRequest(body);
        const QByteArray out = resolveForwardBytes(req, QString::fromUtf8(req));
        chk("unedited: embedded NUL body preserved", out == req);
        chk("unedited: embedded NUL output keeps full length", out.size() == req.size());
    }
    {
        // multi-byte VALID UTF-8 (cafe with U+00E9), unedited -> preserved and
        // identical to the naive path (valid UTF-8 round-trips losslessly).
        QByteArray body;
        body.append("caf").append(char(0xC3)).append(char(0xA9));   // "café"
        const QByteArray req = binaryRequest(body);
        const QByteArray out = resolveForwardBytes(req, QString::fromUtf8(req));
        chk("unedited valid-utf8: preserved", out == req);
        chk("unedited valid-utf8: matches naive (lossless here)", out == naiveRoundTrip(req));
    }

    // ===== edited forward uses the operator's text =======================
    {
        const QByteArray req = "GET /a HTTP/1.1\r\nHost: x\r\n\r\n";
        const QString edited = QString::fromUtf8("GET /b HTTP/1.1\r\nHost: x\r\nX-Edit: 1\r\n\r\n");
        const QByteArray out = resolveForwardBytes(req, edited);
        chk("edited: returns the edited text encoded", out == edited.toUtf8());
        chk("edited: differs from the original", out != req);
    }
    {
        // editing a binary-body request: the edit wins (operator's choice),
        // even though it is lossy -- we just confirm it is the edited text.
        QByteArray body; body.append(char(0x80)).append(char(0xFF));
        const QByteArray req = binaryRequest(body);
        const QString edited = QString::fromUtf8(req) + QString("X-Added: yes\r\n");
        const QByteArray out = resolveForwardBytes(req, edited);
        chk("edited binary: returns edited text's utf8", out == edited.toUtf8());
    }

    // ===== RESPONSE direction reuses the same faithful resolver ==========
    // pendResponse() serializes an upstream response and runs it through the
    // exact same resolveForwardBytes(). These lock that a response is passed
    // through byte-for-byte when the operator doesn't touch it (so we never
    // silently corrupt a gzip/binary response body or desync Content-Length)
    // and re-encoded only on an explicit edit -- e.g. flipping an auth flag or
    // injecting a test marker before the browser sees it.
    {
        // full 0..255 response body, unedited -> byte-for-byte identical.
        QByteArray body;
        for (int b = 0; b < 256; ++b) body.append(char(b));
        const QByteArray resp = binaryResponse(body);
        const QByteArray out = resolveForwardBytes(resp, QString::fromUtf8(resp));
        chk("response unedited: full 0..255 body preserved verbatim", out == resp);
        chk("response unedited: not the corrupting naive path", out == resp && out != naiveRoundTrip(resp));
        chk("response unedited: Content-Length still matches body",
            declaredContentLength(out) == actualBodyLength(out));
    }
    {
        // gzip-magic-prefixed binary response, unedited -> preserved (the common
        // real case: a compressed response the operator forwards untouched).
        QByteArray body;
        body.append(char(0x1F)).append(char(0x8B)).append(char(0x08)).append(char(0x00)).append(char(0xFF));
        const QByteArray resp = binaryResponse(body);
        const QByteArray out = resolveForwardBytes(resp, QString::fromUtf8(resp));
        chk("response unedited: gzip-magic body preserved", out == resp);
    }
    {
        // operator edits a response before it reaches the browser (flip status,
        // inject a marker header): the edited text wins, encoded to utf8.
        const QByteArray resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        const QString edited = QString::fromUtf8(
            "HTTP/1.1 403 Forbidden\r\nX-Marker: tampered\r\nContent-Length: 0\r\n\r\n");
        const QByteArray out = resolveForwardBytes(resp, edited);
        chk("response edited: returns the edited status/headers encoded", out == edited.toUtf8());
        chk("response edited: differs from the original", out != resp);
    }

    // ===== intercept queue backpressure cap =============================
    // The cap bounds simultaneously-parked intercepted requests so a flood of
    // in-scope traffic can't pin unbounded worker threads + secret-bearing
    // bytes. At/over the cap, the caller auto-forwards instead of enqueueing.
    chk("cap: empty queue has room", interceptQueueHasRoom(0));
    chk("cap: one below cap has room", interceptQueueHasRoom(kMaxPendingIntercepts - 1));
    chk("cap: exactly at cap is FULL", !interceptQueueHasRoom(kMaxPendingIntercepts));
    chk("cap: over cap is FULL", !interceptQueueHasRoom(kMaxPendingIntercepts + 1));
    chk("cap: a wildly-over count is FULL", !interceptQueueHasRoom(kMaxPendingIntercepts * 10));
    chk("cap: negative count is defensive room (not full)", interceptQueueHasRoom(-1));
    chk("cap: the cap is a sane positive bound", kMaxPendingIntercepts > 0 && kMaxPendingIntercepts <= 4096);

    // ===== degenerate inputs ============================================
    chk("empty bytes + empty text -> empty", resolveForwardBytes(QByteArray(), QString()).isEmpty());
    {
        const QByteArray req = "x";
        // empty edit string is a real (if odd) edit -> NOT equal to fromUtf8("x")
        const QByteArray out = resolveForwardBytes(req, QString());
        chk("non-empty original + empty edit -> empty (treated as edit)", out.isEmpty());
    }
    {
        // unedited single byte preserved
        const QByteArray req = "x";
        chk("unedited single byte preserved", resolveForwardBytes(req, QString::fromUtf8(req)) == req);
    }

    // ===== intercept match rules: field extraction ======================
    {
        const QByteArray req =
            "POST /api/login.json?x=1 HTTP/1.1\r\n"
            "Host: app.example.com\r\n"
            "Content-Type: application/json; charset=utf-8\r\n"
            "Authorization: Bearer t\r\n"
            "\r\n{\"u\":\"a\"}";
        const InterceptFields f = extractRequestFields(req, "conn.example");
        chk("extract req: method POST", f.method == "POST");
        chk("extract req: url has path+query", f.url == "/api/login.json?x=1");
        chk("extract req: extension json (query stripped)", f.fileExtension == "json");
        chk("extract req: content-type lowercased", f.contentType.startsWith("application/json"));
        // The connection host (from the proxy, unspoofable) wins over the Host
        // header -- a malicious Host: can't redirect a rule's host match.
        chk("extract req: connection host wins over Host header", f.host == "conn.example");
        chk("extract req: header names lowercased", f.headerNames.contains("authorization"));
        chk("extract req: not a response", !f.isResponse);
    }
    {
        // With no connection host, the Host header fills it.
        const QByteArray req = "GET / HTTP/1.1\r\nHost: fromheader.example\r\n\r\n";
        const InterceptFields f = extractRequestFields(req, QString());
        chk("extract req: empty conn host -> Host header fills it", f.host == "fromheader.example");
    }
    {
        const QByteArray resp = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<html>";
        const InterceptFields f = extractResponseFields(resp, "h");
        chk("extract resp: status 404", f.statusCode == 404);
        chk("extract resp: content-type text/html", f.contentType == "text/html");
        chk("extract resp: is a response", f.isResponse);
    }
    {
        const QByteArray req = "GET /x HTTP/1.1\r\n\r\n";
        const InterceptFields f = extractRequestFields(req, "fallback.host");
        chk("extract req: host falls back to the connection", f.host == "fallback.host");
        chk("extract req: no extension on /x", f.fileExtension.isEmpty());
    }

    // ===== intercept match rules: the fold predicate ====================
    auto reqF = [](const QString &method, const QString &url) {
        InterceptFields f;
        f.isResponse = false; f.method = method; f.url = url;
        QString p = url; const int q = p.indexOf('?'); if (q >= 0) p = p.left(q);
        const int s = p.lastIndexOf('/'); const QString seg = s >= 0 ? p.mid(s + 1) : p;
        const int d = seg.lastIndexOf('.');
        if (d >= 0 && d < seg.size() - 1) f.fileExtension = seg.mid(d + 1).toLower();
        return f;
    };
    {
        QVector<InterceptRule> none;
        chk("rules: empty list holds everything", interceptRulesHold(none, reqF("GET", "/a")));
    }
    {
        // Burp's classic default: hold unless it's a static-asset extension.
        InterceptRule r;
        r.match = InterceptRule::Match::FileExtension;
        r.condition = "css,png,gif,jpg,js,woff2,ico";
        r.negate = true;
        const QVector<InterceptRule> rules { r };
        chk("rules: dynamic .json held", interceptRulesHold(rules, reqF("GET", "/a.json")));
        chk("rules: no-ext /login held", interceptRulesHold(rules, reqF("GET", "/login")));
        chk("rules: static .png NOT held", !interceptRulesHold(rules, reqF("GET", "/logo.png")));
        chk("rules: static .css NOT held", !interceptRulesHold(rules, reqF("GET", "/a.css")));
    }
    {
        InterceptRule r; r.match = InterceptRule::Match::Method; r.condition = "POST";
        const QVector<InterceptRule> rules { r };
        chk("rules: POST held", interceptRulesHold(rules, reqF("POST", "/x")));
        chk("rules: GET not held", !interceptRulesHold(rules, reqF("GET", "/x")));
    }
    {
        // And fold: (method==POST) AND (url matches /api/).
        InterceptRule a; a.match = InterceptRule::Match::Method; a.condition = "POST";
        InterceptRule b; b.match = InterceptRule::Match::UrlRegex; b.condition = "/api/";
        b.op = InterceptRule::BoolOp::And;
        const QVector<InterceptRule> rules { a, b };
        chk("rules: POST+/api/ held", interceptRulesHold(rules, reqF("POST", "/api/x")));
        chk("rules: POST but not /api/ not held", !interceptRulesHold(rules, reqF("POST", "/other")));
        chk("rules: /api/ but GET not held", !interceptRulesHold(rules, reqF("GET", "/api/x")));
    }
    {
        // Or fold: method==POST OR method==PUT.
        InterceptRule a; a.match = InterceptRule::Match::Method; a.condition = "POST";
        InterceptRule b; b.match = InterceptRule::Match::Method; b.condition = "PUT";
        b.op = InterceptRule::BoolOp::Or;
        const QVector<InterceptRule> rules { a, b };
        chk("rules: PUT held via Or", interceptRulesHold(rules, reqF("PUT", "/x")));
        chk("rules: DELETE not held", !interceptRulesHold(rules, reqF("DELETE", "/x")));
    }
    {
        // Direction filter: a Response-only rule never affects requests.
        InterceptRule r; r.match = InterceptRule::Match::StatusCode; r.condition = "500";
        r.dir = InterceptRule::Dir::Response;
        const QVector<InterceptRule> rules { r };
        chk("rules: response-only rule ignored for a request", interceptRulesHold(rules, reqF("GET", "/x")));
        InterceptFields r500; r500.isResponse = true; r500.statusCode = 500;
        InterceptFields r200; r200.isResponse = true; r200.statusCode = 200;
        chk("rules: 500 response held", interceptRulesHold(rules, r500));
        chk("rules: 200 response not held", !interceptRulesHold(rules, r200));
    }
    {
        InterceptRule r; r.enabled = false; r.match = InterceptRule::Match::Method; r.condition = "POST";
        const QVector<InterceptRule> rules { r };
        chk("rules: disabled rule skipped -> hold everything", interceptRulesHold(rules, reqF("GET", "/x")));
    }
    {
        InterceptRule r; r.match = InterceptRule::Match::HostGlob; r.condition = "*.example.com";
        const QVector<InterceptRule> rules { r };
        InterceptFields in;  in.host = "app.example.com";
        InterceptFields out; out.host = "evil.test";
        chk("rules: hostglob in-domain held", interceptRulesHold(rules, in));
        chk("rules: hostglob out-domain not held", !interceptRulesHold(rules, out));
    }

    // ===== intercept rules: JSON round-trip (API + persistence share it) =
    {
        InterceptRule a;
        a.enabled = true;  a.op = InterceptRule::BoolOp::And;
        a.match = InterceptRule::Match::FileExtension; a.negate = true;
        a.condition = "css,png"; a.dir = InterceptRule::Dir::Request;
        InterceptRule b;
        b.enabled = false; b.op = InterceptRule::BoolOp::Or;
        b.match = InterceptRule::Match::StatusCode; b.condition = "500";
        b.dir = InterceptRule::Dir::Response;
        QVector<InterceptRule> rules; rules << a << b;
        const QVector<InterceptRule> back =
            interceptRulesFromJson(interceptRulesToJson(rules));
        bool ok = (back.size() == 2);
        if (ok) {
            ok = back[0].enabled == a.enabled && back[0].op == a.op
              && back[0].match == a.match && back[0].negate == a.negate
              && back[0].condition == a.condition && back[0].dir == a.dir
              && back[1].enabled == b.enabled && back[1].op == b.op
              && back[1].match == b.match && back[1].negate == b.negate
              && back[1].condition == b.condition && back[1].dir == b.dir;
        }
        chk("rules JSON round-trip preserves every field", ok);
        const QJsonArray bad { QJsonObject{ { "match", "bogus" } } };
        const QVector<InterceptRule> d = interceptRulesFromJson(bad);
        chk("rules JSON: unknown match -> url-regex default, enabled default true",
            d.size() == 1 && d[0].match == InterceptRule::Match::UrlRegex && d[0].enabled);
    }

    // ===== auto-update Content-Length on an EDITED intercepted request =====
    // resolveForward reports the `edited` bit -- the single source of truth the
    // recompute gate consumes, so verbatim-passthrough and recompute can't drift.
    {
        const QByteArray orig = binaryRequest("hello");
        const ForwardResult unedited = resolveForward(orig, QString::fromUtf8(orig));
        chk("resolveForward: unedited -> edited=false + verbatim bytes",
            !unedited.edited && unedited.bytes == orig);
        QString t = QString::fromUtf8(orig); t.replace("hello", "hello world");
        const ForwardResult edited = resolveForward(orig, t);
        chk("resolveForward: edited -> edited=true + re-encoded bytes",
            edited.edited && edited.bytes == t.toUtf8());
        // The one-arg wrapper still returns only the bytes (existing callers).
        chk("resolveForwardBytes wrapper matches resolveForward().bytes",
            resolveForwardBytes(orig, t) == edited.bytes);
    }

    // The gate: only a non-dropped, EDITED, REQUEST with auto-CL on recomputes.
    {
        chk("gate: all conditions -> recompute",
            shouldRecomputeContentLength(false, true, true, true));
        chk("gate: dropped -> no",   !shouldRecomputeContentLength(true,  true,  true,  true));
        chk("gate: response -> no",  !shouldRecomputeContentLength(false, false, true,  true));
        chk("gate: autoCL off -> no",!shouldRecomputeContentLength(false, true,  false, true));
        chk("gate: unedited -> no",  !shouldRecomputeContentLength(false, true,  true,  false));
    }

    // recomputeContentLength: CL follows the ACTUAL body after an edit.
    {
        QByteArray req = "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nHELLO";
        const QByteArray out = recomputeContentLength(req);
        chk("recompute: grown body -> CL == new body length",
            declaredContentLength(out) == 5 && actualBodyLength(out) == 5);
        chk("recompute: surrounding header block + body left intact",
            out.startsWith("POST /x HTTP/1.1\r\nHost: h\r\n") && out.endsWith("\r\n\r\nHELLO"));
    }
    {
        QByteArray req = "POST /x HTTP/1.1\r\nContent-Length: 99\r\n\r\nab";
        chk("recompute: shrunk body -> CL == 2",
            declaredContentLength(recomputeContentLength(req)) == 2);
    }
    {
        QByteArray req = "POST /x HTTP/1.1\r\nHost: h\r\n\r\nbody!";
        const QByteArray out = recomputeContentLength(req);
        chk("recompute: absent CL + non-empty body -> exactly one CL added",
            declaredContentLength(out) == 5 && out.count("Content-Length:") == 1);
    }
    {
        QByteArray req = "GET /x HTTP/1.1\r\nHost: h\r\n\r\n";
        chk("recompute: absent CL + empty body -> unchanged",
            recomputeContentLength(req) == req);
    }
    // Deliberate-desync PRESERVATION: chunked + duplicate-CL forward VERBATIM,
    // so an intercepted smuggling probe survives even with auto-CL ON.
    {
        QByteArray req = "POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n"
                         "Content-Length: 3\r\n\r\n5\r\nHELLO\r\n0\r\n\r\n";
        chk("recompute: Transfer-Encoding chunked -> verbatim (CL not dropped, not changed)",
            recomputeContentLength(req) == req);
    }
    {
        QByteArray req = "POST /x HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 99\r\n\r\nHELLO";
        chk("recompute: duplicate Content-Length -> verbatim (not collapsed)",
            recomputeContentLength(req) == req);
    }
    // Terminator fidelity: a bare-LF single-CL head stays bare-LF; only the value moves.
    {
        QByteArray req = "POST /x HTTP/1.1\nContent-Length: 2\n\nHELLO";
        chk("recompute: bare-LF head -> CL value updated, terminators preserved",
            recomputeContentLength(req) == QByteArray("POST /x HTTP/1.1\nContent-Length: 5\n\nHELLO"));
    }
    // The operator's header-NAME bytes are preserved; only the value is normalized.
    {
        QByteArray req = "POST /x HTTP/1.1\r\ncontent-length:0\r\n\r\nHELLO";
        const QByteArray out = recomputeContentLength(req);
        chk("recompute: original header name kept, value normalized",
            out.contains("content-length: 5\r\n") && actualBodyLength(out) == 5);
    }

    std::fprintf(stderr, "intercept_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
