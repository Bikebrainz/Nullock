#include "proto_pollution.hpp"
#include "networking.hpp"

#include <QRandomGenerator>
#include <QThread>
#include <QUrlQuery>

namespace Nullock::Core::ProtoPollution {

namespace {

using Proxy::HttpResponse;

// A distinctive, non-default indent width. Express's default is undefined
// (compact) in production and 2 in dev; no framework defaults to 7, so a
// response that suddenly indents top-level keys by EXACTLY 7 spaces did so
// because of the value WE injected -- that specificity is what keeps this
// free of false positives.
constexpr int kSpaces = 7;

QString randTok() {
    static const char hex[] = "0123456789abcdef";
    QString s = QStringLiteral("pp");
    for (int i = 0; i < 10; ++i)
        s += hex[QRandomGenerator::global()->bounded(16)];
    return s;
}

QString headerValue(const HttpResponse &r, const QString &name) {
    for (const auto &h : r.headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return QString();
}

// Append a unique cache-buster so an intermediary cache can't serve us a stale
// (pre- or post-pollution) copy of the observation endpoint.
QString withBuster(const QString &query) {
    // Double-underscore prefix so it is exceedingly unlikely to clobber a real
    // application parameter on the observation endpoint.
    QUrlQuery q(query);
    q.removeAllQueryItems(QStringLiteral("__nlcb"));
    q.addQueryItem(QStringLiteral("__nlcb"), randTok());
    return q.toString(QUrl::FullyEncoded);
}

QByteArray buildGet(const Request &req, const QString &path, const QString &query) {
    const QString q = withBuster(query);
    const QString target = q.isEmpty() ? path : path + "?" + q;
    QByteArray out = "GET " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/proto-pollution\r\n";
    out += "Accept: application/json, */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

QByteArray buildPollute(const Request &req, const QString &path, const QByteArray &body) {
    QByteArray out = "POST " + path.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/proto-pollution\r\n";
    out += "Accept: application/json, */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    out += "Content-Type: application/json\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Type", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
    out += "Connection: close\r\n\r\n";
    out += body;
    return out;
}

// Does the body read as a JSON object (first non-space byte is '{')?
bool looksJsonObject(const QByteArray &body) {
    for (char c : body) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        return c == '{';
    }
    return false;
}

// Is the TOP-LEVEL object indented by EXACTLY `kSpaces` spaces? With json
// spaces set, a serialiser opens the root object and immediately puts the first
// key on its own indented line: `{\n<N spaces>"`. We anchor on that opening so
// the match is structural -- it cannot be satisfied by the same byte sequence
// appearing inside a string *value* (which would have `"key":` between the `{`
// and the newline), which is the one false-positive vector for a bare run-of-
// spaces search. Pinning to exactly N spaces (a deeper level is 2*N, so the
// byte after N spaces there is a space, not the quote) detects "indented by our
// injected value" rather than "indented somehow". Both LF and CRLF are handled.
bool indentedByN(const QByteArray &body, int n) {
    const QByteArray sp(n, ' ');
    return body.indexOf(QByteArray("{\n")   + sp + "\"") >= 0
        || body.indexOf(QByteArray("{\r\n") + sp + "\"") >= 0;
}

// True when the response carries a non-identity Content-Encoding (gzip/br/...)
// whose body we therefore can't read as text. The whole probe suite assumes
// Accept-Encoding: identity is honoured; if a server compresses anyway, the
// formatting signal is unreadable and we must report inconclusive rather than
// silently mislabel a vulnerable target "not vulnerable".
bool bodyUnreadable(const HttpResponse &r) {
    const QString enc = headerValue(r, "Content-Encoding").trimmed().toLower();
    return !enc.isEmpty() && enc != "identity";
}

} // namespace

Result test(const Request &reqIn) {
    Result result;
    result.gadget = QStringLiteral("json spaces");
    if (reqIn.host.isEmpty()) { result.error = "host required"; return result; }

    Request req = reqIn;
    if (req.jsonPath.isEmpty())    req.jsonPath    = QStringLiteral("/");
    if (req.pollutePath.isEmpty()) req.pollutePath = req.jsonPath;

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    auto get = [&]() {
        ++result.requestsSent;
        return client.send(req.host, port, req.tls,
                           buildGet(req, req.jsonPath, req.jsonQuery));
    };
    auto pollute = [&](const QByteArray &body) {
        ++result.requestsSent;
        return client.send(req.host, port, req.tls,
                           buildPollute(req, req.pollutePath, body));
    };

    // 1) Baseline. The observation endpoint must return a JSON object that is
    //    currently COMPACT; otherwise this gadget can't show a clean delta.
    const auto base = get();
    if (!base.ok) { result.error = "baseline failed: " + base.errorMessage; return result; }
    result.baselineStatus = base.parsed.statusCode;
    if (bodyUnreadable(base.parsed)) {
        result.error = "observation endpoint returned a compressed ("
                       + headerValue(base.parsed, "Content-Encoding").trimmed()
                       + ") body the probe cannot read; the json-spaces gadget "
                         "needs an uncompressed JSON endpoint -- inconclusive";
        return result;
    }
    const QByteArray baseBody = base.parsed.body;
    const QString ctype = headerValue(base.parsed, "Content-Type");
    result.observedJson = looksJsonObject(baseBody)
                          || ctype.contains("json", Qt::CaseInsensitive);
    if (!result.observedJson) {
        result.error = "observation endpoint did not return a JSON object body; "
                       "point --json at an endpoint that returns JSON";
        return result;
    }
    if (indentedByN(baseBody, kSpaces)) {
        result.error = "baseline JSON is already indented by the probe width; "
                       "the json-spaces gadget is inconclusive on this endpoint";
        return result;
    }
    result.baselineCompact = true;

    // 2) Pollute Object.prototype["json spaces"] with our distinctive width.
    const QByteArray polluteBody =
        "{\"__proto__\":{\"json spaces\":" + QByteArray::number(kSpaces) + "}}";
    const auto pr = pollute(polluteBody);
    if (!pr.ok) { result.error = "pollute request failed: " + pr.errorMessage; return result; }

    // 3) Re-observe. A JSON response now indented by exactly our width is the
    //    causal proof: the formatting changed to the value we injected.
    const auto after = get();
    if (!after.ok) { result.error = "re-observe failed: " + after.errorMessage; return result; }
    result.indentedAfterPollute = indentedByN(after.parsed.body, kSpaces);

    // 4) Cleanup -- revert to compact (json spaces 0) and confirm it tracks our
    //    change back. This both leaves the target as we found it and rules out a
    //    server that merely happened to start indenting on its own. Step 2
    //    mutated server-global state, so a transient cleanup failure must NOT
    //    silently leave a shared target dirty: retry the revert a few times.
    const QByteArray cleanupBody = "{\"__proto__\":{\"json spaces\":0}}";
    for (int attempt = 0; attempt < 3 && !result.revertedAfterCleanup; ++attempt) {
        if (attempt) QThread::msleep(static_cast<unsigned long>(150 * attempt));
        const auto cr = pollute(cleanupBody);
        if (!cr.ok) continue;
        const auto reobs = get();
        result.revertedAfterCleanup = reobs.ok && !indentedByN(reobs.parsed.body, kSpaces);
    }

    // If we demonstrably polluted but could not confirm the revert, the target
    // may be left mutated. Surface that as a hard error so the endpoint reports
    // ok=false and the operator knows to clean up rather than reading a quiet
    // ok=true. (A non-vulnerable target never indents, so its cleanup -- a no-op
    // the server ignores -- always "reverts" and this never fires for it.)
    if (result.indentedAfterPollute && !result.revertedAfterCleanup)
        result.error = "WARNING: pollution succeeded but the revert could not be "
                       "confirmed after 3 attempts -- the target may be left with "
                       "Object.prototype[\"json spaces\"] set; re-run, manually POST "
                       "{\"__proto__\":{\"json spaces\":0}}, or restart the service";

    result.vulnerable = result.baselineCompact && result.indentedAfterPollute
                        && result.revertedAfterCleanup;
    if (result.vulnerable) {
        result.evidence = QStringLiteral(
            "Object.prototype[\"json spaces\"] pollution reformatted JSON responses "
            "to a %1-space indent and reverted on cleanup").arg(kSpaces);
    } else if (result.indentedAfterPollute && !result.revertedAfterCleanup) {
        result.evidence = QStringLiteral(
            "pollution likely succeeded but the revert was not confirmed; the target "
            "may be left mutated (see error)");
    } else {
        result.evidence = QStringLiteral(
            "no json-spaces gadget reaction; not vulnerable via this gadget "
            "(other prototype-pollution gadgets are not covered)");
    }
    return result;
}

} // namespace Nullock::Core::ProtoPollution
