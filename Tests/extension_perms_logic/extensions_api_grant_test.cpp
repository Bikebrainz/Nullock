// Does the "modify-responses" grant ACTUALLY hold, and are binary bodies left
// alone? Drives the real ExtensionsApi + QJSEngine against real extension files.
//
// Two shipped security fixes rode on hand-tracing alone until this existed,
// because a test target linking APIs could not LINK (APIs pulled Networking,
// whose shared moc drags Intruder/Repeater -> ProxyModel -> FrontEndGUI). That
// dependency is gone -- APIs now talks to Core::IFindingSink, header-only -- so
// the two fixes finally have coverage:
//
//   119bada  the grant gate read only the handler's RETURN value, but every
//            handler was passed the SAME QJSValue, which is a REFERENCE. An
//            ungranted extension just assigned to its argument
//            (`function (e) { e.bodyText = "x"; }`) and the mutation reached the
//            wire. The pure ExtensionPerms tests cannot see this: the permission
//            DECISION was always right, the ENFORCEMENT leaked.
//   b10dec0  applyBack rewrote resp.body unconditionally, so a GRANTED
//            extension that merely READ the body still round-tripped it through
//            a QString -- corrupting every binary response.
//
// QStandardPaths test mode is enabled BEFORE constructing ExtensionsApi, so
// extensionsDir() resolves into a throwaway sandbox and this never touches the
// user's real extensions directory.
//
// Run via:  ctest -R extensions_api_grant -V

#include "extensions_api.hpp"

#include <QCoreApplication>
#include <QDir>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QStandardPaths>
#include <QTextStream>
#include <QThread>
#include <QTimer>

#include <cstdio>
#include <functional>

using Nullock::Core::ExtensionsApi;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}

void clearDir(const QString &dir) {
    for (const QFileInfo &fi : QDir(dir).entryInfoList({ "*.js" }, QDir::Files))
        QFile::remove(fi.absoluteFilePath());
}

bool writeScript(const QString &dir, const QString &name, const QString &body) {
    QFile f(dir + "/" + name);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
    QTextStream ts(&f);
    ts << body;
    return true;
}

Nullock::Proxy::HttpRequest makeReq() {
    Nullock::Proxy::HttpRequest r;
    r.method = QStringLiteral("GET");
    r.host   = QStringLiteral("target.example");
    r.port   = 80;
    r.path   = QStringLiteral("/");
    return r;
}

Nullock::Proxy::HttpResponse makeResp(const QByteArray &body = QByteArrayLiteral("original-body")) {
    Nullock::Proxy::HttpResponse r;
    r.statusCode   = 200;
    r.reasonPhrase = QStringLiteral("OK");
    r.body         = body;
    return r;
}

// A PNG header plus bytes that are NOT valid UTF-8 (0xC3 0x28 is an invalid
// two-byte sequence, 0xFF/0xFE never appear in UTF-8). fromUtf8() turns these
// into U+FFFD and toUtf8() gives back DIFFERENT bytes, which is exactly the
// corruption b10dec0 fixed.
QByteArray binaryBody() {
    return QByteArrayLiteral("\x89PNG\r\n\x1a\n") + QByteArray("\xC3\x28\xFF\xFE\x00\x01", 6);
}

// Run fn on a throwaway worker thread while the MAIN thread spins an event
// loop, which is what lets a BlockingQueuedConnection back into the main thread
// actually complete. Returns false if the worker did not finish (watchdog), so
// a deadlock surfaces as a failed assertion instead of a hung CI job.
//
// QThread::create() returns an UNPARENTED QThread -- we own and delete it.
bool runOnWorkerThread(const std::function<void()> &fn) {
    QThread *t = QThread::create(fn);
    QEventLoop loop;
    QObject::connect(t, &QThread::finished, &loop, &QEventLoop::quit);
    QTimer::singleShot(30000, &loop, &QEventLoop::quit);
    t->start();
    loop.exec();
    const bool finished = t->wait(5000);
    if (finished) delete t;   // leak it rather than destroy a running QThread
    return finished;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("NullockTest"));
    QCoreApplication::setApplicationName(QStringLiteral("NullockExtGrantTest"));
    // Sandbox AppDataLocation BEFORE ExtensionsApi resolves extensionsDir().
    QStandardPaths::setTestModeEnabled(true);

    ExtensionsApi api;
    const QString dir = api.extensionsDir();
    QDir().mkpath(dir);
    chk("fixture: the extensions dir is sandboxed, not the real one",
        !dir.isEmpty() && dir.contains(QStringLiteral("NullockTest")));

    // ===== THE BYPASS: an ungranted handler mutates its ARGUMENT ==========
    {
        clearDir(dir);
        chk("fixture: ungranted script written", writeScript(dir, "ungranted.js",
            QStringLiteral(
                "nullock.onResponse(function (e) {\n"
                "  e.bodyText = 'INJECTED';\n"
                "  e.status = 418;\n"
                "  e.reasonPhrase = 'Teapot';\n"
                "});\n")));
        api.reload();
        chk("ungranted: the observe-only handler still LOADS (not refused)",
            api.loadedCount() == 1);

        const auto out = api.doMutateResponse(makeReq(), makeResp());
        chk("BYPASS: an ungranted in-place body edit is discarded",
            out.body == QByteArrayLiteral("original-body"));
        chk("BYPASS: an ungranted in-place status edit is discarded",
            out.statusCode == 200);
        chk("BYPASS: an ungranted in-place reason-phrase edit is discarded",
            out.reasonPhrase == QStringLiteral("OK"));
    }
    {
        clearDir(dir);
        writeScript(dir, "ungranted_return.js", QStringLiteral(
            "nullock.onResponse(function (e) { e.bodyText = 'RETURNED'; return e; });\n"));
        api.reload();
        const auto out = api.doMutateResponse(makeReq(), makeResp());
        chk("ungranted: a RETURNED object is denied too (the original gate)",
            out.body == QByteArrayLiteral("original-body"));
    }

    // ===== NOT over-broad: a GRANTED extension still mutates ==============
    // Without these the fix could have silently disabled the whole feature.
    {
        clearDir(dir);
        writeScript(dir, "granted_inplace.js", QStringLiteral(
            "// nullock:permissions modify-responses\n"
            "nullock.onResponse(function (e) { e.bodyText = 'GRANTED-INPLACE'; });\n"));
        api.reload();
        const auto out = api.doMutateResponse(makeReq(), makeResp());
        chk("granted: an in-place edit IS applied",
            out.body == QByteArrayLiteral("GRANTED-INPLACE"));
    }
    {
        clearDir(dir);
        writeScript(dir, "granted_return.js", QStringLiteral(
            "// nullock:permissions modify-responses\n"
            "nullock.onResponse(function (e) { e.bodyText = 'GRANTED-RETURN'; return e; });\n"));
        api.reload();
        const auto out = api.doMutateResponse(makeReq(), makeResp());
        chk("granted: a returned object IS applied",
            out.body == QByteArrayLiteral("GRANTED-RETURN"));
    }

    // ===== b10dec0: a GRANTED OBSERVER must not corrupt a binary body =====
    {
        clearDir(dir);
        writeScript(dir, "granted_observer.js", QStringLiteral(
            "// nullock:permissions modify-responses\n"
            "nullock.onResponse(function (e) { var n = e.bodyText.length; });\n"));
        api.reload();
        const QByteArray bin = binaryBody();
        const auto out = api.doMutateResponse(makeReq(), makeResp(bin));
        chk("binary: a granted handler that only READS leaves the bytes intact",
            out.body == bin);
        chk("binary: no U+FFFD replacement bytes leaked into the body",
            !out.body.contains("\xEF\xBF\xBD"));
    }
    {
        // An ungranted observer must be safe too, by a different route (its whole
        // copy is discarded rather than the body being compared).
        clearDir(dir);
        writeScript(dir, "ungranted_observer.js", QStringLiteral(
            "nullock.onResponse(function (e) { var n = e.bodyText.length; });\n"));
        api.reload();
        const QByteArray bin = binaryBody();
        chk("binary: an UNGRANTED observer also leaves the bytes intact",
            api.doMutateResponse(makeReq(), makeResp(bin)).body == bin);
    }

    // ===== a throwing handler is skipped, not fatal =======================
    {
        clearDir(dir);
        writeScript(dir, "thrower.js", QStringLiteral(
            "// nullock:permissions modify-responses\n"
            "nullock.onResponse(function (e) { throw new Error('boom'); });\n"));
        api.reload();
        const auto out = api.doMutateResponse(makeReq(), makeResp());
        chk("a throwing handler leaves the response untouched",
            out.body == QByteArrayLiteral("original-body") && out.statusCode == 200);
    }

    // ===== the status clamp / reason-phrase CR-LF guard still hold ========
    // 119bada moved these inside the loop, so re-pin them at the new call site.
    {
        clearDir(dir);
        writeScript(dir, "granted_bad.js", QStringLiteral(
            "// nullock:permissions modify-responses\n"
            "nullock.onResponse(function (e) {\n"
            "  e.status = 9999;\n"
            "  e.reasonPhrase = 'bad\\r\\nX-Injected: 1';\n"
            "});\n"));
        api.reload();
        const auto out = api.doMutateResponse(makeReq(), makeResp());
        chk("granted: an out-of-range status is clamped away", out.statusCode == 200);
        chk("granted: a CR/LF reason phrase is rejected (no status-line split)",
            out.reasonPhrase == QStringLiteral("OK"));
    }

    // ===== onRequest is gated at REGISTRATION, not per call ===============
    // The sibling strategy: an ungranted onRequest handler is never registered.
    {
        clearDir(dir);
        writeScript(dir, "ungranted_req.js", QStringLiteral(
            "nullock.onRequest(function (e) { e.path = '/PWNED'; return e; });\n"));
        api.reload();
        auto req = makeReq();
        chk("onRequest: an ungranted handler cannot touch the request",
            api.doMutateRequest(req).path == QStringLiteral("/"));
    }
    {
        clearDir(dir);
        writeScript(dir, "granted_req.js", QStringLiteral(
            "// nullock:permissions modify-requests\n"
            "nullock.onRequest(function (e) { e.path = '/rewritten'; return e; });\n"));
        api.reload();
        chk("onRequest: a granted handler CAN rewrite the path",
            api.doMutateRequest(makeReq()).path == QStringLiteral("/rewritten"));
    }

    // ===== the CROSS-THREAD path: worker -> BlockingQueuedConnection ======
    // Everything above calls doMutate* directly on the main thread. In the real
    // proxy the caller is a per-client worker thread entering through
    // applyRequestMutation/applyResponseMutation, and that entry point was
    // never exercised by any test.
    //
    // Its early-out used to read the handler QLists on the WORKER thread --
    // before the very thread hop that exists to make those lists safe to touch,
    // and while reload() could be clearing and re-appending them on the owner
    // thread. It now reads std::atomic<bool> mirrors that refreshHandlerFlags()
    // republishes at every registration and clear site.
    //
    // WHAT THIS DOES NOT DO: it does not try to catch the interleaving. A data
    // race is not deterministically observable, so swapping the atomic read
    // back for the QList read does NOT fail these cases -- they are not a lock
    // on the race itself, and are not labelled as one.
    //
    // WHAT IT DOES LOCK: the mirrors' correctness. If a registration site stops
    // calling refreshHandlerFlags(), the flag stays false, every worker call
    // early-outs, and EVERY extension is silently skipped for EVERY proxied
    // message -- a total feature outage with no error anywhere. That is the
    // failure mode this fix introduces, and it is deterministic. The reverse
    // staleness (a flag left true after a clear) is harmless by design, because
    // doMutate* re-checks the real list once it is on the owner thread.
    {
        clearDir(dir);
        writeScript(dir, "granted_xthread.js", QStringLiteral(
            "// nullock:permissions modify-responses\n"
            "nullock.onResponse(function (e) { e.bodyText = 'XTHREAD'; });\n"));
        api.reload();
        Nullock::Proxy::HttpResponse out;
        const bool done = runOnWorkerThread([&] {
            out = api.applyResponseMutation(makeReq(), makeResp());
        });
        chk("xthread: the worker response call completed (no deadlock)", done);
        chk("MIRROR: a registered response handler is visible to a worker's early-out",
            out.body == QByteArrayLiteral("XTHREAD"));
    }
    {
        clearDir(dir);
        writeScript(dir, "granted_req_xthread.js", QStringLiteral(
            "// nullock:permissions modify-requests\n"
            "nullock.onRequest(function (e) { e.path = '/xthread'; return e; });\n"));
        api.reload();
        Nullock::Proxy::HttpRequest out;
        const bool done = runOnWorkerThread([&] {
            out = api.applyRequestMutation(makeReq());
        });
        chk("xthread: the worker request call completed (no deadlock)", done);
        chk("MIRROR: a registered request handler is visible to a worker's early-out",
            out.path == QStringLiteral("/xthread"));
    }
    {
        // Zero handlers: the worker must hand the response straight back.
        // NOT discriminating -- it passes with a stale-true flag too, because
        // the owner-thread re-check catches it. Kept to pin the harmless
        // direction of the asymmetry, and to prove the no-handler worker path
        // does not deadlock.
        clearDir(dir);
        api.reload();
        chk("fixture: no handlers loaded", api.loadedCount() == 0);
        Nullock::Proxy::HttpResponse out;
        const bool done = runOnWorkerThread([&] {
            out = api.applyResponseMutation(makeReq(), makeResp());
        });
        chk("xthread: with zero handlers the worker returns the response untouched",
            done && out.body == QByteArrayLiteral("original-body"));
    }

    clearDir(dir);
    std::fprintf(stderr, "extensions_api_grant_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
