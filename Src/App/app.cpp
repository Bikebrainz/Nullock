#include "Proxy/proxy_model.hpp"
#include "cert_authority.hpp"
#include "intercept.hpp"
#include "project_store.hpp"
#include "proxy_server.hpp"
#include "repeater.hpp"

#include <QCoreApplication>
#include <QEventLoop>
#include <QGuiApplication>
#include <QProcess>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QTextStream>
#include <QTimer>

namespace {

// Run a curl invocation under our proxy. Uses QEventLoop so the
// surrounding main-thread Q* (QTimer, intercept controller) can keep
// processing while curl runs.
struct CurlResult {
    int     exitCode = -1;
    QByteArray stdoutBytes;
    QByteArray stderrBytes;
    bool       timedOut = false;
};

CurlResult runCurl(const QStringList &args, int timeoutMs) {
    QProcess curl;
    curl.setProgram("C:/Windows/System32/curl.exe");
    curl.setArguments(args);

    QEventLoop loop;
    QObject::connect(&curl,
        QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
        &loop, &QEventLoop::quit);

    CurlResult result;
    QTimer killer;
    killer.setSingleShot(true);
    QObject::connect(&killer, &QTimer::timeout, [&]() {
        result.timedOut = true;
        curl.kill();
        loop.quit();
    });

    curl.start();
    killer.start(timeoutMs);
    loop.exec();
    killer.stop();

    result.exitCode    = curl.exitCode();
    result.stdoutBytes = curl.readAllStandardOutput();
    result.stderrBytes = curl.readAllStandardError();
    return result;
}

void waitMs(int ms) {
    QEventLoop loop;
    QTimer::singleShot(ms, &loop, &QEventLoop::quit);
    loop.exec();
}

int runSmokeTest(Nullock::Proxy::ProxyServer        &proxy,
                 Nullock::Proxy::InterceptController &intercept,
                 Nullock::Core::Repeater            &repeater) {
    QTextStream out(stdout);
    int passed = 0, failed = 0;
    auto pass = [&](const QString &m) { out << "PASS  " << m << Qt::endl; ++passed; };
    auto fail = [&](const QString &m) { out << "FAIL  " << m << Qt::endl; ++failed; };

    // -- 1. proxy listening ---------------------------------------------------
    if (proxy.isRunning())
        pass(QString("proxy listening on 127.0.0.1:%1").arg(proxy.listeningPort()));
    else
        fail("proxy not listening");

    // All curl invocations below point at whatever port the proxy actually
    // grabbed, not a hard-coded 8080 -- Windows protected-port quirks mean
    // start() may have walked to a fallback.
    const QString proxyUrl = QString("http://127.0.0.1:%1").arg(proxy.listeningPort());

    // -- 2. intercept blocks + forward completes the request ------------------
    intercept.setEnabled(true);

    QProcess curl;
    curl.setProgram("C:/Windows/System32/curl.exe");
    curl.setArguments({ "-s", "--max-time", "20",
                        "--proxy", proxyUrl,
                        "http://httpbin.org/uuid" });

    QEventLoop curlLoop;
    QObject::connect(&curl,
        QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
        &curlLoop, &QEventLoop::quit);
    curl.start();

    bool sawPending = false;
    QTimer::singleShot(2500, [&]() {
        QObject *cur = intercept.current();
        if (cur) {
            sawPending = true;
            // Forward unmodified.
            intercept.forward(cur->property("text").toString());
        }
    });

    QTimer curlKill;
    curlKill.setSingleShot(true);
    QObject::connect(&curlKill, &QTimer::timeout, [&]() {
        curl.kill();
        curlLoop.quit();
    });
    curlKill.start(20000);
    curlLoop.exec();
    intercept.setEnabled(false);

    const QByteArray body = curl.readAllStandardOutput();
    if (sawPending && curl.exitCode() == 0 && body.contains("\"uuid\""))
        pass("intercept blocks and forward completes the request");
    else
        fail(QString("intercept forward: sawPending=%1 exit=%2 bodyLen=%3")
                 .arg(sawPending).arg(curl.exitCode()).arg(body.size()));

    // -- 3. intercept drop breaks the connection ------------------------------
    intercept.setEnabled(true);
    QProcess curl2;
    curl2.setProgram("C:/Windows/System32/curl.exe");
    curl2.setArguments({ "-s", "--max-time", "20",
                         "--proxy", proxyUrl,
                         "http://httpbin.org/uuid" });

    QEventLoop curl2Loop;
    QObject::connect(&curl2,
        QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
        &curl2Loop, &QEventLoop::quit);
    curl2.start();

    QTimer::singleShot(2500, [&]() {
        if (intercept.current()) intercept.drop();
    });

    QTimer curl2Kill;
    curl2Kill.setSingleShot(true);
    QObject::connect(&curl2Kill, &QTimer::timeout, [&]() {
        curl2.kill();
        curl2Loop.quit();
    });
    curl2Kill.start(20000);
    curl2Loop.exec();
    intercept.setEnabled(false);

    const QByteArray body2 = curl2.readAllStandardOutput();
    if (curl2.exitCode() != 0 || body2.isEmpty())
        pass("intercept drop breaks the connection");
    else
        fail("intercept drop: connection still completed normally");

    // -- 4. repeater fires a direct request and gets a real response ----------
    repeater.setHost("httpbin.org");
    repeater.setPort(80);
    repeater.setUseTls(false);
    repeater.setRequestText("GET /uuid HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n");
    repeater.send();

    if (repeater.responseText().contains("200") && repeater.responseText().contains("\"uuid\""))
        pass("repeater send returns a 200 with a real body");
    else
        fail(QString("repeater send: status=%1 bodyPreview=%2")
                 .arg(repeater.statusLine())
                 .arg(QString::fromUtf8(repeater.responseText().toUtf8().left(80))));

    // -- 5. HTTPS MITM completes via either h1 or h2 upstream ----------------
    //  httpbin.org typically negotiates h2 these days, but the test passes
    //  as long as we got a real 200 back -- the h2 counter is recorded so
    //  we can tell which path actually fired.
    const int h2Before = proxy.h2UpstreamCount();
    const auto h2Curl = runCurl({
        "-sk", "--max-time", "20",
        "--proxy", proxyUrl,
        "https://httpbin.org/uuid" }, 20000);
    const int h2After = proxy.h2UpstreamCount();
    const bool gotJson = h2Curl.stdoutBytes.contains("\"uuid\"");
    if (h2Curl.exitCode == 0 && gotJson) {
        const QString viaPath = (h2After > h2Before) ? "h2 upstream" : "h1 upstream";
        pass(QString("HTTPS MITM end-to-end (%1, counter %2 -> %3)")
                 .arg(viaPath).arg(h2Before).arg(h2After));
    } else {
        fail(QString("HTTPS MITM failed: curl exit=%1 gotJson=%2 (h2 counter %3 -> %4)")
                 .arg(h2Curl.exitCode).arg(gotJson).arg(h2Before).arg(h2After));
    }

    // -- 6. POST a body via HTTPS -- exercises the h2 data-provider path -----
    //  httpbin /post echoes the request body back inside its JSON response,
    //  so we can verify the body actually made it across.
    const auto postCurl = runCurl({
        "-sk", "--max-time", "20",
        "--proxy", proxyUrl,
        "-X", "POST",
        "-H", "Content-Type: application/json",
        "--data", "{\"smoke\":\"nullock\",\"value\":42}",
        "https://httpbin.org/post" }, 20000);
    const bool postEchoed = postCurl.stdoutBytes.contains("\"smoke\"")
                         && postCurl.stdoutBytes.contains("\"nullock\"");
    if (postCurl.exitCode == 0 && postEchoed)
        pass("HTTPS POST body round-trips (h2 data-provider)");
    else
        fail(QString("HTTPS POST failed: curl exit=%1 echoed=%2 bodyPreview=%3")
                 .arg(postCurl.exitCode).arg(postEchoed)
                 .arg(QString::fromUtf8(postCurl.stdoutBytes.left(120))));

    out << Qt::endl << "smoke test: " << passed << " passed, "
        << failed << " failed" << Qt::endl;
    return failed == 0 ? 0 : 1;
}

} // namespace

int main(int argc, char *argv[]) {
    QCoreApplication::setOrganizationName("Nullock");
    QCoreApplication::setApplicationName("Nullock");
    QGuiApplication app(argc, argv);

    const bool smokeTest = app.arguments().contains("--smoke-test");

    Nullock::Proxy::CertAuthority certAuthority;
    certAuthority.ensureCa();

    Nullock::Proxy::ProxyServer proxy;
    proxy.setCertAuthority(&certAuthority);
    // Persist the MITM bypass list next to the CA. Cert-pinned hosts stay
    // on the list across app restarts so we never re-fail their handshake.
    proxy.setBlocklistPath(certAuthority.caDir() + "/mitm_blocked.txt");

    Nullock::FrontEnd::ProxyModel model;
    Nullock::Core::ProjectStore projectStore;

    // Wire the model BEFORE we open the store so streamed history lands in
    // the table immediately.
    QObject::connect(&projectStore, &Nullock::Core::ProjectStore::entryLoaded,
                     &model, &Nullock::FrontEnd::ProxyModel::addResponse);

    projectStore.open(projectStore.defaultProjectDir());

    // Initial scope from the project file, plus live updates when the user
    // edits scope from the GUI (or any Q_INVOKABLE caller).
    proxy.setScope(projectStore.metadata().inScope,
                   projectStore.metadata().outOfScope);
    QObject::connect(&projectStore, &Nullock::Core::ProjectStore::scopeChanged,
                     &proxy, &Nullock::Proxy::ProxyServer::setScope);

    // New traffic feeds both the live model and the on-disk history.
    QObject::connect(&proxy, &Nullock::Proxy::ProxyServer::responseReceived,
                     &model, &Nullock::FrontEnd::ProxyModel::addResponse);
    QObject::connect(&proxy, &Nullock::Proxy::ProxyServer::responseReceived,
                     &projectStore, &Nullock::Core::ProjectStore::appendEntry);

    proxy.start();

    Nullock::Core::Repeater repeater(&model);

    Nullock::Proxy::InterceptController intercept;
    proxy.setInterceptController(&intercept);

    if (smokeTest) {
        // Smoke test exercises HTTPS via the h2 path -- if a previous run
        // marked one of the test hosts as MITM-blocked we'd blind-pipe and
        // never count an h2 round-trip. Reset for a clean run.
        proxy.clearMitmBlocked();
        return runSmokeTest(proxy, intercept, repeater);
    }

    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty("proxyModel", &model);
    engine.rootContext()->setContextProperty("proxyServer", &proxy);
    engine.rootContext()->setContextProperty("certAuthority", &certAuthority);
    engine.rootContext()->setContextProperty("projectStore", &projectStore);
    engine.rootContext()->setContextProperty("repeater", &repeater);
    engine.rootContext()->setContextProperty("intercept", &intercept);

    // run from project root so this relative path resolves to Nullock/Src/App/app.qml
    const QUrl url(QStringLiteral("./Src/App/app.qml"));
    engine.load(url);
    if (engine.rootObjects().isEmpty()) return -1;

    return app.exec();
}
