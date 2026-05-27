#include "Proxy/proxy_filter_model.hpp"
#include "Proxy/proxy_model.hpp"
#include "Proxy/site_map_model.hpp"
#include "cert_authority.hpp"
#include "intercept.hpp"
#include "intruder.hpp"
#include "project_store.hpp"
#include "proxy_server.hpp"
#include "repeater.hpp"

#include <QCoreApplication>
#include <QEventLoop>
#include <QFile>
#include <QGuiApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>
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
                 Nullock::Core::Repeater            &repeater,
                 Nullock::Core::Intruder            &intruder,
                 Nullock::Core::ProjectStore        &projectStore) {
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

    // -- 7. Intruder fires N variants and collects results -------------------
    //  Done before #6 because both hit httpbin and we want to keep the
    //  network state simple. Uses plain HTTP so we test the Intruder
    //  pipeline without depending on h2.
    intruder.setHost("httpbin.org");
    intruder.setPort(80);
    intruder.setUseTls(false);
    intruder.setRequestTemplate(
        "GET /status/§200§ HTTP/1.1\r\n"
        "Host: httpbin.org\r\n"
        "Connection: close\r\n\r\n");
    intruder.setPayloads("200\n404\n418\n500");
    intruder.start();

    // Spin a 30-second event loop waiting for Intruder to finish.
    {
        QEventLoop loop;
        QTimer ticker;
        ticker.start(200);
        QObject::connect(&ticker, &QTimer::timeout, [&]() {
            if (!intruder.running()) loop.quit();
        });
        QTimer timeout;
        timeout.setSingleShot(true);
        QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
        timeout.start(30000);
        loop.exec();
    }

    if (!intruder.running() && intruder.totalCount() == 4
        && intruder.completedCount() == 4
        && intruder.data(intruder.index(0), Nullock::Core::Intruder::StatusRole).toInt() == 200
        && intruder.data(intruder.index(1), Nullock::Core::Intruder::StatusRole).toInt() == 404
        && intruder.data(intruder.index(2), Nullock::Core::Intruder::StatusRole).toInt() == 418
        && intruder.data(intruder.index(3), Nullock::Core::Intruder::StatusRole).toInt() == 500) {
        pass("intruder fires variants and records the expected statuses");
    } else {
        const auto statusAt = [&](int row) {
            return intruder.data(intruder.index(row),
                                 Nullock::Core::Intruder::StatusRole).toInt();
        };
        fail(QString("intruder: running=%1 done=%2/%3 statuses=[%4,%5,%6,%7]")
                 .arg(intruder.running()).arg(intruder.completedCount()).arg(intruder.totalCount())
                 .arg(statusAt(0)).arg(statusAt(1)).arg(statusAt(2)).arg(statusAt(3)));
    }

    // -- 8. HAR export of the history collected so far -----------------------
    //  Sanity: a freshly-exported HAR is valid JSON, has the right shape,
    //  and the entries.length matches what we've actually accumulated.
    const QString harPath = projectStore.exportHar(QString());
    QFile harFile(harPath);
    bool harOk = false;
    int harEntries = 0;
    if (!harPath.isEmpty() && harFile.open(QIODevice::ReadOnly)) {
        const QJsonDocument doc = QJsonDocument::fromJson(harFile.readAll());
        if (doc.isObject()) {
            const QJsonObject log = doc.object().value("log").toObject();
            const QJsonArray  entries = log.value("entries").toArray();
            harEntries = entries.size();
            const QString version = log.value("version").toString();
            const QString creator = log.value("creator").toObject().value("name").toString();
            // First entry sanity: must have request.url and response.status.
            bool entriesValid = !entries.isEmpty();
            for (const QJsonValue &v : entries) {
                const QJsonObject e = v.toObject();
                if (e.value("request").toObject().value("url").toString().isEmpty()
                    || e.value("response").toObject().value("status").toInt() == 0) {
                    entriesValid = false;
                    break;
                }
            }
            harOk = (version == "1.2") && (creator == "Nullock") && entriesValid;
        }
    }
    if (harOk)
        pass(QString("HAR export at %1 (%2 entries)").arg(harPath).arg(harEntries));
    else
        fail(QString("HAR export failed: path=%1 entries=%2").arg(harPath).arg(harEntries));

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
    // Basic style honors Rectangle backgrounds on TextField/TextArea/etc.
    // Native (Windows) style refuses to be customized and floods stderr
    // with "background customization not supported" warnings every launch.
    QQuickStyle::setStyle(QStringLiteral("Basic"));
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
    Nullock::FrontEnd::ProxyFilterModel filteredModel;
    filteredModel.setSourceModel(&model);
    Nullock::FrontEnd::SiteMapModel siteMap(&model);
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
    Nullock::Core::Intruder intruder(&model);

    Nullock::Proxy::InterceptController intercept;
    proxy.setInterceptController(&intercept);

    if (smokeTest) {
        // Smoke test exercises HTTPS via the h2 path -- if a previous run
        // marked one of the test hosts as MITM-blocked we'd blind-pipe and
        // never count an h2 round-trip. Reset for a clean run.
        proxy.clearMitmBlocked();
        return runSmokeTest(proxy, intercept, repeater, intruder, projectStore);
    }

    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty("proxyModel", &model);
    engine.rootContext()->setContextProperty("historyView", &filteredModel);
    engine.rootContext()->setContextProperty("siteMap", &siteMap);
    engine.rootContext()->setContextProperty("proxyServer", &proxy);
    engine.rootContext()->setContextProperty("certAuthority", &certAuthority);
    engine.rootContext()->setContextProperty("projectStore", &projectStore);
    engine.rootContext()->setContextProperty("repeater", &repeater);
    engine.rootContext()->setContextProperty("intercept", &intercept);
    engine.rootContext()->setContextProperty("intruder", &intruder);

    // run from project root so this relative path resolves to Nullock/Src/App/app.qml
    const QUrl url(QStringLiteral("./Src/App/app.qml"));
    engine.load(url);
    if (engine.rootObjects().isEmpty()) return -1;

    return app.exec();
}
