#include "Proxy/proxy_model.hpp"
#include "cert_authority.hpp"
#include "intercept.hpp"
#include "project_store.hpp"
#include "proxy_server.hpp"
#include "repeater.hpp"

#include <QCoreApplication>
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>

int main(int argc, char *argv[]) {
    QCoreApplication::setOrganizationName("Nullock");
    QCoreApplication::setApplicationName("Nullock");
    QGuiApplication app(argc, argv);

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
