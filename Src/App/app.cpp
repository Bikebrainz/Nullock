#include "Proxy/proxy_model.hpp"
#include "cert_authority.hpp"
#include "project_store.hpp"
#include "proxy_server.hpp"

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
    Nullock::FrontEnd::ProxyModel model;
    Nullock::Core::ProjectStore projectStore;

    // Wire the model BEFORE we open the store so streamed history lands in
    // the table immediately.
    QObject::connect(&projectStore, &Nullock::Core::ProjectStore::entryLoaded,
                     &model, &Nullock::FrontEnd::ProxyModel::addResponse);

    projectStore.open(projectStore.defaultProjectDir());

    // Apply the project's scope to the proxy. Out-of-scope hosts skip the
    // MITM path and never touch the live model or history.ndjson.
    proxy.setScope(projectStore.metadata().inScope,
                   projectStore.metadata().outOfScope);

    // New traffic feeds both the live model and the on-disk history.
    QObject::connect(&proxy, &Nullock::Proxy::ProxyServer::responseReceived,
                     &model, &Nullock::FrontEnd::ProxyModel::addResponse);
    QObject::connect(&proxy, &Nullock::Proxy::ProxyServer::responseReceived,
                     &projectStore, &Nullock::Core::ProjectStore::appendEntry);

    proxy.start();

    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty("proxyModel", &model);
    engine.rootContext()->setContextProperty("proxyServer", &proxy);
    engine.rootContext()->setContextProperty("certAuthority", &certAuthority);
    engine.rootContext()->setContextProperty("projectStore", &projectStore);

    // run from project root so this relative path resolves to Nullock/Src/App/app.qml
    const QUrl url(QStringLiteral("./Src/App/app.qml"));
    engine.load(url);
    if (engine.rootObjects().isEmpty()) return -1;

    return app.exec();
}
