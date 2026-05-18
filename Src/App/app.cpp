#include "Proxy/proxy_model.hpp"
#include "cert_authority.hpp"
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

    QObject::connect(&proxy, &Nullock::Proxy::ProxyServer::responseReceived,
                     &model, &Nullock::FrontEnd::ProxyModel::addResponse);

    proxy.start();

    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty("proxyModel", &model);
    engine.rootContext()->setContextProperty("proxyServer", &proxy);
    engine.rootContext()->setContextProperty("certAuthority", &certAuthority);

    // run from project root so this relative path resolves to Nullock/Src/App/app.qml
    const QUrl url(QStringLiteral("./Src/App/app.qml"));
    engine.load(url);
    if (engine.rootObjects().isEmpty()) return -1;

    return app.exec();
}
