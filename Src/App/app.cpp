#include "Proxy/proxy_model.hpp"
#include "proxy_server.hpp"

#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>

int main(int argc, char *argv[]) {
    QGuiApplication app(argc, argv);

    Nullock::Proxy::ProxyServer proxy;
    Nullock::FrontEnd::ProxyModel model;

    QObject::connect(&proxy, &Nullock::Proxy::ProxyServer::responseReceived,
                     &model, &Nullock::FrontEnd::ProxyModel::addResponse);

    proxy.start();

    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty("proxyModel", &model);
    engine.rootContext()->setContextProperty("proxyServer", &proxy);

    // run from project root so this relative path resolves to Nullock/Src/App/app.qml
    const QUrl url(QStringLiteral("./Src/App/app.qml"));
    engine.load(url);
    if (engine.rootObjects().isEmpty()) return -1;

    return app.exec();
}
