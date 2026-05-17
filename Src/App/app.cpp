#include <QGuiApplication>
#include <QQmlApplicationEngine>

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);
    
    // note: the program is run from the project rooot, so the app.qml filepath is Nullock/Src/App/app.qml
    QQmlApplicationEngine engine;
    const QUrl url(QStringLiteral("./Src/App/app.qml"));
    engine.load(url);

    if (engine.rootObjects().isEmpty())
        return -1;

    return app.exec();
}
