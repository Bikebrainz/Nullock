#include "themes_manager.hpp"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QStandardPaths>

namespace Nullock::FrontEnd {

ThemesManager::ThemesManager(QObject *parent) : QObject(parent), m_current("cyber") {
    loadBuiltins();
    loadUserThemes();
}

QStringList ThemesManager::availableThemes() const {
    QStringList names = m_themes.keys();
    names.sort();
    return names;
}

void ThemesManager::setCurrentTheme(const QString &name) {
    if (name == m_current) return;
    if (!m_themes.contains(name)) return;
    m_current = name;
    emit themeChanged();
}

QString ThemesManager::themesDir() const {
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
           + "/themes";
}

bool ThemesManager::reload() {
    const QString prev = m_current;
    m_themes.clear();
    loadBuiltins();
    loadUserThemes();
    if (!m_themes.contains(prev)) m_current = "retro";
    emit themesChanged();
    emit themeChanged();
    return true;
}

QColor ThemesManager::color(const QString &key, const char *fallbackHex) const {
    const auto it = m_themes.constFind(m_current);
    if (it != m_themes.constEnd()) {
        const auto cit = it.value().colors.constFind(key);
        if (cit != it.value().colors.constEnd()) return cit.value();
    }
    return QColor(fallbackHex);
}

void ThemesManager::loadBuiltins() {
    Theme retro;
    retro.name = "retro";
    retro.colors = {
        { "accent",    QColor("#ff8c1a") },
        { "text",      QColor("#80f0c0") },
        { "dim",       QColor("#5a5a5a") },
        { "rowAlt",    QColor("#141414") },
        { "rowEven",   QColor("#1c1c1c") },
        { "rowSelect", QColor("#3a2010") },
        { "pane",      QColor("#0f0f0f") },
        { "line",      QColor("#222222") },
        { "bg",        QColor("#0a0a0a") },
    };
    m_themes.insert(retro.name, retro);

    Theme mono;
    mono.name = "mono";
    mono.colors = {
        { "accent",    QColor("#e0e0e0") },
        { "text",      QColor("#bdbdbd") },
        { "dim",       QColor("#666666") },
        { "rowAlt",    QColor("#141414") },
        { "rowEven",   QColor("#1c1c1c") },
        { "rowSelect", QColor("#2a2a2a") },
        { "pane",      QColor("#0e0e0e") },
        { "line",      QColor("#262626") },
        { "bg",        QColor("#080808") },
    };
    m_themes.insert(mono.name, mono);

    Theme amber;
    amber.name = "amber";
    amber.colors = {
        { "accent",    QColor("#ffb000") },
        { "text",      QColor("#ffcc66") },
        { "dim",       QColor("#7a5500") },
        { "rowAlt",    QColor("#1a1000") },
        { "rowEven",   QColor("#231400") },
        { "rowSelect", QColor("#4a2a00") },
        { "pane",      QColor("#100a00") },
        { "line",      QColor("#2a1800") },
        { "bg",        QColor("#0a0500") },
    };
    m_themes.insert(amber.name, amber);

    // cyber + ice are also defined in ui-v2/styles.css; their authoritative
    // colors live in the CSS (the React UI swaps on [data-theme=…]) so the
    // values here only matter for the QML legacy host. Approximate RGB
    // conversions of the oklch() values from styles.css.
    Theme cyber;
    cyber.name = "cyber";
    cyber.colors = {
        { "accent",    QColor("#3df0a9") },
        { "text",      QColor("#e9ecf2") },
        { "dim",       QColor("#7d8390") },
        { "rowAlt",    QColor("#181f2c") },
        { "rowEven",   QColor("#141a26") },
        { "rowSelect", QColor("#2d3f3d") },
        { "pane",      QColor("#161e2a") },
        { "line",      QColor("#262f3f") },
        { "bg",        QColor("#0d1422") },
    };
    m_themes.insert(cyber.name, cyber);

    Theme ice;
    ice.name = "ice";
    ice.colors = {
        { "accent",    QColor("#7dc8ec") },
        { "text",      QColor("#e7eef5") },
        { "dim",       QColor("#7a8694") },
        { "rowAlt",    QColor("#161e2a") },
        { "rowEven",   QColor("#121a26") },
        { "rowSelect", QColor("#2c4055") },
        { "pane",      QColor("#161f2c") },
        { "line",      QColor("#252f3d") },
        { "bg",        QColor("#0c1219") },
    };
    m_themes.insert(ice.name, ice);
}

void ThemesManager::loadUserThemes() {
    const QString dir = themesDir();
    QDir().mkpath(dir);
    QDir d(dir);
    for (const QFileInfo &fi : d.entryInfoList({ "*.json" }, QDir::Files)) {
        QFile f(fi.absoluteFilePath());
        if (!f.open(QIODevice::ReadOnly)) continue;
        const QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
        if (!doc.isObject()) continue;
        const QJsonObject root = doc.object();
        const QString name = root.value("name").toString();
        if (name.isEmpty()) continue;

        Theme t;
        t.name = name;
        const QJsonObject colors = root.value("colors").toObject();
        for (auto it = colors.constBegin(); it != colors.constEnd(); ++it) {
            const QColor c(it.value().toString());
            if (c.isValid()) t.colors.insert(it.key(), c);
        }
        m_themes.insert(name, t);
    }
}

} // namespace Nullock::FrontEnd
