#pragma once

#include "frontend_gui_export.hpp"

#include <QColor>
#include <QHash>
#include <QObject>
#include <QString>
#include <QStringList>

namespace Nullock::FrontEnd {

// Single source of truth for the GUI color palette. QML's root
// ApplicationWindow binds its color properties to ThemesManager, so
// switching themes at runtime just changes m_current and fires
// themeChanged -- all Rectangle/Text bindings re-evaluate.
//
// Themes ship as JSON files at <appdata>/Nullock/Nullock/themes/<name>.json:
//
//   {
//     "name": "retro",
//     "colors": {
//       "accent":    "#ff8c1a",
//       "text":      "#80f0c0",
//       ...
//     }
//   }
//
// Two themes are baked in ("retro" and "mono"); user JSON files are
// loaded on startup and supersede the built-ins if they share a name.
class FRONTEND_GUI_EXPORT ThemesManager : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString     currentTheme    READ currentTheme    WRITE setCurrentTheme NOTIFY themeChanged)
    Q_PROPERTY(QStringList availableThemes READ availableThemes                       NOTIFY themesChanged)

    Q_PROPERTY(QColor colorAccent    READ colorAccent    NOTIFY themeChanged)
    Q_PROPERTY(QColor colorText      READ colorText      NOTIFY themeChanged)
    Q_PROPERTY(QColor colorDim       READ colorDim       NOTIFY themeChanged)
    Q_PROPERTY(QColor colorRowAlt    READ colorRowAlt    NOTIFY themeChanged)
    Q_PROPERTY(QColor colorRowEven   READ colorRowEven   NOTIFY themeChanged)
    Q_PROPERTY(QColor colorRowSelect READ colorRowSelect NOTIFY themeChanged)
    Q_PROPERTY(QColor colorPane      READ colorPane      NOTIFY themeChanged)
    Q_PROPERTY(QColor colorLine      READ colorLine      NOTIFY themeChanged)
    Q_PROPERTY(QColor colorBg        READ colorBg        NOTIFY themeChanged)
public:
    explicit ThemesManager(QObject *parent = nullptr);

    QString     currentTheme() const { return m_current; }
    QStringList availableThemes() const;

    QColor colorAccent() const    { return color("accent",    "#ff8c1a"); }
    QColor colorText() const      { return color("text",      "#80f0c0"); }
    QColor colorDim() const       { return color("dim",       "#5a5a5a"); }
    QColor colorRowAlt() const    { return color("rowAlt",    "#141414"); }
    QColor colorRowEven() const   { return color("rowEven",   "#1c1c1c"); }
    QColor colorRowSelect() const { return color("rowSelect", "#3a2010"); }
    QColor colorPane() const      { return color("pane",      "#0f0f0f"); }
    QColor colorLine() const      { return color("line",      "#222222"); }
    QColor colorBg() const        { return color("bg",        "#0a0a0a"); }

    Q_INVOKABLE void setCurrentTheme(const QString &name);
    Q_INVOKABLE QString themesDir() const;
    Q_INVOKABLE bool reload();

signals:
    void themeChanged();
    void themesChanged();

private:
    struct Theme {
        QString name;
        QHash<QString, QColor> colors;
    };

    QColor color(const QString &key, const char *fallbackHex) const;
    void loadBuiltins();
    void loadUserThemes();

    QHash<QString, Theme> m_themes;
    QString m_current;
};

} // namespace Nullock::FrontEnd
