// Regression lock for the bundled detection template library
// (templates/detections/*.json). Every shipped template must:
//   * be valid JSON with a non-empty id / name / severity (honest severity from
//     the known set);
//   * parse through the real template engine with AT LEAST ONE matcher (a
//     template with no matchers silently never fires);
//   * use only known matcher types (status/word/regex).
// This catches a hand-edited template breaking before it ships.
//
// TEMPLATES_DIR is injected by CMake. Run via: ctest -R template_library -V

#include "template_engine_logic.hpp"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSet>
#include <QString>

#include <cstdio>

using namespace Nullock::Core;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    const QSet<QString> knownSev{ "critical", "high", "medium", "low", "info" };
    const QSet<QString> knownMatcher{ "status", "word", "regex" };

    QDir dir(QStringLiteral(TEMPLATES_DIR));
    const QStringList files = dir.entryList({ "*.json" }, QDir::Files, QDir::Name);
    std::fprintf(stderr, "template library dir: %s (%d files)\n",
                 dir.absolutePath().toUtf8().constData(), int(files.size()));
    chk("library has at least 6 templates", files.size() >= 6);

    QSet<QString> ids;
    for (const QString &fn : files) {
        const QByteArray label = fn.toUtf8();
        QFile f(dir.filePath(fn));
        if (!f.open(QIODevice::ReadOnly)) { chk((label + ": open").constData(), false); continue; }
        QJsonParseError pe{};
        const QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &pe);
        if (pe.error != QJsonParseError::NoError || !doc.isObject()) {
            chk((label + ": valid JSON object").constData(), false);
            continue;
        }
        const QJsonObject o = doc.object();

        chk((label + ": id non-empty").constData(), !o.value("id").toString().isEmpty());
        chk((label + ": name non-empty").constData(), !o.value("name").toString().isEmpty());
        chk((label + ": description non-empty").constData(), !o.value("description").toString().isEmpty());
        const QString sev = o.value("severity").toString();
        chk((label + ": severity known").constData(), knownSev.contains(sev));

        // filename should match the id (discoverable by id).
        chk((label + ": filename matches id").constData(), fn == o.value("id").toString() + ".json");

        // unique id.
        const QString id = o.value("id").toString();
        chk((label + ": id unique").constData(), !ids.contains(id));
        ids.insert(id);

        // engine parses it with at least one matcher of a known type.
        const TemplateEngine::Template t = TemplateEngine::parseTemplate(o);
        chk((label + ": has >=1 matcher").constData(), !t.matchers.isEmpty());
        bool allKnown = true;
        for (const auto &m : t.matchers) if (!knownMatcher.contains(m.type)) allKnown = false;
        chk((label + ": matcher types known").constData(), allKnown);
    }

    std::fprintf(stderr, "template_library_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
