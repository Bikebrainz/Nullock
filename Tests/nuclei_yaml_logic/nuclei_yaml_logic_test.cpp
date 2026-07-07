// Tests for the nuclei YAML -> Nullock template shim
// (Src/Core/Networking/nuclei_yaml_logic.cpp). Invariants:
//   * the YAML subset (maps, sequences, sequences-of-maps, quoted/bare scalars,
//     "[a,b]" flow, comments) parses to the right nested JSON;
//   * a realistic nuclei template maps to a Nullock template with the right
//     id/name/severity/matchers/extractors/request(path stripped of {{BaseURL}});
//   * the produced template ROUND-TRIPS through the real template engine and
//     matches/extracts against a response;
//   * garbage/empty input is default-safe (no crash).
//
// Run via:  ctest -R nuclei_yaml_logic -V

#include "nuclei_yaml_logic.hpp"
#include "template_engine_logic.hpp"

#include <QCoreApplication>
#include <QJsonArray>
#include <QJsonObject>

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

    // ----- YAML subset parsing -----
    {
        const QJsonValue v = NucleiYaml::parseYaml(
            "id: t1\n"
            "info:\n"
            "  name: Example\n"
            "  severity: high\n"
            "  count: 3\n"
            "list:\n"
            "  - a\n"
            "  - b\n"
            "flow: [x, y, z]  # a comment\n");
        const QJsonObject o = v.toObject();
        chk("scalar key", o.value("id").toString() == "t1");
        chk("nested map", o.value("info").toObject().value("name").toString() == "Example");
        chk("nested severity", o.value("info").toObject().value("severity").toString() == "high");
        chk("integer scalar", o.value("info").toObject().value("count").toInt() == 3);
        chk("block sequence", o.value("list").toArray().size() == 2
            && o.value("list").toArray().first().toString() == "a");
        chk("flow sequence", o.value("flow").toArray().size() == 3
            && o.value("flow").toArray().at(2).toString() == "z");
        chk("comment stripped", !o.contains("# a comment"));
    }

    // ----- realistic nuclei template -----
    const QString yaml =
        "id: git-config-exposure\n"
        "info:\n"
        "  name: Git Config Exposure\n"
        "  author: pdteam\n"
        "  severity: medium\n"
        "  tags: exposure,git\n"
        "http:\n"
        "  - method: GET\n"
        "    path:\n"
        "      - \"{{BaseURL}}/.git/config\"\n"
        "    matchers-condition: and\n"
        "    matchers:\n"
        "      - type: word\n"
        "        part: body\n"
        "        words:\n"
        "          - \"[core]\"\n"
        "          - \"repositoryformatversion\"\n"
        "        condition: and\n"
        "      - type: status\n"
        "        status:\n"
        "          - 200\n"
        "    extractors:\n"
        "      - type: regex\n"
        "        part: body\n"
        "        name: repo\n"
        "        regex:\n"
        "          - \"url = (.+)\"\n";

    const QJsonObject tpl = NucleiYaml::nucleiYamlToTemplate(yaml);
    chk("map id", tpl.value("id").toString() == "git-config-exposure");
    chk("map name from info", tpl.value("name").toString() == "Git Config Exposure");
    chk("map severity from info", tpl.value("severity").toString() == "medium");
    chk("map matchers-condition", tpl.value("matchers-condition").toString() == "and");
    chk("map matchers count", tpl.value("matchers").toArray().size() == 2);
    chk("map extractors count", tpl.value("extractors").toArray().size() == 1);
    {
        const QJsonObject req = tpl.value("request").toObject();
        chk("request method", req.value("method").toString() == "GET");
        chk("request path strips {{BaseURL}}", req.value("path").toString() == "/.git/config");
    }
    {
        const QJsonObject m0 = tpl.value("matchers").toArray().first().toObject();
        chk("matcher type word", m0.value("type").toString() == "word");
        chk("matcher words carried", m0.value("words").toArray().size() == 2);
        const QJsonObject m1 = tpl.value("matchers").toArray().at(1).toObject();
        chk("matcher status carried", m1.value("status").toArray().first().toInt() == 200);
    }

    // ----- ROUND-TRIP through the real template engine -----
    {
        const TemplateEngine::Template t = TemplateEngine::parseTemplate(tpl);
        chk("engine parsed 2 matchers", t.matchers.size() == 2);
        TemplateEngine::Response r;
        r.statusCode = 200;
        r.headersText = "Content-Type: text/plain\n";
        r.body = "[core]\n\trepositoryformatversion = 0\n[remote]\n\turl = git@github.com:x/y.git\n";
        const TemplateEngine::MatchResult mr = TemplateEngine::evaluate(t, r);
        chk("round-trip: nuclei template matches live response", mr.matched);
        chk("round-trip: extractor captured url",
            mr.extracted.value("repo").contains(QStringLiteral("git@github.com:x/y.git")));

        // negative control: wrong status -> no match (matchers-condition and).
        TemplateEngine::Response r404 = r; r404.statusCode = 404;
        chk("round-trip: 404 -> no match", !TemplateEngine::evaluate(t, r404).matched);
    }

    // ----- default-safe -----
    chk("empty yaml -> empty object", NucleiYaml::nucleiYamlToTemplate("").isEmpty());
    chk("garbage yaml -> no crash, id empty",
        NucleiYaml::nucleiYamlToTemplate(":::\n\t- [[[\n").value("id").toString().isEmpty());
    {
        // a doc with only info still yields id/name, no request.
        const QJsonObject t = NucleiYaml::nucleiYamlToTemplate(
            "id: x\ninfo:\n  name: N\n  severity: low\n");
        chk("no http block -> id/name only", t.value("id").toString() == "x"
            && !t.contains("request"));
    }

    std::fprintf(stderr, "nuclei_yaml_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
