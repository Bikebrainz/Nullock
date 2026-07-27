// Tests for the template/signature match engine
// (Src/Core/Networking/template_engine_logic.cpp). Invariants:
//   * status/word/regex matchers, and/or over values, negative inversion, and
//     and/or across matchers all combine correctly;
//   * part selects body/header/all;
//   * extractors pull capture groups (or whole match);
//   * an invalid regex is a safe no-match (never a throw);
//   * a token past kMaxScan is never seen (bounded scan);
//   * parseTemplate is default-safe on garbage.
//
// Run via:  ctest -R template_engine_logic -V

#include "template_engine_logic.hpp"

#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonObject>

#include <cstdio>

using namespace Nullock::Core::TemplateEngine;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}

Response resp(int status, const QString &headers, const QString &body) {
    Response r; r.statusCode = status; r.headersText = headers; r.body = body; return r;
}

Matcher M(const QString &type, const QString &part, const QStringList &vals,
          const QString &cond = "or", bool neg = false) {
    Matcher m; m.type = type; m.part = part; m.values = vals; m.condition = cond; m.negative = neg;
    return m;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    const Response r = resp(
        200,
        "Content-Type: application/json\nServer: nginx\nSet-Cookie: sid=abc123",
        "{\"status\":\"ok\",\"token\":\"tok_A1B2\",\"role\":\"admin\"}");

    // ----- status matcher -----
    { Template t; t.matchers = { M("status","body",{"200"}) };
      chk("status 200 hits", evaluate(t, r).matched); }
    { Template t; t.matchers = { M("status","body",{"404","500"}) };
      chk("status 404/500 miss", !evaluate(t, r).matched); }

    // ----- word matcher: OR / AND -----
    { Template t; t.matchers = { M("word","body",{"nope","admin"},"or") };
      chk("word OR any hit", evaluate(t, r).matched); }
    { Template t; t.matchers = { M("word","body",{"admin","token"},"and") };
      chk("word AND all present", evaluate(t, r).matched); }
    { Template t; t.matchers = { M("word","body",{"admin","MISSING"},"and") };
      chk("word AND one missing -> miss", !evaluate(t, r).matched); }

    // ----- regex matcher + invalid safety -----
    { Template t; t.matchers = { M("regex","body",{"tok_[A-Z0-9]+"}) };
      chk("regex hit", evaluate(t, r).matched); }
    { Template t; t.matchers = { M("regex","body",{"tok_[0-9]{9,}"}) };
      chk("regex miss", !evaluate(t, r).matched); }
    { Template t; t.matchers = { M("regex","body",{"[unclosed"}) };
      chk("invalid regex -> safe no-match", !evaluate(t, r).matched); }

    // ----- part: header vs body vs all -----
    { Template t; t.matchers = { M("word","header",{"nginx"}) };
      chk("part=header sees Server", evaluate(t, r).matched); }
    { Template t; t.matchers = { M("word","body",{"nginx"}) };
      chk("part=body does NOT see header", !evaluate(t, r).matched); }
    { Template t; t.matchers = { M("word","all",{"nginx"}) };
      chk("part=all sees header", evaluate(t, r).matched); }

    // ----- negative -----
    { Template t; t.matchers = { M("word","body",{"MISSING"},"or",/*neg*/true) };
      chk("negative on absent word -> matches", evaluate(t, r).matched); }
    { Template t; t.matchers = { M("word","body",{"admin"},"or",/*neg*/true) };
      chk("negative on present word -> no match", !evaluate(t, r).matched); }

    // ----- matchers-condition across matchers -----
    { Template t; t.matchersCondition = "and";
      t.matchers = { M("status","body",{"200"}), M("word","body",{"admin"}) };
      chk("AND across matchers: both -> match", evaluate(t, r).matched); }
    { Template t; t.matchersCondition = "and";
      t.matchers = { M("status","body",{"200"}), M("word","body",{"MISSING"}) };
      chk("AND across matchers: one fails -> miss", !evaluate(t, r).matched); }
    { Template t; t.matchersCondition = "or";
      t.matchers = { M("status","body",{"500"}), M("word","body",{"admin"}) };
      chk("OR across matchers: one hits -> match", evaluate(t, r).matched); }

    // ----- empty matchers -> no match -----
    { Template t; chk("empty matchers -> no match", !evaluate(t, r).matched); }

    // ----- extractors -----
    { Template t;
      Extractor e; e.type = "regex"; e.part = "body"; e.name = "token";
      e.values = { "\"token\":\"([^\"]+)\"" };
      t.extractors = { e };
      const MatchResult mr = evaluate(t, r);
      chk("extractor capture group",
          mr.extracted.value("token") == QStringList{ "tok_A1B2" }); }
    { Template t;
      Extractor e; e.type = "regex"; e.part = "header"; e.name = "cookie";
      e.values = { "sid=[a-z0-9]+" };   // no capture group -> whole match
      t.extractors = { e };
      chk("extractor whole match from header",
          evaluate(t, r).extracted.value("cookie") == QStringList{ "sid=abc123" }); }

    // ----- bounded scan: token past kMaxScan is never matched -----
    {
        QString huge(kMaxScan * 2, QLatin1Char('.'));
        huge += "NEEDLE_PAST_CAP";
        Template t; t.matchers = { M("word","body",{"NEEDLE_PAST_CAP"}) };
        chk("word past kMaxScan not matched", !evaluate(t, resp(200, "", huge)).matched);
    }

    // ----- parseTemplate default-safe -----
    {
        const QJsonObject o = QJsonDocument::fromJson(QByteArray(
            "{\"id\":\"t1\",\"name\":\"admin panel\",\"severity\":\"high\","
            "\"matchers-condition\":\"and\","
            "\"matchers\":[{\"type\":\"status\",\"status\":[200]},"
            "{\"type\":\"word\",\"part\":\"body\",\"words\":[\"admin\"]}],"
            "\"extractors\":[{\"type\":\"regex\",\"name\":\"tok\",\"regex\":[\"tok_[A-Z0-9]+\"]}]}"
        )).object();
        const Template t = parseTemplate(o);
        chk("parse id/severity", t.id == "t1" && t.severity == "high");
        chk("parse matchers count", t.matchers.size() == 2);
        chk("parse status values via 'status' key", t.matchers[0].values == QStringList{"200"});
        chk("parse word values via 'words' key", t.matchers[1].values == QStringList{"admin"});
        chk("parse extractor", t.extractors.size() == 1 && t.extractors[0].name == "tok");
        const MatchResult mr = evaluate(t, r);
        chk("parsed template matches + extracts",
            mr.matched && mr.extracted.value("tok") == QStringList{"tok_A1B2"});
    }
    {
        const Template t = parseTemplate(QJsonObject{});
        chk("empty object -> no matchers, no crash", t.matchers.isEmpty() && !evaluate(t, r).matched);
    }
    {
        // wrong types must not throw.
        const QJsonObject o = QJsonDocument::fromJson(
            QByteArray("{\"matchers\":\"nope\",\"extractors\":42}")).object();
        const Template t = parseTemplate(o);
        chk("wrong-typed template -> safe empty", t.matchers.isEmpty() && t.extractors.isEmpty());
    }
    {
        // audit-3: a numeric template value beyond INT64_MAX must not execute an
        // out-of-range double->qint64 cast (UB) and must not stringify to the
        // lossy 6-sig-fig scientific form (QString::number(double) default 'g'/6).
        const QJsonObject o = QJsonDocument::fromJson(QByteArray(
            "{\"matchers\":[{\"type\":\"word\",\"part\":\"body\",\"words\":[12345678901234567890]}]}"
        )).object();
        const Template t = parseTemplate(o);
        chk("parse: huge numeric word value -> one matcher, one value (no crash/UB)",
            t.matchers.size() == 1 && t.matchers[0].values.size() == 1);
        chk("parse: huge numeric value is not the lossy 6-sig-fig form",
            t.matchers.size() == 1 && t.matchers[0].values.size() == 1
            && t.matchers[0].values[0] != "1.23457e+19"
            && !t.matchers[0].values[0].isEmpty());
    }

    std::fprintf(stderr, "template_engine_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
